"""Bounded IPv4 fragment reassembly.

The capture/parser boundary passes only the IPv4 header and payload to this
module.  Reassembly is deliberately independent from Scapy so the behaviour
is deterministic for live capture and offline tests alike.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import time

from .models import FragmentKey, IPv4Fragment, ReassemblyResult


@dataclass(slots=True)
class _StoredFragment:
    offset: int
    payload: bytes
    more_fragments: bool

    @property
    def end(self) -> int:
        return self.offset + len(self.payload)


@dataclass(slots=True)
class _FragmentGroup:
    key: FragmentKey
    created_at: float
    updated_at: float
    fragments: list[_StoredFragment] = field(default_factory=list)
    first_header: bytes | None = None
    first_link_header: bytes = b""
    final_size: int | None = None
    stored_bytes: int = 0


class IPv4Reassembler:
    """Reassemble IPv4 fragments while enforcing finite cache limits.

    ``max_bytes`` counts accepted fragment payload bytes.  Exact duplicate
    fragments do not consume additional space.  When a cache limit is met,
    the least-recently-updated *other* datagrams are evicted first so an
    actively arriving datagram can still make progress.
    """

    def __init__(
        self,
        timeout: float = 30.0,
        max_groups: int = 1024,
        max_bytes: int = 64 * 1024 * 1024,
    ) -> None:
        if timeout <= 0:
            raise ValueError("timeout must be greater than zero")
        if max_groups <= 0:
            raise ValueError("max_groups must be greater than zero")
        if max_bytes <= 0:
            raise ValueError("max_bytes must be greater than zero")

        self.timeout = float(timeout)
        self.max_groups = int(max_groups)
        self.max_bytes = int(max_bytes)
        self._groups: dict[FragmentKey, _FragmentGroup] = {}
        self._cached_bytes = 0

    @property
    def group_count(self) -> int:
        return len(self._groups)

    @property
    def cached_bytes(self) -> int:
        return self._cached_bytes

    # A readable alias is useful to callers displaying cache statistics.
    @property
    def total_bytes(self) -> int:
        return self._cached_bytes

    def add(self, fragment: IPv4Fragment) -> ReassemblyResult:
        """Add one fragment and return its cache/reassembly outcome."""

        self.expire(now=fragment.timestamp)
        key = fragment.key

        if fragment.offset_bytes < 0:
            return self._standalone_error(key, "fragment offset cannot be negative")
        if not fragment.payload and fragment.more_fragments:
            return self._standalone_error(key, "non-final fragment has an empty payload")
        if fragment.more_fragments and len(fragment.payload) % 8 != 0:
            self._drop(key)
            return self._standalone_error(
                key,
                "non-final fragment payload length must be a multiple of 8",
            )
        if len(fragment.payload) > self.max_bytes:
            self._drop(key)
            return self._standalone_error(key, "fragment exceeds reassembly byte limit")

        group = self._groups.get(key)
        if group is None:
            self._make_room_for_group()
            group = _FragmentGroup(
                key=key,
                created_at=fragment.timestamp,
                updated_at=fragment.timestamp,
            )
            self._groups[key] = group

        new = _StoredFragment(
            offset=fragment.offset_bytes,
            payload=bytes(fragment.payload),
            more_fragments=fragment.more_fragments,
        )

        duplicate = self._find_duplicate(group, new)
        if duplicate:
            group.updated_at = max(group.updated_at, fragment.timestamp)
            return self._result(group, status="duplicate")

        conflict = self._find_conflict(group, new)
        if conflict is not None:
            count = len(group.fragments)
            self._drop(key)
            return ReassemblyResult(
                key=key,
                fragment_count=count,
                status="error",
                error=conflict,
            )

        new_end = new.end
        if not new.more_fragments:
            if group.final_size is not None and group.final_size != new_end:
                count = len(group.fragments)
                self._drop(key)
                return ReassemblyResult(
                    key=key,
                    fragment_count=count,
                    status="error",
                    error="conflicting final fragment sizes",
                )
            if any(existing.end > new_end for existing in group.fragments):
                count = len(group.fragments)
                self._drop(key)
                return ReassemblyResult(
                    key=key,
                    fragment_count=count,
                    status="error",
                    error="fragment data extends beyond the final fragment",
                )
            group.final_size = new_end
        elif group.final_size is not None and new_end > group.final_size:
            count = len(group.fragments)
            self._drop(key)
            return ReassemblyResult(
                key=key,
                fragment_count=count,
                status="error",
                error="fragment data extends beyond the final fragment",
            )

        group.fragments.append(new)
        group.stored_bytes += len(new.payload)
        group.updated_at = max(group.updated_at, fragment.timestamp)
        self._cached_bytes += len(new.payload)

        if new.offset == 0 and group.first_header is None:
            group.first_header = bytes(fragment.ip_header)
            group.first_link_header = bytes(fragment.link_header)

        if not self._make_room_for_bytes(protected_key=key):
            count = len(group.fragments)
            self._drop(key)
            return ReassemblyResult(
                key=key,
                fragment_count=count,
                status="error",
                error="reassembly cache byte limit exceeded",
            )

        payload = self._complete_payload(group)
        if payload is None:
            return self._result(group, status="cached")

        try:
            ip_packet = _build_ipv4_packet(group.first_header or b"", payload)
        except ValueError as exc:
            count = len(group.fragments)
            self._drop(key)
            return ReassemblyResult(
                key=key,
                fragment_count=count,
                status="error",
                error=str(exc),
            )

        result = ReassemblyResult(
            key=key,
            complete=True,
            ip_packet=ip_packet,
            link_header=group.first_link_header,
            fragment_count=len(group.fragments),
            status="complete",
        )
        self._drop(key)
        return result

    def expire(self, now: float | None = None) -> list[ReassemblyResult]:
        """Remove timed-out groups and describe each removed datagram."""

        current = time.time() if now is None else float(now)
        expired: list[ReassemblyResult] = []
        for key, group in list(self._groups.items()):
            if current - group.updated_at >= self.timeout:
                expired.append(
                    ReassemblyResult(
                        key=key,
                        fragment_count=len(group.fragments),
                        status="expired",
                        error="fragment reassembly timed out",
                    )
                )
                self._drop(key)
        return expired

    def clear(self) -> None:
        """Discard every cached fragment group."""

        self._groups.clear()
        self._cached_bytes = 0

    @staticmethod
    def _find_duplicate(group: _FragmentGroup, new: _StoredFragment) -> bool:
        return any(
            old.offset == new.offset
            and old.payload == new.payload
            and old.more_fragments == new.more_fragments
            for old in group.fragments
        )

    @staticmethod
    def _find_conflict(group: _FragmentGroup, new: _StoredFragment) -> str | None:
        for old in group.fragments:
            # Identical bytes with contradictory MF meaning are not a benign
            # retransmission, even though their payload overlap is consistent.
            if (
                old.offset == new.offset
                and old.payload == new.payload
                and old.more_fragments != new.more_fragments
            ):
                return "duplicate fragment has inconsistent MF flag"

            overlap_start = max(old.offset, new.offset)
            overlap_end = min(old.end, new.end)
            if overlap_start >= overlap_end:
                continue
            old_bytes = old.payload[overlap_start - old.offset : overlap_end - old.offset]
            new_bytes = new.payload[overlap_start - new.offset : overlap_end - new.offset]
            if old_bytes != new_bytes:
                return "inconsistent overlapping fragments"
        return None

    @staticmethod
    def _complete_payload(group: _FragmentGroup) -> bytes | None:
        if group.first_header is None or group.final_size is None:
            return None

        final_size = group.final_size
        ordered = sorted(group.fragments, key=lambda item: (item.offset, item.end))
        cursor = 0
        for item in ordered:
            if item.offset > cursor:
                return None
            cursor = max(cursor, min(item.end, final_size))
            if cursor >= final_size:
                break
        if cursor < final_size:
            return None

        payload = bytearray(final_size)
        for item in ordered:
            if item.offset >= final_size:
                continue
            end = min(item.end, final_size)
            payload[item.offset:end] = item.payload[: end - item.offset]
        return bytes(payload)

    def _make_room_for_group(self) -> None:
        while len(self._groups) >= self.max_groups:
            oldest = min(
                self._groups.values(),
                key=lambda group: (group.updated_at, group.created_at),
            )
            self._drop(oldest.key)

    def _make_room_for_bytes(self, protected_key: FragmentKey) -> bool:
        while self._cached_bytes > self.max_bytes:
            candidates = [
                group for key, group in self._groups.items() if key != protected_key
            ]
            if not candidates:
                return False
            oldest = min(candidates, key=lambda group: (group.updated_at, group.created_at))
            self._drop(oldest.key)
        return True

    def _drop(self, key: FragmentKey) -> None:
        group = self._groups.pop(key, None)
        if group is not None:
            self._cached_bytes -= group.stored_bytes
            # Defensive normalization guards against accounting drift if a
            # future caller changes group mutation order.
            if self._cached_bytes < 0:
                self._cached_bytes = 0

    @staticmethod
    def _result(group: _FragmentGroup, status: str) -> ReassemblyResult:
        return ReassemblyResult(
            key=group.key,
            fragment_count=len(group.fragments),
            status=status,
        )

    @staticmethod
    def _standalone_error(key: FragmentKey, message: str) -> ReassemblyResult:
        return ReassemblyResult(key=key, status="error", error=message)


def _build_ipv4_packet(header_bytes: bytes, payload: bytes) -> bytes:
    """Create an unfragmented IPv4 datagram and recalculate its checksum."""

    if len(header_bytes) < 20:
        raise ValueError("first fragment contains an invalid IPv4 header")
    if header_bytes[0] >> 4 != 4:
        raise ValueError("first fragment is not IPv4")

    header_length = (header_bytes[0] & 0x0F) * 4
    if header_length < 20 or header_length > len(header_bytes):
        raise ValueError("first fragment contains an invalid IPv4 header length")
    total_length = header_length + len(payload)
    if total_length > 0xFFFF:
        raise ValueError("reassembled IPv4 datagram exceeds 65535 bytes")

    header = bytearray(header_bytes[:header_length])
    header[2:4] = total_length.to_bytes(2, "big")
    flags_and_offset = int.from_bytes(header[6:8], "big")
    header[6:8] = (flags_and_offset & 0x4000).to_bytes(2, "big")
    header[10:12] = b"\x00\x00"
    header[10:12] = _internet_checksum(header).to_bytes(2, "big")
    return bytes(header) + payload


def _internet_checksum(data: bytes | bytearray) -> int:
    if len(data) % 2:
        data = bytes(data) + b"\x00"
    total = sum(int.from_bytes(data[index : index + 2], "big") for index in range(0, len(data), 2))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF
