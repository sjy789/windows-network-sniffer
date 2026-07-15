"""Real-time traffic metrics and bidirectional transport-flow aggregation."""

from __future__ import annotations

from collections import Counter, deque
from dataclasses import dataclass, field
import struct
from typing import Iterable

from .models import PacketRecord


@dataclass(slots=True)
class TrafficPoint:
    timestamp: float
    packets: int
    bytes: int


class TrafficMeter:
    """Keep a bounded, one-second time series for the live dashboard."""

    def __init__(self, window: int = 60) -> None:
        self.window = window
        self.points: deque[TrafficPoint] = deque(maxlen=window)
        self.protocols: Counter[str] = Counter()
        self.total_packets = 0
        self.total_bytes = 0

    def add(self, records: Iterable[PacketRecord]) -> None:
        buckets: dict[int, list[int]] = {}
        for record in records:
            # Reassembled records are synthetic analysis results, not another
            # frame observed on the wire.  Counting them inflates traffic rate.
            if record.is_reassembled:
                continue
            second = int(record.timestamp)
            bucket = buckets.setdefault(second, [0, 0])
            bucket[0] += 1
            bucket[1] += record.length
            self.total_packets += 1
            self.total_bytes += record.length
            self.protocols[record.protocol or "UNKNOWN"] += 1
        for second in sorted(buckets):
            packets, byte_count = buckets[second]
            if self.points and int(self.points[-1].timestamp) == second:
                point = self.points[-1]
                point.packets += packets
                point.bytes += byte_count
            else:
                self.points.append(TrafficPoint(float(second), packets, byte_count))

    def clear(self) -> None:
        self.points.clear()
        self.protocols.clear()
        self.total_packets = self.total_bytes = 0


@dataclass(slots=True)
class Flow:
    protocol: str
    endpoint_a: tuple[str, int]
    endpoint_b: tuple[str, int]
    first_seen: float
    last_seen: float
    packets_ab: int = 0
    packets_ba: int = 0
    bytes_ab: int = 0
    bytes_ba: int = 0
    tcp_state: str = "—"
    flags: set[str] = field(default_factory=set)
    stream_ab: bytearray = field(default_factory=bytearray, repr=False)
    stream_ba: bytearray = field(default_factory=bytearray, repr=False)
    segments_ab: dict[int, bytes] = field(default_factory=dict, repr=False)
    segments_ba: dict[int, bytes] = field(default_factory=dict, repr=False)

    @property
    def duration(self) -> float:
        return max(0.0, self.last_seen - self.first_seen)

    @property
    def packet_count(self) -> int:
        return self.packets_ab + self.packets_ba

    @property
    def byte_count(self) -> int:
        return self.bytes_ab + self.bytes_ba

    def stream_text(self, limit: int = 256_000) -> str:
        def render(label: str, data: bytearray) -> str:
            clipped = bytes(data[:limit])
            text = clipped.decode("utf-8", errors="replace")
            suffix = "\n… stream truncated …" if len(data) > limit else ""
            return f"[{label} | {len(data)} bytes]\n{text}{suffix}"
        return render("A → B", self.stream_ab) + "\n\n" + render("B → A", self.stream_ba)


class FlowTracker:
    """Aggregate TCP/UDP packets into stable, direction-aware conversations."""

    def __init__(self, max_flows: int = 5000, max_stream_bytes: int = 2_000_000) -> None:
        self.max_flows = max_flows
        self.max_stream_bytes = max_stream_bytes
        self._flows: dict[tuple[object, ...], Flow] = {}

    @property
    def flows(self) -> list[Flow]:
        return sorted(self._flows.values(), key=lambda flow: flow.last_seen, reverse=True)

    def clear(self) -> None:
        self._flows.clear()

    def add(self, records: Iterable[PacketRecord]) -> None:
        for record in records:
            # Do not create a partial transport conversation from the first IP
            # fragment and then count the reassembled virtual record again.
            if record.fragment is not None:
                continue
            transport = self._transport(record)
            if transport not in {"TCP", "UDP"} or record.source_port is None or record.destination_port is None:
                continue
            source = (record.source, record.source_port)
            destination = (record.destination, record.destination_port)
            first, second = sorted((source, destination))
            key = (transport, first, second)
            flow = self._flows.get(key)
            if flow is None:
                if len(self._flows) >= self.max_flows:
                    oldest = min(self._flows, key=lambda item: self._flows[item].last_seen)
                    del self._flows[oldest]
                flow = Flow(transport, first, second, record.timestamp, record.timestamp)
                self._flows[key] = flow
            flow.last_seen = max(flow.last_seen, record.timestamp)
            ab = source == flow.endpoint_a
            if ab:
                flow.packets_ab += 1
                flow.bytes_ab += record.length
            else:
                flow.packets_ba += 1
                flow.bytes_ba += record.length
            if transport == "TCP":
                sequence, flags, payload = _tcp_segment(record)
                flow.flags.update(flags)
                if "RST" in flags:
                    flow.tcp_state = "Reset"
                elif "FIN" in flags:
                    flow.tcp_state = "Closing"
                elif "SYN" in flags and "ACK" in flags:
                    flow.tcp_state = "Handshake"
                elif "SYN" in flags:
                    flow.tcp_state = "Opening"
                elif "ACK" in flags:
                    flow.tcp_state = "Established"
                if payload:
                    segments = flow.segments_ab if ab else flow.segments_ba
                    segments.setdefault(sequence, payload)
                    self._rebuild_stream(flow, ab)

    def _rebuild_stream(self, flow: Flow, ab: bool) -> None:
        segments = flow.segments_ab if ab else flow.segments_ba
        stream = flow.stream_ab if ab else flow.stream_ba
        stream.clear()
        next_sequence: int | None = None
        for sequence, payload in sorted(segments.items()):
            if next_sequence is not None and sequence < next_sequence:
                payload = payload[next_sequence - sequence :]
            if payload and len(stream) < self.max_stream_bytes:
                stream.extend(payload[: self.max_stream_bytes - len(stream)])
                next_sequence = sequence + len(payload)

    @staticmethod
    def _transport(record: PacketRecord) -> str:
        names = {layer.name for layer in record.layers}
        if "Transmission Control Protocol" in names:
            return "TCP"
        if "User Datagram Protocol" in names:
            return "UDP"
        return record.protocol.upper()


def _tcp_segment(record: PacketRecord) -> tuple[int, set[str], bytes]:
    """Extract TCP sequence, flags and payload from supported raw frame layouts."""
    raw = record.raw
    offset = 0
    normalized_link_type = record.link_type.strip().lower().replace("_", "-")
    if normalized_link_type in {"ethernet", "ether", "en10mb"}:
        if len(raw) < 14:
            return 0, set(), b""
        offset = 14
        ethertype = int.from_bytes(raw[12:14], "big")
        while ethertype in {0x8100, 0x88A8, 0x9100} and offset + 4 <= len(raw):
            ethertype = int.from_bytes(raw[offset + 2 : offset + 4], "big")
            offset += 4
        if ethertype not in {0x0800, 0x86DD}:
            return 0, set(), b""
    elif normalized_link_type in {"loopback", "null", "dlt-null"}:
        if len(raw) < 4:
            return 0, set(), b""
        offset = 4
    if offset >= len(raw):
        return 0, set(), b""
    version = raw[offset] >> 4
    if version == 4:
        if offset + 20 > len(raw) or raw[offset + 9] != 6:
            return 0, set(), b""
        ihl = (raw[offset] & 0x0F) * 4
        total = int.from_bytes(raw[offset + 2 : offset + 4], "big")
        tcp = offset + ihl
        end = min(len(raw), offset + total)
    elif version == 6:
        located = _ipv6_tcp_bounds(raw, offset)
        if located is None:
            return 0, set(), b""
        tcp, end = located
    else:
        return 0, set(), b""
    if tcp + 20 > end:
        return 0, set(), b""
    sequence = struct.unpack_from("!I", raw, tcp + 4)[0]
    header_length = (raw[tcp + 12] >> 4) * 4
    value = ((raw[tcp + 12] & 1) << 8) | raw[tcp + 13]
    names = ("FIN", "SYN", "RST", "PSH", "ACK", "URG", "ECE", "CWR")
    flags = {name for bit, name in enumerate(names) if value & (1 << bit)}
    payload_start = tcp + header_length
    return sequence, flags, raw[payload_start:end] if payload_start <= end else b""


def _ipv6_tcp_bounds(raw: bytes, offset: int) -> tuple[int, int] | None:
    """Return TCP offset/end while safely walking common IPv6 extensions."""

    if offset + 40 > len(raw):
        return None
    payload_length = int.from_bytes(raw[offset + 4 : offset + 6], "big")
    end = len(raw) if payload_length == 0 else min(len(raw), offset + 40 + payload_length)
    next_header = raw[offset + 6]
    cursor = offset + 40
    for _ in range(16):
        if next_header == 6:
            return (cursor, end)
        if next_header in {0, 43, 60}:  # Hop-by-Hop, Routing, Destination
            if cursor + 2 > end:
                return None
            header_length = (raw[cursor + 1] + 1) * 8
        elif next_header == 44:  # Fragment
            if cursor + 8 > end:
                return None
            flags_offset = int.from_bytes(raw[cursor + 2 : cursor + 4], "big")
            if (flags_offset >> 3) != 0:
                return None
            header_length = 8
        elif next_header == 51:  # Authentication Header
            if cursor + 2 > end:
                return None
            header_length = (raw[cursor + 1] + 2) * 4
        else:
            return None
        if header_length <= 0 or cursor + header_length > end:
            return None
        next_header = raw[cursor]
        cursor += header_length
    return None


__all__ = ["Flow", "FlowTracker", "TrafficMeter", "TrafficPoint"]
