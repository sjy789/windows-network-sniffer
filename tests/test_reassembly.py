from __future__ import annotations

import struct

import pytest

from sniffer.models import IPv4Fragment
from sniffer.reassembly import IPv4Reassembler


def _checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    total = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def _header(*, flags_offset: int = 0x2000, options: bytes = b"") -> bytes:
    assert len(options) % 4 == 0
    ihl = 5 + len(options) // 4
    header = bytearray(20 + len(options))
    header[0] = (4 << 4) | ihl
    header[1] = 0
    header[2:4] = (28 + len(options)).to_bytes(2, "big")
    header[4:6] = (0x1234).to_bytes(2, "big")
    header[6:8] = flags_offset.to_bytes(2, "big")
    header[8] = 64
    header[9] = 17
    header[12:16] = bytes((192, 0, 2, 10))
    header[16:20] = bytes((198, 51, 100, 20))
    header[20:] = options
    header[10:12] = _checksum(bytes(header)).to_bytes(2, "big")
    return bytes(header)


def _fragment(
    offset: int,
    payload: bytes,
    mf: bool,
    *,
    timestamp: float = 1.0,
    key=("192.0.2.10", "198.51.100.20", 17, 0x1234),
    header: bytes | None = None,
    link_header: bytes = b"ethernet-head",
) -> IPv4Fragment:
    return IPv4Fragment(
        key=key,
        identification=key[3],
        offset_bytes=offset,
        more_fragments=mf,
        payload=payload,
        ip_header=_header() if header is None else header,
        link_header=link_header,
        timestamp=timestamp,
    )


def test_out_of_order_reassembly_builds_valid_ipv4_datagram() -> None:
    reassembler = IPv4Reassembler()

    assert reassembler.add(_fragment(8, b"ijkl", False, timestamp=2)).status == "cached"
    first_header = _header(flags_offset=0x6000, options=b"\x01\x01\x00\x00")
    result = reassembler.add(
        _fragment(0, b"abcdefgh", True, timestamp=3, header=first_header)
    )

    assert result.complete
    assert result.status == "complete"
    assert result.fragment_count == 2
    assert result.link_header == b"ethernet-head"
    assert result.ip_packet is not None
    header_length = (result.ip_packet[0] & 0x0F) * 4
    assert int.from_bytes(result.ip_packet[2:4], "big") == len(result.ip_packet)
    assert int.from_bytes(result.ip_packet[6:8], "big") == 0x4000  # preserve DF only
    assert _checksum(result.ip_packet[:header_length]) == 0
    assert result.ip_packet[header_length:] == b"abcdefghijkl"
    assert reassembler.group_count == 0
    assert reassembler.cached_bytes == 0


def test_completion_requires_first_last_and_continuous_coverage() -> None:
    reassembler = IPv4Reassembler()

    assert reassembler.add(_fragment(0, b"aaaaaaaa", True)).status == "cached"
    assert reassembler.add(_fragment(16, b"cccc", False)).status == "cached"
    result = reassembler.add(_fragment(8, b"bbbbbbbb", True))

    assert result.complete
    assert result.ip_packet is not None
    assert result.ip_packet[20:] == b"aaaaaaaabbbbbbbbcccc"


def test_exact_duplicate_is_ignored_without_consuming_space() -> None:
    reassembler = IPv4Reassembler()
    fragment = _fragment(0, b"abcdefgh", True)

    first = reassembler.add(fragment)
    duplicate = reassembler.add(fragment)

    assert first.status == "cached"
    assert duplicate.status == "duplicate"
    assert duplicate.fragment_count == 1
    assert reassembler.cached_bytes == 8


def test_inconsistent_overlap_is_error_and_discards_group() -> None:
    reassembler = IPv4Reassembler()
    reassembler.add(_fragment(0, b"abcdefgh", True))

    result = reassembler.add(_fragment(4, b"XXXXijkl", True))

    assert result.status == "error"
    assert "overlap" in (result.error or "")
    assert reassembler.group_count == 0
    assert reassembler.cached_bytes == 0


def test_consistent_partial_overlap_can_complete() -> None:
    reassembler = IPv4Reassembler()
    reassembler.add(_fragment(0, b"abcdefgh", True))
    reassembler.add(_fragment(4, b"efghijkl", True))

    result = reassembler.add(_fragment(12, b"mnop", False))

    assert result.complete
    assert result.fragment_count == 3
    assert result.ip_packet is not None
    assert result.ip_packet[20:] == b"abcdefghijklmnop"


def test_conflicting_last_fragments_discard_group() -> None:
    reassembler = IPv4Reassembler()
    reassembler.add(_fragment(16, b"last", False))

    result = reassembler.add(_fragment(24, b"other", False))

    assert result.status == "error"
    assert "final" in (result.error or "")
    assert reassembler.group_count == 0


def test_expire_and_clear_release_accounted_bytes() -> None:
    reassembler = IPv4Reassembler(timeout=30)
    key2 = ("192.0.2.11", "198.51.100.20", 17, 2)
    reassembler.add(_fragment(0, b"abcdefgh", True, timestamp=10))
    reassembler.add(_fragment(0, b"12345678", True, timestamp=25, key=key2))

    expired = reassembler.expire(now=40)

    assert len(expired) == 1
    assert expired[0].status == "expired"
    assert reassembler.group_count == 1
    assert reassembler.cached_bytes == 8
    reassembler.clear()
    assert reassembler.group_count == 0
    assert reassembler.total_bytes == 0


def test_group_and_byte_limits_evict_oldest_groups() -> None:
    key1 = ("192.0.2.1", "198.51.100.1", 17, 1)
    key2 = ("192.0.2.2", "198.51.100.2", 17, 2)
    by_groups = IPv4Reassembler(max_groups=1)
    by_groups.add(_fragment(0, b"11111111", True, timestamp=1, key=key1))
    by_groups.add(_fragment(0, b"22222222", True, timestamp=2, key=key2))
    assert by_groups.group_count == 1
    assert by_groups.cached_bytes == 8

    by_bytes = IPv4Reassembler(max_bytes=10)
    by_bytes.add(_fragment(0, b"11111111", True, timestamp=1, key=key1))
    result = by_bytes.add(_fragment(0, b"22222222", True, timestamp=2, key=key2))
    assert result.status == "cached"
    assert by_bytes.group_count == 1
    assert by_bytes.cached_bytes == 8


def test_single_fragment_over_byte_limit_is_rejected() -> None:
    reassembler = IPv4Reassembler(max_bytes=4)
    result = reassembler.add(_fragment(0, b"12345", True))
    assert result.status == "error"
    assert reassembler.group_count == 0


def test_non_final_fragment_requires_eight_byte_payload_alignment() -> None:
    reassembler = IPv4Reassembler()

    result = reassembler.add(_fragment(0, b"1234567", True))

    assert result.status == "error"
    assert "multiple of 8" in (result.error or "")
    assert reassembler.group_count == 0


def test_invalid_first_header_is_reported_when_coverage_completes() -> None:
    reassembler = IPv4Reassembler()
    result = reassembler.add(_fragment(0, b"payload", False, header=b"bad"))
    assert result.status == "error"
    assert not result.complete
    assert "header" in (result.error or "")


@pytest.mark.parametrize(
    ("kwargs", "message"),
    [
        ({"timeout": 0}, "timeout"),
        ({"max_groups": 0}, "max_groups"),
        ({"max_bytes": 0}, "max_bytes"),
    ],
)
def test_invalid_configuration(kwargs: dict[str, int], message: str) -> None:
    with pytest.raises(ValueError, match=message):
        IPv4Reassembler(**kwargs)
