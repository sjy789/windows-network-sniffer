from __future__ import annotations

import pytest

from sniffer.formatting import format_hex_ascii, format_payload_summary


def test_hex_ascii_has_aligned_hex_and_printable_columns() -> None:
    result = format_hex_ascii(b"ABC\x00\x7f xyz", width=4)

    assert result.splitlines() == [
        "0000  41 42 43 00  |ABC.|",
        "0004  7F 20 78 79  |. xy|",
        "0008  7A           |z|",
    ]


def test_hex_ascii_limit_discloses_omitted_bytes() -> None:
    result = format_hex_ascii(bytes(range(10)), width=8, limit=3)

    assert "00 01 02" in result
    assert "omitted 7 bytes" in result
    assert "03" not in result.splitlines()[0]


def test_hex_ascii_empty_and_validation() -> None:
    assert format_hex_ascii(b"") == ""
    with pytest.raises(ValueError):
        format_hex_ascii(b"abc", width=0)
    with pytest.raises(ValueError):
        format_hex_ascii(b"abc", limit=-1)


def test_payload_summary_marks_binary_and_truncation() -> None:
    assert format_payload_summary(b"GET /\r\n\x00") == "GET /..."
    assert format_payload_summary(b"abcdef", limit=3) == "abc… (+3 bytes)"


def test_payload_summary_accepts_memoryview() -> None:
    assert format_payload_summary(memoryview(b"hello")) == "hello"
