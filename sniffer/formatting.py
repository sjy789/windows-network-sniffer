"""Formatting helpers used by the packet detail view.

The functions in this module deliberately work on bytes only.  Keeping them
independent from Scapy makes them usable for captured packets, reassembled
packets and the parser unit tests alike.
"""

from __future__ import annotations

BytesLike = bytes | bytearray | memoryview


def _as_bytes(data: BytesLike) -> bytes:
    """Return *data* as immutable bytes with a useful error for bad callers."""

    try:
        return bytes(data)
    except (TypeError, ValueError) as exc:  # pragma: no cover - defensive API guard
        raise TypeError("data must be a bytes-like object") from exc


def format_hex_ascii(
    data: BytesLike,
    width: int = 16,
    limit: int | None = None,
) -> str:
    """Format bytes as an offset/hex/ASCII dump.

    ``limit`` limits display only; it never changes the packet stored by the
    caller.  A final line states how many bytes were omitted, which avoids the
    misleading impression that the packet itself was truncated.
    """

    if width <= 0:
        raise ValueError("width must be greater than zero")
    if limit is not None and limit < 0:
        raise ValueError("limit must be non-negative or None")

    raw = _as_bytes(data)
    shown = raw if limit is None else raw[:limit]
    # Four digits are familiar for normal frames, but large reassembled
    # datagrams need enough digits to keep offsets aligned.
    offset_width = max(4, len(f"{max(len(shown) - 1, 0):X}"))
    lines: list[str] = []

    for offset in range(0, len(shown), width):
        chunk = shown[offset : offset + width]
        hex_text = " ".join(f"{value:02X}" for value in chunk)
        # Each byte consumes three columns except the final byte.  Using
        # ``width * 3 - 1`` keeps the ASCII column fixed on short final rows.
        hex_text = hex_text.ljust(width * 3 - 1)
        ascii_text = "".join(chr(value) if 0x20 <= value <= 0x7E else "." for value in chunk)
        lines.append(f"{offset:0{offset_width}X}  {hex_text}  |{ascii_text}|")

    omitted = len(raw) - len(shown)
    if omitted:
        lines.append(f"... omitted {omitted} byte{'s' if omitted != 1 else ''} ...")
    return "\n".join(lines)


def format_payload_summary(
    data: BytesLike,
    limit: int = 64,
) -> str:
    """Return a compact printable-ASCII preview of application payload bytes.

    Non-printable bytes are represented by a dot.  This is intentionally a
    preview rather than a decoder: encrypted, compressed or binary payloads
    must not be mistaken for application text.
    """

    if limit < 0:
        raise ValueError("limit must be non-negative")
    raw = _as_bytes(data)
    shown = raw[:limit]
    text = "".join(chr(value) if 0x20 <= value <= 0x7E else "." for value in shown)
    if len(raw) > len(shown):
        text += f"… (+{len(raw) - len(shown)} bytes)"
    return text


# Short, discoverable aliases for GUI and third-party callers.
payload_summary = format_payload_summary
printable_payload_summary = format_payload_summary


__all__ = [
    "format_hex_ascii",
    "format_payload_summary",
    "payload_summary",
    "printable_payload_summary",
]
