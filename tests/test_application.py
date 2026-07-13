from __future__ import annotations

import struct

from sniffer.application import decode_application


def fields(layer) -> dict[str, str]:  # noqa: ANN001
    assert layer is not None
    return dict(layer.fields)


def test_decodes_dns_query_name_and_type() -> None:
    question = b"\x03www\x07example\x03com\x00" + struct.pack("!HH", 1, 1)
    payload = struct.pack("!HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0) + question
    layer = decode_application("UDP", 53000, 53, payload)
    assert layer.name == "Domain Name System"
    assert fields(layer)["Query Name"] == "www.example.com"
    assert fields(layer)["Query Type"] == "A"


def test_decodes_http_request_metadata() -> None:
    layer = decode_application("TCP", 50000, 80, b"GET /demo HTTP/1.1\r\nHost: example.test\r\nUser-Agent: Lab\r\n\r\n")
    values = fields(layer)
    assert values["Start Line"] == "GET /demo HTTP/1.1"
    assert values["Host"] == "example.test"


def test_decodes_tls_record_metadata() -> None:
    body = b"\x02\x00\x00\x00"
    layer = decode_application("TCP", 443, 50000, b"\x16\x03\x03" + len(body).to_bytes(2, "big") + body)
    assert fields(layer)["Handshake Type"] == "Server Hello"


def test_invalid_or_encrypted_payload_is_not_claimed_as_decoded() -> None:
    assert decode_application("TCP", 50000, 443, b"encrypted-ish") is None
