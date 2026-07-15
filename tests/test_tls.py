from __future__ import annotations

from scapy.all import Ether, IP, Raw, TCP
from scapy.utils import wrpcap

from sniffer.models import PacketRecord
from sniffer.offline import load_capture_file
from sniffer.parser import PacketParser
from sniffer.tls import TLSStreamReassembler, parse_client_hello


def client_hello(*, host: str | None = "example.com", alpn: tuple[str, ...] = ("h2", "http/1.1")) -> bytes:
    extensions = bytearray()
    if host is not None:
        encoded = host.encode("ascii")
        names = b"\x00" + len(encoded).to_bytes(2, "big") + encoded
        value = len(names).to_bytes(2, "big") + names
        extensions += b"\x00\x00" + len(value).to_bytes(2, "big") + value
    if alpn:
        names = b"".join(bytes([len(item)]) + item.encode("ascii") for item in alpn)
        value = len(names).to_bytes(2, "big") + names
        extensions += b"\x00\x10" + len(value).to_bytes(2, "big") + value

    body = b"\x03\x03" + bytes(range(32))
    body += b"\x00"  # session id
    body += b"\x00\x02\x13\x01"  # one cipher suite
    body += b"\x01\x00"  # null compression
    body += len(extensions).to_bytes(2, "big") + extensions
    handshake = b"\x01" + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x01" + len(handshake).to_bytes(2, "big") + handshake


def record(payload: bytes, sequence: int) -> PacketRecord:
    return PacketRecord(
        timestamp=10.0,
        raw=b"",
        length=len(payload),
        source="192.0.2.10",
        destination="198.51.100.20",
        protocol="TLS",
        source_port=51000,
        destination_port=443,
        transport_payload=payload,
        tcp_sequence=sequence,
    )


def test_client_hello_decodes_sni_and_alpn() -> None:
    result = parse_client_hello(client_hello())

    assert result.status == "complete"
    assert result.hello is not None
    assert result.hello.server_name == "example.com"
    assert result.hello.alpn_protocols == ("h2", "http/1.1")


def test_optional_sni_and_alpn_are_explicitly_absent() -> None:
    result = parse_client_hello(client_hello(host=None, alpn=()))

    assert result.status == "complete"
    assert result.hello is not None
    assert result.hello.server_name is None
    assert result.hello.alpn_protocols == ()


def test_truncated_client_hello_is_incomplete_not_malformed() -> None:
    payload = client_hello()

    assert parse_client_hello(payload[:20]).status == "incomplete"


def test_invalid_sni_vector_is_rejected() -> None:
    payload = bytearray(client_hello())
    # Locate SNI extension value and make its inner list one byte too large.
    # TLS record (5) + handshake header (4) + ClientHello prefix (43) +
    # extension type/length (4).
    value_start = 56
    payload[value_start : value_start + 2] = (999).to_bytes(2, "big")

    result = parse_client_hello(bytes(payload))

    assert result.status == "malformed"
    assert result.error and "SNI list length" in result.error


def test_tcp_reassembler_handles_out_of_order_client_hello_segments() -> None:
    payload = client_hello()
    split = 27
    reassembler = TLSStreamReassembler()
    later = record(payload[split:], 1000 + split)
    first = record(payload[:split], 1000)

    assert reassembler.process(later).status == "incomplete"
    result = reassembler.process(first)

    assert result.status == "complete"
    fields = dict(next(layer for layer in first.layers if layer.name == "TLS ClientHello").fields)
    assert fields["Server Name (SNI)"] == "example.com"
    assert fields["ALPN Protocols"] == "h2, http/1.1"
    assert fields["TCP Reassembly"] == "是"


def test_tcp_reassembler_handles_sequence_number_wraparound() -> None:
    payload = client_hello()
    split = 24
    first_sequence = 0xFFFFFFF0
    reassembler = TLSStreamReassembler()
    first = record(payload[:split], first_sequence)
    wrapped_sequence = (first_sequence + split) & 0xFFFFFFFF
    second = record(payload[split:], wrapped_sequence)

    assert reassembler.process(first).status == "incomplete"
    assert reassembler.process(second).status == "complete"


def test_packet_parser_attaches_client_hello_metadata() -> None:
    payload = client_hello()
    packet = (
        Ether()
        / IP(src="192.0.2.10", dst="198.51.100.20")
        / TCP(sport=51000, dport=443, seq=1000)
        / Raw(payload)
    )

    parsed = PacketParser().parse(bytes(packet))

    fields = dict(next(layer for layer in parsed.layers if layer.name == "TLS ClientHello").fields)
    assert fields["Server Name (SNI)"] == "example.com"
    assert fields["ALPN Protocols"] == "h2, http/1.1"
    assert parsed.transport_payload == payload


def test_offline_loader_reassembles_split_client_hello(tmp_path) -> None:
    payload = client_hello()
    split = 31
    packets = [
        Ether()
        / IP(src="192.0.2.10", dst="198.51.100.20")
        / TCP(sport=51000, dport=443, seq=1000)
        / Raw(payload[:split]),
        Ether()
        / IP(src="192.0.2.10", dst="198.51.100.20")
        / TCP(sport=51000, dport=443, seq=1000 + split)
        / Raw(payload[split:]),
    ]
    target = tmp_path / "split-client-hello.pcap"
    wrpcap(str(target), packets)

    loaded = load_capture_file(target)

    completing_record = loaded.records[-1]
    fields = dict(
        next(layer for layer in completing_record.layers if layer.name == "TLS ClientHello").fields
    )
    assert fields["Server Name (SNI)"] == "example.com"
    assert fields["TCP Reassembly"] == "是"
