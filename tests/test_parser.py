from __future__ import annotations

import ipaddress
import struct

import pytest

from sniffer.parser import PacketParser


DESTINATION_MAC = bytes.fromhex("001122334455")
SOURCE_MAC = bytes.fromhex("AABBCCDDEEFF")


def ethernet_header(ethertype: int = 0x0800) -> bytes:
    return DESTINATION_MAC + SOURCE_MAC + struct.pack("!H", ethertype)


def ipv4_packet(
    payload: bytes,
    *,
    protocol: int,
    source: str = "192.0.2.1",
    destination: str = "198.51.100.2",
    identification: int = 0x1234,
    flags_fragment: int = 0,
    options: bytes = b"",
    total_length: int | None = None,
) -> bytes:
    assert len(options) % 4 == 0
    header_length = 20 + len(options)
    version_ihl = (4 << 4) | (header_length // 4)
    declared_length = total_length if total_length is not None else header_length + len(payload)
    fixed = struct.pack(
        "!BBHHHBBH4s4s",
        version_ihl,
        0x2E,
        declared_length,
        identification,
        flags_fragment,
        64,
        protocol,
        0xABCD,
        ipaddress.ip_address(source).packed,
        ipaddress.ip_address(destination).packed,
    )
    return fixed + options + payload


def tcp_segment(payload: bytes = b"", *, options: bytes = b"") -> bytes:
    assert len(options) % 4 == 0
    offset_words = (20 + len(options)) // 4
    return struct.pack(
        "!HHIIBBHHH",
        12345,
        443,
        0x01020304,
        0x05060708,
        offset_words << 4,
        0x12,  # SYN + ACK
        8192,
        0xBEEF,
        0,
    ) + options + payload


def udp_datagram(payload: bytes = b"", *, declared_length: int | None = None) -> bytes:
    length = 8 + len(payload) if declared_length is None else declared_length
    return struct.pack("!HHHH", 5353, 9999, length, 0xCAFE) + payload


def icmp_echo(payload: bytes = b"") -> bytes:
    return struct.pack("!BBHHH", 8, 0, 0x1234, 0x5678, 9) + payload


def fields_for(record, layer_name: str) -> dict[str, str]:
    layer = next(layer for layer in record.layers if layer.name == layer_name)
    return dict(layer.fields)


class PoisonOriginalPacket:
    """Any attempt to use captured-object protocol fields fails the test."""

    def __getattribute__(self, name: str):
        if name.startswith("__"):
            return object.__getattribute__(self, name)
        raise AssertionError(f"parser accessed original_packet.{name}")


def test_parser_decodes_double_vlan_ipv4_tcp_options_from_bytes_only() -> None:
    parser = PacketParser()
    tcp = tcp_segment(b"hello", options=b"\x02\x04\x05\xB4")
    ip = ipv4_packet(tcp, protocol=6, options=b"\x01\x01\x00\x00")
    # Provider VLAN 100, then customer VLAN 42.
    frame = (
        DESTINATION_MAC
        + SOURCE_MAC
        + struct.pack("!HHHHH", 0x88A8, 100, 0x8100, 42, 0x0800)
        + ip
    )
    poison = PoisonOriginalPacket()

    record = parser.parse(frame, timestamp=123.5, original_packet=poison)

    assert record.errors == []
    assert record.timestamp == 123.5
    assert record.original_packet is poison
    assert record.protocol == "TLS"
    assert record.source == "192.0.2.1"
    assert record.destination == "198.51.100.2"
    assert (record.source_port, record.destination_port) == (12345, 443)
    assert [layer.name for layer in record.layers].count("802.1Q VLAN") == 2
    assert fields_for(record, "Internet Protocol Version 4")["Header Length"].startswith("24 bytes")
    tcp_fields = fields_for(record, "Transmission Control Protocol")
    assert tcp_fields["Sequence Number"] == str(0x01020304)
    assert "SYN" in tcp_fields["Flags"] and "ACK" in tcp_fields["Flags"]
    assert tcp_fields["Options"] == "MSS 1460"
    assert fields_for(record, "Data")["Printable Preview"] == "hello"


def test_parser_decodes_arp_addresses_and_operation() -> None:
    arp = struct.pack("!HHBBH", 1, 0x0800, 6, 4, 1)
    arp += SOURCE_MAC + ipaddress.ip_address("10.0.0.5").packed
    arp += bytes(6) + ipaddress.ip_address("10.0.0.1").packed

    record = PacketParser().parse(ethernet_header(0x0806) + arp)

    assert record.errors == []
    assert record.protocol == "ARP"
    assert record.source == "10.0.0.5"
    assert record.destination == "10.0.0.1"
    assert record.info == "Who has 10.0.0.1? Tell 10.0.0.5"
    arp_fields = fields_for(record, "Address Resolution Protocol")
    assert arp_fields["Sender MAC"] == "AA:BB:CC:DD:EE:FF"
    assert arp_fields["Target Protocol Address"] == "10.0.0.1"


def test_parser_decodes_icmp_echo_and_payload() -> None:
    frame = ethernet_header() + ipv4_packet(icmp_echo(b"ping-data"), protocol=1)

    record = PacketParser().parse(frame)

    assert record.protocol == "ICMP"
    assert record.errors == []
    assert "Echo Request" in record.info
    icmp_fields = fields_for(record, "Internet Control Message Protocol")
    assert icmp_fields["Identifier"].endswith("(22136)")
    assert icmp_fields["Sequence Number"] == "9"
    assert fields_for(record, "Data")["Printable Preview"] == "ping-data"


def test_parser_decodes_udp_and_honours_declared_length_over_padding() -> None:
    udp = udp_datagram(b"abc")
    frame = ethernet_header() + ipv4_packet(udp, protocol=17) + b"ETHERNET-PADDING"

    record = PacketParser().parse(frame)

    assert record.errors == []
    assert record.protocol == "UDP"
    assert (record.source_port, record.destination_port) == (5353, 9999)
    assert fields_for(record, "Data")["Length"] == "3 bytes"
    assert "PADDING" not in fields_for(record, "Data")["Printable Preview"]


def test_non_initial_ipv4_fragment_never_interprets_payload_as_ports() -> None:
    fake_transport_start = struct.pack("!HH", 65000, 22) + b"fragment-body"
    # Offset field 3 means 24 bytes, and MF remains set.
    ip = ipv4_packet(fake_transport_start, protocol=6, flags_fragment=0x2003)

    record = PacketParser().parse(ethernet_header() + ip)

    assert record.protocol == "IPv4-FRAG"
    assert record.source_port is None
    assert record.destination_port is None
    assert record.fragment is not None
    assert record.fragment.key == ("192.0.2.1", "198.51.100.2", 6, 0x1234)
    assert record.fragment.offset_bytes == 24
    assert record.fragment.more_fragments is True
    assert record.fragment.payload == fake_transport_start
    assert record.fragment.link_header == ethernet_header()
    assert not any(layer.name == "Transmission Control Protocol" for layer in record.layers)


def test_first_fragment_has_fragment_model_and_can_decode_udp_header() -> None:
    # UDP's declared length is for the final datagram, so it legitimately
    # exceeds the bytes in the first fragment and must not be called truncated.
    udp_first_piece = udp_datagram(b"12345678", declared_length=40)
    ip = ipv4_packet(udp_first_piece, protocol=17, flags_fragment=0x2000)

    record = PacketParser().parse(ethernet_header() + ip)

    assert record.protocol == "UDP"
    assert record.fragment is not None
    assert record.fragment.offset_bytes == 0
    assert record.fragment.more_fragments is True
    assert (record.source_port, record.destination_port) == (5353, 9999)
    assert not any("UDP 数据报被截断" in error for error in record.errors)


def test_parse_reassembled_ipv4_packet_reuses_normal_parser() -> None:
    segment = tcp_segment(b"complete")
    ip = ipv4_packet(segment, protocol=6, identification=77)

    record = PacketParser().parse_ipv4_packet(
        ip,
        ethernet_header(),
        timestamp=77.25,
        reassembly_note="3 fragments joined",
    )

    assert record.protocol == "TLS"
    assert record.raw == ethernet_header() + ip
    assert record.timestamp == 77.25
    assert record.is_reassembled is True
    assert record.reassembly_note == "3 fragments joined"
    assert record.fragment is None


def test_raw_ipv4_and_loopback_link_types() -> None:
    ip = ipv4_packet(udp_datagram(), protocol=17)
    parser = PacketParser()

    raw_record = parser.parse(ip, link_type="raw_ipv4")
    loopback_record = parser.parse(struct.pack("<I", 2) + ip, link_type="loopback")

    assert raw_record.protocol == "UDP"
    assert loopback_record.protocol == "UDP"
    assert loopback_record.layers[0].name == "Loopback"


def test_unknown_link_type_is_visible_raw_data_instead_of_crashing() -> None:
    record = PacketParser().parse(b"\x01\x02\x03", link_type="future-link")

    assert record.protocol == "Raw"
    assert "future-link" in record.info
    assert fields_for(record, "Raw Data")["Length"] == "3 bytes"
    assert record.errors


@pytest.mark.parametrize(
    ("frame", "expected_error"),
    [
        (b"\x00" * 13, "Ethernet 头部被截断"),
        (ethernet_header() + b"\x45" * 10, "IPv4 固定头部被截断"),
        (ethernet_header(0x0806) + b"\x00" * 7, "ARP 固定头部被截断"),
    ],
)
def test_truncated_headers_return_partial_records(frame: bytes, expected_error: str) -> None:
    record = PacketParser().parse(frame)

    assert any(expected_error in error for error in record.errors)


def test_malformed_ipv4_lengths_and_udp_lengths_are_reported() -> None:
    bad_ihl = bytearray(ipv4_packet(b"", protocol=17))
    bad_ihl[0] = 0x44
    ihl_record = PacketParser().parse(ethernet_header() + bad_ihl)

    udp = udp_datagram(b"x", declared_length=100)
    truncated_udp_record = PacketParser().parse(ethernet_header() + ipv4_packet(udp, protocol=17))

    assert any("IHL 无效" in error for error in ihl_record.errors)
    assert any("UDP 数据报被截断" in error for error in truncated_udp_record.errors)


def test_truncated_ipv4_total_length_does_not_crash_transport_parser() -> None:
    tcp = tcp_segment()
    ip = ipv4_packet(tcp, protocol=6, total_length=200)

    record = PacketParser().parse(ethernet_header() + ip)

    assert record.protocol == "TLS"
    assert any("IPv4 数据报被截断" in error for error in record.errors)


def test_port_based_application_identification_keeps_transport_layer() -> None:
    frame = ethernet_header() + ipv4_packet(tcp_segment(b"encrypted"), protocol=6)

    record = PacketParser().parse(frame)

    assert record.protocol == "TLS"
    assert any(layer.name == "TCP" or layer.name == "Transmission Control Protocol" for layer in record.layers)
    assert fields_for(record, "TLS")["Identification"] == "Port-based identification only"


def test_truncated_fragment_is_not_offered_for_reassembly() -> None:
    ip = ipv4_packet(b"12345678", protocol=17, flags_fragment=0x2000, total_length=80)

    record = PacketParser().parse(ethernet_header() + ip)

    assert record.fragment is None
    assert any("不会进入重组缓存" in error for error in record.errors)
