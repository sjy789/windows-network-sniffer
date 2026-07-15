from __future__ import annotations

import socket
import struct

from scapy.all import Ether, IPv6, Raw, TCP

from sniffer.analytics import FlowTracker, TrafficMeter
from sniffer.models import IPv4Fragment
from sniffer.parser import PacketParser


def tcp_frame(source: str, destination: str, sport: int, dport: int, sequence: int, payload: bytes) -> bytes:
    ethernet = b"\x00" * 12 + b"\x08\x00"
    total = 20 + 20 + len(payload)
    ip = struct.pack(
        "!BBHHHBBH4s4s", 0x45, 0, total, 1, 0, 64, 6, 0,
        socket.inet_aton(source), socket.inet_aton(destination),
    )
    tcp = struct.pack("!HHIIBBHHH", sport, dport, sequence, 0, 0x50, 0x18, 4096, 0, 0)
    return ethernet + ip + tcp + payload


def test_traffic_meter_buckets_packets_and_protocols() -> None:
    parser = PacketParser()
    first = parser.parse(tcp_frame("192.0.2.1", "198.51.100.2", 1234, 80, 1, b"hello"), timestamp=10.1)
    second = parser.parse(tcp_frame("192.0.2.1", "198.51.100.2", 1234, 80, 6, b"world"), timestamp=10.8)
    meter = TrafficMeter()
    meter.add([first, second])
    assert meter.points[-1].packets == 2
    assert meter.total_bytes == first.length + second.length
    assert meter.protocols["HTTP"] == 2


def test_flow_tracker_merges_directions_and_reassembles_tcp_payload_by_sequence() -> None:
    parser = PacketParser()
    records = [
        parser.parse(tcp_frame("192.0.2.1", "198.51.100.2", 1234, 80, 6, b"world"), timestamp=2),
        parser.parse(tcp_frame("192.0.2.1", "198.51.100.2", 1234, 80, 1, b"hello"), timestamp=1),
        parser.parse(tcp_frame("198.51.100.2", "192.0.2.1", 80, 1234, 20, b"reply"), timestamp=3),
    ]
    tracker = FlowTracker()
    tracker.add(records)
    assert len(tracker.flows) == 1
    flow = tracker.flows[0]
    assert flow.packet_count == 3
    assert bytes(flow.stream_ab) == b"helloworld"
    assert bytes(flow.stream_ba) == b"reply"
    assert flow.tcp_state == "Established"


def test_ipv6_tcp_flow_extracts_flags_and_payload() -> None:
    frame = bytes(
        Ether()
        / IPv6(src="2001:db8::1", dst="2001:db8::2")
        / TCP(sport=1234, dport=8080, seq=10, flags="PA")
        / Raw(b"hello-ipv6")
    )
    record = PacketParser().parse(frame, timestamp=1)
    tracker = FlowTracker()

    tracker.add([record])

    flow = tracker.flows[0]
    assert flow.tcp_state == "Established"
    assert bytes(flow.stream_ab) == b"hello-ipv6"


def test_synthetic_reassembly_does_not_inflate_traffic_and_fragments_do_not_duplicate_flow() -> None:
    parser = PacketParser()
    first = parser.parse(tcp_frame("192.0.2.1", "198.51.100.2", 1234, 80, 1, b"partial"), timestamp=1)
    first.fragment = IPv4Fragment(
        key=("192.0.2.1", "198.51.100.2", 6, 1), identification=1,
        offset_bytes=0, more_fragments=True, payload=b"partial", ip_header=b"", link_header=b"", timestamp=1,
    )
    complete = parser.parse(tcp_frame("192.0.2.1", "198.51.100.2", 1234, 80, 1, b"complete"), timestamp=2)
    complete.is_reassembled = True
    meter = TrafficMeter()
    tracker = FlowTracker()

    meter.add([first, complete])
    tracker.add([first, complete])

    assert meter.total_packets == 1
    assert meter.total_bytes == first.length
    assert tracker.flows[0].packet_count == 1
    assert bytes(tracker.flows[0].stream_ab) == b"complete"
