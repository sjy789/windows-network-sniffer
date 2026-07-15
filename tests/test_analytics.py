from __future__ import annotations

import socket
import struct

from sniffer.analytics import FlowTracker, TrafficMeter
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


def test_traffic_meter_keeps_idle_seconds_and_resets_on_stop() -> None:
    parser = PacketParser()
    captured = parser.parse(
        tcp_frame("192.0.2.1", "198.51.100.2", 1234, 80, 1, b"hello"),
        timestamp=100.4,
    )
    meter = TrafficMeter(window=10)
    meter.advance(100.2)
    meter.add([captured])

    meter.advance(103.1)

    assert [int(point.timestamp) for point in meter.points] == [100, 101, 102, 103]
    assert [point.packets for point in meter.points] == [1, 0, 0, 0]
    assert meter.mark_stopped(103.5) is False

    later = parser.parse(
        tcp_frame("192.0.2.1", "198.51.100.2", 1234, 80, 6, b"world"),
        timestamp=104.1,
    )
    meter.add([later])
    meter.mark_stopped(104.2)
    assert meter.points[-1].packets == 0
    assert int(meter.points[-1].timestamp) == 105


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
