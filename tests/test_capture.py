from __future__ import annotations

from types import SimpleNamespace

import pytest
from scapy.all import Ether, IP, IPv6, UDP

import sniffer.capture as capture_module
from sniffer.capture import CaptureError, CaptureSession
from sniffer.models import InterfaceInfo, IPv4Fragment, PacketRecord, ReassemblyResult


class FakeParser:
    def __init__(self, *, fragment=None, fail=False):
        self.calls = []
        self.fragment = fragment
        self.fail = fail

    def parse(self, raw, *, timestamp, original_packet, link_type):
        self.calls.append(
            {
                "raw": raw,
                "timestamp": timestamp,
                "original_packet": original_packet,
                "link_type": link_type,
            }
        )
        if self.fail:
            raise ValueError("bad frame")
        fragment = self.fragment
        self.fragment = None
        return PacketRecord(
            timestamp=timestamp,
            raw=raw,
            length=len(raw),
            protocol="UDP",
            fragment=fragment,
            original_packet=original_packet,
            link_type=link_type,
        )


class FakeReassembler:
    def __init__(self, result=None):
        self.result = result
        self.fragments = []
        self.clear_count = 0
        self.expire_calls = []

    def clear(self):
        self.clear_count += 1

    def add(self, fragment):
        self.fragments.append(fragment)
        if self.result is None:
            return ReassemblyResult(key=fragment.key)
        return self.result

    def expire(self, now=None):
        self.expire_calls.append(now)
        return []


class FakeAsyncSniffer:
    instances = []

    def __init__(self, **kwargs):
        self.kwargs = kwargs
        self.running = False
        self.exception = None
        self.thread = None
        self.stop_calls = []
        self.__class__.instances.append(self)

    def start(self):
        self.running = True
        self.kwargs["started_callback"]()

    def stop(self, join=True):
        self.stop_calls.append(join)
        self.running = False

    def emit(self, packet):
        self.kwargs["prn"](packet)


@pytest.fixture
def fake_sniffer(monkeypatch):
    FakeAsyncSniffer.instances.clear()
    monkeypatch.setattr(capture_module, "AsyncSniffer", FakeAsyncSniffer)
    return FakeAsyncSniffer


@pytest.fixture
def interface():
    return InterfaceInfo(
        name="WLAN",
        description="Wireless Adapter",
        pcap_name=r"\Device\NPF_{TEST}",
    )


def test_start_captures_parses_and_stops_without_touching_gui(fake_sniffer, interface):
    parser = FakeParser()
    reassembler = FakeReassembler()
    session = CaptureSession(parser=parser, reassembler=reassembler)

    session.start(interface, " udp ")
    worker = fake_sniffer.instances[-1]
    assert worker.kwargs["iface"] == interface.pcap_name
    assert worker.kwargs["filter"] == "udp"
    assert worker.kwargs["store"] is False
    assert reassembler.clear_count == 1
    assert session.running is True

    packet = Ether() / IP(src="192.0.2.1", dst="198.51.100.2") / UDP(sport=10, dport=20)
    packet.time = 1234.5
    worker.emit(packet)

    records = session.drain()
    assert len(records) == 1
    assert parser.calls[0]["raw"] == bytes(packet)
    assert parser.calls[0]["link_type"] == "ethernet"
    assert parser.calls[0]["original_packet"] is packet
    assert records[0].original_packet is packet
    assert records[0].sequence == 1
    assert session.stats.captured == 1
    assert session.stats.queued == 0
    assert reassembler.expire_calls == [1234.5]

    session.stop()
    assert worker.stop_calls == [False]
    assert session.running is False


def test_raw_ipv4_packet_is_normalized_before_parsing(fake_sniffer, interface):
    parser = FakeParser()
    session = CaptureSession(parser=parser, reassembler=FakeReassembler())
    session.start(interface)
    packet = IP(src="192.0.2.1", dst="198.51.100.2") / UDP(sport=1, dport=2)

    fake_sniffer.instances[-1].emit(packet)

    assert parser.calls[0]["link_type"] == "raw_ipv4"
    assert parser.calls[0]["raw"] == bytes(packet[IP])


def test_raw_ipv6_packet_is_normalized_before_parsing(fake_sniffer, interface):
    parser = FakeParser()
    session = CaptureSession(parser=parser, reassembler=FakeReassembler())
    session.start(interface)
    packet = IPv6(src="2001:db8::1", dst="2001:db8::2") / UDP(sport=1, dport=2)

    fake_sniffer.instances[-1].emit(packet)

    assert parser.calls[0]["link_type"] == "raw_ipv6"
    assert parser.calls[0]["raw"] == bytes(packet[IPv6])


def test_bounded_queue_drops_new_records_instead_of_blocking(fake_sniffer, interface):
    session = CaptureSession(queue_size=1, parser=FakeParser(), reassembler=FakeReassembler())
    assert session.queue_capacity == 1
    session.start(interface)
    worker = fake_sniffer.instances[-1]
    worker.emit(Ether() / IP())
    worker.emit(Ether() / IP())

    assert session.stats.captured == 2
    assert session.stats.queued == 1
    assert session.stats.dropped == 1
    assert len(session.drain()) == 1


def test_parser_exception_becomes_visible_malformed_record(fake_sniffer, interface):
    session = CaptureSession(parser=FakeParser(fail=True), reassembler=FakeReassembler())
    session.start(interface)
    packet = Ether() / IP()

    fake_sniffer.instances[-1].emit(packet)
    record = session.drain()[0]

    assert record.protocol == "MALFORMED"
    assert "数据包解析失败" in record.info
    assert record.original_packet is packet
    assert session.stats.parse_errors == 1
    assert session.last_error is None
    assert "bad frame" in (session.last_warning or "")


def test_completed_fragment_emits_virtual_record_without_original_packet(
    fake_sniffer, interface
):
    fragment = IPv4Fragment(
        key=("192.0.2.1", "198.51.100.2", 17, 7),
        identification=7,
        offset_bytes=0,
        more_fragments=True,
        payload=b"abcdefgh",
        ip_header=b"I" * 20,
        link_header=b"E" * 14,
        timestamp=10.0,
    )
    result = ReassemblyResult(
        key=fragment.key,
        complete=True,
        ip_packet=b"I" * 28,
        link_header=fragment.link_header,
        fragment_count=2,
        status="complete",
    )
    parser = FakeParser(fragment=fragment)
    reassembler = FakeReassembler(result=result)
    session = CaptureSession(parser=parser, reassembler=reassembler)
    session.start(interface)

    fake_sniffer.instances[-1].emit(Ether() / IP())
    original, virtual = session.drain()

    assert original.fragment is fragment
    assert reassembler.fragments == [fragment]
    assert parser.calls[1]["raw"] == fragment.link_header + result.ip_packet
    assert parser.calls[1]["link_type"] == "ethernet"
    assert virtual.is_reassembled is True
    assert virtual.original_packet is None
    assert virtual.fragment is None
    assert "2 个 IPv4 分片" in virtual.reassembly_note
    assert session.stats.reassembled == 1


def test_invalid_arguments_and_double_start_are_friendly(fake_sniffer, interface):
    with pytest.raises(ValueError, match="正整数"):
        CaptureSession(queue_size=0, parser=FakeParser(), reassembler=FakeReassembler())

    session = CaptureSession(parser=FakeParser(), reassembler=FakeReassembler())
    session.start(interface)
    with pytest.raises(CaptureError, match="已在运行"):
        session.start(interface)
    with pytest.raises(ValueError, match="正整数"):
        session.drain(0)


def test_failed_stop_keeps_session_running_and_blocks_second_worker(
    fake_sniffer, interface
):
    session = CaptureSession(parser=FakeParser(), reassembler=FakeReassembler())
    session.start(interface)
    worker = fake_sniffer.instances[-1]

    def fail_stop(*, join=True):
        raise OSError("socket close failed")

    worker.stop = fail_stop
    with pytest.raises(CaptureError, match="socket close failed"):
        session.stop()

    assert session.running is True
    with pytest.raises(CaptureError, match="已在运行"):
        session.start(interface)
    assert len(fake_sniffer.instances) == 1


def test_unexpected_worker_failure_becomes_fatal_session_error(
    fake_sniffer, interface
):
    session = CaptureSession(parser=FakeParser(), reassembler=FakeReassembler())
    session.start(interface)
    worker = fake_sniffer.instances[-1]
    worker.running = False
    worker.exception = OSError("Npcap read failed")

    assert session.running is False
    assert "Npcap read failed" in (session.last_error or "")
