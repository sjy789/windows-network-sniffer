from __future__ import annotations

import pytest
from scapy.all import Ether, IP, IPv6, UDP
from scapy.utils import PcapNgWriter, wrpcap

import sniffer.offline as offline_module
from sniffer.models import IPv4Fragment, PacketRecord, ReassemblyResult
from sniffer.offline import OfflineCaptureError, load_capture_file


class FakeReader:
    def __init__(self, _path: str, packets=None):
        self.packets = packets if packets is not None else []

    def __enter__(self):
        return iter(self.packets)

    def __exit__(self, exc_type, exc, tb):
        return False


class FakeParser:
    def __init__(self, fragment=None):
        self.fragment = fragment
        self.calls = []

    def parse(self, raw, *, timestamp, original_packet, link_type):
        self.calls.append((raw, timestamp, original_packet, link_type))
        fragment = self.fragment
        self.fragment = None
        return PacketRecord(
            timestamp=timestamp,
            raw=raw,
            length=len(raw),
            protocol="UDP",
            source="192.0.2.1",
            destination="198.51.100.2",
            source_port=10,
            destination_port=20,
            fragment=fragment,
            original_packet=original_packet,
            link_type=link_type,
        )


class FakeReassembler:
    def __init__(self, result=None):
        self.result = result
        self.fragments = []

    def add(self, fragment):
        self.fragments.append(fragment)
        return self.result or ReassemblyResult(key=fragment.key)

    def expire(self, now=None):
        return []


def test_load_capture_file_parses_packets_with_normal_pipeline(monkeypatch, tmp_path) -> None:
    packet = Ether() / IP(src="192.0.2.1", dst="198.51.100.2") / UDP(sport=10, dport=20)
    packet.time = 123.25
    monkeypatch.setattr(offline_module, "PcapReader", lambda path: FakeReader(path, [packet]))
    path = tmp_path / "sample.pcap"
    path.write_bytes(b"placeholder")

    result = load_capture_file(path)

    assert result.stats.captured == 1
    assert result.stats.queued == 1
    assert len(result.records) == 1
    assert result.records[0].original_packet is packet
    assert result.records[0].link_type == "ethernet"


def test_load_capture_file_recognizes_raw_ipv6_packets(monkeypatch, tmp_path) -> None:
    packet = IPv6(src="2001:db8::1", dst="2001:db8::2") / UDP(sport=1000, dport=2000)
    packet.time = 42.0
    monkeypatch.setattr(offline_module, "PcapReader", lambda path: FakeReader(path, [packet]))
    path = tmp_path / "raw-ipv6.pcap"
    path.write_bytes(b"placeholder")

    result = load_capture_file(path)

    assert result.records[0].link_type == "raw_ipv6"
    assert result.records[0].protocol == "UDP"
    assert result.records[0].source == "2001:db8::1"


def test_load_capture_file_emits_reassembled_virtual_record(monkeypatch, tmp_path) -> None:
    packet = Ether() / IP(src="192.0.2.1", dst="198.51.100.2") / UDP(sport=10, dport=20)
    fragment = IPv4Fragment(
        key=("192.0.2.1", "198.51.100.2", 17, 7),
        identification=7,
        offset_bytes=0,
        more_fragments=False,
        payload=b"payload",
        ip_header=b"E\x00\x00\x1c\x00\x07\x00\x00@\x11\x00\x00\xc0\x00\x02\x01\xc63d\x02",
        link_header=b"\x00" * 14,
        timestamp=1.0,
    )
    reassembled = ReassemblyResult(
        key=fragment.key,
        complete=True,
        ip_packet=fragment.ip_header + fragment.payload,
        link_header=fragment.link_header,
        fragment_count=2,
        status="complete",
    )
    parser = FakeParser(fragment=fragment)
    reassembler = FakeReassembler(result=reassembled)
    monkeypatch.setattr(offline_module, "PcapReader", lambda path: FakeReader(path, [packet]))
    path = tmp_path / "fragments.pcap"
    path.write_bytes(b"placeholder")

    result = load_capture_file(path, parser=parser, reassembler=reassembler)

    assert len(result.records) == 2
    assert result.stats.reassembled == 1
    assert result.records[1].is_reassembled is True
    assert result.records[1].original_packet is None


def test_load_capture_file_streams_bounded_batches(monkeypatch, tmp_path) -> None:
    packets = [Ether() / IP() / UDP(sport=index, dport=53) for index in range(1, 6)]
    monkeypatch.setattr(offline_module, "PcapReader", lambda path: FakeReader(path, packets))
    path = tmp_path / "batch.pcap"
    path.write_bytes(b"placeholder")
    batches: list[list[PacketRecord]] = []
    progress: list[int] = []

    result = load_capture_file(
        path,
        batch_size=2,
        batch_callback=batches.append,
        progress_callback=progress.append,
    )

    assert [len(batch) for batch in batches] == [2, 2, 1]
    assert result.records == []
    assert result.stats.captured == 5
    assert result.stats.queued == 5
    assert progress[-1] == 5


def test_load_capture_file_can_be_cancelled(monkeypatch, tmp_path) -> None:
    packets = [Ether() / IP() / UDP() for _ in range(10)]
    monkeypatch.setattr(offline_module, "PcapReader", lambda path: FakeReader(path, packets))
    path = tmp_path / "cancel.pcap"
    path.write_bytes(b"placeholder")
    batches: list[list[PacketRecord]] = []

    result = load_capture_file(
        path,
        batch_size=2,
        batch_callback=batches.append,
        cancel_requested=lambda: sum(map(len, batches)) >= 2,
    )

    assert result.cancelled is True
    assert result.stats.captured == 2
    assert result.stats.queued == 2


@pytest.mark.parametrize("suffix", [".pcap", ".pcapng"])
def test_loads_real_capture_files(suffix, tmp_path) -> None:
    path = tmp_path / f"real{suffix}"
    packet = Ether() / IP(src="192.0.2.10", dst="198.51.100.20") / UDP(sport=5353, dport=53)
    packet.time = 123.5
    if suffix == ".pcap":
        wrpcap(str(path), [packet])
    else:
        writer = PcapNgWriter(str(path))
        try:
            writer.write(packet)
        finally:
            writer.close()

    result = load_capture_file(path)

    assert result.stats.captured == 1
    assert result.records[0].source == "192.0.2.10"
    assert result.records[0].destination_port == 53
    assert result.records[0].timestamp == pytest.approx(123.5)


def test_real_capture_respects_packet_limit(tmp_path) -> None:
    path = tmp_path / "limited.pcap"
    packets = [
        Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02")
        / IP(src="192.0.2.1", dst="198.51.100.2")
        / UDP(sport=index + 1, dport=53)
        for index in range(5)
    ]
    wrpcap(str(path), packets)

    result = load_capture_file(path, max_packets=2)

    assert result.stats.captured == 2
    assert len(result.records) == 2


def test_corrupted_capture_has_user_facing_error(tmp_path) -> None:
    path = tmp_path / "corrupted.pcapng"
    path.write_bytes(b"not a capture file")

    with pytest.raises(OfflineCaptureError, match="捕获文件|抓包文件"):
        load_capture_file(path)
