from __future__ import annotations

import csv

import pytest
from scapy.all import Ether, IP, IPv6, UDP
from scapy.layers.l2 import Loopback
from scapy.utils import PcapReader

import sniffer.storage as storage_module
from sniffer.models import PacketRecord
from sniffer.offline import load_capture_file
from sniffer.storage import CSV_HEADERS, StorageError, export_csv, save_pcap


def make_record(**overrides):
    values = {
        "timestamp": 1_700_000_000.125,
        "raw": b"packet",
        "length": 6,
        "source": "192.0.2.1",
        "destination": "198.51.100.2",
        "protocol": "UDP",
        "source_port": 1234,
        "destination_port": 53,
        "info": "1234 → 53 Len=8",
        "sequence": 3,
    }
    values.update(overrides)
    return PacketRecord(**values)


def test_save_pcap_writes_only_original_non_reassembled_packets(monkeypatch, tmp_path):
    packet = Ether() / IP()
    virtual_packet = Ether() / IP()
    records = [
        make_record(original_packet=packet),
        make_record(original_packet=None),
        make_record(original_packet=virtual_packet, is_reassembled=True),
    ]
    target = tmp_path / "nested" / "capture.pcap"
    records[0].raw = bytes(packet)
    records[0].length = len(records[0].raw)

    count = save_pcap(target, records)

    assert count == 1
    assert target.parent.is_dir()
    with PcapReader(str(target)) as reader:
        saved = list(reader)
    assert len(saved) == 1
    assert saved[0].haslayer(Ether)


def test_save_pcap_rejects_empty_original_packet_set(tmp_path):
    with pytest.raises(StorageError, match="没有可保存"):
        save_pcap(tmp_path / "empty.pcap", [make_record(is_reassembled=True)])


def test_save_pcap_wraps_scapy_error(monkeypatch, tmp_path):
    class FailingWriter:
        def __init__(self, *_args, **_kwargs):
            pass

        def write_header(self, *_args, **_kwargs):
            raise OSError("disk full")

        def close(self):
            pass

    monkeypatch.setattr(storage_module, "RawPcapWriter", FailingWriter)
    with pytest.raises(StorageError, match="保存 PCAP 文件失败"):
        save_pcap(
            tmp_path / "capture.pcap",
            [make_record(raw=bytes(Ether()), length=len(Ether()), original_packet=Ether())],
        )


def test_save_pcap_rejects_mixed_link_layer_types(monkeypatch, tmp_path):
    records = [
        make_record(original_packet=Ether(), link_type="ethernet"),
        make_record(original_packet=IP(), link_type="raw_ipv4"),
    ]

    with pytest.raises(StorageError, match="不同链路层类型"):
        save_pcap(tmp_path / "mixed.pcap", records)


def test_save_and_reload_mixed_raw_ipv4_ipv6(tmp_path):
    ipv4 = IP(src="192.0.2.1", dst="198.51.100.2") / UDP(sport=1000, dport=53)
    ipv6 = IPv6(src="2001:db8::1", dst="2001:db8::2") / UDP(sport=2000, dport=53)
    records = [
        make_record(
            timestamp=100.125,
            raw=bytes(ipv4),
            length=len(ipv4),
            original_packet=ipv4,
            link_type="raw_ipv4",
        ),
        make_record(
            timestamp=101.5,
            raw=bytes(ipv6),
            length=len(ipv6),
            original_packet=ipv6,
            link_type="raw_ipv6",
        ),
    ]
    target = tmp_path / "mixed-raw-ip.pcap"

    assert save_pcap(target, records) == 2

    with PcapReader(str(target)) as reader:
        saved = list(reader)
        assert reader.linktype == 12
    assert [packet.__class__.__name__ for packet in saved] == ["IP", "IPv6"]
    assert float(saved[0].time) == pytest.approx(100.125)
    assert float(saved[1].time) == pytest.approx(101.5)
    reloaded = load_capture_file(target)
    assert [record.protocol for record in reloaded.records] == ["DNS", "DNS"]
    assert [record.source for record in reloaded.records] == ["192.0.2.1", "2001:db8::1"]
    assert [record.link_type for record in reloaded.records] == ["raw_ipv4", "raw_ipv6"]


def test_save_mixed_loopback_ipv4_ipv6_uses_one_linktype(tmp_path):
    ipv4 = Loopback(type=2) / IP() / UDP()
    ipv6 = Loopback(type=24) / IPv6() / UDP()
    records = [
        make_record(raw=bytes(packet), length=len(packet), original_packet=packet, link_type="loopback")
        for packet in (ipv4, ipv6)
    ]
    target = tmp_path / "mixed-loopback.pcap"

    assert save_pcap(target, records) == 2
    with PcapReader(str(target)) as reader:
        saved = list(reader)
        assert reader.linktype == 0
    assert saved[0].haslayer(IP)
    assert saved[1].haslayer(IPv6)
    reloaded = load_capture_file(target)
    assert [record.link_type for record in reloaded.records] == ["loopback", "loopback"]
    assert [record.protocol for record in reloaded.records] == ["DNS", "DNS"]


def test_save_and_reload_mixed_ethernet_ipv4_ipv6(tmp_path):
    frames = [
        Ether() / IP(src="192.0.2.1", dst="198.51.100.2") / UDP(sport=10, dport=20),
        Ether()
        / IPv6(src="2001:db8::1", dst="2001:db8::2")
        / UDP(sport=30, dport=40),
    ]
    records = [
        make_record(raw=bytes(frame), length=len(frame), original_packet=frame, link_type="ethernet")
        for frame in frames
    ]
    target = tmp_path / "mixed-ethernet.pcap"

    assert save_pcap(target, records) == 2
    reloaded = load_capture_file(target)

    assert [record.link_type for record in reloaded.records] == ["ethernet", "ethernet"]
    assert [record.protocol for record in reloaded.records] == ["UDP", "UDP"]
    assert reloaded.records[1].source == "2001:db8::1"


def test_export_csv_uses_utf8_bom_and_exports_all_summaries(tmp_path):
    records = [
        make_record(info="=WEBSERVICE()", errors=["截断"]),
        make_record(
            sequence=0,
            source_port=None,
            destination_port=None,
            is_reassembled=True,
            reassembly_note="two fragments",
        ),
    ]
    target = tmp_path / "summary.csv"

    count = export_csv(target, records)

    assert count == 2
    assert target.read_bytes().startswith(b"\xef\xbb\xbf")
    with target.open(encoding="utf-8-sig", newline="") as stream:
        rows = list(csv.reader(stream))
    assert tuple(rows[0]) == CSV_HEADERS
    assert rows[1][0] == "3"
    assert rows[1][8] == "'=WEBSERVICE()"
    assert rows[1][10] == "截断"
    assert rows[2][0] == "2"
    assert rows[2][5:7] == ["", ""]
    assert rows[2][9] == "是"


def test_export_csv_supports_empty_record_list(tmp_path):
    target = tmp_path / "empty.csv"

    assert export_csv(target, []) == 0
    with target.open(encoding="utf-8-sig", newline="") as stream:
        assert next(csv.reader(stream)) == list(CSV_HEADERS)
