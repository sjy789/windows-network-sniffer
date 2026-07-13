from __future__ import annotations

import csv

import pytest
from scapy.all import Ether, IP

import sniffer.storage as storage_module
from sniffer.models import PacketRecord
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
    calls = []
    monkeypatch.setattr(storage_module, "wrpcap", lambda path, packets: calls.append((path, packets)))
    target = tmp_path / "nested" / "capture.pcap"

    count = save_pcap(target, records)

    assert count == 1
    assert calls == [(str(target), [packet])]
    assert target.parent.is_dir()


def test_save_pcap_rejects_empty_original_packet_set(tmp_path):
    with pytest.raises(StorageError, match="没有可保存"):
        save_pcap(tmp_path / "empty.pcap", [make_record(is_reassembled=True)])


def test_save_pcap_wraps_scapy_error(monkeypatch, tmp_path):
    def fail(*_args, **_kwargs):
        raise OSError("disk full")

    monkeypatch.setattr(storage_module, "wrpcap", fail)
    with pytest.raises(StorageError, match="保存 PCAP 文件失败"):
        save_pcap(tmp_path / "capture.pcap", [make_record(original_packet=Ether())])


def test_save_pcap_rejects_mixed_link_layer_types(monkeypatch, tmp_path):
    calls = []
    monkeypatch.setattr(storage_module, "wrpcap", lambda *args: calls.append(args))
    records = [
        make_record(original_packet=Ether(), link_type="ethernet"),
        make_record(original_packet=IP(), link_type="raw_ipv4"),
    ]

    with pytest.raises(StorageError, match="不同链路层类型"):
        save_pcap(tmp_path / "mixed.pcap", records)

    assert calls == []


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
