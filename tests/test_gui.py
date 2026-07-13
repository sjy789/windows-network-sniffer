from __future__ import annotations

import os
import time

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PyQt6.QtCore import QModelIndex
from PyQt6.QtWidgets import QApplication

import sniffer.gui as gui_module
from sniffer.models import CaptureStats, InterfaceInfo, PacketRecord, ProtocolLayer


APP = QApplication.instance() or QApplication([])


class FakeCaptureSession:
    def __init__(self) -> None:
        self.running = False
        self.last_error = ""
        self.stats = CaptureStats()
        self.items: list[PacketRecord] = []

    def start(self, interface: InterfaceInfo, capture_filter: str = "") -> None:
        assert interface.pcap_name
        self.running = True

    def stop(self) -> None:
        self.running = False

    def drain(self, max_items: int = 200) -> list[PacketRecord]:
        result, self.items = self.items[:max_items], self.items[max_items:]
        return result


def sample_record() -> PacketRecord:
    return PacketRecord(
        timestamp=time.time(),
        raw=b"\x00\x01hello",
        length=7,
        source="192.0.2.1",
        destination="198.51.100.2",
        protocol="UDP",
        source_port=1234,
        destination_port=53,
        info="UDP 1234 -> 53",
        layers=[ProtocolLayer("UDP", [("源端口", "1234"), ("目的端口", "53")])],
    )


def test_main_window_smoke(monkeypatch) -> None:
    interface = InterfaceInfo("测试网卡", "Npcap test", r"\Device\NPF_TEST")
    monkeypatch.setattr(gui_module, "list_capture_interfaces", lambda: [interface])
    session = FakeCaptureSession()
    window = gui_module.MainWindow(capture_session=session)

    assert window.interface_combo.count() == 1
    assert window.start_button.isEnabled()
    window.start_capture()
    assert session.running
    assert window.stop_button.isEnabled()
    window.stop_capture()
    assert not session.running
    window.close()


def test_packet_detail_and_hex_view(monkeypatch) -> None:
    monkeypatch.setattr(gui_module, "list_capture_interfaces", lambda: [])
    window = gui_module.MainWindow(capture_session=FakeCaptureSession())
    window.table_model.add_records([sample_record()])
    window._show_selected_packet(window.table_model.index(0, 0), QModelIndex())

    assert window.detail_tree.topLevelItemCount() >= 2
    assert "68 65 6C 6C 6F" in window.raw_view.toPlainText()
    assert "hello" in window.raw_view.toPlainText()
    window.close()


def test_table_model_reports_records_evicted_by_rolling_limit() -> None:
    model = gui_module.PacketTableModel(max_records=2)

    model.add_records([sample_record(), sample_record(), sample_record()])

    assert len(model.records) == 2
    assert model.evicted_count == 1
    model.clear()
    assert model.evicted_count == 0


def test_background_failure_restores_controls_and_surfaces_error(monkeypatch) -> None:
    interface = InterfaceInfo("测试网卡", "Npcap test", r"\Device\NPF_TEST")
    monkeypatch.setattr(gui_module, "list_capture_interfaces", lambda: [interface])
    session = FakeCaptureSession()
    window = gui_module.MainWindow(capture_session=session)
    window.start_capture()
    assert window.stop_button.isEnabled()

    session.running = False
    session.last_error = "Npcap read failed"
    window._drain_capture_queue()

    assert window.start_button.isEnabled()
    assert not window.stop_button.isEnabled()
    assert "Npcap read failed" in window.capture_status_label.text()
    window.close()
