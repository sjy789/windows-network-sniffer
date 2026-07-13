"""PyQt6 主界面。

界面只消费 ``CaptureSession`` 的有界队列；Scapy 回调线程不会直接操作任何
Qt 控件，避免高流量时界面线程被捕获逻辑阻塞。
"""

from __future__ import annotations

from pathlib import Path

from PyQt6.QtCore import QAbstractTableModel, QModelIndex, Qt, QTimer
from PyQt6.QtGui import QColor, QCloseEvent, QFontDatabase
from PyQt6.QtWidgets import (
    QAbstractItemView,
    QApplication,
    QComboBox,
    QFileDialog,
    QGridLayout,
    QGroupBox,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QMainWindow,
    QMessageBox,
    QPlainTextEdit,
    QPushButton,
    QSplitter,
    QTableView,
    QTreeWidget,
    QTreeWidgetItem,
    QVBoxLayout,
    QWidget,
)

from .capture import CaptureSession
from .filtering import DisplayFilter, FilterSyntaxError
from .formatting import format_hex_ascii
from .interfaces import list_capture_interfaces
from .models import InterfaceInfo, PacketRecord
from .storage import export_csv, save_pcap


class PacketTableModel(QAbstractTableModel):
    """带显示过滤和容量上限的数据包表模型。"""

    HEADERS = ("序号", "时间", "源地址", "目的地址", "协议", "源端口", "目的端口", "长度", "摘要")

    def __init__(self, *, max_records: int = 20_000, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.max_records = max_records
        self._records: list[PacketRecord] = []
        self._visible: list[int] = []
        self._filter = DisplayFilter.parse("")
        self._next_sequence = 1

    def rowCount(self, parent: QModelIndex = QModelIndex()) -> int:  # noqa: N802
        return 0 if parent.isValid() else len(self._visible)

    def columnCount(self, parent: QModelIndex = QModelIndex()) -> int:  # noqa: N802
        return 0 if parent.isValid() else len(self.HEADERS)

    def headerData(self, section: int, orientation: Qt.Orientation, role: int = Qt.ItemDataRole.DisplayRole):  # noqa: N802, ANN201
        if role == Qt.ItemDataRole.DisplayRole and orientation == Qt.Orientation.Horizontal:
            return self.HEADERS[section]
        return super().headerData(section, orientation, role)

    def data(self, index: QModelIndex, role: int = Qt.ItemDataRole.DisplayRole):  # noqa: ANN201
        if not index.isValid() or index.row() >= len(self._visible):
            return None
        record = self._records[self._visible[index.row()]]
        if role == Qt.ItemDataRole.DisplayRole:
            values = (
                record.sequence,
                record.timestamp_text,
                record.source,
                record.destination,
                record.protocol,
                "" if record.source_port is None else record.source_port,
                "" if record.destination_port is None else record.destination_port,
                record.length,
                record.info,
            )
            return values[index.column()]
        if role == Qt.ItemDataRole.TextAlignmentRole and index.column() in {0, 1, 4, 5, 6, 7}:
            return int(Qt.AlignmentFlag.AlignCenter)
        if role == Qt.ItemDataRole.ForegroundRole:
            if record.errors:
                return QColor("#b42318")
            if record.is_reassembled:
                return QColor("#6f42c1")
            if record.is_fragment:
                return QColor("#9a6700")
        if role == Qt.ItemDataRole.ToolTipRole:
            if record.errors:
                return "\n".join(record.errors)
            if record.reassembly_note:
                return record.reassembly_note
        return None

    @property
    def records(self) -> list[PacketRecord]:
        return list(self._records)

    @property
    def visible_count(self) -> int:
        return len(self._visible)

    def record_at(self, visible_row: int) -> PacketRecord | None:
        if 0 <= visible_row < len(self._visible):
            return self._records[self._visible[visible_row]]
        return None

    def add_records(self, records: list[PacketRecord]) -> None:
        if not records:
            return
        for record in records:
            # Keep display numbers unique across capture restarts.  A session
            # may reset its own counter, while the existing table is retained.
            record.sequence = self._next_sequence
            self._next_sequence += 1
        self.beginResetModel()
        self._records.extend(records)
        overflow = len(self._records) - self.max_records
        if overflow > 0:
            del self._records[:overflow]
        self._rebuild_visible()
        self.endResetModel()

    def clear(self) -> None:
        self.beginResetModel()
        self._records.clear()
        self._visible.clear()
        self._next_sequence = 1
        self.endResetModel()

    def set_filter(self, display_filter: DisplayFilter) -> None:
        self.beginResetModel()
        self._filter = display_filter
        self._rebuild_visible()
        self.endResetModel()

    def _rebuild_visible(self) -> None:
        self._visible = [index for index, record in enumerate(self._records) if self._filter.matches(record)]


class MainWindow(QMainWindow):
    """网络嗅探器主窗口。"""

    def __init__(self, *, capture_session: CaptureSession | None = None) -> None:
        super().__init__()
        self.setWindowTitle("网络嗅探器")
        self.resize(1280, 820)
        self._session = capture_session or CaptureSession(queue_size=5_000)
        self._interfaces: list[InterfaceInfo] = []

        self._build_ui()
        self._connect_signals()

        self._drain_timer = QTimer(self)
        self._drain_timer.setInterval(100)
        self._drain_timer.timeout.connect(self._drain_capture_queue)
        self._drain_timer.start()
        self.refresh_interfaces()
        self._update_controls()

    def _build_ui(self) -> None:
        central = QWidget(self)
        outer = QVBoxLayout(central)
        outer.setContentsMargins(8, 8, 8, 8)
        outer.setSpacing(7)

        capture_group = QGroupBox("抓包控制")
        capture_layout = QGridLayout(capture_group)
        self.interface_combo = QComboBox()
        self.interface_combo.setMinimumWidth(480)
        self.refresh_button = QPushButton("刷新网卡")
        self.capture_filter_edit = QLineEdit()
        self.capture_filter_edit.setPlaceholderText("可选 BPF 抓取过滤，例如 tcp or udp port 53")
        self.start_button = QPushButton("开始")
        self.stop_button = QPushButton("停止")
        self.clear_button = QPushButton("清空")
        self.save_pcap_button = QPushButton("保存 PCAP")
        self.export_csv_button = QPushButton("导出 CSV")

        capture_layout.addWidget(QLabel("监听网卡："), 0, 0)
        capture_layout.addWidget(self.interface_combo, 0, 1, 1, 4)
        capture_layout.addWidget(self.refresh_button, 0, 5)
        capture_layout.addWidget(QLabel("抓取过滤："), 1, 0)
        capture_layout.addWidget(self.capture_filter_edit, 1, 1, 1, 2)
        capture_layout.addWidget(self.start_button, 1, 3)
        capture_layout.addWidget(self.stop_button, 1, 4)
        capture_layout.addWidget(self.clear_button, 1, 5)
        capture_layout.addWidget(self.save_pcap_button, 2, 3)
        capture_layout.addWidget(self.export_csv_button, 2, 4)

        filter_row = QHBoxLayout()
        filter_row.addWidget(QLabel("显示过滤："))
        self.display_filter_edit = QLineEdit()
        self.display_filter_edit.setPlaceholderText("例如：tcp ip:192.168.1.10 port:443（多个条件为 AND）")
        self.apply_filter_button = QPushButton("应用")
        self.clear_filter_button = QPushButton("清除过滤")
        self.filter_feedback = QLabel("")
        filter_row.addWidget(self.display_filter_edit, 1)
        filter_row.addWidget(self.apply_filter_button)
        filter_row.addWidget(self.clear_filter_button)
        filter_row.addWidget(self.filter_feedback)

        self.table_model = PacketTableModel(parent=self)
        self.packet_table = QTableView()
        self.packet_table.setModel(self.table_model)
        self.packet_table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.packet_table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.packet_table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.packet_table.setAlternatingRowColors(True)
        self.packet_table.verticalHeader().setVisible(False)
        header = self.packet_table.horizontalHeader()
        header.setSectionResizeMode(QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(8, QHeaderView.ResizeMode.Stretch)

        self.detail_tree = QTreeWidget()
        self.detail_tree.setHeaderLabels(["字段", "值"])
        self.detail_tree.header().setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        self.detail_tree.header().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)

        self.raw_view = QPlainTextEdit()
        self.raw_view.setReadOnly(True)
        self.raw_view.setLineWrapMode(QPlainTextEdit.LineWrapMode.NoWrap)
        self.raw_view.setFont(QFontDatabase.systemFont(QFontDatabase.SystemFont.FixedFont))
        self.raw_view.setPlaceholderText("选择数据包后显示十六进制与 ASCII 数据")

        detail_splitter = QSplitter(Qt.Orientation.Horizontal)
        detail_splitter.addWidget(self.detail_tree)
        detail_splitter.addWidget(self.raw_view)
        detail_splitter.setSizes([500, 750])

        main_splitter = QSplitter(Qt.Orientation.Vertical)
        main_splitter.addWidget(self.packet_table)
        main_splitter.addWidget(detail_splitter)
        main_splitter.setSizes([470, 280])

        outer.addWidget(capture_group)
        outer.addLayout(filter_row)
        outer.addWidget(main_splitter, 1)
        self.setCentralWidget(central)

        self.capture_status_label = QLabel("未开始抓包")
        self.counter_label = QLabel("捕获 0 | 显示 0 | 丢弃 0 | 重组 0")
        self.statusBar().addWidget(self.capture_status_label, 1)
        self.statusBar().addPermanentWidget(self.counter_label)

    def _connect_signals(self) -> None:
        self.refresh_button.clicked.connect(self.refresh_interfaces)
        self.start_button.clicked.connect(self.start_capture)
        self.stop_button.clicked.connect(self.stop_capture)
        self.clear_button.clicked.connect(self.clear_packets)
        self.save_pcap_button.clicked.connect(self.save_capture)
        self.export_csv_button.clicked.connect(self.export_summary)
        self.apply_filter_button.clicked.connect(self.apply_display_filter)
        self.clear_filter_button.clicked.connect(self.clear_display_filter)
        self.display_filter_edit.returnPressed.connect(self.apply_display_filter)
        self.packet_table.selectionModel().currentRowChanged.connect(self._show_selected_packet)

    def refresh_interfaces(self) -> None:
        if self._session.running:
            return
        current_name = self.interface_combo.currentData().pcap_name if self.interface_combo.currentData() else ""
        self.interface_combo.clear()
        try:
            self._interfaces = list_capture_interfaces()
        except Exception as exc:  # noqa: BLE001 - 向 GUI 转换底层错误
            self._interfaces = []
            self.capture_status_label.setText(f"网卡枚举失败：{exc}")
            self._update_controls()
            return
        for interface in self._interfaces:
            self.interface_combo.addItem(interface.display_name, interface)
            if interface.pcap_name == current_name:
                self.interface_combo.setCurrentIndex(self.interface_combo.count() - 1)
        self.capture_status_label.setText(f"发现 {len(self._interfaces)} 个可捕获接口")
        self._update_controls()

    def start_capture(self) -> None:
        interface = self.interface_combo.currentData()
        if not isinstance(interface, InterfaceInfo):
            QMessageBox.warning(self, "无法开始", "请先选择可用网卡。")
            return
        try:
            self._session.start(interface, self.capture_filter_edit.text().strip())
        except Exception as exc:  # noqa: BLE001
            QMessageBox.critical(self, "抓包启动失败", str(exc))
            self.capture_status_label.setText(f"启动失败：{exc}")
        else:
            self.capture_status_label.setText(f"正在监听：{interface.name}")
        self._update_controls()

    def stop_capture(self) -> None:
        try:
            self._session.stop()
        except Exception as exc:  # noqa: BLE001
            QMessageBox.warning(self, "停止抓包", str(exc))
        self._drain_capture_queue()
        self.capture_status_label.setText("抓包已停止")
        self._update_controls()

    def clear_packets(self) -> None:
        self.table_model.clear()
        self.detail_tree.clear()
        self.raw_view.clear()
        self._update_status_counts()

    def apply_display_filter(self) -> None:
        try:
            display_filter = DisplayFilter.parse(self.display_filter_edit.text())
        except FilterSyntaxError as exc:
            self.filter_feedback.setStyleSheet("color: #b42318")
            self.filter_feedback.setText(str(exc))
            return
        self.table_model.set_filter(display_filter)
        self.filter_feedback.setStyleSheet("color: #067647")
        self.filter_feedback.setText("已应用")
        self._update_status_counts()

    def clear_display_filter(self) -> None:
        self.display_filter_edit.clear()
        self.table_model.set_filter(DisplayFilter.parse(""))
        self.filter_feedback.clear()
        self._update_status_counts()

    def save_capture(self) -> None:
        records = self.table_model.records
        if not records:
            QMessageBox.information(self, "保存 PCAP", "当前没有可保存的数据包。")
            return
        path, _ = QFileDialog.getSaveFileName(self, "保存原始抓包", "capture.pcap", "PCAP 文件 (*.pcap)")
        if not path:
            return
        try:
            count = save_pcap(Path(path), records)
        except Exception as exc:  # noqa: BLE001
            QMessageBox.critical(self, "保存失败", str(exc))
            return
        self.statusBar().showMessage(f"已保存 {count} 个原始包到 {path}", 5000)

    def export_summary(self) -> None:
        records = self.table_model.records
        if not records:
            QMessageBox.information(self, "导出 CSV", "当前没有可导出的数据包摘要。")
            return
        path, _ = QFileDialog.getSaveFileName(self, "导出摘要", "capture-summary.csv", "CSV 文件 (*.csv)")
        if not path:
            return
        try:
            count = export_csv(Path(path), records)
        except Exception as exc:  # noqa: BLE001
            QMessageBox.critical(self, "导出失败", str(exc))
            return
        self.statusBar().showMessage(f"已导出 {count} 条摘要到 {path}", 5000)

    def _drain_capture_queue(self) -> None:
        records = self._session.drain(max_items=300)
        if records:
            self.table_model.add_records(records)
            if self.packet_table.currentIndex().isValid() is False and self.table_model.rowCount() > 0:
                self.packet_table.selectRow(0)
        if self._session.last_error:
            self.capture_status_label.setText(f"抓包错误：{self._session.last_error}")
        self._update_status_counts()

    def _show_selected_packet(self, current: QModelIndex, _previous: QModelIndex) -> None:
        record = self.table_model.record_at(current.row())
        self.detail_tree.clear()
        self.raw_view.clear()
        if record is None:
            return
        summary = QTreeWidgetItem(["数据包摘要", ""])
        summary.addChild(QTreeWidgetItem(["时间", record.timestamp_text]))
        summary.addChild(QTreeWidgetItem(["捕获长度", str(record.length)]))
        summary.addChild(QTreeWidgetItem(["协议", record.protocol]))
        if record.reassembly_note:
            summary.addChild(QTreeWidgetItem(["重组状态", record.reassembly_note]))
        self.detail_tree.addTopLevelItem(summary)
        for layer in record.layers:
            parent = QTreeWidgetItem([layer.name, ""])
            for name, value in layer.fields:
                parent.addChild(QTreeWidgetItem([name, value]))
            self.detail_tree.addTopLevelItem(parent)
        if record.errors:
            error_item = QTreeWidgetItem(["解析警告", ""])
            error_item.setForeground(0, QColor("#b42318"))
            for error in record.errors:
                error_item.addChild(QTreeWidgetItem(["警告", error]))
            self.detail_tree.addTopLevelItem(error_item)
        self.detail_tree.expandAll()
        self.raw_view.setPlainText(format_hex_ascii(record.raw))

    def _update_controls(self) -> None:
        running = self._session.running
        self.start_button.setEnabled(not running and bool(self._interfaces))
        self.stop_button.setEnabled(running)
        self.interface_combo.setEnabled(not running)
        self.refresh_button.setEnabled(not running)
        self.capture_filter_edit.setEnabled(not running)

    def _update_status_counts(self) -> None:
        stats = self._session.stats
        self.counter_label.setText(
            f"捕获 {stats.captured} | 显示 {self.table_model.visible_count} | "
            f"丢弃 {stats.dropped} | 解析警告 {stats.parse_errors} | 重组 {stats.reassembled}"
        )

    def closeEvent(self, event: QCloseEvent) -> None:  # noqa: N802
        if self._session.running:
            self._session.stop()
        event.accept()


def create_window_for_test() -> MainWindow:
    """测试和离屏截图使用的稳定工厂。"""

    if QApplication.instance() is None:
        QApplication([])
    return MainWindow()


__all__ = ["MainWindow", "PacketTableModel", "create_window_for_test"]
