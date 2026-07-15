"""PyQt6 desktop interface for the packet-capture dashboard.

The capture worker still hands parsed records to the GUI through a bounded
queue.  This module deliberately keeps all visual work on Qt's main thread.
"""

from __future__ import annotations

from pathlib import Path
from threading import Event
from time import monotonic

from PyQt6.QtCore import QAbstractTableModel, QModelIndex, QObject, QPoint, QPointF, QSize, Qt, QThread, QTimer, pyqtSignal
from PyQt6.QtGui import (
    QColor,
    QCloseEvent,
    QFont,
    QFontDatabase,
    QLinearGradient,
    QMouseEvent,
    QPainter,
    QPainterPath,
    QPen,
    QSyntaxHighlighter,
    QTextCharFormat,
)
from PyQt6.QtWidgets import (
    QAbstractItemView,
    QApplication,
    QComboBox,
    QFileDialog,
    QFrame,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QMainWindow,
    QMessageBox,
    QPlainTextEdit,
    QProgressBar,
    QProgressDialog,
    QPushButton,
    QSplitter,
    QStackedWidget,
    QStyle,
    QStyledItemDelegate,
    QStyleOptionViewItem,
    QTableView,
    QTreeWidget,
    QTreeWidgetItem,
    QVBoxLayout,
    QWidget,
)

from .capture import CaptureSession
from .analytics import Flow, FlowTracker, TrafficMeter
from .anomaly import Alert, AnomalyDetector
from .dashboard import MetricCard, TrafficChart
from .filtering import DisplayFilter, FilterSyntaxError
from .formatting import format_hex_ascii
from .interfaces import list_capture_interfaces
from .models import CaptureStats, InterfaceInfo, PacketRecord
from .offline import OfflineLoadResult, load_capture_file
from .storage import export_csv, save_pcap
from .theme import APP_STYLESHEET, COLORS, make_icon


def _repolish(widget: QWidget) -> None:
    """Refresh a widget after changing a dynamic stylesheet property."""

    style = widget.style()
    style.unpolish(widget)
    style.polish(widget)
    widget.update()


def _configure_button(
    button: QPushButton,
    *,
    icon: str,
    kind: str = "secondary",
    icon_color: str | None = None,
    icon_size: int = 17,
) -> QPushButton:
    button.setProperty("kind", kind)
    color = icon_color or ("#ffffff" if kind == "primary" else COLORS["text"])
    button.setIcon(make_icon(icon, color, icon_size))
    button.setIconSize(QSize(icon_size, icon_size))
    button.setCursor(Qt.CursorShape.PointingHandCursor)
    return button


class OfflineLoadWorker(QObject):
    """Read a capture file off the GUI thread and emit bounded batches."""

    batch_ready = pyqtSignal(object)
    progress = pyqtSignal(int)
    completed = pyqtSignal(object)
    failed = pyqtSignal(str)

    def __init__(self, path: Path, *, batch_size: int = 250) -> None:
        super().__init__()
        self.path = path
        self.batch_size = batch_size
        self._cancelled = Event()

    def cancel(self) -> None:
        self._cancelled.set()

    def run(self) -> None:
        try:
            result = load_capture_file(
                self.path,
                batch_callback=self.batch_ready.emit,
                progress_callback=self.progress.emit,
                cancel_requested=self._cancelled.is_set,
                batch_size=self.batch_size,
            )
        except Exception as exc:  # noqa: BLE001
            self.failed.emit(str(exc))
            return
        self.completed.emit(result)


class PacketTableModel(QAbstractTableModel):
    """Packet summary model with display filtering and a bounded history."""

    HEADERS = ("序号", "时间", "源地址", "目的地址", "协议", "源端口", "目的端口", "长度", "摘要")

    def __init__(self, *, max_records: int = 20_000, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.max_records = max_records
        self._records: list[PacketRecord] = []
        self._visible: list[int] = []
        self._filter = DisplayFilter.parse("")
        self._next_sequence = 1
        self._evicted_count = 0

    def rowCount(self, parent: QModelIndex = QModelIndex()) -> int:  # noqa: N802
        return 0 if parent.isValid() else len(self._visible)

    def columnCount(self, parent: QModelIndex = QModelIndex()) -> int:  # noqa: N802
        return 0 if parent.isValid() else len(self.HEADERS)

    def headerData(
        self,
        section: int,
        orientation: Qt.Orientation,
        role: int = Qt.ItemDataRole.DisplayRole,
    ):  # noqa: N802, ANN201
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
                return QColor(COLORS["danger"])
            if record.is_reassembled:
                return QColor(COLORS["purple"])
            if record.is_fragment:
                return QColor(COLORS["warning_dark"])
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

    @property
    def evicted_count(self) -> int:
        """Rows removed from the bounded in-memory table history."""

        return self._evicted_count

    def record_at(self, visible_row: int) -> PacketRecord | None:
        if 0 <= visible_row < len(self._visible):
            return self._records[self._visible[visible_row]]
        return None

    def add_records(self, records: list[PacketRecord]) -> None:
        if not records:
            return
        for record in records:
            # Session sequence numbers can restart; the table's numbers do not.
            record.sequence = self._next_sequence
            self._next_sequence += 1
        self.beginResetModel()
        self._records.extend(records)
        overflow = len(self._records) - self.max_records
        if overflow > 0:
            del self._records[:overflow]
            self._evicted_count += overflow
        self._rebuild_visible()
        self.endResetModel()

    def clear(self) -> None:
        self.beginResetModel()
        self._records.clear()
        self._visible.clear()
        self._next_sequence = 1
        self._evicted_count = 0
        self.endResetModel()

    def set_filter(self, display_filter: DisplayFilter) -> None:
        self.beginResetModel()
        self._filter = display_filter
        self._rebuild_visible()
        self.endResetModel()

    def _rebuild_visible(self) -> None:
        self._visible = [index for index, record in enumerate(self._records) if self._filter.matches(record)]


class FlowTableModel(QAbstractTableModel):
    HEADERS = ("协议", "端点 A", "端点 B", "状态", "持续时间", "A→B 包", "B→A 包", "总字节")

    def __init__(self, tracker: FlowTracker, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.tracker = tracker
        self._flows: list[Flow] = []

    def rowCount(self, parent: QModelIndex = QModelIndex()) -> int:  # noqa: N802
        return 0 if parent.isValid() else len(self._flows)

    def columnCount(self, parent: QModelIndex = QModelIndex()) -> int:  # noqa: N802
        return 0 if parent.isValid() else len(self.HEADERS)

    def headerData(self, section: int, orientation: Qt.Orientation, role: int = Qt.ItemDataRole.DisplayRole):  # noqa: N802, ANN201
        return self.HEADERS[section] if role == Qt.ItemDataRole.DisplayRole and orientation == Qt.Orientation.Horizontal else None

    def data(self, index: QModelIndex, role: int = Qt.ItemDataRole.DisplayRole):  # noqa: ANN201
        if not index.isValid() or index.row() >= len(self._flows):
            return None
        flow = self._flows[index.row()]
        if role == Qt.ItemDataRole.DisplayRole:
            values = (flow.protocol, f"{flow.endpoint_a[0]}:{flow.endpoint_a[1]}", f"{flow.endpoint_b[0]}:{flow.endpoint_b[1]}", flow.tcp_state, f"{flow.duration:.3f}s", flow.packets_ab, flow.packets_ba, flow.byte_count)
            return values[index.column()]
        return None

    def refresh(self) -> None:
        self.beginResetModel()
        self._flows = self.tracker.flows
        self.endResetModel()

    def flow_at(self, row: int) -> Flow | None:
        return self._flows[row] if 0 <= row < len(self._flows) else None

    def row_for_flow(self, target: Flow) -> int:
        """Return the current row for a flow after a model refresh."""
        return next((row for row, flow in enumerate(self._flows) if flow is target), -1)


class AlertTableModel(QAbstractTableModel):
    HEADERS = ("时间", "级别", "类型", "来源", "说明", "数据包")

    def __init__(self, detector: AnomalyDetector, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.detector = detector
        self._alerts: list[Alert] = []

    def rowCount(self, parent: QModelIndex = QModelIndex()) -> int:  # noqa: N802
        return 0 if parent.isValid() else len(self._alerts)

    def columnCount(self, parent: QModelIndex = QModelIndex()) -> int:  # noqa: N802
        return 0 if parent.isValid() else len(self.HEADERS)

    def headerData(self, section: int, orientation: Qt.Orientation, role: int = Qt.ItemDataRole.DisplayRole):  # noqa: N802, ANN201
        return self.HEADERS[section] if role == Qt.ItemDataRole.DisplayRole and orientation == Qt.Orientation.Horizontal else None

    def data(self, index: QModelIndex, role: int = Qt.ItemDataRole.DisplayRole):  # noqa: ANN201
        if not index.isValid() or index.row() >= len(self._alerts):
            return None
        alert = self._alerts[index.row()]
        if role == Qt.ItemDataRole.DisplayRole:
            return (alert.timestamp_text, alert.severity.upper(), alert.category, alert.source, alert.description, alert.packet_sequence)[index.column()]
        if role == Qt.ItemDataRole.ForegroundRole:
            return QColor({"critical": "#b42318", "high": "#dc6803", "medium": "#9a6700", "low": "#175cd3"}.get(alert.severity, "#344054"))
        return None

    def refresh(self) -> None:
        self.beginResetModel()
        self._alerts = list(self.detector.alerts)
        self.endResetModel()


class PacketItemDelegate(QStyledItemDelegate):
    """Paint compact protocol badges and the cyan selected-row marker."""

    PROTOCOL_COLORS = {
        "TCP": ("#0879d9", "#ffffff"),
        "UDP": ("#099866", "#ffffff"),
        "DNS": ("#4e63df", "#ffffff"),
        "TLS": ("#7444d4", "#ffffff"),
        "HTTP": ("#f27822", "#ffffff"),
        "HTTPS": ("#7444d4", "#ffffff"),
        "ARP": ("#3d9297", "#ffffff"),
        "ICMP": ("#d98900", "#ffffff"),
        "DHCP": ("#0f9eb2", "#ffffff"),
        "QUIC": ("#7655d8", "#ffffff"),
        "IPv4": ("#1769d2", "#ffffff"),
        "UNKNOWN": ("#718096", "#ffffff"),
    }

    def paint(self, painter: QPainter, option: QStyleOptionViewItem, index: QModelIndex) -> None:
        selected = bool(option.state & QStyle.StateFlag.State_Selected)
        if index.column() != 4:
            super().paint(painter, option, index)
        else:
            badge_option = QStyleOptionViewItem(option)
            self.initStyleOption(badge_option, index)
            text = badge_option.text
            badge_option.text = ""
            style = option.widget.style() if option.widget is not None else QApplication.style()
            style.drawControl(QStyle.ControlElement.CE_ItemViewItem, badge_option, painter, option.widget)

            background, foreground = self.PROTOCOL_COLORS.get(text.upper(), ("#687a8d", "#ffffff"))
            metrics = option.fontMetrics
            badge_width = min(option.rect.width() - 10, max(42, metrics.horizontalAdvance(text) + 18))
            badge_height = min(20, option.rect.height() - 6)
            badge_rect = option.rect.adjusted(
                (option.rect.width() - badge_width) // 2,
                (option.rect.height() - badge_height) // 2,
                -(option.rect.width() - badge_width + 1) // 2,
                -(option.rect.height() - badge_height + 1) // 2,
            )
            painter.save()
            painter.setRenderHint(QPainter.RenderHint.Antialiasing)
            painter.setPen(Qt.PenStyle.NoPen)
            painter.setBrush(QColor(background))
            painter.drawRoundedRect(badge_rect, 3, 3)
            painter.setPen(QColor(foreground))
            font = painter.font()
            font.setPointSizeF(max(7.5, font.pointSizeF() - 0.2))
            font.setBold(True)
            painter.setFont(font)
            painter.drawText(badge_rect, Qt.AlignmentFlag.AlignCenter, text)
            painter.restore()

        if selected and index.column() == 0:
            painter.save()
            painter.fillRect(option.rect.left(), option.rect.top(), 3, option.rect.height(), QColor(COLORS["cyan"]))
            painter.restore()


class HexSyntaxHighlighter(QSyntaxHighlighter):
    """Give the plain-text hex dump the three-column look of an analyser."""

    def __init__(self, document) -> None:  # noqa: ANN001
        super().__init__(document)
        self.offset_format = QTextCharFormat()
        self.offset_format.setForeground(QColor(COLORS["primary"]))
        self.offset_format.setFontWeight(QFont.Weight.DemiBold)
        self.ascii_format = QTextCharFormat()
        self.ascii_format.setForeground(QColor("#40536a"))
        self.ip_header_format = QTextCharFormat()
        self.ip_header_format.setBackground(QColor("#b9edf1"))
        self.ip_header_format.setForeground(QColor("#164b58"))

    def highlightBlock(self, text: str) -> None:  # noqa: N802
        if not text or text.startswith("..."):
            return
        offset_end = text.find("  ")
        if offset_end > 0:
            self.setFormat(0, offset_end, self.offset_format)
        ascii_start = text.find("|")
        if ascii_start >= 0:
            self.setFormat(ascii_start, len(text) - ascii_start, self.ascii_format)
        # IPv4's common first two bytes are a useful visual anchor, matching
        # the highlighted header bytes in the reference analyser.
        marker = text.find("45 00")
        if marker >= 0 and (ascii_start < 0 or marker < ascii_start):
            self.setFormat(marker, 5, self.ip_header_format)


class BrandMark(QWidget):
    """Small vector shield used by the NetScope wordmark."""

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setFixedSize(38, 48)

    def paintEvent(self, _event) -> None:  # noqa: ANN001, N802
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        gradient = QLinearGradient(0, 4, 0, 44)
        gradient.setColorAt(0, QColor("#1f8dff"))
        gradient.setColorAt(1, QColor("#0758cf"))
        shield = QPainterPath()
        shield.moveTo(19, 2)
        shield.cubicTo(13, 7, 8, 8, 3, 9)
        shield.lineTo(4.5, 25)
        shield.cubicTo(5.2, 34, 11.5, 41, 19, 45)
        shield.cubicTo(26.5, 41, 32.8, 34, 33.5, 25)
        shield.lineTo(35, 9)
        shield.cubicTo(30, 8, 25, 7, 19, 2)
        painter.setBrush(gradient)
        painter.setPen(QPen(QColor("#e9f7ff"), 2.2))
        painter.drawPath(shield)

        painter.setPen(QPen(QColor("#dff8ff"), 1.3))
        painter.drawLine(QPoint(12, 18), QPoint(20, 25))
        painter.drawLine(QPoint(20, 25), QPoint(26, 16))
        painter.drawLine(QPoint(20, 25), QPoint(23, 33))
        painter.setBrush(QColor("#ffffff"))
        painter.setPen(Qt.PenStyle.NoPen)
        for point in (QPointF(12, 18), QPointF(26, 16), QPointF(20, 25), QPointF(23, 33)):
            painter.drawEllipse(point, 2.2, 2.2)


class WindowTitleBar(QFrame):
    """Reference-style title bar with drag and window controls."""

    def __init__(self, window: "MainWindow") -> None:
        super().__init__(window)
        self._window = window
        self._drag_position: QPoint | None = None
        self.setObjectName("topbar")
        self.setFixedHeight(65)

        layout = QHBoxLayout(self)
        layout.setContentsMargins(23, 0, 8, 0)
        layout.setSpacing(5)

        title_column = QVBoxLayout()
        title_column.setContentsMargins(0, 10, 0, 9)
        title_column.setSpacing(0)
        title = QLabel("网络嗅探器")
        title.setObjectName("windowTitle")
        subtitle = QLabel("Windows 实时流量捕获与协议分析")
        subtitle.setObjectName("windowSubtitle")
        title_column.addWidget(title)
        title_column.addWidget(subtitle)
        layout.addLayout(title_column)
        layout.addStretch(1)

        self.capture_state = QLabel()
        self.capture_state.setObjectName("captureState")
        self.capture_state.setProperty("state", "stopped")
        self.capture_state.setTextFormat(Qt.TextFormat.RichText)
        self.capture_state.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.capture_state.setFixedSize(112, 34)
        self.set_capture_running(False)
        layout.addWidget(self.capture_state)
        layout.addSpacing(18)

        self.settings_button = self._window_button("settings", "设置")
        self.help_button = self._window_button("help", "帮助")
        self.minimize_button = self._window_button("minimize", "最小化")
        self.maximize_button = self._window_button("maximize", "最大化")
        self.close_button = self._window_button("close", "关闭", close=True)
        layout.addWidget(self.settings_button)
        layout.addWidget(self.help_button)
        layout.addSpacing(8)
        layout.addWidget(self.minimize_button)
        layout.addWidget(self.maximize_button)
        layout.addWidget(self.close_button)

        self.minimize_button.clicked.connect(window.showMinimized)
        self.maximize_button.clicked.connect(self.toggle_maximize)
        self.close_button.clicked.connect(window.close)
        self.settings_button.clicked.connect(lambda: window.show_section_notice("设置中心"))
        self.help_button.clicked.connect(lambda: window.show_section_notice("使用帮助"))

    def _window_button(self, icon: str, tooltip: str, *, close: bool = False) -> QPushButton:
        button = QPushButton()
        button.setObjectName("windowControl")
        button.setProperty("kind", "close" if close else "window")
        button.setIcon(make_icon(icon, "#d9e5f1", 18))
        button.setIconSize(QSize(18, 18))
        button.setFixedSize(46, 44)
        button.setToolTip(tooltip)
        button.setCursor(Qt.CursorShape.PointingHandCursor)
        return button

    def set_capture_running(self, running: bool) -> None:
        self.capture_state.setProperty("state", "running" if running else "stopped")
        dot = COLORS["success"] if running else "#8295a8"
        label = "正在抓包" if running else "已停止"
        self.capture_state.setText(
            f'<span style="color:{dot}">●</span>&nbsp;&nbsp;'
            f'<span style="color:#dce8f3">{label}</span>'
        )
        _repolish(self.capture_state)

    def toggle_maximize(self) -> None:
        if self._window.isMaximized():
            self._window.showNormal()
            icon = "maximize"
            tooltip = "最大化"
        else:
            self._window.showMaximized()
            icon = "maximize"
            tooltip = "还原"
        self.maximize_button.setIcon(make_icon(icon, "#d9e5f1", 18))
        self.maximize_button.setToolTip(tooltip)

    def mousePressEvent(self, event: QMouseEvent) -> None:  # noqa: N802
        if event.button() == Qt.MouseButton.LeftButton:
            self._drag_position = event.globalPosition().toPoint() - self._window.frameGeometry().topLeft()
            event.accept()
            return
        super().mousePressEvent(event)

    def mouseMoveEvent(self, event: QMouseEvent) -> None:  # noqa: N802
        if self._drag_position is not None and event.buttons() & Qt.MouseButton.LeftButton:
            if self._window.isMaximized():
                self._window.showNormal()
                self._drag_position = QPoint(self._window.width() // 2, 24)
            self._window.move(event.globalPosition().toPoint() - self._drag_position)
            event.accept()
            return
        super().mouseMoveEvent(event)

    def mouseReleaseEvent(self, event: QMouseEvent) -> None:  # noqa: N802
        self._drag_position = None
        super().mouseReleaseEvent(event)

    def mouseDoubleClickEvent(self, event: QMouseEvent) -> None:  # noqa: N802
        if event.button() == Qt.MouseButton.LeftButton:
            self.toggle_maximize()
            event.accept()
            return
        super().mouseDoubleClickEvent(event)


class StatisticCard(QFrame):
    """A live-value card used by the capture dashboard."""

    def __init__(self, title: str, icon: str, accent: str, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setObjectName("statCard")
        self.setProperty("accent", accent)
        self.setFixedHeight(98)

        layout = QHBoxLayout(self)
        layout.setContentsMargins(16, 11, 14, 10)
        layout.setSpacing(10)
        text_column = QVBoxLayout()
        text_column.setSpacing(0)
        title_label = QLabel(title)
        title_label.setObjectName("statTitle")
        self.value_label = QLabel("0")
        self.value_label.setObjectName("statValue")
        self.caption_label = QLabel("—")
        self.caption_label.setObjectName("statCaption")
        self.caption_label.setStyleSheet(f"color: {accent};")
        text_column.addWidget(title_label)
        text_column.addWidget(self.value_label, 1)
        text_column.addWidget(self.caption_label)
        layout.addLayout(text_column, 1)

        icon_label = QLabel()
        icon_label.setPixmap(make_icon(icon, accent, 38).pixmap(38, 38))
        icon_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        icon_label.setFixedSize(48, 48)
        layout.addWidget(icon_label, 0, Qt.AlignmentFlag.AlignVCenter)

    def set_value(self, value: str, caption: str | None = None) -> None:
        self.value_label.setText(value)
        if caption is not None:
            self.caption_label.setText(caption)


class MainWindow(QMainWindow):
    """Network sniffer main window."""

    def __init__(self, *, capture_session: CaptureSession | None = None) -> None:
        super().__init__()
        self.setObjectName("mainWindow")
        self.setWindowTitle("NetScope · 网络嗅探器")
        self.setWindowFlag(Qt.WindowType.FramelessWindowHint, True)
        self.setMinimumSize(1180, 760)
        self.resize(1480, 987)
        self.setStyleSheet(APP_STYLESHEET)

        self._session = capture_session or CaptureSession(queue_size=5_000)
        self._queue_capacity = int(getattr(self._session, "queue_capacity", 5_000))
        self._interfaces: list[InterfaceInfo] = []
        self.traffic_meter = TrafficMeter(window=60)
        self.flow_tracker = FlowTracker()
        self.anomaly_detector = AnomalyDetector()
        self._active_interface_name = ""
        self._last_rate_time = monotonic()
        self._last_rate_count = 0
        self._capture_rate = 0
        self._offline_stats: CaptureStats | None = None
        self._offline_source = ""
        self._offline_loading = False
        self._offline_thread: QThread | None = None
        self._offline_worker: OfflineLoadWorker | None = None
        self._offline_progress: QProgressDialog | None = None
        self._footer_restore_text = ""
        self._footer_notice_generation = 0

        self._build_ui()
        self._connect_signals()

        self._drain_timer = QTimer(self)
        self._drain_timer.setInterval(100)
        self._drain_timer.timeout.connect(self._drain_capture_queue)
        self._drain_timer.start()
        self.refresh_interfaces()
        self._update_controls()

    def _build_ui(self) -> None:
        root = QWidget(self)
        root.setObjectName("root")
        shell = QHBoxLayout(root)
        shell.setContentsMargins(0, 0, 0, 0)
        shell.setSpacing(0)

        shell.addWidget(self._build_sidebar())

        workspace = QWidget()
        workspace.setObjectName("workspace")
        workspace_layout = QVBoxLayout(workspace)
        workspace_layout.setContentsMargins(0, 0, 0, 0)
        workspace_layout.setSpacing(0)

        self.title_bar = WindowTitleBar(self)
        workspace_layout.addWidget(self.title_bar)

        content = QWidget()
        content.setObjectName("content")
        content_layout = QVBoxLayout(content)
        content_layout.setContentsMargins(10, 12, 14, 14)
        content_layout.setSpacing(10)
        content_layout.addWidget(self._build_capture_toolbar())
        content_layout.addLayout(self._build_statistics_row())

        self.table_model = PacketTableModel(parent=self)
        self.packet_table = self._build_packet_table()
        packet_panel = self._build_packet_panel()

        self.detail_tree = self._build_detail_tree()
        protocol_panel = self._panel("协议字段", self.detail_tree)

        self.raw_view = self._build_raw_view()
        self._hex_highlighter = HexSyntaxHighlighter(self.raw_view.document())
        raw_panel = self._panel("原始数据  Hex / ASCII", self.raw_view)

        detail_splitter = QSplitter(Qt.Orientation.Horizontal)
        detail_splitter.setObjectName("contentSplitter")
        detail_splitter.setChildrenCollapsible(False)
        detail_splitter.setHandleWidth(10)
        detail_splitter.addWidget(protocol_panel)
        detail_splitter.addWidget(raw_panel)
        detail_splitter.setStretchFactor(0, 4)
        detail_splitter.setStretchFactor(1, 7)
        detail_splitter.setSizes([470, 760])

        main_splitter = QSplitter(Qt.Orientation.Vertical)
        main_splitter.setObjectName("contentSplitter")
        main_splitter.setChildrenCollapsible(False)
        main_splitter.setHandleWidth(10)
        main_splitter.addWidget(packet_panel)
        main_splitter.addWidget(detail_splitter)
        main_splitter.setStretchFactor(0, 1)
        main_splitter.setStretchFactor(1, 1)
        main_splitter.setSizes([303, 322])
        content_layout.addWidget(main_splitter, 1)

        self.workspace_pages = QStackedWidget()
        self.workspace_pages.setObjectName("workspacePages")
        self.workspace_pages.addWidget(content)
        self.workspace_pages.addWidget(self._build_dashboard_page())
        self.workspace_pages.addWidget(self._build_sessions_page())
        self.workspace_pages.addWidget(self._build_alerts_page())
        # Keep the remote feature branch's public handle available while the
        # NetScope shell presents those pages through its sidebar, not tabs.
        self.workspace_tabs = self.workspace_pages
        workspace_layout.addWidget(self.workspace_pages, 1)
        workspace_layout.addWidget(self._build_footer())
        shell.addWidget(workspace, 1)
        self.setCentralWidget(root)

    @staticmethod
    def _analysis_header(title: str, subtitle: str, icon_name: str) -> QFrame:
        header = QFrame()
        header.setObjectName("analysisHeader")
        header.setFixedHeight(70)
        layout = QHBoxLayout(header)
        layout.setContentsMargins(18, 9, 18, 9)
        layout.setSpacing(12)
        icon = QLabel()
        icon.setPixmap(make_icon(icon_name, COLORS["primary"], 30).pixmap(30, 30))
        icon.setFixedSize(38, 38)
        layout.addWidget(icon)
        labels = QVBoxLayout()
        labels.setSpacing(1)
        title_label = QLabel(title)
        title_label.setObjectName("analysisTitle")
        subtitle_label = QLabel(subtitle)
        subtitle_label.setObjectName("analysisSubtitle")
        labels.addWidget(title_label)
        labels.addWidget(subtitle_label)
        layout.addLayout(labels)
        layout.addStretch(1)
        return header

    def _build_dashboard_page(self) -> QWidget:
        page = QWidget()
        page.setObjectName("content")
        layout = QVBoxLayout(page)
        layout.setContentsMargins(10, 12, 14, 14)
        layout.setSpacing(10)
        layout.addWidget(
            self._analysis_header(
                "流量态势",
                "实时聚合最近 60 秒的数据包、字节、协议分布与安全告警",
                "pie",
            )
        )

        cards = QHBoxLayout()
        cards.setSpacing(10)
        self.packet_rate_card = MetricCard("Packets / second")
        self.byte_rate_card = MetricCard("Bytes / second")
        self.flow_count_card = MetricCard("Active conversations")
        self.alert_count_card = MetricCard("Security alerts")
        for card in (self.packet_rate_card, self.byte_rate_card, self.flow_count_card, self.alert_count_card):
            cards.addWidget(card, 1)
        layout.addLayout(cards)

        self.traffic_chart = TrafficChart(self.traffic_meter)
        layout.addWidget(self._panel("60 秒实时流量波形", self.traffic_chart), 1)

        protocol_panel = QFrame()
        protocol_panel.setObjectName("panel")
        protocol_layout = QHBoxLayout(protocol_panel)
        protocol_layout.setContentsMargins(14, 9, 14, 9)
        protocol_label = QLabel("协议分布")
        protocol_label.setObjectName("panelTitle")
        self.protocol_summary = QLabel("等待实时数据")
        self.protocol_summary.setObjectName("analysisSummary")
        protocol_layout.addWidget(protocol_label)
        protocol_layout.addSpacing(18)
        protocol_layout.addWidget(self.protocol_summary, 1)
        layout.addWidget(protocol_panel)
        return page

    def _build_sessions_page(self) -> QWidget:
        page = QWidget()
        page.setObjectName("content")
        layout = QVBoxLayout(page)
        layout.setContentsMargins(10, 12, 14, 14)
        layout.setSpacing(10)
        layout.addWidget(
            self._analysis_header(
                "会话与 TCP 流",
                "按双向端点归并 TCP/UDP 会话，并查看 TCP 载荷重组结果",
                "fragments",
            )
        )

        self.flow_model = FlowTableModel(self.flow_tracker, self)
        self.flow_table = QTableView()
        self.flow_table.setObjectName("analysisTable")
        self.flow_table.setModel(self.flow_model)
        self.flow_table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.flow_table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.flow_table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.flow_table.setAlternatingRowColors(False)
        self.flow_table.verticalHeader().setVisible(False)
        self.flow_table.verticalHeader().setDefaultSectionSize(28)
        flow_header = self.flow_table.horizontalHeader()
        flow_header.setSectionResizeMode(QHeaderView.ResizeMode.ResizeToContents)
        flow_header.setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)

        self.stream_view = QPlainTextEdit()
        self.stream_view.setObjectName("rawView")
        self.stream_view.setReadOnly(True)
        self.stream_view.setLineWrapMode(QPlainTextEdit.LineWrapMode.NoWrap)
        self.stream_view.setFont(QFontDatabase.systemFont(QFontDatabase.SystemFont.FixedFont))
        self.stream_view.setPlaceholderText("选择 TCP 会话查看双向重组流")

        flow_splitter = QSplitter(Qt.Orientation.Vertical)
        flow_splitter.setObjectName("contentSplitter")
        flow_splitter.setChildrenCollapsible(False)
        flow_splitter.setHandleWidth(10)
        flow_splitter.addWidget(self._panel("活动会话", self.flow_table))
        flow_splitter.addWidget(self._panel("重组字节流", self.stream_view))
        flow_splitter.setSizes([470, 260])
        layout.addWidget(flow_splitter, 1)
        return page

    def _build_alerts_page(self) -> QWidget:
        page = QWidget()
        page.setObjectName("content")
        layout = QVBoxLayout(page)
        layout.setContentsMargins(10, 12, 14, 14)
        layout.setSpacing(10)
        layout.addWidget(
            self._analysis_header(
                "异常检测",
                "被动检测端口扫描、SYN 洪泛、DNS 异常、ARP 冲突、异常分片与 TCP Reset",
                "warning",
            )
        )

        self.alert_model = AlertTableModel(self.anomaly_detector, self)
        self.alert_table = QTableView()
        self.alert_table.setObjectName("analysisTable")
        self.alert_table.setModel(self.alert_model)
        self.alert_table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.alert_table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.alert_table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.alert_table.setAlternatingRowColors(False)
        self.alert_table.verticalHeader().setVisible(False)
        self.alert_table.verticalHeader().setDefaultSectionSize(28)
        alert_header = self.alert_table.horizontalHeader()
        alert_header.setSectionResizeMode(QHeaderView.ResizeMode.ResizeToContents)
        alert_header.setSectionResizeMode(4, QHeaderView.ResizeMode.Stretch)
        layout.addWidget(self._panel("安全告警记录", self.alert_table), 1)
        return page

    def _set_workspace_page(self, index: int) -> None:
        if not hasattr(self, "workspace_pages") or not 0 <= index < self.workspace_pages.count():
            return
        self.workspace_pages.setCurrentIndex(index)
        for button_index, button in enumerate(self.nav_buttons):
            active = button_index == index
            button.setProperty("active", active)
            icon_name = self._nav_icon_names[button_index]
            button.setIcon(make_icon(icon_name, "#29a4ff" if active else "#dbe7f3", 24))
            _repolish(button)

    def _build_sidebar(self) -> QFrame:
        sidebar = QFrame()
        sidebar.setObjectName("sidebar")
        sidebar.setFixedWidth(183)
        layout = QVBoxLayout(sidebar)
        # The connection card ends above the right-side footer, like the
        # reference layout, while the navy rail itself continues to the edge.
        layout.setContentsMargins(8, 0, 8, 70)
        layout.setSpacing(4)

        brand = QWidget()
        brand.setFixedHeight(74)
        brand_layout = QHBoxLayout(brand)
        brand_layout.setContentsMargins(15, 8, 6, 7)
        brand_layout.setSpacing(9)
        brand_layout.addWidget(BrandMark())
        brand_text = QLabel("NetScope")
        brand_text.setObjectName("brandText")
        brand_layout.addWidget(brand_text)
        brand_layout.addStretch(1)
        layout.addWidget(brand)

        navigation = (
            ("实时抓包", "capture", True),
            ("流量态势", "pie", False),
            ("会话分析", "fragments", False),
            ("异常检测", "warning", False),
        )
        self.nav_buttons: list[QPushButton] = []
        self._nav_icon_names = [icon_name for _text, icon_name, _active in navigation]
        for index, (text, icon_name, active) in enumerate(navigation):
            button = QPushButton(text)
            button.setObjectName("navButton")
            button.setProperty("active", active)
            button.setIcon(make_icon(icon_name, "#29a4ff" if active else "#dbe7f3", 24))
            button.setIconSize(QSize(24, 24))
            button.setFixedHeight(50)
            button.setCursor(Qt.CursorShape.PointingHandCursor)
            button.clicked.connect(lambda _checked=False, page=index: self._set_workspace_page(page))
            self.nav_buttons.append(button)
            layout.addWidget(button)
        layout.addStretch(1)

        connection = QFrame()
        connection.setObjectName("connectionCard")
        connection.setFixedHeight(86)
        connection_layout = QVBoxLayout(connection)
        connection_layout.setContentsMargins(14, 11, 14, 11)
        connection_layout.setSpacing(6)
        self.npcap_status_label = QLabel("●  Npcap  检测中")
        self.npcap_status_label.setObjectName("npcapStatus")
        self.npcap_status_label.setProperty("connected", False)
        self.npcap_status_label.setTextFormat(Qt.TextFormat.RichText)
        self.queue_label = QLabel(f"队列  0 / {self._queue_capacity:,}")
        self.queue_label.setObjectName("queueLabel")
        self.queue_progress = QProgressBar()
        self.queue_progress.setObjectName("queueProgress")
        self.queue_progress.setRange(0, max(1, self._queue_capacity))
        self.queue_progress.setValue(0)
        self.queue_progress.setTextVisible(False)
        self.queue_progress.setFixedHeight(7)
        connection_layout.addWidget(self.npcap_status_label)
        connection_layout.addWidget(self.queue_label)
        connection_layout.addWidget(self.queue_progress)
        layout.addWidget(connection)
        return sidebar

    def _build_capture_toolbar(self) -> QFrame:
        toolbar = QFrame()
        toolbar.setObjectName("toolbarPanel")
        toolbar.setFixedHeight(85)
        layout = QHBoxLayout(toolbar)
        layout.setContentsMargins(16, 9, 12, 9)
        layout.setSpacing(10)

        self.interface_combo = QComboBox()
        self.interface_combo.setMinimumWidth(220)
        self.interface_combo.setSizeAdjustPolicy(QComboBox.SizeAdjustPolicy.AdjustToMinimumContentsLengthWithIcon)
        self.interface_combo.setMinimumContentsLength(24)
        self.refresh_button = _configure_button(QPushButton("刷新"), icon="refresh")
        self.refresh_button.setMinimumWidth(72)
        interface_row = QHBoxLayout()
        interface_row.setSpacing(6)
        interface_row.addWidget(self.interface_combo, 1)
        interface_row.addWidget(self.refresh_button)
        layout.addWidget(self._toolbar_section("监听网卡", interface_row), 5)

        self.capture_filter_edit = QLineEdit()
        self.capture_filter_edit.setMinimumWidth(140)
        self.capture_filter_edit.setPlaceholderText("ip and (tcp or udp)")
        filter_row = QHBoxLayout()
        filter_row.addWidget(self.capture_filter_edit)
        layout.addWidget(self._toolbar_section("BPF 抓取过滤", filter_row), 3)

        self.start_button = _configure_button(QPushButton("开始"), icon="play", kind="primary")
        self.stop_button = _configure_button(QPushButton("停止"), icon="stop")
        self.clear_button = _configure_button(QPushButton("清空"), icon="trash")
        self.open_pcap_button = _configure_button(QPushButton("打开 PCAP"), icon="document")
        self.save_pcap_button = _configure_button(QPushButton("保存 PCAP"), icon="save")
        self.export_csv_button = _configure_button(QPushButton("导出 CSV"), icon="csv")
        for button, width in (
            (self.start_button, 76),
            (self.stop_button, 70),
            (self.clear_button, 70),
            (self.open_pcap_button, 103),
            (self.save_pcap_button, 103),
            (self.export_csv_button, 98),
        ):
            button.setMinimumWidth(width)
            button.setFixedHeight(36)

        button_row = QHBoxLayout()
        button_row.setSpacing(7)
        button_row.addWidget(self.start_button)
        button_row.addWidget(self.stop_button)
        button_row.addWidget(self.clear_button)
        button_row.addSpacing(5)
        button_row.addWidget(self.open_pcap_button)
        button_row.addWidget(self.save_pcap_button)
        button_row.addWidget(self.export_csv_button)
        layout.addWidget(self._toolbar_section(" ", button_row), 0)
        return toolbar

    @staticmethod
    def _toolbar_section(title: str, row: QHBoxLayout) -> QWidget:
        section = QWidget()
        section_layout = QVBoxLayout(section)
        section_layout.setContentsMargins(0, 0, 0, 0)
        section_layout.setSpacing(4)
        label = QLabel(title)
        label.setObjectName("toolbarLabel")
        section_layout.addWidget(label)
        section_layout.addLayout(row)
        return section

    def _build_statistics_row(self) -> QHBoxLayout:
        row = QHBoxLayout()
        row.setContentsMargins(0, 0, 0, 0)
        row.setSpacing(10)
        self.captured_card = StatisticCard("捕获数据包", "document", COLORS["primary"])
        self.visible_card = StatisticCard("当前显示", "filter", "#0759c7")
        self.health_card = StatisticCard("丢弃 / 警告", "warning", COLORS["warning"])
        self.reassembly_card = StatisticCard("成功重组", "layers", COLORS["purple"])
        for card, stretch in zip(
            (self.captured_card, self.visible_card, self.health_card, self.reassembly_card),
            (98, 100, 100, 113),
            strict=True,
        ):
            row.addWidget(card, stretch)
        return row

    def _build_packet_table(self) -> QTableView:
        table = QTableView()
        table.setObjectName("packetTable")
        table.setModel(self.table_model)
        table.setItemDelegate(PacketItemDelegate(table))
        table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        table.setAlternatingRowColors(False)
        table.setShowGrid(True)
        table.setWordWrap(False)
        table.setSortingEnabled(False)
        table.verticalHeader().setVisible(False)
        table.verticalHeader().setDefaultSectionSize(26)
        table.verticalHeader().setMinimumSectionSize(26)
        header = table.horizontalHeader()
        header.setDefaultAlignment(Qt.AlignmentFlag.AlignCenter)
        header.setFixedHeight(29)
        header.setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        widths = (79, 158, 137, 141, 92, 92, 116, 91)
        for column, width in enumerate(widths):
            table.setColumnWidth(column, width)
        header.setSectionResizeMode(8, QHeaderView.ResizeMode.Stretch)
        return table

    def _build_packet_panel(self) -> QFrame:
        panel = QFrame()
        panel.setObjectName("panel")
        layout = QVBoxLayout(panel)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        header = QFrame()
        header.setObjectName("panelHeader")
        header.setFixedHeight(43)
        header_layout = QHBoxLayout(header)
        header_layout.setContentsMargins(13, 5, 10, 5)
        header_layout.setSpacing(8)
        title = QLabel("数据包列表")
        title.setObjectName("panelTitle")
        pulse = QLabel()
        pulse.setPixmap(make_icon("pulse", COLORS["cyan"], 23).pixmap(23, 23))
        header_layout.addWidget(title)
        header_layout.addWidget(pulse)
        header_layout.addStretch(1)

        self.display_filter_edit = QLineEdit()
        self.display_filter_edit.setObjectName("displayFilter")
        self.display_filter_edit.setPlaceholderText("tcp   ip:192.168.1.105   port:443")
        self.display_filter_edit.setMinimumWidth(270)
        self.display_filter_edit.setMaximumWidth(430)
        self.apply_filter_button = _configure_button(QPushButton("应用"), icon="filter", kind="primary", icon_size=15)
        self.apply_filter_button.setFixedSize(70, 32)
        self.clear_filter_button = QPushButton("清除")
        self.clear_filter_button.setProperty("kind", "quiet")
        self.clear_filter_button.setCursor(Qt.CursorShape.PointingHandCursor)
        self.clear_filter_button.setFixedSize(52, 32)
        self.filter_feedback = QLabel("")
        self.filter_feedback.setObjectName("filterFeedback")
        self.filter_feedback.setFixedWidth(68)
        header_layout.addWidget(self.display_filter_edit, 1)
        header_layout.addWidget(self.apply_filter_button)
        header_layout.addWidget(self.clear_filter_button)
        header_layout.addWidget(self.filter_feedback)
        layout.addWidget(header)
        layout.addWidget(self.packet_table, 1)
        return panel

    def _build_detail_tree(self) -> QTreeWidget:
        tree = QTreeWidget()
        tree.setObjectName("detailTree")
        tree.setHeaderLabels(["字段", "值"])
        tree.setRootIsDecorated(True)
        tree.setAlternatingRowColors(False)
        tree.setIndentation(15)
        tree.setUniformRowHeights(True)
        tree.header().setFixedHeight(26)
        tree.header().setSectionResizeMode(0, QHeaderView.ResizeMode.Interactive)
        tree.header().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        tree.setColumnWidth(0, 275)
        return tree

    @staticmethod
    def _build_raw_view() -> QPlainTextEdit:
        raw_view = QPlainTextEdit()
        raw_view.setObjectName("rawView")
        raw_view.setReadOnly(True)
        raw_view.setLineWrapMode(QPlainTextEdit.LineWrapMode.NoWrap)
        fixed_font = QFontDatabase.systemFont(QFontDatabase.SystemFont.FixedFont)
        fixed_font.setPointSize(9)
        raw_view.setFont(fixed_font)
        raw_view.setPlaceholderText("选择数据包后显示十六进制与 ASCII 数据")
        return raw_view

    @staticmethod
    def _panel(title_text: str, body: QWidget) -> QFrame:
        panel = QFrame()
        panel.setObjectName("panel")
        layout = QVBoxLayout(panel)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)
        header = QFrame()
        header.setObjectName("panelHeader")
        header.setFixedHeight(34)
        header_layout = QHBoxLayout(header)
        header_layout.setContentsMargins(12, 0, 8, 0)
        title = QLabel(title_text)
        title.setObjectName("panelTitle")
        header_layout.addWidget(title)
        header_layout.addStretch(1)
        layout.addWidget(header)
        layout.addWidget(body, 1)
        return panel

    def _build_footer(self) -> QFrame:
        footer = QFrame()
        footer.setObjectName("footer")
        footer.setFixedHeight(58)
        layout = QHBoxLayout(footer)
        layout.setContentsMargins(24, 0, 24, 0)
        layout.setSpacing(15)
        self.capture_status_label = QLabel("准备就绪")
        self.capture_status_label.setObjectName("footerStatus")
        layout.addWidget(self.capture_status_label, 1)
        self.counter_label = QLabel("捕获 0   |   显示 0   |   淘汰 0   |   丢弃 0   |   解析警告 0   |   重组 0")
        self.counter_label.setObjectName("footerCounter")
        layout.addWidget(self.counter_label)
        heartbeat = QLabel()
        heartbeat.setPixmap(make_icon("pulse", COLORS["success"], 30).pixmap(30, 30))
        layout.addWidget(heartbeat)
        return footer

    def _connect_signals(self) -> None:
        self.refresh_button.clicked.connect(self.refresh_interfaces)
        self.start_button.clicked.connect(self.start_capture)
        self.stop_button.clicked.connect(self.stop_capture)
        self.clear_button.clicked.connect(self.clear_packets)
        self.open_pcap_button.clicked.connect(self.open_offline_capture)
        self.save_pcap_button.clicked.connect(self.save_capture)
        self.export_csv_button.clicked.connect(self.export_summary)
        self.apply_filter_button.clicked.connect(self.apply_display_filter)
        self.clear_filter_button.clicked.connect(self.clear_display_filter)
        self.display_filter_edit.returnPressed.connect(self.apply_display_filter)
        self.packet_table.selectionModel().currentRowChanged.connect(self._show_selected_packet)
        self.flow_table.selectionModel().currentRowChanged.connect(self._show_selected_flow)

    def _set_capture_status(self, text: str) -> None:
        self._footer_notice_generation += 1
        self._footer_restore_text = text
        self.capture_status_label.setText(text)

    def _show_temporary_status(self, text: str, timeout_ms: int = 5_000) -> None:
        self._footer_notice_generation += 1
        generation = self._footer_notice_generation
        self.capture_status_label.setText(text)

        def restore() -> None:
            if generation == self._footer_notice_generation:
                self.capture_status_label.setText(self._footer_restore_text)

        QTimer.singleShot(timeout_ms, restore)

    def show_section_notice(self, section: str) -> None:
        self._show_temporary_status(f"{section}将在后续版本开放；当前页面保留全部实时抓包功能。", 3_500)

    def refresh_interfaces(self) -> None:
        if self._session.running:
            return
        current = self.interface_combo.currentData()
        current_name = current.pcap_name if isinstance(current, InterfaceInfo) else ""
        self.interface_combo.clear()
        try:
            self._interfaces = list_capture_interfaces()
        except Exception as exc:  # noqa: BLE001 - translate a low-level error for the GUI
            self._interfaces = []
            self._set_capture_status(f"网卡枚举失败：{exc}")
            self._set_npcap_connected(False)
            self._update_controls()
            return
        for interface in self._interfaces:
            self.interface_combo.addItem(interface.display_name, interface)
            if interface.pcap_name == current_name:
                self.interface_combo.setCurrentIndex(self.interface_combo.count() - 1)
        self._set_npcap_connected(bool(self._interfaces))
        self._set_capture_status(f"已发现 {len(self._interfaces)} 个可捕获接口")
        self._update_controls()

    def _set_npcap_connected(self, connected: bool) -> None:
        self.npcap_status_label.setProperty("connected", connected)
        dot = COLORS["success"] if connected else "#8194a6"
        state = "已连接" if connected else "未连接"
        self.npcap_status_label.setText(
            f'<span style="color:{dot}">●</span>&nbsp;&nbsp;'
            f'<span style="color:#e5eef6">Npcap&nbsp;&nbsp;{state}</span>'
        )
        _repolish(self.npcap_status_label)

    def start_capture(self) -> None:
        interface = self.interface_combo.currentData()
        if not isinstance(interface, InterfaceInfo):
            QMessageBox.warning(self, "无法开始", "请先选择可用网卡。")
            return
        self._offline_stats = None
        self._offline_source = ""
        try:
            self._session.start(interface, self.capture_filter_edit.text().strip())
        except Exception as exc:  # noqa: BLE001
            QMessageBox.critical(self, "抓包启动失败", str(exc))
            self._set_capture_status(f"启动失败：{exc}")
        else:
            self._active_interface_name = interface.name
            self._last_rate_time = monotonic()
            self._last_rate_count = 0
            self._capture_rate = 0
            self._set_capture_status(f"正在监听： {interface.name}")
        self._update_controls()

    def stop_capture(self) -> None:
        try:
            self._session.stop()
        except Exception as exc:  # noqa: BLE001
            QMessageBox.warning(self, "停止抓包", str(exc))
            self._set_capture_status(f"停止失败：{exc}")
        else:
            self._set_capture_status("抓包已停止")
        self._update_controls()
        self._drain_capture_queue()

    def clear_packets(self) -> None:
        self.table_model.clear()
        self.detail_tree.clear()
        self.raw_view.clear()
        self.traffic_meter.clear()
        self.flow_tracker.clear()
        self.anomaly_detector.clear()
        self._offline_stats = None
        self._offline_source = ""
        self.flow_model.refresh()
        self.alert_model.refresh()
        self.stream_view.clear()
        self._refresh_dashboard()
        self._capture_rate = 0
        self._last_rate_count = self._session.stats.captured
        self._last_rate_time = monotonic()
        self._update_status_counts()

    def open_offline_capture(self) -> None:
        if self._session.running or self._offline_loading:
            QMessageBox.warning(self, "打开 PCAP", "请先停止当前实时抓包。")
            return
        path, _ = QFileDialog.getOpenFileName(
            self,
            "打开离线抓包",
            "",
            "Capture files (*.pcap *.pcapng);;PCAP (*.pcap);;PCAPNG (*.pcapng);;All files (*)",
        )
        if not path:
            return
        self.clear_packets()
        self._offline_source = Path(path).name
        self._offline_stats = CaptureStats()
        self._offline_loading = True
        self._set_capture_status(f"正在加载离线抓包：{self._offline_source}")

        progress = QProgressDialog("已解析 0 个数据包", "取消", 0, 0, self)
        progress.setWindowTitle("加载离线抓包")
        progress.setWindowModality(Qt.WindowModality.WindowModal)
        progress.setMinimumDuration(0)
        progress.setAutoClose(False)
        progress.setAutoReset(False)

        thread = QThread(self)
        worker = OfflineLoadWorker(Path(path))
        worker.moveToThread(thread)
        thread.started.connect(worker.run)
        worker.batch_ready.connect(self._on_offline_batch)
        worker.progress.connect(self._on_offline_progress)
        worker.completed.connect(self._on_offline_complete)
        worker.failed.connect(self._on_offline_failed)
        worker.completed.connect(thread.quit)
        worker.failed.connect(thread.quit)
        worker.completed.connect(worker.deleteLater)
        worker.failed.connect(worker.deleteLater)
        progress.canceled.connect(worker.cancel)
        thread.finished.connect(self._on_offline_thread_finished)

        self._offline_thread = thread
        self._offline_worker = worker
        self._offline_progress = progress
        self._update_controls()
        self._update_status_counts()
        progress.show()
        thread.start()

    def _on_offline_batch(self, records: object) -> None:
        batch = records if isinstance(records, list) else []
        if not batch:
            return
        self._ingest_records(batch)
        if self._offline_stats is not None:
            self._offline_stats.queued += len(batch)
        self._update_status_counts()

    def _on_offline_progress(self, captured: int) -> None:
        if self._offline_stats is not None:
            self._offline_stats.captured = captured
        if self._offline_progress is not None:
            self._offline_progress.setLabelText(f"已解析 {captured:,} 个数据包")

    def _on_offline_complete(self, result: object) -> None:
        if not isinstance(result, OfflineLoadResult):
            self._on_offline_failed("离线加载器返回了无效结果")
            return
        self._offline_stats = result.stats
        self._offline_loading = False
        if self._offline_progress is not None:
            self._offline_progress.close()
        if result.cancelled:
            self._set_capture_status(
                f"已取消加载：{self._offline_source}，保留 {result.stats.queued:,} 条记录"
            )
        else:
            self._set_capture_status(f"已加载离线抓包：{self._offline_source}")
        self._update_controls()
        self._update_status_counts()

    def _on_offline_failed(self, message: str) -> None:
        self._offline_loading = False
        if self._offline_progress is not None:
            self._offline_progress.close()
        self._set_capture_status(f"离线加载失败：{message}")
        self._update_controls()
        QMessageBox.critical(self, "打开失败", message)

    def _on_offline_thread_finished(self) -> None:
        self._offline_thread = None
        self._offline_worker = None
        self._offline_progress = None

    def _set_filter_feedback(self, text: str, status: str = "") -> None:
        self.filter_feedback.setText(text)
        self.filter_feedback.setProperty("status", status)
        _repolish(self.filter_feedback)

    def apply_display_filter(self) -> None:
        try:
            display_filter = DisplayFilter.parse(self.display_filter_edit.text())
        except FilterSyntaxError as exc:
            self._set_filter_feedback("语法错误", "error")
            self.filter_feedback.setToolTip(str(exc))
            return
        self.table_model.set_filter(display_filter)
        self._set_filter_feedback("已应用", "success")
        self.filter_feedback.setToolTip("")
        self._update_status_counts()

    def clear_display_filter(self) -> None:
        self.display_filter_edit.clear()
        self.table_model.set_filter(DisplayFilter.parse(""))
        self._set_filter_feedback("")
        self.filter_feedback.setToolTip("")
        self._update_status_counts()

    def save_capture(self) -> None:
        records = self.table_model.records
        if not records:
            QMessageBox.information(self, "保存 PCAP", "当前没有可保存的数据包。")
            return
        if self.table_model.evicted_count:
            answer = QMessageBox.question(
                self,
                "保存范围不完整",
                f"显示缓存已淘汰 {self.table_model.evicted_count} 条较早记录，"
                "PCAP 只能保存当前保留的数据。是否继续？",
            )
            if answer != QMessageBox.StandardButton.Yes:
                return
        path, _ = QFileDialog.getSaveFileName(self, "保存原始抓包", "capture.pcap", "PCAP 文件 (*.pcap)")
        if not path:
            return
        try:
            count = save_pcap(Path(path), records)
        except Exception as exc:  # noqa: BLE001
            QMessageBox.critical(self, "保存失败", str(exc))
            return
        self._show_temporary_status(f"已保存 {count} 个原始包到 {path}")

    def export_summary(self) -> None:
        records = self.table_model.records
        if not records:
            QMessageBox.information(self, "导出 CSV", "当前没有可导出的数据包摘要。")
            return
        if self.table_model.evicted_count:
            answer = QMessageBox.question(
                self,
                "导出范围不完整",
                f"显示缓存已淘汰 {self.table_model.evicted_count} 条较早记录，"
                "CSV 只能导出当前保留的摘要。是否继续？",
            )
            if answer != QMessageBox.StandardButton.Yes:
                return
        path, _ = QFileDialog.getSaveFileName(self, "导出摘要", "capture-summary.csv", "CSV 文件 (*.csv)")
        if not path:
            return
        try:
            count = export_csv(Path(path), records)
        except Exception as exc:  # noqa: BLE001
            QMessageBox.critical(self, "导出失败", str(exc))
            return
        self._show_temporary_status(f"已导出 {count} 条摘要到 {path}")

    def _drain_capture_queue(self) -> None:
        records = self._session.drain(max_items=300)
        if records:
            self._ingest_records(records)
        # Reading running synchronizes unexpected AsyncSniffer termination and
        # keeps the controls usable after a background worker failure.
        running = self._session.running
        if self._session.last_error:
            self._set_capture_status(f"抓包错误：{self._session.last_error}")
        elif running and getattr(self._session, "last_warning", None):
            self._set_capture_status(f"最近解析警告：{self._session.last_warning}")
        elif not running and self.stop_button.isEnabled():
            self._set_capture_status("抓包线程已停止")
        self._update_controls()
        self._update_status_counts()

    def _ingest_records(self, records: list[PacketRecord]) -> None:
        if not records:
            return
        selected_flow = self.flow_model.flow_at(self.flow_table.currentIndex().row())
        self.table_model.add_records(records)
        self.traffic_meter.add(records)
        self.flow_tracker.add(records)
        self.anomaly_detector.add(records)
        self.flow_model.refresh()
        self.alert_model.refresh()
        self._refresh_dashboard()
        if selected_flow is not None:
            selected_row = self.flow_model.row_for_flow(selected_flow)
            if selected_row >= 0:
                self.flow_table.selectRow(selected_row)
        if not self.packet_table.currentIndex().isValid() and self.table_model.rowCount() > 0:
            self.packet_table.selectRow(0)

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
        summary.setForeground(0, QColor("#34485f"))
        self.detail_tree.addTopLevelItem(summary)

        expanded_layers = {"Internet Protocol Version 4", "Transmission Control Protocol", "User Datagram Protocol"}
        for layer in record.layers:
            parent = QTreeWidgetItem([layer.name, ""])
            for name, value in layer.fields:
                parent.addChild(QTreeWidgetItem([name, value]))
            color = "#7042c8" if "Protocol" in layer.name else "#1f6fd2"
            if "Control" in layer.name:
                color = "#c46511"
            parent.setForeground(0, QColor(color))
            self.detail_tree.addTopLevelItem(parent)
            parent.setExpanded(layer.name in expanded_layers)
        if record.errors:
            error_item = QTreeWidgetItem(["解析警告", ""])
            error_item.setForeground(0, QColor(COLORS["danger"]))
            for error in record.errors:
                error_item.addChild(QTreeWidgetItem(["警告", error]))
            self.detail_tree.addTopLevelItem(error_item)
            error_item.setExpanded(True)
        self.raw_view.setPlainText(format_hex_ascii(record.raw))

    def _show_selected_flow(self, current: QModelIndex, _previous: QModelIndex) -> None:
        flow = self.flow_model.flow_at(current.row())
        if flow is None:
            self.stream_view.clear()
        elif flow.protocol == "TCP":
            self.stream_view.setPlainText(flow.stream_text())
        else:
            self.stream_view.setPlainText("UDP 会话不提供字节流重组。")

    def _refresh_dashboard(self) -> None:
        point = self.traffic_meter.points[-1] if self.traffic_meter.points else None
        self.packet_rate_card.value.setText(str(point.packets if point else 0))
        self.byte_rate_card.value.setText(f"{point.bytes:,}" if point else "0")
        self.flow_count_card.value.setText(str(len(self.flow_tracker.flows)))
        self.alert_count_card.value.setText(str(len(self.anomaly_detector.alerts)))
        total = self.traffic_meter.total_packets
        self.protocol_summary.setText(
            "   ".join(f"{name}: {count} ({count / total:.0%})" for name, count in self.traffic_meter.protocols.most_common(8))
            if total else "等待实时数据"
        )
        self.traffic_chart.update()

    def _update_controls(self) -> None:
        running = self._session.running
        loading = self._offline_loading
        self.start_button.setEnabled(not running and not loading and bool(self._interfaces))
        self.stop_button.setEnabled(running)
        self.interface_combo.setEnabled(not running and not loading)
        self.refresh_button.setEnabled(not running and not loading)
        self.capture_filter_edit.setEnabled(not running and not loading)
        self.open_pcap_button.setEnabled(not running and not loading)
        self.clear_button.setEnabled(not loading)
        self.save_pcap_button.setEnabled(not loading)
        self.export_csv_button.setEnabled(not loading)
        self.title_bar.set_capture_running(running)

    def _update_capture_rate(self, captured: int, running: bool) -> None:
        now = monotonic()
        elapsed = now - self._last_rate_time
        if captured < self._last_rate_count:
            self._last_rate_count = captured
            self._last_rate_time = now
            self._capture_rate = 0
            return
        if elapsed >= 1.0:
            instant = int((captured - self._last_rate_count) * 60 / elapsed)
            self._capture_rate = instant if self._capture_rate == 0 else int(self._capture_rate * 0.55 + instant * 0.45)
            self._last_rate_count = captured
            self._last_rate_time = now
        if not running and captured == 0:
            self._capture_rate = 0

    def _update_status_counts(self) -> None:
        stats = self._offline_stats or self._session.stats
        running = self._session.running
        self._update_capture_rate(stats.captured, running)

        rate_caption = f"+{self._capture_rate:,} / min" if running else "实时捕获速率"
        if self._offline_stats is not None:
            rate_caption = f"离线文件 {self._offline_source}"
        filter_text = self.display_filter_edit.text().strip()
        visible_caption = filter_text[:30] if filter_text else "全部数据包"
        self.captured_card.set_value(f"{stats.captured:,}", rate_caption)
        self.visible_card.set_value(f"{self.table_model.visible_count:,}", visible_caption)
        self.health_card.set_value(f"{stats.dropped:,} / {stats.parse_errors:,}", "↓ 丢弃      ⚠ 解析警告")
        self.reassembly_card.set_value(f"{stats.reassembled:,}", "IPv4 fragments")

        queue_value = min(max(0, stats.queued), self._queue_capacity)
        self.queue_label.setText(f"队列  {stats.queued:,} / {self._queue_capacity:,}")
        self.queue_progress.setValue(queue_value)
        self.counter_label.setText(
            f"捕获  {stats.captured:,}   |   显示  {self.table_model.visible_count:,}   |   "
            f"淘汰  {self.table_model.evicted_count:,}   |   丢弃  {stats.dropped:,}   |   "
            f"解析警告  {stats.parse_errors:,}   |   "
            f"重组  {stats.reassembled:,}"
        )
        self.title_bar.set_capture_running(running)

    def closeEvent(self, event: QCloseEvent) -> None:  # noqa: N802
        if self._offline_worker is not None:
            self._offline_worker.cancel()
        if self._offline_thread is not None and self._offline_thread.isRunning():
            self._offline_thread.quit()
            self._offline_thread.wait(2000)
        if self._session.running:
            try:
                self._session.stop()
            except Exception as exc:  # noqa: BLE001
                self.capture_status_label.setText(f"停止失败：{exc}")
                QMessageBox.warning(self, "无法关闭", f"抓包线程尚未安全停止：{exc}")
                event.ignore()
                return
        event.accept()


def create_window_for_test() -> MainWindow:
    """Stable factory used by automated tests and off-screen screenshots."""

    if QApplication.instance() is None:
        QApplication([])
    return MainWindow()


__all__ = ["MainWindow", "PacketTableModel", "create_window_for_test"]
