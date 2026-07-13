"""Small dependency-free Qt widgets for the live analysis workspace."""

from __future__ import annotations

from PyQt6.QtCore import QRectF, Qt
from PyQt6.QtGui import QColor, QFont, QPainter, QPainterPath, QPen
from PyQt6.QtWidgets import QFrame, QLabel, QVBoxLayout, QWidget

from .analytics import TrafficMeter


class MetricCard(QFrame):
    def __init__(self, label: str, value: str = "0", parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setObjectName("metricCard")
        layout = QVBoxLayout(self)
        layout.setContentsMargins(16, 12, 16, 12)
        self.caption = QLabel(label.upper())
        self.caption.setObjectName("metricCaption")
        self.value = QLabel(value)
        self.value.setObjectName("metricValue")
        layout.addWidget(self.caption)
        layout.addWidget(self.value)


class TrafficChart(QWidget):
    """A compact dual-track packets/bytes waveform rendered with QPainter."""

    def __init__(self, meter: TrafficMeter, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.meter = meter
        self.setMinimumHeight(220)
        self.setObjectName("trafficChart")

    def paintEvent(self, _event) -> None:  # noqa: N802, ANN001
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        bounds = QRectF(self.rect()).adjusted(24, 28, -20, -28)
        painter.fillRect(self.rect(), QColor("#111b27"))
        painter.setPen(QPen(QColor("#243447"), 1))
        for index in range(5):
            y = bounds.top() + bounds.height() * index / 4
            painter.drawLine(int(bounds.left()), int(y), int(bounds.right()), int(y))
        painter.setFont(QFont("Segoe UI", 9))
        painter.setPen(QColor("#7e91a8"))
        painter.drawText(24, 19, "LIVE TRAFFIC · 60 SECOND SIGNAL")
        points = list(self.meter.points)
        if not points:
            painter.drawText(bounds, Qt.AlignmentFlag.AlignCenter, "开始抓包后显示实时流量波形")
            return
        max_packets = max(1, max(point.packets for point in points))
        max_bytes = max(1, max(point.bytes for point in points))

        def path_for(values: list[int], maximum: int) -> QPainterPath:
            path = QPainterPath()
            for index, value in enumerate(values):
                x = bounds.left() + bounds.width() * index / max(1, len(values) - 1)
                y = bounds.bottom() - bounds.height() * value / maximum
                path.moveTo(x, y) if index == 0 else path.lineTo(x, y)
            return path

        painter.setPen(QPen(QColor("#34d6c7"), 2.4))
        painter.drawPath(path_for([point.packets for point in points], max_packets))
        painter.setPen(QPen(QColor("#e9b44c"), 1.8, Qt.PenStyle.DashLine))
        painter.drawPath(path_for([point.bytes for point in points], max_bytes))
        painter.setPen(QColor("#34d6c7"))
        painter.drawText(int(bounds.left()), int(bounds.bottom() + 18), f"● packets/s  peak {max_packets}")
        painter.setPen(QColor("#e9b44c"))
        painter.drawText(int(bounds.left() + 180), int(bounds.bottom() + 18), f"◆ bytes/s  peak {max_bytes:,}")


THEME = """
QMainWindow, QWidget { background: #0b131d; color: #dce7f2; font-family: 'Segoe UI', 'Microsoft YaHei UI'; font-size: 13px; }
QFrame#topBar { background: #101c29; border-bottom: 1px solid #26384a; }
QLabel#brand { color: #f3f8fc; font-size: 21px; font-weight: 700; letter-spacing: 1px; }
QLabel#eyebrow, QLabel#metricCaption { color: #7890a8; font-size: 10px; font-weight: 700; letter-spacing: 1px; }
QLabel#metricValue { color: #f4f8fb; font-size: 26px; font-weight: 650; }
QFrame#metricCard { background: #111d2a; border: 1px solid #24374a; border-radius: 8px; }
QGroupBox { border: 1px solid #26394c; border-radius: 8px; margin-top: 9px; padding-top: 10px; font-weight: 600; }
QGroupBox::title { subcontrol-origin: margin; left: 12px; color: #8fa7bd; }
QPushButton { background: #17283a; border: 1px solid #31506b; border-radius: 5px; padding: 7px 13px; font-weight: 600; }
QPushButton:hover { border-color: #34d6c7; color: #ffffff; }
QPushButton:pressed { background: #203c50; }
QPushButton:disabled { color: #536476; border-color: #263442; }
QPushButton#primaryButton { background: #147b77; border-color: #34d6c7; color: white; }
QLineEdit, QComboBox, QPlainTextEdit, QTreeWidget, QTableView { background: #0e1925; border: 1px solid #293f54; border-radius: 4px; padding: 5px; selection-background-color: #176d70; }
QHeaderView::section { background: #152332; color: #9eb2c5; border: none; border-right: 1px solid #26394c; border-bottom: 1px solid #26394c; padding: 7px; font-weight: 600; }
QTableView { gridline-color: #1c2c3c; alternate-background-color: #101d29; }
QTabWidget::pane { border: 1px solid #24374a; border-radius: 6px; }
QTabBar::tab { background: #0e1925; color: #8198ae; padding: 9px 18px; border-bottom: 2px solid transparent; }
QTabBar::tab:selected { color: #eaf4fa; border-bottom-color: #34d6c7; }
QSplitter::handle { background: #25384a; }
QStatusBar { background: #101c29; border-top: 1px solid #26384a; }
QScrollBar:vertical { width: 10px; background: #0b131d; }
QScrollBar::handle:vertical { background: #2b4155; border-radius: 4px; min-height: 24px; }
"""


__all__ = ["MetricCard", "THEME", "TrafficChart"]
