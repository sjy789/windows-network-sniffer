"""Visual theme and asset-free vector icons for the sniffer UI.

The module deliberately keeps all visual assets in code.  ``make_icon`` draws
small monochrome icons onto a transparent pixmap, so the application can tint
the same icon for light and dark surfaces without shipping image files.
"""

from __future__ import annotations

from math import cos, pi, sin

from PyQt6.QtCore import QPointF, QRectF, Qt
from PyQt6.QtGui import (
    QColor,
    QIcon,
    QPainter,
    QPainterPath,
    QPen,
    QPixmap,
    QPolygonF,
)


COLORS: dict[str, str] = {
    # Brand colours from the visual reference.
    "navy": "#002643",
    "deep_navy": "#001d35",
    "navy_hover": "#073b63",
    "navy_active": "#0b4072",
    "primary": "#0865e9",
    "primary_hover": "#0759cc",
    "primary_pressed": "#064cac",
    "primary_soft": "#e6f0ff",
    "cyan": "#11bfd0",
    "cyan_soft": "#def8fb",
    "background": "#f4f8fc",
    "surface": "#ffffff",
    "surface_alt": "#f8fbfe",
    "border": "#cfdce8",
    "border_light": "#e3ebf2",
    # Text and semantic colours.
    "text": "#17283a",
    "text_muted": "#65788b",
    "text_subtle": "#8b9cad",
    "text_on_dark": "#edf6ff",
    "text_on_dark_muted": "#a9bfd2",
    "selection": "#dff6fb",
    "success": "#35d866",
    "success_dark": "#168a47",
    "success_soft": "#e8f9ef",
    "warning": "#f59e0b",
    "warning_dark": "#b86600",
    "warning_soft": "#fff5dd",
    "danger": "#e64b55",
    "danger_hover": "#cb3440",
    "danger_soft": "#fff0f1",
    "purple": "#8657d9",
    "purple_soft": "#f1ebff",
    "disabled": "#edf2f6",
    "disabled_text": "#9caab7",
}


SUPPORTED_ICONS = frozenset(
    {
        "capture",
        "pie",
        "fragments",
        "export",
        "refresh",
        "play",
        "stop",
        "trash",
        "save",
        "csv",
        "settings",
        "help",
        "minimize",
        "maximize",
        "close",
        "filter",
        "document",
        "warning",
        "layers",
        "pulse",
        "chevron",
    }
)


def make_icon(name: str, color: str = "#0865e9", size: int = 20) -> QIcon:
    """Return a crisp, monochrome :class:`QIcon` drawn with ``QPainter``.

    Parameters are intentionally small and predictable: ``name`` is one of
    :data:`SUPPORTED_ICONS`, ``color`` is any Qt-compatible colour string, and
    ``size`` is the square pixmap size in device-independent pixels.
    """

    icon_name = name.strip().lower().replace("-", "_")
    if icon_name not in SUPPORTED_ICONS:
        choices = ", ".join(sorted(SUPPORTED_ICONS))
        raise ValueError(f"Unknown icon {name!r}; expected one of: {choices}")
    if isinstance(size, bool) or not isinstance(size, int) or size <= 0:
        raise ValueError("Icon size must be a positive integer")

    ink = QColor(color)
    if not ink.isValid():
        raise ValueError(f"Invalid icon colour: {color!r}")

    pixmap = QPixmap(size, size)
    pixmap.fill(Qt.GlobalColor.transparent)
    painter = QPainter(pixmap)
    painter.setRenderHint(QPainter.RenderHint.Antialiasing, True)
    painter.setRenderHint(QPainter.RenderHint.TextAntialiasing, True)
    painter.scale(size / 24.0, size / 24.0)

    pen = QPen(ink)
    pen.setWidthF(1.8)
    pen.setCapStyle(Qt.PenCapStyle.RoundCap)
    pen.setJoinStyle(Qt.PenJoinStyle.RoundJoin)
    painter.setPen(pen)
    painter.setBrush(Qt.BrushStyle.NoBrush)

    def line(x1: float, y1: float, x2: float, y2: float) -> None:
        painter.drawLine(QPointF(x1, y1), QPointF(x2, y2))

    def polyline(*points: tuple[float, float]) -> None:
        painter.drawPolyline(QPolygonF([QPointF(x, y) for x, y in points]))

    def filled_path(points: tuple[tuple[float, float], ...]) -> None:
        path = QPainterPath()
        path.moveTo(*points[0])
        for point in points[1:]:
            path.lineTo(*point)
        path.closeSubpath()
        painter.save()
        painter.setPen(Qt.PenStyle.NoPen)
        painter.setBrush(ink)
        painter.drawPath(path)
        painter.restore()

    try:
        if icon_name == "capture":
            painter.drawRoundedRect(QRectF(3.0, 3.5, 18.0, 17.0), 2.4, 2.4)
            line(7.0, 16.5, 7.0, 11.0)
            line(11.0, 16.5, 11.0, 7.5)
            line(15.0, 16.5, 15.0, 13.0)
            line(18.5, 7.5, 18.5, 16.5)

        elif icon_name == "pie":
            painter.drawArc(QRectF(3.5, 3.5, 17.0, 17.0), 35 * 16, 300 * 16)
            filled_path(((13.0, 3.2), (13.0, 11.0), (20.8, 11.0)))
            line(13.0, 3.2, 13.0, 11.0)
            line(13.0, 11.0, 20.8, 11.0)

        elif icon_name == "fragments":
            line(8.0, 7.0, 16.0, 7.0)
            line(8.0, 17.0, 16.0, 17.0)
            line(12.0, 7.0, 12.0, 17.0)
            for rect in (
                QRectF(3.0, 4.0, 5.0, 5.0),
                QRectF(16.0, 4.0, 5.0, 5.0),
                QRectF(3.0, 14.0, 5.0, 5.0),
                QRectF(16.0, 14.0, 5.0, 5.0),
            ):
                painter.drawRoundedRect(rect, 1.0, 1.0)

        elif icon_name == "export":
            path = QPainterPath()
            path.moveTo(3.5, 7.0)
            path.lineTo(9.0, 7.0)
            path.lineTo(11.0, 9.0)
            path.lineTo(15.0, 9.0)
            path.lineTo(15.0, 19.5)
            path.lineTo(3.5, 19.5)
            path.closeSubpath()
            painter.drawPath(path)
            line(11.5, 4.5, 20.5, 4.5)
            line(20.5, 4.5, 20.5, 13.5)
            line(20.2, 4.8, 12.0, 13.0)

        elif icon_name == "refresh":
            painter.drawArc(QRectF(4.0, 4.0, 16.0, 16.0), 35 * 16, 135 * 16)
            painter.drawArc(QRectF(4.0, 4.0, 16.0, 16.0), 215 * 16, 135 * 16)
            filled_path(((18.8, 3.6), (20.7, 8.5), (15.6, 7.5)))
            filled_path(((5.2, 20.4), (3.3, 15.5), (8.4, 16.5)))

        elif icon_name == "play":
            filled_path(((7.2, 4.5), (19.0, 12.0), (7.2, 19.5)))

        elif icon_name == "stop":
            painter.save()
            painter.setPen(Qt.PenStyle.NoPen)
            painter.setBrush(ink)
            painter.drawRoundedRect(QRectF(5.0, 5.0, 14.0, 14.0), 1.8, 1.8)
            painter.restore()

        elif icon_name == "trash":
            line(5.0, 7.0, 19.0, 7.0)
            line(9.0, 4.0, 15.0, 4.0)
            path = QPainterPath()
            path.moveTo(6.5, 7.0)
            path.lineTo(7.5, 20.0)
            path.lineTo(16.5, 20.0)
            path.lineTo(17.5, 7.0)
            painter.drawPath(path)
            line(10.0, 10.0, 10.5, 17.0)
            line(14.0, 10.0, 13.5, 17.0)

        elif icon_name == "save":
            path = QPainterPath()
            path.moveTo(4.0, 3.5)
            path.lineTo(17.0, 3.5)
            path.lineTo(20.0, 6.5)
            path.lineTo(20.0, 20.0)
            path.lineTo(4.0, 20.0)
            path.closeSubpath()
            painter.drawPath(path)
            painter.drawRect(QRectF(7.0, 3.5, 8.5, 6.0))
            painter.drawRoundedRect(QRectF(7.0, 13.0, 10.0, 7.0), 1.0, 1.0)

        elif icon_name == "csv":
            path = QPainterPath()
            path.moveTo(5.0, 2.8)
            path.lineTo(14.5, 2.8)
            path.lineTo(19.0, 7.3)
            path.lineTo(19.0, 21.0)
            path.lineTo(5.0, 21.0)
            path.closeSubpath()
            painter.drawPath(path)
            line(14.5, 3.0, 14.5, 7.5)
            line(14.5, 7.5, 18.8, 7.5)
            font = painter.font()
            font.setBold(True)
            font.setPixelSize(5)
            painter.setFont(font)
            painter.drawText(QRectF(5.8, 10.0, 12.4, 8.0), Qt.AlignmentFlag.AlignCenter, "CSV")

        elif icon_name == "settings":
            painter.drawEllipse(QPointF(12.0, 12.0), 3.1, 3.1)
            painter.drawEllipse(QPointF(12.0, 12.0), 7.0, 7.0)
            for index in range(8):
                angle = index * pi / 4.0
                inner = QPointF(12.0 + cos(angle) * 7.0, 12.0 + sin(angle) * 7.0)
                outer = QPointF(12.0 + cos(angle) * 9.5, 12.0 + sin(angle) * 9.5)
                painter.drawLine(inner, outer)

        elif icon_name == "help":
            painter.drawEllipse(QRectF(3.5, 3.5, 17.0, 17.0))
            path = QPainterPath()
            path.moveTo(9.0, 9.0)
            path.cubicTo(9.3, 6.3, 14.9, 6.2, 15.1, 9.3)
            path.cubicTo(15.2, 11.2, 12.0, 11.4, 12.0, 14.1)
            painter.drawPath(path)
            painter.save()
            painter.setPen(Qt.PenStyle.NoPen)
            painter.setBrush(ink)
            painter.drawEllipse(QPointF(12.0, 17.0), 1.0, 1.0)
            painter.restore()

        elif icon_name == "minimize":
            line(5.0, 17.0, 19.0, 17.0)

        elif icon_name == "maximize":
            painter.drawRect(QRectF(5.0, 5.0, 14.0, 14.0))

        elif icon_name == "close":
            line(6.0, 6.0, 18.0, 18.0)
            line(18.0, 6.0, 6.0, 18.0)

        elif icon_name == "filter":
            filled_path(((3.0, 4.0), (21.0, 4.0), (14.2, 12.0), (14.2, 20.0), (9.8, 17.5), (9.8, 12.0)))

        elif icon_name == "document":
            path = QPainterPath()
            path.moveTo(5.0, 2.8)
            path.lineTo(14.5, 2.8)
            path.lineTo(19.0, 7.3)
            path.lineTo(19.0, 21.0)
            path.lineTo(5.0, 21.0)
            path.closeSubpath()
            painter.drawPath(path)
            line(14.5, 3.0, 14.5, 7.5)
            line(14.5, 7.5, 18.8, 7.5)
            line(8.0, 11.0, 16.0, 11.0)
            line(8.0, 14.5, 16.0, 14.5)
            line(8.0, 18.0, 13.5, 18.0)

        elif icon_name == "warning":
            path = QPainterPath()
            path.moveTo(12.0, 3.0)
            path.lineTo(21.0, 20.0)
            path.lineTo(3.0, 20.0)
            path.closeSubpath()
            painter.drawPath(path)
            line(12.0, 8.0, 12.0, 14.0)
            painter.save()
            painter.setPen(Qt.PenStyle.NoPen)
            painter.setBrush(ink)
            painter.drawEllipse(QPointF(12.0, 17.2), 1.0, 1.0)
            painter.restore()

        elif icon_name == "layers":
            polyline((3.5, 8.0), (12.0, 3.5), (20.5, 8.0), (12.0, 12.5), (3.5, 8.0))
            polyline((4.0, 12.0), (12.0, 16.3), (20.0, 12.0))
            polyline((4.0, 16.0), (12.0, 20.3), (20.0, 16.0))

        elif icon_name == "pulse":
            polyline(
                (2.0, 12.5),
                (6.0, 12.5),
                (8.2, 7.0),
                (11.0, 18.0),
                (14.0, 4.0),
                (16.5, 12.5),
                (22.0, 12.5),
            )

        elif icon_name == "chevron":
            polyline((8.5, 5.0), (15.5, 12.0), (8.5, 19.0))
    finally:
        painter.end()

    return QIcon(pixmap)


APP_STYLESHEET = r"""
/* ---- Application shell ------------------------------------------------ */
QMainWindow#mainWindow,
QWidget#root,
QWidget[uiRole="root"] {
    background: %(background)s;
    color: %(text)s;
}

QWidget {
    color: %(text)s;
    font-family: "Microsoft YaHei UI", "Segoe UI", sans-serif;
    font-size: 13px;
}

QWidget#content,
QWidget[uiRole="content"] {
    background: %(background)s;
}

QWidget#sidebar,
QFrame#sidebar,
QWidget[uiRole="sidebar"] {
    background: %(navy)s;
    border: none;
}

QWidget#topbar,
QFrame#topbar,
QWidget[uiRole="topbar"] {
    background: %(deep_navy)s;
    border: none;
    border-bottom: 1px solid #0b3a5e;
}

QWidget#footer,
QFrame#footer,
QWidget[uiRole="footer"],
QStatusBar {
    background: %(navy)s;
    color: %(text_on_dark)s;
    border: none;
    border-top: 1px solid #0b3a5e;
}

QStatusBar::item {
    border: none;
}

/* ---- Panels and cards ------------------------------------------------- */
QFrame#toolbarPanel,
QWidget#toolbarPanel,
QFrame[uiRole="toolbarPanel"] {
    background: %(surface)s;
    border: 1px solid %(border)s;
    border-radius: 8px;
}

QFrame#statCard,
QWidget#statCard,
QFrame[uiRole="statCard"],
QWidget[uiRole="statCard"] {
    background: %(surface)s;
    border: 1px solid %(border)s;
    border-radius: 8px;
}

QFrame#panel,
QWidget#panel,
QFrame[uiRole="panel"],
QWidget[uiRole="panel"],
QGroupBox {
    background: %(surface)s;
    border: 1px solid %(border)s;
    border-radius: 7px;
}

QGroupBox {
    margin-top: 13px;
    padding: 12px 9px 8px 9px;
    font-weight: 600;
}

QGroupBox::title {
    subcontrol-origin: margin;
    subcontrol-position: top left;
    left: 10px;
    padding: 0 5px;
    color: %(text)s;
    background: %(surface)s;
}

QFrame#panelHeader,
QWidget#panelHeader,
QFrame[uiRole="panelHeader"] {
    background: %(surface)s;
    border: none;
    border-bottom: 1px solid %(border_light)s;
}

QFrame#connectionCard,
QWidget#connectionCard {
    background: #052f50;
    border: 1px solid #174b70;
    border-radius: 8px;
}

QFrame#analysisHeader {
    background: %(surface)s;
    border: 1px solid %(border)s;
    border-radius: 8px;
}

QFrame#metricCard {
    min-height: 82px;
    background: %(surface)s;
    border: 1px solid %(border)s;
    border-radius: 8px;
}

QStackedWidget#workspacePages {
    background: %(background)s;
    border: none;
}

QFrame[uiRole="separator"] {
    background: %(border_light)s;
    border: none;
    max-height: 1px;
}

/* ---- Labels ----------------------------------------------------------- */
QLabel#toolbarLabel,
QLabel[uiRole="toolbarLabel"] {
    color: %(text)s;
    font-size: 13px;
    font-weight: 600;
}

QLabel#statTitle,
QLabel[uiRole="statTitle"] {
    color: %(text_muted)s;
    font-size: 13px;
    font-weight: 600;
}

QLabel#statValue,
QLabel[uiRole="statValue"] {
    color: #111c28;
    font-size: 28px;
    font-weight: 700;
}

QLabel#statCaption,
QLabel[uiRole="statCaption"] {
    color: %(primary)s;
    font-size: 12px;
}

QLabel#panelTitle,
QLabel[uiRole="panelTitle"] {
    color: %(text)s;
    font-size: 15px;
    font-weight: 700;
}

QLabel#brandText {
    color: #f4f9ff;
    font-size: 20px;
    font-weight: 600;
}

QLabel#windowTitle {
    color: #f4f9ff;
    font-size: 18px;
    font-weight: 600;
}

QLabel#windowSubtitle {
    color: #a9bfd2;
    font-size: 12px;
}

QLabel#npcapStatus {
    color: %(success)s;
    font-size: 12px;
    font-weight: 500;
}

QLabel#npcapStatus[connected="false"] {
    color: %(text_on_dark_muted)s;
}

QLabel#queueLabel {
    color: #cfdeeb;
    font-size: 12px;
}

QLabel#analysisTitle {
    color: %(text)s;
    font-size: 18px;
    font-weight: 700;
}

QLabel#analysisSubtitle,
QLabel#analysisSummary,
QLabel#metricCaption {
    color: %(text_muted)s;
    font-size: 12px;
}

QLabel#metricValue {
    color: #111c28;
    font-size: 27px;
    font-weight: 700;
}

QLabel#footerStatus,
QLabel#footerCounter {
    color: #e0ebf5;
    font-size: 13px;
    font-weight: 500;
}

QLabel#captureState {
    color: %(text_on_dark)s;
    background: #082f4c;
    border: 1px solid #194865;
    border-radius: 6px;
    padding: 5px 10px;
    font-size: 12px;
    font-weight: 600;
}

QLabel#captureState[state="running"] {
    color: %(success)s;
}

QLabel#filterFeedback,
QLabel[muted="true"] {
    color: %(text_muted)s;
}

QLabel#filterFeedback[status="success"] {
    color: %(success_dark)s;
}

QLabel#filterFeedback[status="error"] {
    color: %(danger)s;
}

QLabel[onDark="true"],
QWidget#sidebar QLabel,
QWidget#topbar QLabel,
QWidget#footer QLabel,
QFrame#connectionCard QLabel {
    color: %(text_on_dark)s;
    background: transparent;
    border: none;
}

/* Keep muted/status colors on dark containers. These selectors are more
   specific than the container-wide rule above. */
QWidget#topbar QLabel#windowSubtitle {
    color: #a9bfd2;
}

QWidget#sidebar QLabel#queueLabel {
    color: #cfdeeb;
}

QWidget#footer QLabel#footerStatus,
QWidget#footer QLabel#footerCounter {
    color: #e0ebf5;
}

QFrame#connectionCard QLabel#npcapStatus {
    color: %(success)s;
}

QFrame#connectionCard QLabel#npcapStatus[connected="false"] {
    color: %(text_on_dark_muted)s;
}

QLabel[onDark="muted"] {
    color: %(text_on_dark_muted)s;
}

/* ---- Buttons ---------------------------------------------------------- */
QPushButton {
    min-height: 32px;
    padding: 0 13px;
    color: %(text)s;
    background: %(surface)s;
    border: 1px solid #bfcddb;
    border-radius: 5px;
    font-weight: 500;
}

QPushButton:hover {
    color: %(primary)s;
    background: #f7fbff;
    border-color: #8fb4df;
}

QPushButton:pressed {
    background: %(primary_soft)s;
    border-color: %(primary)s;
}

QPushButton:focus {
    border-color: %(primary)s;
}

QPushButton:disabled {
    color: %(disabled_text)s;
    background: %(disabled)s;
    border-color: #d9e2e9;
}

QPushButton[kind="primary"] {
    color: white;
    background: %(primary)s;
    border-color: %(primary)s;
    font-weight: 600;
}

QPushButton[kind="primary"]:hover {
    color: white;
    background: %(primary_hover)s;
    border-color: %(primary_hover)s;
}

QPushButton[kind="primary"]:pressed {
    background: %(primary_pressed)s;
    border-color: %(primary_pressed)s;
}

QPushButton[kind="primary"]:disabled {
    color: #dbe5ef;
    background: #98b9e6;
    border-color: #98b9e6;
}

QPushButton[kind="secondary"] {
    color: #314457;
    background: %(surface)s;
    border-color: #b7c7d6;
}

QPushButton[kind="quiet"] {
    min-width: 0;
    padding: 0 8px;
    color: %(text_muted)s;
    background: transparent;
    border-color: transparent;
}

QPushButton[kind="quiet"]:hover {
    color: %(primary)s;
    background: %(primary_soft)s;
    border-color: transparent;
}

QPushButton[kind="window"] {
    min-width: 38px;
    min-height: 36px;
    padding: 0;
    color: %(text_on_dark)s;
    background: transparent;
    border: none;
    border-radius: 0;
}

QPushButton[kind="window"]:hover {
    color: white;
    background: #16486c;
}

QPushButton[kind="close"] {
    min-width: 38px;
    min-height: 36px;
    padding: 0;
    color: %(text_on_dark)s;
    background: transparent;
    border: none;
    border-radius: 0;
}

QPushButton[kind="close"]:hover {
    color: white;
    background: %(danger)s;
}

QPushButton#navButton {
    min-height: 48px;
    padding: 0 17px;
    color: #d7e7f5;
    background: transparent;
    border: none;
    border-left: 4px solid transparent;
    border-radius: 5px;
    text-align: left;
    font-size: 15px;
    font-weight: 500;
}

QPushButton#navButton:hover {
    color: white;
    background: %(navy_hover)s;
}

QPushButton#navButton:checked,
QPushButton#navButton[active="true"] {
    color: white;
    background: %(navy_active)s;
    border-left-color: %(primary)s;
}

/* ---- Inputs ----------------------------------------------------------- */
QLineEdit,
QComboBox,
QSpinBox,
QDoubleSpinBox,
QDateTimeEdit {
    min-height: 32px;
    padding: 0 9px;
    color: %(text)s;
    selection-color: white;
    selection-background-color: %(primary)s;
    background: %(surface)s;
    border: 1px solid #bdcbd8;
    border-radius: 5px;
}

QLineEdit:hover,
QComboBox:hover,
QSpinBox:hover,
QDoubleSpinBox:hover,
QDateTimeEdit:hover {
    border-color: #8faecb;
}

QLineEdit:focus,
QComboBox:focus,
QSpinBox:focus,
QDoubleSpinBox:focus,
QDateTimeEdit:focus {
    border: 1px solid %(primary)s;
}

QLineEdit:disabled,
QComboBox:disabled {
    color: %(disabled_text)s;
    background: %(disabled)s;
    border-color: #d8e1e9;
}

QLineEdit[status="error"] {
    color: #8d2730;
    background: %(danger_soft)s;
    border-color: %(danger)s;
}

QComboBox {
    padding-right: 28px;
}

QComboBox::drop-down {
    subcontrol-origin: padding;
    subcontrol-position: top right;
    width: 27px;
    background: transparent;
    border: none;
    border-left: 1px solid %(border_light)s;
}

QComboBox::down-arrow {
    width: 8px;
    height: 8px;
}

QComboBox QAbstractItemView {
    padding: 3px;
    color: %(text)s;
    background: %(surface)s;
    border: 1px solid %(border)s;
    selection-color: %(text)s;
    selection-background-color: %(selection)s;
    outline: none;
}

/* ---- Data views ------------------------------------------------------- */
QTableView,
QTreeWidget,
QPlainTextEdit {
    color: #26394b;
    background: %(surface)s;
    alternate-background-color: #f8fbfd;
    border: none;
    selection-color: #152b3b;
    selection-background-color: %(selection)s;
    outline: none;
}

QTableView {
    gridline-color: %(border_light)s;
}

QTableView::item {
    min-height: 25px;
    padding: 2px 7px;
    border-bottom: 1px solid #e5edf3;
}

QTableView::item:selected {
    background: %(selection)s;
    border-top: 1px solid #8ddce6;
    border-bottom: 1px solid #8ddce6;
}

QHeaderView {
    background: #f7fafc;
}

QHeaderView::section {
    min-height: 29px;
    padding: 2px 8px;
    color: #34485b;
    background: #f7fafc;
    border: none;
    border-right: 1px solid %(border_light)s;
    border-bottom: 1px solid %(border)s;
    font-size: 12px;
    font-weight: 600;
}

QTableCornerButton::section {
    background: #f7fafc;
    border: none;
    border-right: 1px solid %(border_light)s;
    border-bottom: 1px solid %(border)s;
}

QTreeWidget::item {
    min-height: 21px;
    padding: 1px 4px;
}

QTreeWidget::item:hover {
    background: #eef8fb;
}

QTreeWidget::item:selected {
    color: %(text)s;
    background: %(selection)s;
}

QPlainTextEdit {
    padding: 7px;
    color: #25394d;
    background: #fbfdff;
    font-family: "Cascadia Mono", "Consolas", monospace;
    font-size: 12px;
}

/* ---- Splitters, progress and scrollbars ------------------------------- */
QSplitter::handle {
    background: %(background)s;
}

QSplitter::handle:horizontal {
    width: 7px;
    border-left: 1px solid %(border)s;
    border-right: 1px solid %(border)s;
}

QSplitter::handle:vertical {
    height: 7px;
    border-top: 1px solid %(border)s;
    border-bottom: 1px solid %(border)s;
}

QSplitter::handle:hover {
    background: %(cyan_soft)s;
}

QProgressBar#queueProgress {
    min-height: 6px;
    max-height: 6px;
    color: transparent;
    background: #244d6d;
    border: none;
    border-radius: 3px;
    text-align: center;
}

QProgressBar#queueProgress::chunk {
    background: %(success)s;
    border-radius: 3px;
}

QScrollBar:vertical {
    width: 10px;
    margin: 1px;
    background: transparent;
}

QScrollBar::handle:vertical {
    min-height: 28px;
    background: #bdcad6;
    border: 2px solid transparent;
    border-radius: 4px;
}

QScrollBar::handle:vertical:hover {
    background: #91a5b7;
}

QScrollBar::add-line:vertical,
QScrollBar::sub-line:vertical,
QScrollBar::add-page:vertical,
QScrollBar::sub-page:vertical {
    height: 0;
    background: transparent;
}

QScrollBar:horizontal {
    height: 10px;
    margin: 1px;
    background: transparent;
}

QScrollBar::handle:horizontal {
    min-width: 28px;
    background: #bdcad6;
    border: 2px solid transparent;
    border-radius: 4px;
}

QScrollBar::handle:horizontal:hover {
    background: #91a5b7;
}

QScrollBar::add-line:horizontal,
QScrollBar::sub-line:horizontal,
QScrollBar::add-page:horizontal,
QScrollBar::sub-page:horizontal {
    width: 0;
    background: transparent;
}

QToolTip {
    padding: 5px 7px;
    color: %(text_on_dark)s;
    background: %(navy)s;
    border: 1px solid #2b5878;
    border-radius: 4px;
}
""" % COLORS


__all__ = ["APP_STYLESHEET", "COLORS", "SUPPORTED_ICONS", "make_icon"]
