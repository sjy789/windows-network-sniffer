"""Settings and task-oriented help dialogs for the main window."""

from __future__ import annotations

from dataclasses import dataclass

from PyQt6.QtCore import QSettings
from PyQt6.QtWidgets import (
    QDialog,
    QDialogButtonBox,
    QFormLayout,
    QLabel,
    QSpinBox,
    QTabWidget,
    QTextBrowser,
    QVBoxLayout,
    QWidget,
)


@dataclass(slots=True)
class UiPreferences:
    max_records: int = 20_000
    refresh_interval_ms: int = 100
    chart_window_seconds: int = 60


def load_preferences(store: QSettings) -> UiPreferences:
    def read_int(key: str, default: int, minimum: int, maximum: int) -> int:
        try:
            value = int(store.value(key, default))
        except (TypeError, ValueError):
            value = default
        return min(maximum, max(minimum, value))

    return UiPreferences(
        max_records=read_int("ui/max_records", 20_000, 1_000, 100_000),
        refresh_interval_ms=read_int("ui/refresh_interval_ms", 100, 50, 1_000),
        chart_window_seconds=read_int("ui/chart_window_seconds", 60, 30, 300),
    )


def save_preferences(store: QSettings, preferences: UiPreferences) -> None:
    store.setValue("ui/max_records", preferences.max_records)
    store.setValue("ui/refresh_interval_ms", preferences.refresh_interval_ms)
    store.setValue("ui/chart_window_seconds", preferences.chart_window_seconds)
    store.sync()


class SettingsDialog(QDialog):
    def __init__(self, preferences: UiPreferences, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setWindowTitle("设置 · NetScope")
        self.setModal(True)
        self.setMinimumWidth(470)
        if parent is not None:
            self.setStyleSheet(parent.styleSheet())
        layout = QVBoxLayout(self)
        intro = QLabel("调整显示缓存和实时刷新。保存后立即生效，并在下次启动时保留。")
        intro.setWordWrap(True)
        layout.addWidget(intro)
        form = QFormLayout()
        self.max_records_spin = QSpinBox()
        self.max_records_spin.setRange(1_000, 100_000)
        self.max_records_spin.setSingleStep(1_000)
        self.max_records_spin.setSuffix(" 条")
        self.max_records_spin.setValue(preferences.max_records)
        self.refresh_interval_spin = QSpinBox()
        self.refresh_interval_spin.setRange(50, 1_000)
        self.refresh_interval_spin.setSingleStep(50)
        self.refresh_interval_spin.setSuffix(" ms")
        self.refresh_interval_spin.setValue(preferences.refresh_interval_ms)
        self.chart_window_spin = QSpinBox()
        self.chart_window_spin.setRange(30, 300)
        self.chart_window_spin.setSingleStep(10)
        self.chart_window_spin.setSuffix(" 秒")
        self.chart_window_spin.setValue(preferences.chart_window_seconds)
        form.addRow("数据包列表上限", self.max_records_spin)
        form.addRow("界面队列刷新间隔", self.refresh_interval_spin)
        form.addRow("流量图时间窗口", self.chart_window_spin)
        layout.addLayout(form)
        note = QLabel("列表上限不改变抓包队列容量；缩短刷新间隔会增加界面更新频率。")
        note.setWordWrap(True)
        layout.addWidget(note)
        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Save | QDialogButtonBox.StandardButton.Cancel
        )
        buttons.button(QDialogButtonBox.StandardButton.Save).setText("保存设置")
        buttons.button(QDialogButtonBox.StandardButton.Cancel).setText("取消")
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

    def preferences(self) -> UiPreferences:
        return UiPreferences(
            max_records=self.max_records_spin.value(),
            refresh_interval_ms=self.refresh_interval_spin.value(),
            chart_window_seconds=self.chart_window_spin.value(),
        )


class HelpDialog(QDialog):
    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setWindowTitle("帮助 · NetScope")
        self.resize(720, 520)
        if parent is not None:
            self.setStyleSheet(parent.styleSheet())
        layout = QVBoxLayout(self)
        tabs = QTabWidget()
        tabs.addTab(self._page("""
            <h2>开始捕获</h2>
            <ol><li>选择实际承载流量的捕获接口。</li>
            <li>按需输入 BPF 过滤器，例如 <code>tcp port 443</code>。</li>
            <li>点击“开始捕获”，在数据包分析页查看协议字段和原始字节。</li>
            <li>流量态势使用固定的一秒时间轴，空闲区间会显示为 0。</li></ol>
            <p>停止后可保存 PCAP，或使用“打开 PCAP”重新分析 PCAP/PCAPNG。</p>
        """), "快速开始")
        tabs.addTab(self._page("""
            <h2>显示过滤器</h2>
            <p>多个条件使用 AND 关系，不区分大小写。</p>
            <p><code>tcp</code>、<code>ip:192.0.2.1</code>、<code>src:2001:db8::1</code>、
            <code>port:443</code>、<code>tcp dport:443</code></p>
            <p>显示过滤只改变列表可见内容，不改变后台捕获或保存范围。</p>
        """), "过滤语法")
        tabs.addTab(self._page("""
            <h2>TLS、IPv6 与文件格式</h2>
            <p>NetScope 只解析明文 TLS ClientHello 元数据，包括 SNI 和客户端提供的 ALPN；不解密 TLS。</p>
            <p>SNI 可能因 ECH、直接访问 IP 或客户端未发送扩展而显示“未提供”。</p>
            <p>同一 Ethernet、Loopback 或 Raw IP 链路中的 IPv4/IPv6 可以共同保存；真正不同的链路层仍需分开保存。</p>
            <p>只在本人设备、明确授权设备或隔离实验网络中抓包。</p>
        """), "边界与安全")
        layout.addWidget(tabs)
        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Close)
        buttons.button(QDialogButtonBox.StandardButton.Close).setText("关闭")
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

    @staticmethod
    def _page(html: str) -> QTextBrowser:
        page = QTextBrowser()
        page.setOpenExternalLinks(False)
        page.setHtml(html)
        return page


__all__ = [
    "HelpDialog",
    "SettingsDialog",
    "UiPreferences",
    "load_preferences",
    "save_preferences",
]
