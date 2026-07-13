"""Lightweight passive anomaly detection for course-lab traffic."""

from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import dataclass
from datetime import datetime

from .models import PacketRecord


@dataclass(slots=True, frozen=True)
class Alert:
    timestamp: float
    severity: str
    category: str
    source: str
    description: str
    packet_sequence: int

    @property
    def timestamp_text(self) -> str:
        return datetime.fromtimestamp(self.timestamp).strftime("%H:%M:%S")


class AnomalyDetector:
    """Detect conspicuous patterns without active probing or payload retention."""

    def __init__(self) -> None:
        self.alerts: deque[Alert] = deque(maxlen=2000)
        self._scan: dict[str, deque[tuple[float, int]]] = defaultdict(deque)
        self._syn: dict[str, deque[float]] = defaultdict(deque)
        self._dns: dict[str, deque[float]] = defaultdict(deque)
        self._arp: dict[str, str] = {}
        self._cooldown: dict[tuple[str, str], float] = {}

    def clear(self) -> None:
        self.alerts.clear()
        self._scan.clear()
        self._syn.clear()
        self._dns.clear()
        self._arp.clear()
        self._cooldown.clear()

    def add(self, records: list[PacketRecord]) -> list[Alert]:
        emitted: list[Alert] = []
        for record in records:
            emitted.extend(self._inspect(record))
        return emitted

    def _inspect(self, record: PacketRecord) -> list[Alert]:
        candidates: list[tuple[str, str, str, str]] = []
        flags = _field(record, "Transmission Control Protocol", "Flags")
        if record.destination_port is not None and "SYN" in flags and "ACK" not in flags:
            scan = self._scan[record.source]
            scan.append((record.timestamp, record.destination_port))
            _trim(scan, record.timestamp - 10)
            if len({port for _, port in scan}) >= 15:
                candidates.append(("high", "端口扫描", record.source, f"10 秒内探测了 {len({port for _, port in scan})} 个目标端口"))
            syn = self._syn[record.source]
            syn.append(record.timestamp)
            _trim(syn, record.timestamp - 5)
            if len(syn) >= 50:
                candidates.append(("critical", "SYN 洪泛", record.source, f"5 秒内观察到 {len(syn)} 个未确认 SYN"))
        dns_name = _field(record, "Domain Name System", "Query Name")
        if dns_name:
            dns = self._dns[record.source]
            dns.append(record.timestamp)
            _trim(dns, record.timestamp - 10)
            if len(dns_name) >= 60:
                candidates.append(("medium", "异常 DNS 名称", record.source, f"查询名称长度为 {len(dns_name)}：{dns_name[:80]}"))
            if len(dns) >= 80:
                candidates.append(("high", "DNS 查询突增", record.source, f"10 秒内观察到 {len(dns)} 次 DNS 查询"))
        arp_layer = next((layer for layer in record.layers if layer.name == "Address Resolution Protocol"), None)
        if arp_layer:
            values = dict(arp_layer.fields)
            ip = values.get("Sender Protocol Address", "")
            mac = values.get("Sender MAC", "")
            previous = self._arp.get(ip)
            if ip and mac and previous and previous.casefold() != mac.casefold():
                candidates.append(("critical", "ARP 地址冲突", ip, f"同一 IP 的 MAC 从 {previous} 变为 {mac}"))
            if ip and mac:
                self._arp[ip] = mac
        if record.fragment and (record.errors or "异常" in record.reassembly_note):
            candidates.append(("high", "IPv4 分片异常", record.source, record.reassembly_note or "; ".join(record.errors)))
        if "RST" in flags:
            candidates.append(("low", "TCP Reset", record.source, f"连接被重置：{record.source}:{record.source_port} → {record.destination}:{record.destination_port}"))
        result: list[Alert] = []
        for severity, category, source, description in candidates:
            key = (category, source)
            if record.timestamp - self._cooldown.get(key, float("-inf")) < 5:
                continue
            self._cooldown[key] = record.timestamp
            alert = Alert(record.timestamp, severity, category, source, description, record.sequence)
            self.alerts.appendleft(alert)
            result.append(alert)
        return result


def _field(record: PacketRecord, layer_name: str, field_name: str) -> str:
    for layer in record.layers:
        if layer.name == layer_name:
            return dict(layer.fields).get(field_name, "")
    return ""


def _trim(items: deque, cutoff: float) -> None:  # noqa: ANN001
    while items:
        timestamp = items[0][0] if isinstance(items[0], tuple) else items[0]
        if timestamp >= cutoff:
            break
        items.popleft()


__all__ = ["Alert", "AnomalyDetector"]
