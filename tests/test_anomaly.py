from __future__ import annotations

from sniffer.anomaly import AnomalyDetector
from sniffer.models import PacketRecord, ProtocolLayer


def tcp_record(port: int, timestamp: float) -> PacketRecord:
    return PacketRecord(
        timestamp=timestamp, raw=b"", length=60, source="192.0.2.10", destination="198.51.100.2",
        protocol="TCP", source_port=40000, destination_port=port, sequence=port,
        layers=[ProtocolLayer("Transmission Control Protocol", [("Flags", "0x002 (SYN)")])],
    )


def test_detects_port_scan_and_applies_cooldown() -> None:
    detector = AnomalyDetector()
    alerts = detector.add([tcp_record(port, port / 10) for port in range(1, 17)])
    assert any(alert.category == "端口扫描" for alert in alerts)
    assert sum(alert.category == "端口扫描" for alert in alerts) == 1


def test_detects_long_dns_query() -> None:
    record = PacketRecord(
        timestamp=10, raw=b"", length=100, source="192.0.2.20", sequence=1,
        layers=[ProtocolLayer("Domain Name System", [("Query Name", "a" * 61 + ".example")])],
    )
    alerts = AnomalyDetector().add([record])
    assert alerts[0].category == "异常 DNS 名称"


def test_detects_arp_address_conflict() -> None:
    def arp(mac: str, timestamp: float) -> PacketRecord:
        return PacketRecord(timestamp=timestamp, raw=b"", length=60, sequence=int(timestamp), layers=[
            ProtocolLayer("Address Resolution Protocol", [("Sender Protocol Address", "192.0.2.1"), ("Sender MAC", mac)])
        ])
    alerts = AnomalyDetector().add([arp("00:11:22:33:44:55", 1), arp("AA:BB:CC:DD:EE:FF", 2)])
    assert alerts[0].category == "ARP 地址冲突"
