from __future__ import annotations

from types import SimpleNamespace

import pytest

import sniffer.interfaces as interface_module
from sniffer.interfaces import InterfaceEnumerationError, list_capture_interfaces


class FakeIfaces:
    def __init__(self, values):
        self._values = values

    def values(self):
        return list(self._values)


def fake_interface(
    name: str,
    description: str,
    pcap_name: str,
    *,
    flags: str = "UP+RUNNING+OK",
    ips=None,
    dummy: bool = False,
):
    return SimpleNamespace(
        name=name,
        description=description,
        network_name=pcap_name,
        flags=flags,
        ips={} if ips is None else ips,
        dummy=dummy,
    )


def install_fake_scapy(monkeypatch, interfaces, capture_names):
    monkeypatch.setattr(
        interface_module,
        "conf",
        SimpleNamespace(ifaces=FakeIfaces(interfaces)),
    )
    monkeypatch.setattr(interface_module, "get_if_list", lambda: capture_names)


def test_lists_useful_npf_interfaces_and_filters_components(monkeypatch):
    wlan = r"\Device\NPF_{WLAN}"
    vmware = r"\Device\NPF_{VMWARE}"
    hyperv = r"\Device\NPF_{HYPERV}"
    loopback = r"\Device\NPF_Loopback"
    wan = r"\Device\NPF_{WAN}"
    stale_wifi = r"\Device\NPF_{STALE}"
    native_only = "not-an-npf-device"
    interfaces = [
        fake_interface(
            "WLAN",
            "Intel Wi-Fi Adapter",
            wlan,
            ips={6: ["fe80::1"], 4: ["192.0.2.10", "192.0.2.10"]},
        ),
        fake_interface("VMware Network Adapter VMnet8", "VMware Virtual Ethernet Adapter", vmware),
        fake_interface("vEthernet (Default Switch)", "Hyper-V Virtual Ethernet Adapter", hyperv),
        fake_interface(
            "Loopback Pseudo-Interface 1",
            "Software Loopback Interface 1",
            loopback,
            flags="LOOPBACK+UP+RUNNING+DISCONNECTED",
            ips={4: ["127.0.0.1"], 6: ["::1"]},
        ),
        fake_interface("本地连接* 8", "WAN Miniport (Network Monitor)", wan),
        fake_interface(
            "WLAN 3",
            "Intel Wi-Fi Adapter #3",
            stale_wifi,
            flags="UP+RUNNING+WIRELESS+DISCONNECTED",
        ),
        fake_interface("Native Adapter", "Native Adapter", native_only),
        # Duplicate provider metadata for the same Npcap device is emitted once.
        fake_interface("WLAN duplicate", "Duplicate", wlan),
    ]
    install_fake_scapy(
        monkeypatch,
        interfaces,
        [wlan, vmware, hyperv, loopback, wan, stale_wifi, native_only],
    )

    result = list_capture_interfaces()

    assert [item.name for item in result] == [
        "WLAN",
        "vEthernet (Default Switch)",
        "VMware Network Adapter VMnet8",
        "Loopback Pseudo-Interface 1",
    ]
    assert result[0].addresses == ("192.0.2.10", "fe80::1")
    assert result[0].is_virtual is False
    assert result[1].is_virtual is True
    assert result[-1].is_loopback is True
    assert result[-1].addresses == ("127.0.0.1", "::1")


def test_requires_name_to_be_reported_by_libpcap(monkeypatch):
    interface = fake_interface("WLAN", "Wireless", r"\Device\NPF_{WLAN}")
    install_fake_scapy(monkeypatch, [interface], [])

    assert list_capture_interfaces() == []


def test_wraps_scapy_enumeration_failure(monkeypatch):
    def fail():
        raise OSError("Npcap unavailable")

    monkeypatch.setattr(interface_module, "get_if_list", fail)

    with pytest.raises(InterfaceEnumerationError, match="无法枚举 Npcap 网卡"):
        list_capture_interfaces()
