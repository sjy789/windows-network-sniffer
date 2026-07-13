"""Npcap capture-interface discovery.

Scapy exposes more Windows networking components than are useful in a packet
sniffer's interface picker.  This module keeps discovery independent from
Wireshark/tshark and only returns devices that libpcap/Npcap actually exposes.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from typing import Any

from scapy.all import conf, get_if_list

from .models import InterfaceInfo


class InterfaceEnumerationError(RuntimeError):
    """Raised when Scapy cannot ask Npcap for its capture devices."""


_NPF_PREFIX = "\\device\\npf_"
_WINDOWS_COMPONENT_MARKERS = (
    "wan miniport",
    "wi-fi direct virtual adapter",
    "wifi direct virtual adapter",
    "microsoft kernel debug network adapter",
    "microsoft ip-https platform adapter",
    "teredo tunneling pseudo-interface",
    "isatap adapter",
    "6to4 adapter",
)
_VIRTUAL_MARKERS = (
    "virtual",
    "vmware",
    "hyper-v",
    "vethernet",
    "loopback",
    "tunnel",
    "tuntap",
    "vpn",
    "xray",
)


def _text(value: Any) -> str:
    return "" if value is None else str(value).strip()


def _addresses(raw_addresses: Any) -> tuple[str, ...]:
    """Flatten Scapy's ``{family: [addresses]}`` representation stably."""

    values: Iterable[Any]
    if isinstance(raw_addresses, Mapping):
        ordered: list[Any] = []
        for family in (4, 6):
            family_values = raw_addresses.get(family, ())
            if isinstance(family_values, (str, bytes)):
                ordered.append(family_values)
            else:
                ordered.extend(family_values or ())
        for family, family_values in raw_addresses.items():
            if family in (4, 6):
                continue
            if isinstance(family_values, (str, bytes)):
                ordered.append(family_values)
            else:
                ordered.extend(family_values or ())
        values = ordered
    elif isinstance(raw_addresses, (str, bytes)):
        values = (raw_addresses,)
    else:
        values = raw_addresses or ()

    result: list[str] = []
    seen: set[str] = set()
    for value in values:
        address = _text(value)
        key = address.casefold()
        if address and key not in seen:
            result.append(address)
            seen.add(key)
    return tuple(result)


def _is_npf_device(name: str) -> bool:
    return name.casefold().startswith(_NPF_PREFIX)


def _is_loopback(interface: Any, name: str, description: str, pcap_name: str) -> bool:
    flags = _text(getattr(interface, "flags", "")).casefold()
    combined = f"{name} {description} {pcap_name}".casefold()
    return "loopback" in flags or "loopback" in combined


def _is_disconnected(interface: Any) -> bool:
    return "disconnected" in _text(getattr(interface, "flags", "")).casefold()


def _is_windows_component(name: str, description: str) -> bool:
    combined = f"{name} {description}".casefold()
    return any(marker in combined for marker in _WINDOWS_COMPONENT_MARKERS)


def _is_virtual(name: str, description: str, loopback: bool) -> bool:
    if loopback:
        return True
    combined = f"{name} {description}".casefold()
    return any(marker in combined for marker in _VIRTUAL_MARKERS)


def list_capture_interfaces() -> list[InterfaceInfo]:
    """Return useful Npcap devices known to Scapy.

    ``get_if_list`` is libpcap-backed on Windows.  Cross-checking Scapy's rich
    interface metadata against that list avoids presenting native Windows
    adapters that cannot be opened by Npcap.  Disconnected devices and known
    WAN/pseudo components are omitted; the Npcap loopback adapter is retained.
    """

    try:
        capture_names = {
            _text(name).casefold()
            for name in get_if_list()
            if _is_npf_device(_text(name))
        }
        interfaces = list(conf.ifaces.values())
    except Exception as exc:  # Scapy wraps several platform-specific errors.
        raise InterfaceEnumerationError(f"无法枚举 Npcap 网卡：{exc}") from exc

    results: list[InterfaceInfo] = []
    seen: set[str] = set()

    for interface in interfaces:
        if bool(getattr(interface, "dummy", False)):
            continue

        pcap_name = _text(
            getattr(interface, "network_name", "")
            or getattr(interface, "pcap_name", "")
        )
        pcap_key = pcap_name.casefold()
        if not _is_npf_device(pcap_name) or pcap_key not in capture_names:
            continue
        if pcap_key in seen:
            continue

        name = _text(getattr(interface, "name", "")) or pcap_name
        description = _text(getattr(interface, "description", "")) or name
        loopback = _is_loopback(interface, name, description, pcap_name)
        if _is_disconnected(interface) and not loopback:
            continue
        if _is_windows_component(name, description):
            continue

        results.append(
            InterfaceInfo(
                name=name,
                description=description,
                pcap_name=pcap_name,
                addresses=_addresses(getattr(interface, "ips", ())),
                is_loopback=loopback,
                is_virtual=_is_virtual(name, description, loopback),
            )
        )
        seen.add(pcap_key)

    # Physical adapters first, then virtual adapters, with loopback last.
    results.sort(
        key=lambda item: (
            item.is_loopback,
            item.is_virtual,
            item.name.casefold(),
            item.pcap_name.casefold(),
        )
    )
    return results


__all__ = [
    "InterfaceEnumerationError",
    "list_capture_interfaces",
]
