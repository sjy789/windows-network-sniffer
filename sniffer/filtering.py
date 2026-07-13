"""Small, predictable display-filter language for packet records."""

from __future__ import annotations

from dataclasses import dataclass
import ipaddress
import re

from .models import PacketRecord


class FilterSyntaxError(ValueError):
    """Raised when a display-filter expression cannot be parsed."""


_PROTOCOL_ALIASES = {
    "eth": "ethernet",
    "ethernet": "ethernet",
    "arp": "arp",
    "ip": "ipv4",
    "ipv4": "ipv4",
    "icmp": "icmp",
    "tcp": "tcp",
    "udp": "udp",
    "dns": "dns",
    "dhcp": "dhcp",
    "http": "http",
    "https": "https",
    "tls": "tls",
    "quic": "quic",
    "unknown": "unknown",
    "ethernet ii": "ethernet",
    "address resolution protocol": "arp",
    "internet protocol version 4": "ipv4",
    "internet control message protocol": "icmp",
    "transmission control protocol": "tcp",
    "user datagram protocol": "udp",
}
_ADDRESS_FIELDS = {"ip", "src", "dst"}
_PORT_FIELDS = {"port", "sport", "dport"}
_DECIMAL_PORT = re.compile(r"[0-9]+\Z")


@dataclass(slots=True, frozen=True)
class _Term:
    kind: str
    value: str | int


@dataclass(slots=True, frozen=True)
class DisplayFilter:
    """Parsed conjunction of protocol/address/port predicates."""

    text: str
    _terms: tuple[_Term, ...] = ()

    @classmethod
    def parse(cls, text: str) -> "DisplayFilter":
        if not isinstance(text, str):
            raise FilterSyntaxError("filter must be text")

        stripped = text.strip()
        if not stripped:
            return cls(text="", _terms=())

        terms: list[_Term] = []
        for token in stripped.split():
            if ":" not in token:
                protocol = _PROTOCOL_ALIASES.get(token.casefold())
                if protocol is None:
                    raise FilterSyntaxError(f"unknown protocol: {token}")
                terms.append(_Term("protocol", protocol))
                continue

            field, value = token.split(":", 1)
            field = field.casefold()
            if not field:
                raise FilterSyntaxError(f"missing filter field in {token!r}")
            if not value:
                raise FilterSyntaxError(f"missing value for {field}:")

            if field in _ADDRESS_FIELDS:
                try:
                    address = ipaddress.ip_address(value)
                except ValueError as exc:
                    raise FilterSyntaxError(f"invalid IP address for {field}: {value}") from exc
                terms.append(_Term(field, address.compressed.casefold()))
            elif field in _PORT_FIELDS:
                if _DECIMAL_PORT.fullmatch(value) is None:
                    raise FilterSyntaxError(f"invalid port for {field}: {value}")
                port = int(value)
                if not 0 <= port <= 65535:
                    raise FilterSyntaxError(f"port out of range for {field}: {value}")
                terms.append(_Term(field, port))
            else:
                raise FilterSyntaxError(f"unknown filter field: {field}")

        return cls(text=stripped, _terms=tuple(terms))

    def matches(self, record: PacketRecord) -> bool:
        """Return true only when every parsed token matches ``record``."""

        for term in self._terms:
            if term.kind == "protocol":
                if not _matches_protocol(record, str(term.value)):
                    return False
            elif term.kind == "ip":
                if not (
                    _matches_address(record.source, str(term.value))
                    or _matches_address(record.destination, str(term.value))
                ):
                    return False
            elif term.kind == "src":
                if not _matches_address(record.source, str(term.value)):
                    return False
            elif term.kind == "dst":
                if not _matches_address(record.destination, str(term.value)):
                    return False
            elif term.kind == "port":
                if term.value not in (record.source_port, record.destination_port):
                    return False
            elif term.kind == "sport":
                if record.source_port != term.value:
                    return False
            elif term.kind == "dport":
                if record.destination_port != term.value:
                    return False
        return True


def _matches_protocol(record: PacketRecord, wanted: str) -> bool:
    observed = {record.protocol.casefold()}
    observed.update(layer.name.casefold() for layer in record.layers)

    # Normalize common spelling variants on both the query and record sides.
    normalized = {_PROTOCOL_ALIASES.get(name, name) for name in observed}
    if wanted in normalized:
        return True
    if wanted == "ipv4":
        # Parser records always use IP-shaped endpoints for IPv4, even if the
        # most-specific display protocol is TCP/UDP/ICMP.
        return _is_ip_version(record.source, 4) or _is_ip_version(record.destination, 4)
    return False


def _matches_address(observed: str, wanted: str) -> bool:
    try:
        return ipaddress.ip_address(observed).compressed.casefold() == wanted
    except ValueError:
        return False


def _is_ip_version(value: str, version: int) -> bool:
    try:
        return ipaddress.ip_address(value).version == version
    except ValueError:
        return False
