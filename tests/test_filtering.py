from __future__ import annotations

import pytest

from sniffer.filtering import DisplayFilter, FilterSyntaxError
from sniffer.models import PacketRecord, ProtocolLayer


def _record(**changes: object) -> PacketRecord:
    values: dict[str, object] = {
        "timestamp": 1.0,
        "raw": b"packet",
        "length": 6,
        "source": "192.0.2.10",
        "destination": "198.51.100.20",
        "protocol": "TCP",
        "source_port": 51515,
        "destination_port": 443,
        "layers": [ProtocolLayer("Ethernet"), ProtocolLayer("IPv4"), ProtocolLayer("TCP")],
    }
    values.update(changes)
    return PacketRecord(**values)  # type: ignore[arg-type]


def test_empty_filter_matches_every_record() -> None:
    assert DisplayFilter.parse("").matches(_record())
    assert DisplayFilter.parse("  \t ").matches(_record(protocol="ARP"))


def test_protocol_matching_is_case_insensitive() -> None:
    record = _record()
    assert DisplayFilter.parse("tCp").matches(record)
    assert DisplayFilter.parse("ETH").matches(record)
    assert DisplayFilter.parse("ip").matches(record)
    assert not DisplayFilter.parse("udp").matches(record)


def test_address_and_port_tokens_are_anded() -> None:
    record = _record()
    expression = DisplayFilter.parse(
        "tcp src:192.0.2.10 dst:198.51.100.20 sport:51515 dport:443"
    )
    assert expression.matches(record)
    assert not DisplayFilter.parse("tcp src:192.0.2.99 dport:443").matches(record)
    assert not DisplayFilter.parse("tcp dport:80").matches(record)


def test_ip_and_port_match_either_direction() -> None:
    record = _record()
    assert DisplayFilter.parse("ip:192.0.2.10 port:443").matches(record)
    assert DisplayFilter.parse("ip:198.51.100.20 port:51515").matches(record)
    assert not DisplayFilter.parse("ip:203.0.113.7 port:443").matches(record)


def test_ipv6_addresses_are_normalized() -> None:
    record = _record(
        source="2001:0db8:0:0::1",
        destination="2001:db8::2",
        protocol="ICMPv6",
        source_port=None,
        destination_port=None,
        layers=[
            ProtocolLayer("Ethernet II"),
            ProtocolLayer("Internet Protocol Version 6"),
            ProtocolLayer("Internet Control Message Protocol v6"),
        ],
    )
    assert DisplayFilter.parse("src:2001:db8::1 dst:2001:0db8::2").matches(record)
    assert DisplayFilter.parse("ipv6 icmpv6").matches(record)
    assert DisplayFilter.parse("ip6 icmp6").matches(record)
    assert not DisplayFilter.parse("ipv4").matches(record)


def test_protocol_can_be_observed_in_layer_list() -> None:
    record = _record(protocol="TLS")
    assert DisplayFilter.parse("tcp").matches(record)
    assert DisplayFilter.parse("https").matches(record)


@pytest.mark.parametrize(
    "expression",
    [
        "tcq",
        "foo:bar",
        "src:",
        ":192.0.2.1",
        "src:not-an-ip",
        "port:-1",
        "port:+80",
        "port:65536",
        "dport:http",
    ],
)
def test_invalid_syntax_raises(expression: str) -> None:
    with pytest.raises(FilterSyntaxError):
        DisplayFilter.parse(expression)


def test_non_string_expression_raises_filter_error() -> None:
    with pytest.raises(FilterSyntaxError):
        DisplayFilter.parse(None)  # type: ignore[arg-type]
