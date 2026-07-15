"""Defensive, byte-oriented parsers for the protocols used by the project.

Scapy is intentionally absent from this module.  It is useful for capturing
and saving packets, but protocol fields below are decoded directly from the
wire bytes with :mod:`struct` so the course project demonstrates the actual
packet formats.
"""

from __future__ import annotations

import ipaddress
import socket
import struct
import time
from typing import Any

from .formatting import format_payload_summary
from .application import decode_application
from .models import IPv4Fragment, PacketRecord, ProtocolLayer
from .tls import TLS_PORTS, apply_client_hello, parse_client_hello


_VLAN_ETHERTYPES = {0x8100, 0x88A8, 0x9100}
_ETHERTYPE_NAMES = {
    0x0800: "IPv4",
    0x0806: "ARP",
    0x86DD: "IPv6",
    0x8100: "802.1Q VLAN",
    0x88A8: "802.1ad VLAN",
}
_IP_PROTOCOL_NAMES = {
    0: "Hop-by-Hop Options",
    1: "ICMP",
    2: "IGMP",
    6: "TCP",
    17: "UDP",
    41: "IPv6",
    43: "Routing",
    44: "Fragment",
    47: "GRE",
    50: "ESP",
    51: "AH",
    58: "ICMPv6",
    59: "No Next Header",
    60: "Destination Options",
    89: "OSPF",
    135: "Mobility",
    139: "HIP",
    140: "Shim6",
}
_ICMP_NAMES = {
    0: "Echo Reply",
    3: "Destination Unreachable",
    4: "Source Quench",
    5: "Redirect",
    8: "Echo Request",
    9: "Router Advertisement",
    10: "Router Solicitation",
    11: "Time Exceeded",
    12: "Parameter Problem",
    13: "Timestamp Request",
    14: "Timestamp Reply",
}
_ICMPV6_NAMES = {
    1: "Destination Unreachable",
    2: "Packet Too Big",
    3: "Time Exceeded",
    4: "Parameter Problem",
    128: "Echo Request",
    129: "Echo Reply",
    130: "Multicast Listener Query",
    131: "Multicast Listener Report",
    132: "Multicast Listener Done",
    133: "Router Solicitation",
    134: "Router Advertisement",
    135: "Neighbor Solicitation",
    136: "Neighbor Advertisement",
    137: "Redirect",
    143: "Multicast Listener Report v2",
}
_ICMPV6_CODE_NAMES = {
    1: {
        0: "No route to destination",
        1: "Communication administratively prohibited",
        2: "Beyond scope of source address",
        3: "Address unreachable",
        4: "Port unreachable",
        5: "Source address failed policy",
        6: "Reject route",
        7: "Error in Source Routing Header",
    },
    3: {
        0: "Hop limit exceeded in transit",
        1: "Fragment reassembly time exceeded",
    },
    4: {
        0: "Erroneous header field",
        1: "Unrecognized Next Header",
        2: "Unrecognized IPv6 option",
    },
}
_IPV6_EXTENSION_HEADERS = {0, 43, 44, 50, 51, 60}
_IPV6_EXTENSION_LIMIT = 16
_TCP_APPLICATION_PORTS = {
    53: "DNS",
    80: "HTTP",
    443: "TLS",
    8080: "HTTP",
    8443: "TLS",
}
_UDP_APPLICATION_PORTS = {
    53: "DNS",
    67: "DHCP",
    68: "DHCP",
    443: "QUIC",
}


def _mac_text(value: bytes) -> str:
    return ":".join(f"{part:02X}" for part in value)


def _ipv4_text(value: bytes) -> str:
    # inet_ntoa is available on every supported Windows/Python combination.
    return socket.inet_ntoa(value)


def _ipv6_text(value: bytes) -> str:
    return ipaddress.IPv6Address(value).compressed


def _hex_bytes(value: bytes) -> str:
    return " ".join(f"{part:02X}" for part in value)


class PacketParser:
    """Parse captured frame bytes into :class:`~sniffer.models.PacketRecord`.

    A malformed or truncated frame produces a partial record with explanatory
    entries in ``errors``.  Packet input must never be able to terminate the
    capture/GUI worker with ``IndexError`` or ``struct.error``.
    """

    def parse(
        self,
        raw: bytes | bytearray | memoryview,
        timestamp: float | None = None,
        original_packet: Any = None,
        link_type: str = "ethernet",
    ) -> PacketRecord:
        """Parse a captured frame without consulting ``original_packet`` fields."""

        try:
            data = bytes(raw)
        except (TypeError, ValueError):
            data = b""

        try:
            parsed_timestamp = time.time() if timestamp is None else float(timestamp)
        except (TypeError, ValueError, OverflowError):
            parsed_timestamp = time.time()

        record = PacketRecord(
            timestamp=parsed_timestamp,
            raw=data,
            length=len(data),
            link_type=link_type,
            original_packet=original_packet,
        )

        if not isinstance(raw, (bytes, bytearray, memoryview)):
            record.errors.append("数据包不是有效的字节序列")
            return record

        normalized = link_type.strip().lower().replace("_", "-")
        try:
            if normalized in {"ethernet", "ether", "en10mb"}:
                self._parse_ethernet(record)
            elif normalized in {"ipv4", "raw", "raw-ip", "raw-ipv4"}:
                self._parse_ipv4(record, 0, b"")
            elif normalized in {"ipv6", "raw-ipv6"}:
                self._parse_ipv6(record, 0)
            elif normalized in {"loopback", "null", "dlt-null"}:
                self._parse_loopback(record)
            else:
                record.protocol = "Raw"
                record.info = f"Unsupported link type: {link_type}"
                record.errors.append(f"不支持的链路类型：{link_type}")
                if data:
                    self._add_payload_layer(record, data, name="Raw Data")
        except Exception as exc:  # pragma: no cover - final capture-thread safety net
            # All expected bad-length cases are handled explicitly.  This final
            # guard ensures an unusual bytes-like object or future parser bug
            # still becomes a visible per-packet error instead of killing capture.
            record.errors.append(f"解析数据包时发生异常：{type(exc).__name__}: {exc}")
        return record

    def parse_ipv4_packet(
        self,
        ip_packet: bytes | bytearray | memoryview,
        link_header: bytes | bytearray | memoryview = b"",
        *,
        timestamp: float | None = None,
        original_packet: Any = None,
        link_type: str = "ethernet",
        is_reassembled: bool = True,
        reassembly_note: str = "IPv4 分片重组完成",
    ) -> PacketRecord:
        """Parse a reconstructed IPv4 datagram, optionally with its link header.

        Reassemblers retain the first fragment's Ethernet/VLAN header separately.
        Passing it here reconstructs a complete frame for the normal parsing path.
        With an empty header, the datagram is parsed as raw IPv4.
        """

        try:
            network_data = bytes(ip_packet)
            header = bytes(link_header)
        except (TypeError, ValueError):
            network_data = b""
            header = b""

        if header:
            record = self.parse(
                header + network_data,
                timestamp=timestamp,
                original_packet=original_packet,
                link_type=link_type,
            )
        else:
            record = self.parse(
                network_data,
                timestamp=timestamp,
                original_packet=original_packet,
                link_type="ipv4",
            )
        record.is_reassembled = is_reassembled
        record.reassembly_note = reassembly_note
        # A correctly reconstructed IP header has MF and offset cleared.  If a
        # caller supplies an unnormalised header, avoid feeding it back into the
        # reassembly cache indefinitely while retaining the visible fields.
        if is_reassembled:
            record.fragment = None
        return record

    @staticmethod
    def _add_error(record: PacketRecord, message: str) -> None:
        if message not in record.errors:
            record.errors.append(message)

    def _require(
        self,
        record: PacketRecord,
        offset: int,
        size: int,
        context: str,
        *,
        end: int | None = None,
    ) -> bool:
        available_end = len(record.raw) if end is None else min(end, len(record.raw))
        if offset < 0 or size < 0 or offset + size > available_end:
            available = max(available_end - offset, 0)
            self._add_error(
                record,
                f"{context}被截断：需要 {size} 字节，实际仅 {available} 字节",
            )
            return False
        return True

    def _parse_ethernet(self, record: PacketRecord) -> None:
        data = record.raw
        record.protocol = "Ethernet"
        if not self._require(record, 0, 14, "Ethernet 头部"):
            return

        destination = _mac_text(data[0:6])
        source = _mac_text(data[6:12])
        ethertype = struct.unpack_from("!H", data, 12)[0]
        ethernet = ProtocolLayer("Ethernet II")
        ethernet.add("Destination", destination)
        ethernet.add("Source", source)
        ethernet.add(
            "Type",
            f"{_ETHERTYPE_NAMES.get(ethertype, 'Unknown')} (0x{ethertype:04X})",
        )
        record.layers.append(ethernet)

        cursor = 14
        tag_count = 0
        while ethertype in _VLAN_ETHERTYPES and tag_count < 2:
            if not self._require(record, cursor, 4, f"VLAN 标签 {tag_count + 1}"):
                record.protocol = "VLAN"
                return
            tci, inner_type = struct.unpack_from("!HH", data, cursor)
            vlan = ProtocolLayer("802.1Q VLAN")
            vlan.add("Tag", tag_count + 1)
            vlan.add("TPID", f"0x{ethertype:04X}")
            vlan.add("Priority (PCP)", (tci >> 13) & 0x07)
            vlan.add("Drop Eligible (DEI)", (tci >> 12) & 0x01)
            vlan.add("VLAN ID", tci & 0x0FFF)
            vlan.add(
                "Encapsulated Type",
                f"{_ETHERTYPE_NAMES.get(inner_type, 'Unknown')} (0x{inner_type:04X})",
            )
            record.layers.append(vlan)
            ethertype = inner_type
            cursor += 4
            tag_count += 1

        if ethertype in _VLAN_ETHERTYPES:
            self._add_error(record, "检测到超过两个 VLAN 标签；本项目最多解析双标签")
            record.protocol = "VLAN"
            record.info = "Unsupported VLAN stack (> 2 tags)"
            return

        link_header = data[:cursor]
        if ethertype == 0x0800:
            self._parse_ipv4(record, cursor, link_header)
        elif ethertype == 0x0806:
            self._parse_arp(record, cursor)
        elif ethertype == 0x86DD:
            self._parse_ipv6(record, cursor)
        else:
            name = _ETHERTYPE_NAMES.get(ethertype)
            record.protocol = name or f"0x{ethertype:04X}"
            record.source = source
            record.destination = destination
            record.info = f"EtherType 0x{ethertype:04X}"
            if cursor < len(data):
                self._add_payload_layer(record, data[cursor:])

    def _parse_loopback(self, record: PacketRecord) -> None:
        """Parse the four-byte DLT_NULL family header used by loopback capture."""

        record.protocol = "Loopback"
        if not self._require(record, 0, 4, "Loopback 头部"):
            return
        # DLT_NULL stores the host's native byte order.  Accept both orders so
        # pcap files produced on other platforms remain readable.
        family_le = struct.unpack_from("<I", record.raw, 0)[0]
        family_be = struct.unpack_from(">I", record.raw, 0)[0]
        known_ipv4 = {2}
        # DLT_NULL stores platform-native AF_* values.  Windows uses 23 for
        # AF_INET6, while common BSD/macOS captures use 24, 28, or 30.
        known_ipv6 = {23, 24, 28, 30}
        known_families = known_ipv4 | known_ipv6
        family = family_le if family_le in known_families else family_be
        layer = ProtocolLayer("Loopback")
        layer.add("Address Family", family)
        record.layers.append(layer)
        if family in known_ipv4:
            self._parse_ipv4(record, 4, record.raw[:4])
        elif family in known_ipv6:
            self._parse_ipv6(record, 4)
        else:
            self._add_error(record, f"不支持的 Loopback 地址族：{family}")

    def _parse_arp(self, record: PacketRecord, offset: int) -> None:
        data = record.raw
        record.protocol = "ARP"
        if not self._require(record, offset, 8, "ARP 固定头部"):
            return

        hardware_type, protocol_type, hardware_len, protocol_len, operation = struct.unpack_from(
            "!HHBBH", data, offset
        )
        address_bytes = 2 * hardware_len + 2 * protocol_len
        if not self._require(record, offset + 8, address_bytes, "ARP 地址字段"):
            layer = ProtocolLayer("Address Resolution Protocol")
            layer.add("Hardware Type", hardware_type)
            layer.add("Protocol Type", f"0x{protocol_type:04X}")
            layer.add("Hardware Address Length", hardware_len)
            layer.add("Protocol Address Length", protocol_len)
            layer.add("Operation", operation)
            record.layers.append(layer)
            return

        cursor = offset + 8
        sender_hardware = data[cursor : cursor + hardware_len]
        cursor += hardware_len
        sender_protocol = data[cursor : cursor + protocol_len]
        cursor += protocol_len
        target_hardware = data[cursor : cursor + hardware_len]
        cursor += hardware_len
        target_protocol = data[cursor : cursor + protocol_len]

        def hardware_text(value: bytes) -> str:
            return _mac_text(value) if len(value) == 6 else _hex_bytes(value)

        def protocol_text(value: bytes) -> str:
            if protocol_type == 0x0800 and len(value) == 4:
                return _ipv4_text(value)
            return _hex_bytes(value)

        sha = hardware_text(sender_hardware)
        spa = protocol_text(sender_protocol)
        tha = hardware_text(target_hardware)
        tpa = protocol_text(target_protocol)
        operation_name = {1: "request", 2: "reply"}.get(operation, "unknown")

        layer = ProtocolLayer("Address Resolution Protocol")
        layer.add("Hardware Type", f"{hardware_type} ({'Ethernet' if hardware_type == 1 else 'Unknown'})")
        layer.add("Protocol Type", f"0x{protocol_type:04X}")
        layer.add("Hardware Address Length", hardware_len)
        layer.add("Protocol Address Length", protocol_len)
        layer.add("Operation", f"{operation} ({operation_name})")
        layer.add("Sender MAC", sha)
        layer.add("Sender Protocol Address", spa)
        layer.add("Target MAC", tha)
        layer.add("Target Protocol Address", tpa)
        record.layers.append(layer)

        record.source = spa or sha
        record.destination = tpa or tha
        if operation == 1:
            record.info = f"Who has {tpa}? Tell {spa}"
        elif operation == 2:
            record.info = f"{spa} is at {sha}"
        else:
            record.info = f"ARP operation {operation}: {spa} → {tpa}"

    def _parse_ipv6(self, record: PacketRecord, offset: int) -> None:
        """Parse an IPv6 datagram and walk its extension-header chain."""

        data = record.raw
        record.protocol = "IPv6"
        if not self._require(record, offset, 40, "IPv6 固定头部"):
            return

        first_word, payload_length, next_header, hop_limit, source_bytes, destination_bytes = (
            struct.unpack_from("!IHBB16s16s", data, offset)
        )
        version = first_word >> 28
        traffic_class = (first_word >> 20) & 0xFF
        flow_label = first_word & 0xFFFFF
        source = _ipv6_text(source_bytes)
        destination = _ipv6_text(destination_bytes)
        record.source = source
        record.destination = destination

        layer = ProtocolLayer("Internet Protocol Version 6")
        layer.add("Version", version)
        layer.add("Traffic Class", f"0x{traffic_class:02X}")
        layer.add("DSCP", traffic_class >> 2)
        layer.add("ECN", traffic_class & 0x03)
        layer.add("Flow Label", f"0x{flow_label:05X} ({flow_label})")
        if payload_length == 0:
            layer.add("Payload Length", "0 (empty payload or jumbogram)")
        else:
            layer.add("Payload Length", payload_length)
        layer.add("Next Header", f"{_IP_PROTOCOL_NAMES.get(next_header, 'Unknown')} ({next_header})")
        layer.add("Hop Limit", hop_limit)
        layer.add("Source Address", source)
        layer.add("Destination Address", destination)
        record.layers.append(layer)

        if version != 6:
            self._add_error(record, f"IPv6 版本字段无效：{version}")
            record.protocol = "Malformed IPv6"
            record.info = f"Invalid IP version {version}: {source} → {destination}"
            return

        declared_end = offset + 40 + payload_length
        is_jumbogram = False
        if payload_length == 0:
            # RFC 2675 jumbograms carry the real length in a Hop-by-Hop option.
            jumbo_length = (
                self._peek_ipv6_jumbo_payload_length(data, offset + 40)
                if next_header == 0
                else None
            )
            if jumbo_length is not None:
                is_jumbogram = jumbo_length > 65535
                layer.add("Jumbo Payload Length", jumbo_length)
                jumbo_end = offset + 40 + jumbo_length
                if jumbo_end > len(data):
                    self._add_error(
                        record,
                        f"IPv6 Jumbogram 被截断：长度声明 {jumbo_length} 字节，实际仅 {len(data) - offset - 40} 字节",
                    )
                    ip_end = len(data)
                else:
                    ip_end = jumbo_end
            elif next_header == 0 and len(data) > offset + 40:
                self._add_error(record, "IPv6 Payload Length 为 0，但 Hop-by-Hop 中没有 Jumbo Payload Option")
                # Keep parsing the bounded capture bytes to expose the malformed
                # extension chain instead of hiding useful diagnostics.
                ip_end = len(data)
            else:
                # A genuine empty IPv6 packet may be Ethernet-padded.  Its
                # trailing link-layer bytes are not part of the IPv6 payload.
                ip_end = offset + 40
        elif declared_end > len(data):
            self._add_error(
                record,
                f"IPv6 数据包被截断：负载长度声明 {payload_length} 字节，实际仅 {len(data) - offset - 40} 字节",
            )
            ip_end = len(data)
        else:
            # Exclude Ethernet padding/trailing capture bytes from upper layers.
            ip_end = declared_end
            if next_header == 0 and self._peek_ipv6_jumbo_payload_length(data, offset + 40) is not None:
                self._add_error(record, "IPv6 Payload Length 非 0 时不得包含 Jumbo Payload Option")

        cursor = offset + 40
        extension_count = 0
        seen_fragment = False
        more_fragments = False
        fragment_id: int | None = None

        while next_header in _IPV6_EXTENSION_HEADERS:
            if extension_count >= _IPV6_EXTENSION_LIMIT:
                self._add_error(record, f"IPv6 扩展首部过多：超过 {_IPV6_EXTENSION_LIMIT} 个")
                record.protocol = "Malformed IPv6"
                record.info = f"Too many IPv6 extension headers: {source} → {destination}"
                return

            current_header = next_header
            extension_count += 1
            if current_header == 0:
                if extension_count != 1:
                    self._add_error(record, "IPv6 Hop-by-Hop Options 不是固定首部后的第一个扩展首部")
                result = self._parse_ipv6_options_header(
                    record, cursor, ip_end, "IPv6 Hop-by-Hop Options Header"
                )
            elif current_header == 60:
                result = self._parse_ipv6_options_header(
                    record, cursor, ip_end, "IPv6 Destination Options Header"
                )
            elif current_header == 43:
                result = self._parse_ipv6_routing_header(record, cursor, ip_end)
            elif current_header == 51:
                result = self._parse_ipv6_authentication_header(record, cursor, ip_end)
            elif current_header == 50:
                self._parse_ipv6_esp(record, cursor, ip_end)
                return
            else:  # Fragment header (44)
                if is_jumbogram:
                    self._add_error(record, "IPv6 Jumbogram 不得包含 Fragment Header")
                if seen_fragment:
                    self._add_error(record, "IPv6 扩展首部链包含多个 Fragment Header")
                seen_fragment = True
                if not self._require(record, cursor, 8, "IPv6 Fragment Header", end=ip_end):
                    record.info = f"Truncated IPv6 fragment: {source} → {destination}"
                    return
                next_value, reserved, fragment_field, identification = struct.unpack_from(
                    "!BBHI", data, cursor
                )
                fragment_offset_units = (fragment_field >> 3) & 0x1FFF
                fragment_offset_bytes = fragment_offset_units * 8
                reserved_bits = (fragment_field >> 1) & 0x03
                more_fragments = bool(fragment_field & 0x01)
                fragment_id = identification
                fragment = ProtocolLayer("IPv6 Fragment Header")
                fragment.add(
                    "Next Header",
                    f"{_IP_PROTOCOL_NAMES.get(next_value, 'Unknown')} ({next_value})",
                )
                fragment.add("Reserved Byte", reserved)
                fragment.add("Fragment Offset", f"{fragment_offset_units} ({fragment_offset_bytes} bytes)")
                fragment.add("Reserved Bits", reserved_bits)
                fragment.add("More Fragments", int(more_fragments))
                fragment.add("Identification", f"0x{identification:08X} ({identification})")
                record.layers.append(fragment)
                if reserved or reserved_bits:
                    self._add_error(record, "IPv6 Fragment Header 保留字段不为 0")
                cursor += 8
                next_header = next_value
                if fragment_offset_units != 0:
                    # Non-initial fragments begin in the middle of the
                    # fragmentable part; never guess transport-layer fields.
                    record.protocol = "IPv6-FRAG"
                    record.source_port = None
                    record.destination_port = None
                    record.info = (
                        f"{_IP_PROTOCOL_NAMES.get(next_header, str(next_header))} fragment, "
                        f"id=0x{identification:08X}, offset={fragment_offset_bytes}, "
                        f"M={int(more_fragments)}"
                    )
                    if cursor < ip_end:
                        self._add_payload_layer(record, data[cursor:ip_end], name="Fragment Data")
                    return
                continue

            if result is None:
                record.info = f"Truncated IPv6 extension header: {source} → {destination}"
                return
            next_header, cursor = result

        if next_header == 59:
            record.protocol = "IPv6"
            record.info = f"No Next Header: {source} → {destination}"
            if cursor < ip_end:
                self._add_error(record, "IPv6 No Next Header 后仍存在数据")
                self._add_payload_layer(record, data[cursor:ip_end])
            return

        minimum = {6: 20, 17: 8, 58: 4}.get(next_header, 0)
        if more_fragments and ip_end - cursor < minimum:
            record.protocol = "IPv6-FRAG"
            record.info = (
                f"First {_IP_PROTOCOL_NAMES.get(next_header, str(next_header))} fragment, "
                f"id=0x{fragment_id or 0:08X}, upper-layer header continues in later fragment"
            )
            if cursor < ip_end:
                self._add_payload_layer(record, data[cursor:ip_end], name="Fragment Data")
            return

        if next_header == 58:
            self._parse_icmpv6(record, cursor, ip_end)
        elif next_header == 6:
            self._parse_tcp(record, cursor, ip_end)
        elif next_header == 17:
            self._parse_udp(
                record,
                cursor,
                ip_end,
                first_fragment=more_fragments,
                allow_zero_length=is_jumbogram,
            )
        else:
            protocol_name = _IP_PROTOCOL_NAMES.get(next_header)
            record.protocol = protocol_name or "IPv6"
            record.info = f"{source} → {destination}, IPv6 next header {next_header}"
            if cursor < ip_end:
                self._add_payload_layer(record, data[cursor:ip_end])

        if more_fragments:
            note = f"first fragment id=0x{fragment_id or 0:08X}, M=1"
            record.info = f"{record.info} ({note})" if record.info else note

    @staticmethod
    def _peek_ipv6_jumbo_payload_length(data: bytes, offset: int) -> int | None:
        """Return the Hop-by-Hop Jumbo Payload value without trusting it as a bound."""

        if offset < 0 or offset + 2 > len(data):
            return None
        length_units = data[offset + 1]
        header_length = (length_units + 1) * 8
        if offset + header_length > len(data):
            return None
        options = data[offset + 2 : offset + header_length]
        cursor = 0
        while cursor < len(options):
            option_type = options[cursor]
            if option_type == 0:
                cursor += 1
                continue
            if cursor + 2 > len(options):
                return None
            option_length = options[cursor + 1]
            option_end = cursor + 2 + option_length
            if option_end > len(options):
                return None
            if option_type == 0xC2 and option_length == 4:
                return struct.unpack("!I", options[cursor + 2 : option_end])[0]
            cursor = option_end
        return None

    def _parse_ipv6_options_header(
        self,
        record: PacketRecord,
        offset: int,
        end: int,
        layer_name: str,
    ) -> tuple[int, int] | None:
        if not self._require(record, offset, 2, layer_name, end=end):
            return None
        next_header, length_units = struct.unpack_from("!BB", record.raw, offset)
        header_length = (length_units + 1) * 8
        if not self._require(record, offset, header_length, layer_name, end=end):
            return None

        layer = ProtocolLayer(layer_name)
        layer.add("Next Header", f"{_IP_PROTOCOL_NAMES.get(next_header, 'Unknown')} ({next_header})")
        layer.add("Header Extension Length", length_units)
        layer.add("Header Length", f"{header_length} bytes")
        options = record.raw[offset + 2 : offset + header_length]
        layer.add("Options", self._format_ipv6_options(record, options, layer_name))
        record.layers.append(layer)
        return next_header, offset + header_length

    def _format_ipv6_options(
        self,
        record: PacketRecord,
        options: bytes,
        context: str,
    ) -> str:
        entries: list[str] = []
        cursor = 0
        action_names = {
            0: "skip",
            1: "discard",
            2: "discard+ICMP",
            3: "discard+ICMP(non-multicast)",
        }
        while cursor < len(options):
            option_type = options[cursor]
            if option_type == 0:
                entries.append("Pad1")
                cursor += 1
                continue
            if cursor + 2 > len(options):
                self._add_error(record, f"{context} 选项被截断：缺少长度字段")
                entries.append(f"type {option_type} (truncated)")
                break
            option_length = options[cursor + 1]
            option_end = cursor + 2 + option_length
            if option_end > len(options):
                self._add_error(record, f"{context} Option {option_type} 超出扩展首部")
                entries.append(f"type {option_type} (truncated)")
                break
            value = options[cursor + 2 : option_end]
            action = action_names[(option_type >> 6) & 0x03]
            mutable = bool(option_type & 0x20)
            if option_type == 1:
                detail = f"PadN({option_length})"
            elif option_type == 5 and option_length == 2:
                detail = f"Router Alert={struct.unpack('!H', value)[0]}"
            elif option_type == 0xC2 and option_length == 4:
                jumbo_length = struct.unpack("!I", value)[0]
                detail = f"Jumbo Payload={jumbo_length} bytes"
                if jumbo_length <= 65535:
                    self._add_error(record, f"IPv6 Jumbo Payload 长度无效：{jumbo_length}（必须大于 65535）")
            elif option_type == 0xC9 and option_length == 16:
                detail = f"Home Address={_ipv6_text(value)}"
            else:
                preview = _hex_bytes(value[:24])
                if len(value) > 24:
                    preview += " …"
                detail = f"Option {option_type}[{preview}]"
            if option_type not in {0, 1}:
                detail += f" action={action}, mutable={int(mutable)}"
            entries.append(detail)
            cursor = option_end
        return ", ".join(entries) if entries else "None"

    def _parse_ipv6_routing_header(
        self,
        record: PacketRecord,
        offset: int,
        end: int,
    ) -> tuple[int, int] | None:
        if not self._require(record, offset, 4, "IPv6 Routing Header", end=end):
            return None
        next_header, length_units, routing_type, segments_left = struct.unpack_from(
            "!BBBB", record.raw, offset
        )
        header_length = (length_units + 1) * 8
        if not self._require(record, offset, header_length, "IPv6 Routing Header", end=end):
            return None

        layer = ProtocolLayer("IPv6 Routing Header")
        layer.add("Next Header", f"{_IP_PROTOCOL_NAMES.get(next_header, 'Unknown')} ({next_header})")
        layer.add("Header Extension Length", length_units)
        layer.add("Header Length", f"{header_length} bytes")
        layer.add("Routing Type", routing_type)
        layer.add("Segments Left", segments_left)
        body = record.raw[offset + 4 : offset + header_length]

        if routing_type == 0:
            if length_units % 2:
                self._add_error(record, f"IPv6 Routing Type 0 长度无效：{length_units}")
            addresses = [
                _ipv6_text(record.raw[position : position + 16])
                for position in range(offset + 8, offset + header_length, 16)
                if position + 16 <= offset + header_length
            ]
            layer.add("Addresses", ", ".join(addresses) if addresses else "None")
        elif routing_type == 2 and header_length >= 24:
            layer.add("Home Address", _ipv6_text(record.raw[offset + 8 : offset + 24]))
        elif routing_type == 4 and header_length >= 8:
            last_entry, flags, tag = struct.unpack_from("!BBH", record.raw, offset + 4)
            layer.add("Last Entry", last_entry)
            layer.add("Flags", f"0x{flags:02X}")
            layer.add("Tag", f"0x{tag:04X}")
            segment_count = last_entry + 1
            available_segments = max((header_length - 8) // 16, 0)
            if segment_count > available_segments:
                self._add_error(
                    record,
                    f"IPv6 Segment Routing Header 声明 {segment_count} 个段，实际仅 {available_segments} 个",
                )
            segments = [
                _ipv6_text(record.raw[offset + 8 + index * 16 : offset + 24 + index * 16])
                for index in range(min(segment_count, available_segments))
            ]
            layer.add("Segment List", ", ".join(segments) if segments else "None")
        elif body:
            preview = _hex_bytes(body[:32]) + (" …" if len(body) > 32 else "")
            layer.add("Type-Specific Data", preview)

        record.layers.append(layer)
        return next_header, offset + header_length

    def _parse_ipv6_authentication_header(
        self,
        record: PacketRecord,
        offset: int,
        end: int,
    ) -> tuple[int, int] | None:
        if not self._require(record, offset, 2, "IPv6 Authentication Header", end=end):
            return None
        next_header, payload_length = struct.unpack_from("!BB", record.raw, offset)
        header_length = (payload_length + 2) * 4
        if header_length < 12:
            self._add_error(record, f"IPv6 Authentication Header 长度无效：{header_length} 字节")
            return None
        if not self._require(record, offset, header_length, "IPv6 Authentication Header", end=end):
            return None
        reserved, spi, sequence = struct.unpack_from("!HII", record.raw, offset + 2)
        layer = ProtocolLayer("IPv6 Authentication Header")
        layer.add("Next Header", f"{_IP_PROTOCOL_NAMES.get(next_header, 'Unknown')} ({next_header})")
        layer.add("Payload Length", payload_length)
        layer.add("Header Length", f"{header_length} bytes")
        layer.add("Reserved", reserved)
        layer.add("Security Parameters Index", f"0x{spi:08X}")
        layer.add("Sequence Number", sequence)
        layer.add("Integrity Check Value", _hex_bytes(record.raw[offset + 12 : offset + header_length]))
        record.layers.append(layer)
        if reserved:
            self._add_error(record, "IPv6 Authentication Header 保留字段不为 0")
        return next_header, offset + header_length

    def _parse_ipv6_esp(self, record: PacketRecord, offset: int, end: int) -> None:
        record.protocol = "ESP"
        if not self._require(record, offset, 8, "IPv6 ESP Header", end=end):
            return
        spi, sequence = struct.unpack_from("!II", record.raw, offset)
        layer = ProtocolLayer("Encapsulating Security Payload")
        layer.add("Security Parameters Index", f"0x{spi:08X}")
        layer.add("Sequence Number", sequence)
        layer.add("Encrypted Payload and Trailer", f"{end - offset - 8} bytes")
        record.layers.append(layer)
        record.info = f"ESP SPI=0x{spi:08X} Seq={sequence}"

    def _parse_ipv4(self, record: PacketRecord, offset: int, link_header: bytes) -> None:
        data = record.raw
        record.protocol = "IPv4"
        if not self._require(record, offset, 20, "IPv4 固定头部"):
            return

        (
            version_ihl,
            dscp_ecn,
            total_length,
            identification,
            flags_fragment,
            ttl,
            protocol_number,
            checksum,
            source_bytes,
            destination_bytes,
        ) = struct.unpack_from("!BBHHHBBH4s4s", data, offset)

        version = version_ihl >> 4
        ihl_words = version_ihl & 0x0F
        header_length = ihl_words * 4
        source = _ipv4_text(source_bytes)
        destination = _ipv4_text(destination_bytes)
        record.source = source
        record.destination = destination

        if version != 4:
            self._add_error(record, f"IPv4 版本字段无效：{version}")
        if ihl_words < 5:
            self._add_error(record, f"IPv4 IHL 无效：{ihl_words}（小于 5）")

        flags = (flags_fragment >> 13) & 0x07
        reserved_flag = bool(flags & 0x04)
        dont_fragment = bool(flags & 0x02)
        more_fragments = bool(flags & 0x01)
        fragment_offset_units = flags_fragment & 0x1FFF
        fragment_offset_bytes = fragment_offset_units * 8
        protocol_name = _IP_PROTOCOL_NAMES.get(protocol_number, str(protocol_number))

        layer = ProtocolLayer("Internet Protocol Version 4")
        layer.add("Version", version)
        layer.add("Header Length", f"{header_length} bytes ({ihl_words})")
        layer.add("DSCP", (dscp_ecn >> 2) & 0x3F)
        layer.add("ECN", dscp_ecn & 0x03)
        layer.add("Total Length", total_length)
        layer.add("Identification", f"0x{identification:04X} ({identification})")
        layer.add("Flags", f"R={int(reserved_flag)}, DF={int(dont_fragment)}, MF={int(more_fragments)}")
        layer.add("Fragment Offset", f"{fragment_offset_units} ({fragment_offset_bytes} bytes)")
        layer.add("Time to Live", ttl)
        layer.add("Protocol", f"{protocol_name} ({protocol_number})")
        layer.add("Header Checksum", f"0x{checksum:04X}")
        layer.add("Source Address", source)
        layer.add("Destination Address", destination)
        record.layers.append(layer)

        if version != 4:
            record.protocol = "Malformed IPv4"
            record.info = f"Invalid IP version {version}: {source} → {destination}"
            return
        if reserved_flag:
            self._add_error(record, "IPv4 保留标志位被设置")
        if ihl_words < 5:
            record.info = f"Malformed IPv4: {source} → {destination}"
            return
        if not self._require(record, offset, header_length, "IPv4 可变头部"):
            record.info = f"Truncated IPv4: {source} → {destination}"
            return

        if header_length > 20:
            options = data[offset + 20 : offset + header_length]
            layer.add("Options", self._format_ipv4_options(record, options))

        if total_length < header_length:
            self._add_error(
                record,
                f"IPv4 总长度无效：{total_length} 小于头部长度 {header_length}",
            )
            record.info = f"Malformed IPv4: {source} → {destination}"
            return

        declared_end = offset + total_length
        truncated_datagram = declared_end > len(data)
        if truncated_datagram:
            self._add_error(
                record,
                f"IPv4 数据报被截断：总长度声明 {total_length} 字节，实际仅 {len(data) - offset} 字节",
            )
            ip_end = len(data)
        else:
            # Exclude Ethernet padding/trailing capture bytes from L4 parsing.
            ip_end = declared_end

        payload_offset = offset + header_length
        payload = data[payload_offset:ip_end]
        is_fragment = more_fragments or fragment_offset_units != 0
        if is_fragment and not truncated_datagram:
            record.fragment = IPv4Fragment(
                key=(source, destination, protocol_number, identification),
                identification=identification,
                offset_bytes=fragment_offset_bytes,
                more_fragments=more_fragments,
                payload=payload,
                ip_header=data[offset : offset + header_length],
                link_header=link_header,
                timestamp=record.timestamp,
            )
        elif is_fragment:
            self._add_error(record, "截断的 IPv4 分片不会进入重组缓存")

        if fragment_offset_units != 0:
            # A continuation fragment starts in the middle of a transport
            # datagram.  Its first bytes are payload, never source/dest ports.
            record.protocol = "IPv4-FRAG"
            record.source_port = None
            record.destination_port = None
            record.info = (
                f"{protocol_name} fragment, id=0x{identification:04X}, "
                f"offset={fragment_offset_bytes}, MF={int(more_fragments)}"
            )
            if payload:
                self._add_payload_layer(record, payload, name="Fragment Data")
            return

        # For a valid first fragment, parse the complete transport header when
        # present.  Very small first fragments are legal, so report them as a
        # fragment rather than falsely labelling the capture as truncated.
        minimum = {1: 4, 6: 20, 17: 8}.get(protocol_number, 0)
        if more_fragments and len(payload) < minimum:
            record.protocol = "IPv4-FRAG"
            record.info = (
                f"First {protocol_name} fragment, id=0x{identification:04X}, "
                f"transport header continues in later fragment"
            )
            if payload:
                self._add_payload_layer(record, payload, name="Fragment Data")
            return

        if protocol_number == 1:
            self._parse_icmp(record, payload_offset, ip_end)
        elif protocol_number == 6:
            self._parse_tcp(record, payload_offset, ip_end)
        elif protocol_number == 17:
            self._parse_udp(record, payload_offset, ip_end, first_fragment=more_fragments)
        else:
            record.protocol = protocol_name if protocol_number in _IP_PROTOCOL_NAMES else "IPv4"
            record.info = f"{source} → {destination}, IP protocol {protocol_number}"
            if payload:
                self._add_payload_layer(record, payload)

        if more_fragments:
            fragment_note = f"first fragment id=0x{identification:04X}, MF=1"
            record.info = f"{record.info} ({fragment_note})" if record.info else fragment_note

    def _format_ipv4_options(self, record: PacketRecord, options: bytes) -> str:
        entries: list[str] = []
        cursor = 0
        option_names = {
            0: "EOL",
            1: "NOP",
            7: "Record Route",
            68: "Timestamp",
            131: "Loose Source Route",
            137: "Strict Source Route",
        }
        while cursor < len(options):
            kind = options[cursor]
            if kind == 0:
                entries.append("EOL")
                break
            if kind == 1:
                entries.append("NOP")
                cursor += 1
                continue
            if cursor + 2 > len(options):
                self._add_error(record, "IPv4 Options 被截断：缺少长度字段")
                entries.append(f"kind {kind} (truncated)")
                break
            option_length = options[cursor + 1]
            if option_length < 2:
                self._add_error(record, f"IPv4 Option {kind} 长度无效：{option_length}")
                entries.append(f"kind {kind} (invalid length {option_length})")
                break
            if cursor + option_length > len(options):
                self._add_error(record, f"IPv4 Option {kind} 超出 IPv4 头部")
                entries.append(f"kind {kind} (truncated)")
                break
            value = options[cursor + 2 : cursor + option_length]
            name = option_names.get(kind, f"Option {kind}")
            entries.append(f"{name}[{_hex_bytes(value)}]" if value else name)
            cursor += option_length
        return ", ".join(entries) if entries else _hex_bytes(options)

    def _parse_icmp(self, record: PacketRecord, offset: int, end: int) -> None:
        record.protocol = "ICMP"
        if not self._require(record, offset, 4, "ICMP 头部", end=end):
            return
        data = record.raw
        icmp_type, code, checksum = struct.unpack_from("!BBH", data, offset)
        layer = ProtocolLayer("Internet Control Message Protocol")
        layer.add("Type", f"{icmp_type} ({_ICMP_NAMES.get(icmp_type, 'Unknown')})")
        layer.add("Code", code)
        layer.add("Checksum", f"0x{checksum:04X}")
        record.layers.append(layer)

        header_length = 4
        if icmp_type in {0, 8}:
            if not self._require(record, offset, 8, "ICMP Echo 头部", end=end):
                record.info = f"{_ICMP_NAMES.get(icmp_type, 'ICMP')} (truncated)"
                return
            identifier, sequence = struct.unpack_from("!HH", data, offset + 4)
            layer.add("Identifier", f"0x{identifier:04X} ({identifier})")
            layer.add("Sequence Number", sequence)
            header_length = 8
            record.info = f"{_ICMP_NAMES[icmp_type]} id={identifier} seq={sequence}"
        elif icmp_type in {3, 11, 12} and end - offset >= 8:
            # These error messages include a 32-bit type-specific/rest field.
            rest = struct.unpack_from("!I", data, offset + 4)[0]
            layer.add("Rest of Header", f"0x{rest:08X}")
            header_length = 8
            record.info = f"{_ICMP_NAMES.get(icmp_type, 'ICMP')} (code {code})"
        else:
            record.info = f"{_ICMP_NAMES.get(icmp_type, 'ICMP type ' + str(icmp_type))} (code {code})"

        payload = data[offset + header_length : end]
        if payload:
            self._add_payload_layer(record, payload)

    def _parse_icmpv6(self, record: PacketRecord, offset: int, end: int) -> None:
        record.protocol = "ICMPv6"
        if not self._require(record, offset, 4, "ICMPv6 头部", end=end):
            return
        data = record.raw
        icmp_type, code, checksum = struct.unpack_from("!BBH", data, offset)
        type_name = _ICMPV6_NAMES.get(icmp_type, "Unknown")
        code_name = _ICMPV6_CODE_NAMES.get(icmp_type, {}).get(code)
        layer = ProtocolLayer("Internet Control Message Protocol v6")
        layer.add("Type", f"{icmp_type} ({type_name})")
        layer.add("Code", f"{code} ({code_name})" if code_name else code)
        layer.add("Checksum", f"0x{checksum:04X}")
        record.layers.append(layer)

        if icmp_type in {128, 129}:
            if not self._require(record, offset, 8, "ICMPv6 Echo 头部", end=end):
                record.info = f"{type_name} (truncated)"
                return
            identifier, sequence = struct.unpack_from("!HH", data, offset + 4)
            layer.add("Identifier", f"0x{identifier:04X} ({identifier})")
            layer.add("Sequence Number", sequence)
            record.info = f"{type_name} id={identifier} seq={sequence}"
            if offset + 8 < end:
                self._add_payload_layer(record, data[offset + 8 : end])
            return

        if icmp_type in {1, 2, 3, 4}:
            if not self._require(record, offset, 8, f"ICMPv6 {type_name} 头部", end=end):
                record.info = f"{type_name} (truncated)"
                return
            value = struct.unpack_from("!I", data, offset + 4)[0]
            if icmp_type == 2:
                layer.add("MTU", value)
            elif icmp_type == 4:
                layer.add("Pointer", value)
            else:
                layer.add("Reserved", f"0x{value:08X}")
                if value:
                    self._add_error(record, f"ICMPv6 {type_name} 保留字段不为 0")
            detail = code_name or f"code {code}"
            record.info = f"{type_name}: {detail}"
            if offset + 8 < end:
                self._add_payload_layer(record, data[offset + 8 : end], name="Invoking Packet")
            return

        if icmp_type in {130, 131, 132}:
            self._parse_icmpv6_mld(record, layer, offset, end, icmp_type, type_name)
            return

        if icmp_type == 143:
            self._parse_icmpv6_mldv2_report(record, layer, offset, end)
            return

        if icmp_type == 133:  # Router Solicitation
            if not self._require(record, offset, 8, "ICMPv6 Router Solicitation", end=end):
                record.info = "Router Solicitation (truncated)"
                return
            reserved = struct.unpack_from("!I", data, offset + 4)[0]
            layer.add("Reserved", f"0x{reserved:08X}")
            if reserved:
                self._add_error(record, "ICMPv6 Router Solicitation 保留字段不为 0")
            record.info = "Router Solicitation"
            self._parse_icmpv6_nd_options(record, offset + 8, end)
            return

        if icmp_type == 134:  # Router Advertisement
            if not self._require(record, offset, 16, "ICMPv6 Router Advertisement", end=end):
                record.info = "Router Advertisement (truncated)"
                return
            current_hop_limit, flags, router_lifetime, reachable_time, retrans_timer = (
                struct.unpack_from("!BBHII", data, offset + 4)
            )
            preference = (flags >> 3) & 0x03
            preference_name = {0: "Medium", 1: "High", 3: "Low"}.get(preference, "Reserved")
            layer.add("Current Hop Limit", current_hop_limit)
            layer.add(
                "Flags",
                f"0x{flags:02X} (M={int(bool(flags & 0x80))}, O={int(bool(flags & 0x40))}, "
                f"H={int(bool(flags & 0x20))}, Prf={preference_name}, P={int(bool(flags & 0x04))})",
            )
            layer.add("Router Lifetime", f"{router_lifetime} seconds")
            layer.add("Reachable Time", f"{reachable_time} ms")
            layer.add("Retrans Timer", f"{retrans_timer} ms")
            record.info = f"Router Advertisement lifetime={router_lifetime}s preference={preference_name}"
            self._parse_icmpv6_nd_options(record, offset + 16, end)
            return

        if icmp_type == 135:  # Neighbor Solicitation
            if not self._require(record, offset, 24, "ICMPv6 Neighbor Solicitation", end=end):
                record.info = "Neighbor Solicitation (truncated)"
                return
            reserved = struct.unpack_from("!I", data, offset + 4)[0]
            target = _ipv6_text(data[offset + 8 : offset + 24])
            layer.add("Reserved", f"0x{reserved:08X}")
            layer.add("Target Address", target)
            if reserved:
                self._add_error(record, "ICMPv6 Neighbor Solicitation 保留字段不为 0")
            record.info = f"Neighbor Solicitation for {target}"
            self._parse_icmpv6_nd_options(record, offset + 24, end)
            return

        if icmp_type == 136:  # Neighbor Advertisement
            if not self._require(record, offset, 24, "ICMPv6 Neighbor Advertisement", end=end):
                record.info = "Neighbor Advertisement (truncated)"
                return
            flags_reserved = struct.unpack_from("!I", data, offset + 4)[0]
            target = _ipv6_text(data[offset + 8 : offset + 24])
            reserved = flags_reserved & 0x1FFFFFFF
            layer.add(
                "Flags",
                f"R={int(bool(flags_reserved & 0x80000000))}, "
                f"S={int(bool(flags_reserved & 0x40000000))}, "
                f"O={int(bool(flags_reserved & 0x20000000))}",
            )
            layer.add("Reserved", f"0x{reserved:08X}")
            layer.add("Target Address", target)
            if reserved:
                self._add_error(record, "ICMPv6 Neighbor Advertisement 保留字段不为 0")
            record.info = f"Neighbor Advertisement for {target}"
            self._parse_icmpv6_nd_options(record, offset + 24, end)
            return

        if icmp_type == 137:  # Redirect
            if not self._require(record, offset, 40, "ICMPv6 Redirect", end=end):
                record.info = "Redirect (truncated)"
                return
            reserved = struct.unpack_from("!I", data, offset + 4)[0]
            target = _ipv6_text(data[offset + 8 : offset + 24])
            destination = _ipv6_text(data[offset + 24 : offset + 40])
            layer.add("Reserved", f"0x{reserved:08X}")
            layer.add("Target Address", target)
            layer.add("Destination Address", destination)
            if reserved:
                self._add_error(record, "ICMPv6 Redirect 保留字段不为 0")
            record.info = f"Redirect {destination} via {target}"
            self._parse_icmpv6_nd_options(record, offset + 40, end)
            return

        record.info = f"{type_name if type_name != 'Unknown' else 'ICMPv6 type ' + str(icmp_type)} (code {code})"
        if offset + 4 < end:
            self._add_payload_layer(record, data[offset + 4 : end])

    def _parse_icmpv6_mld(
        self,
        record: PacketRecord,
        layer: ProtocolLayer,
        offset: int,
        end: int,
        icmp_type: int,
        type_name: str,
    ) -> None:
        if not self._require(record, offset, 24, f"ICMPv6 {type_name}", end=end):
            record.info = f"{type_name} (truncated)"
            return
        maximum_response, reserved = struct.unpack_from("!HH", record.raw, offset + 4)
        multicast_address = _ipv6_text(record.raw[offset + 8 : offset + 24])
        layer.add("Maximum Response Code", maximum_response)
        layer.add("Reserved", reserved)
        layer.add("Multicast Address", multicast_address)
        if reserved:
            self._add_error(record, f"ICMPv6 {type_name} 保留字段不为 0")
        record.info = f"{type_name} {multicast_address}"

        # MLDv2 queries append S/QRV, QQIC, source count, and source addresses.
        if icmp_type == 130 and end - offset >= 28:
            flags_qrv, qqic, source_count = struct.unpack_from("!BBH", record.raw, offset + 24)
            layer.add("Suppress Router-Side Processing", int(bool(flags_qrv & 0x08)))
            layer.add("Querier Robustness Variable", flags_qrv & 0x07)
            layer.add("Querier Query Interval Code", qqic)
            layer.add("Source Address Count", source_count)
            available_sources = max((end - offset - 28) // 16, 0)
            if source_count > available_sources:
                self._add_error(
                    record,
                    f"ICMPv6 MLDv2 Query 声明 {source_count} 个源地址，实际仅 {available_sources} 个",
                )
            sources = [
                _ipv6_text(record.raw[offset + 28 + index * 16 : offset + 44 + index * 16])
                for index in range(min(source_count, available_sources))
            ]
            layer.add("Source Addresses", ", ".join(sources) if sources else "None")

    def _parse_icmpv6_mldv2_report(
        self,
        record: PacketRecord,
        layer: ProtocolLayer,
        offset: int,
        end: int,
    ) -> None:
        if not self._require(record, offset, 8, "ICMPv6 MLDv2 Report", end=end):
            record.info = "Multicast Listener Report v2 (truncated)"
            return
        reserved, record_count = struct.unpack_from("!HH", record.raw, offset + 4)
        layer.add("Reserved", reserved)
        layer.add("Multicast Address Record Count", record_count)
        if reserved:
            self._add_error(record, "ICMPv6 MLDv2 Report 保留字段不为 0")
        cursor = offset + 8
        parsed_count = 0
        record_type_names = {
            1: "MODE_IS_INCLUDE",
            2: "MODE_IS_EXCLUDE",
            3: "CHANGE_TO_INCLUDE_MODE",
            4: "CHANGE_TO_EXCLUDE_MODE",
            5: "ALLOW_NEW_SOURCES",
            6: "BLOCK_OLD_SOURCES",
        }
        while parsed_count < record_count:
            if not self._require(record, cursor, 20, "ICMPv6 MLDv2 Multicast Address Record", end=end):
                break
            record_type, auxiliary_units, source_count = struct.unpack_from(
                "!BBH", record.raw, cursor
            )
            multicast_address = _ipv6_text(record.raw[cursor + 4 : cursor + 20])
            total_length = 20 + source_count * 16 + auxiliary_units * 4
            if not self._require(
                record, cursor, total_length, "ICMPv6 MLDv2 Multicast Address Record", end=end
            ):
                break
            item = ProtocolLayer(f"ICMPv6 MLDv2 Record {parsed_count + 1}")
            item.add("Record Type", f"{record_type} ({record_type_names.get(record_type, 'Unknown')})")
            item.add("Auxiliary Data Length", f"{auxiliary_units * 4} bytes")
            item.add("Source Address Count", source_count)
            item.add("Multicast Address", multicast_address)
            sources = [
                _ipv6_text(record.raw[cursor + 20 + index * 16 : cursor + 36 + index * 16])
                for index in range(source_count)
            ]
            item.add("Source Addresses", ", ".join(sources) if sources else "None")
            if auxiliary_units:
                auxiliary_offset = cursor + 20 + source_count * 16
                item.add(
                    "Auxiliary Data",
                    _hex_bytes(record.raw[auxiliary_offset : auxiliary_offset + auxiliary_units * 4]),
                )
            record.layers.append(item)
            cursor += total_length
            parsed_count += 1
        if parsed_count != record_count:
            self._add_error(
                record,
                f"ICMPv6 MLDv2 Report 声明 {record_count} 条记录，实际解析 {parsed_count} 条",
            )
        record.info = f"Multicast Listener Report v2, {record_count} record(s)"

    def _parse_icmpv6_nd_options(self, record: PacketRecord, offset: int, end: int) -> None:
        cursor = offset
        option_names = {
            1: "Source Link-Layer Address",
            2: "Target Link-Layer Address",
            3: "Prefix Information",
            4: "Redirected Header",
            5: "MTU",
            24: "Route Information",
            25: "Recursive DNS Server",
            31: "DNS Search List",
        }
        while cursor < end:
            if not self._require(record, cursor, 2, "ICMPv6 邻居发现选项", end=end):
                return
            option_type, length_units = struct.unpack_from("!BB", record.raw, cursor)
            if length_units == 0:
                self._add_error(record, f"ICMPv6 邻居发现 Option {option_type} 长度为 0")
                return
            option_length = length_units * 8
            if not self._require(
                record, cursor, option_length, f"ICMPv6 邻居发现 Option {option_type}", end=end
            ):
                return

            option_name = option_names.get(option_type, f"Unknown ({option_type})")
            option = ProtocolLayer(f"ICMPv6 Option: {option_name}")
            option.add("Type", option_type)
            option.add("Length", f"{option_length} bytes ({length_units})")
            value = record.raw[cursor + 2 : cursor + option_length]

            if option_type in {1, 2}:
                option.add("Link-Layer Address", _mac_text(value[:6]) if len(value) >= 6 else _hex_bytes(value))
            elif option_type == 3 and option_length == 32:
                prefix_length, flags, valid_lifetime, preferred_lifetime, reserved, prefix_bytes = (
                    struct.unpack_from("!BBIII16s", record.raw, cursor + 2)
                )
                option.add("Prefix Length", prefix_length)
                option.add(
                    "Flags",
                    f"L={int(bool(flags & 0x80))}, A={int(bool(flags & 0x40))}, R={int(bool(flags & 0x20))}",
                )
                option.add("Valid Lifetime", f"{valid_lifetime} seconds")
                option.add("Preferred Lifetime", f"{preferred_lifetime} seconds")
                option.add("Reserved", f"0x{reserved:08X}")
                option.add("Prefix", f"{_ipv6_text(prefix_bytes)}/{prefix_length}")
                if reserved:
                    self._add_error(record, "ICMPv6 Prefix Information 保留字段不为 0")
            elif option_type == 4 and option_length >= 8:
                option.add("Reserved", _hex_bytes(value[:6]))
                option.add("Redirected Packet", f"{max(option_length - 8, 0)} bytes")
            elif option_type == 5 and option_length == 8:
                reserved, mtu = struct.unpack_from("!HI", record.raw, cursor + 2)
                option.add("Reserved", reserved)
                option.add("MTU", mtu)
                if reserved:
                    self._add_error(record, "ICMPv6 MTU Option 保留字段不为 0")
            elif option_type == 24 and option_length in {8, 16, 24}:
                prefix_length, flags, route_lifetime = struct.unpack_from("!BBI", record.raw, cursor + 2)
                preference = (flags >> 3) & 0x03
                option.add("Prefix Length", prefix_length)
                option.add("Route Preference", {0: "Medium", 1: "High", 3: "Low"}.get(preference, "Reserved"))
                option.add("Route Lifetime", f"{route_lifetime} seconds")
                prefix_part = record.raw[cursor + 8 : cursor + option_length]
                prefix = _ipv6_text(prefix_part.ljust(16, b"\x00"))
                option.add("Prefix", f"{prefix}/{prefix_length}")
            elif option_type == 25 and option_length >= 24 and (option_length - 8) % 16 == 0:
                reserved, lifetime = struct.unpack_from("!HI", record.raw, cursor + 2)
                option.add("Reserved", reserved)
                option.add("Lifetime", f"{lifetime} seconds")
                servers = [
                    _ipv6_text(record.raw[position : position + 16])
                    for position in range(cursor + 8, cursor + option_length, 16)
                ]
                option.add("DNS Servers", ", ".join(servers))
                if reserved:
                    self._add_error(record, "ICMPv6 RDNSS Option 保留字段不为 0")
            elif option_type == 31 and option_length >= 16:
                reserved, lifetime = struct.unpack_from("!HI", record.raw, cursor + 2)
                option.add("Reserved", reserved)
                option.add("Lifetime", f"{lifetime} seconds")
                option.add("Domain Names", self._decode_dns_search_list(record.raw[cursor + 8 : cursor + option_length]))
                if reserved:
                    self._add_error(record, "ICMPv6 DNSSL Option 保留字段不为 0")
            else:
                preview = _hex_bytes(value[:32]) + (" …" if len(value) > 32 else "")
                option.add("Data", preview)
            record.layers.append(option)
            cursor += option_length

    @staticmethod
    def _decode_dns_search_list(value: bytes) -> str:
        names: list[str] = []
        labels: list[str] = []
        cursor = 0
        while cursor < len(value):
            length = value[cursor]
            cursor += 1
            if length == 0:
                if labels:
                    names.append(".".join(labels))
                    labels = []
                elif all(part == 0 for part in value[cursor:]):
                    break
                continue
            if length > 63 or cursor + length > len(value):
                return ", ".join(names) + (", " if names else "") + "<malformed>"
            labels.append(value[cursor : cursor + length].decode("ascii", errors="replace"))
            cursor += length
        if labels:
            names.append(".".join(labels))
        return ", ".join(names) if names else "None"

    def _parse_tcp(self, record: PacketRecord, offset: int, end: int) -> None:
        record.protocol = "TCP"
        if not self._require(record, offset, 20, "TCP 固定头部", end=end):
            return
        data = record.raw
        (
            source_port,
            destination_port,
            sequence,
            acknowledgment,
            offset_reserved_ns,
            low_flags,
            window,
            checksum,
            urgent_pointer,
        ) = struct.unpack_from("!HHIIBBHHH", data, offset)

        record.source_port = source_port
        record.destination_port = destination_port
        data_offset_words = offset_reserved_ns >> 4
        tcp_header_length = data_offset_words * 4
        reserved = (offset_reserved_ns >> 1) & 0x07
        flags_value = ((offset_reserved_ns & 0x01) << 8) | low_flags
        flag_pairs = (
            (0x100, "NS"),
            (0x080, "CWR"),
            (0x040, "ECE"),
            (0x020, "URG"),
            (0x010, "ACK"),
            (0x008, "PSH"),
            (0x004, "RST"),
            (0x002, "SYN"),
            (0x001, "FIN"),
        )
        flags = [name for bit, name in flag_pairs if flags_value & bit]
        flag_text = ", ".join(flags) if flags else "None"

        layer = ProtocolLayer("Transmission Control Protocol")
        layer.add("Source Port", source_port)
        layer.add("Destination Port", destination_port)
        layer.add("Sequence Number", sequence)
        layer.add("Acknowledgment Number", acknowledgment)
        layer.add("Header Length", f"{tcp_header_length} bytes ({data_offset_words})")
        layer.add("Reserved", reserved)
        layer.add("Flags", f"0x{flags_value:03X} ({flag_text})")
        layer.add("Window Size", window)
        layer.add("Checksum", f"0x{checksum:04X}")
        layer.add("Urgent Pointer", urgent_pointer)
        record.layers.append(layer)

        if data_offset_words < 5:
            self._add_error(record, f"TCP Data Offset 无效：{data_offset_words}（小于 5）")
            record.info = f"{source_port} → {destination_port} [Malformed TCP]"
            return
        if not self._require(record, offset, tcp_header_length, "TCP 可变头部", end=end):
            record.info = f"{source_port} → {destination_port} [Truncated TCP]"
            return

        if tcp_header_length > 20:
            options = data[offset + 20 : offset + tcp_header_length]
            layer.add("Options", self._format_tcp_options(record, options))

        payload = data[offset + tcp_header_length : end]
        record.transport_payload = payload
        record.tcp_sequence = sequence
        record.tcp_flags = flags_value
        record.info = (
            f"{source_port} → {destination_port} [{flag_text}] "
            f"Seq={sequence} Ack={acknowledgment} Len={len(payload)}"
        )
        self._identify_application(record, "TCP", source_port, destination_port)
        if payload:
            self._decode_application_payload(record, "TCP", source_port, destination_port, payload)
            if destination_port in TLS_PORTS:
                tls_result = parse_client_hello(payload)
                if tls_result.status == "complete":
                    apply_client_hello(record, tls_result)
                elif tls_result.status == "incomplete":
                    tls_layer = next((item for item in record.layers if item.name == "TLS"), None)
                    if tls_layer is not None:
                        tls_layer.add("ClientHello Parsing", "等待后续 TCP 分段重组")
                elif tls_result.status == "malformed" and tls_result.error:
                    self._add_error(record, f"TLS ClientHello 解析失败：{tls_result.error}")
            self._add_payload_layer(record, payload)

    def _format_tcp_options(self, record: PacketRecord, options: bytes) -> str:
        entries: list[str] = []
        cursor = 0
        while cursor < len(options):
            kind = options[cursor]
            if kind == 0:
                entries.append("EOL")
                break
            if kind == 1:
                entries.append("NOP")
                cursor += 1
                continue
            if cursor + 2 > len(options):
                self._add_error(record, "TCP Options 被截断：缺少长度字段")
                entries.append(f"kind {kind} (truncated)")
                break
            option_length = options[cursor + 1]
            if option_length < 2:
                self._add_error(record, f"TCP Option {kind} 长度无效：{option_length}")
                entries.append(f"kind {kind} (invalid length {option_length})")
                break
            if cursor + option_length > len(options):
                self._add_error(record, f"TCP Option {kind} 超出 TCP 头部")
                entries.append(f"kind {kind} (truncated)")
                break
            value = options[cursor + 2 : cursor + option_length]
            if kind == 2 and option_length == 4:
                entries.append(f"MSS {struct.unpack('!H', value)[0]}")
            elif kind == 3 and option_length == 3:
                entries.append(f"Window Scale {value[0]}")
            elif kind == 4 and option_length == 2:
                entries.append("SACK Permitted")
            elif kind == 5 and option_length >= 10 and (option_length - 2) % 8 == 0:
                blocks = []
                for block_offset in range(0, len(value), 8):
                    left, right = struct.unpack_from("!II", value, block_offset)
                    blocks.append(f"{left}-{right}")
                entries.append(f"SACK {'; '.join(blocks)}")
            elif kind == 8 and option_length == 10:
                timestamp_value, timestamp_echo = struct.unpack("!II", value)
                entries.append(f"Timestamps val={timestamp_value} ecr={timestamp_echo}")
            else:
                entries.append(f"Option {kind}[{_hex_bytes(value)}]")
            cursor += option_length
        return ", ".join(entries) if entries else _hex_bytes(options)

    def _parse_udp(
        self,
        record: PacketRecord,
        offset: int,
        end: int,
        *,
        first_fragment: bool,
        allow_zero_length: bool = False,
    ) -> None:
        record.protocol = "UDP"
        if not self._require(record, offset, 8, "UDP 头部", end=end):
            return
        data = record.raw
        source_port, destination_port, udp_length, checksum = struct.unpack_from("!HHHH", data, offset)
        record.source_port = source_port
        record.destination_port = destination_port

        layer = ProtocolLayer("User Datagram Protocol")
        layer.add("Source Port", source_port)
        layer.add("Destination Port", destination_port)
        layer.add("Length", "0 (IPv6 jumbogram)" if udp_length == 0 and allow_zero_length else udp_length)
        layer.add("Checksum", f"0x{checksum:04X}")
        record.layers.append(layer)

        available = end - offset
        if udp_length == 0 and allow_zero_length:
            payload_end = end
        elif udp_length < 8:
            self._add_error(record, f"UDP 长度无效：{udp_length}（小于 8）")
            payload_end = end
        elif udp_length > available:
            if not first_fragment:
                self._add_error(
                    record,
                    f"UDP 数据报被截断：长度声明 {udp_length} 字节，实际仅 {available} 字节",
                )
            payload_end = end
        else:
            payload_end = offset + udp_length

        payload = data[offset + 8 : payload_end]
        displayed_length = available if udp_length == 0 and allow_zero_length else udp_length
        record.info = f"{source_port} → {destination_port} Len={displayed_length}"
        self._identify_application(record, "UDP", source_port, destination_port)
        if payload:
            self._decode_application_payload(record, "UDP", source_port, destination_port, payload)
            self._add_payload_layer(record, payload)

    @staticmethod
    def _decode_application_payload(record: PacketRecord, transport: str, source_port: int, destination_port: int, payload: bytes) -> None:
        layer = decode_application(transport, source_port, destination_port, payload)
        if layer is None:
            return
        record.layers = [candidate for candidate in record.layers if candidate.name not in {"DNS", "HTTP", "TLS", "DHCP", "QUIC"}]
        record.layers.append(layer)

    @staticmethod
    def _identify_application(
        record: PacketRecord,
        transport: str,
        source_port: int,
        destination_port: int,
    ) -> None:
        """Add a transparent port-based label without pretending to decode payload."""

        table = _TCP_APPLICATION_PORTS if transport == "TCP" else _UDP_APPLICATION_PORTS
        application = table.get(destination_port) or table.get(source_port)
        if application is None:
            return
        layer = ProtocolLayer(application)
        layer.add("Identification", "Port-based identification only")
        layer.add("Transport", transport)
        layer.add("Ports", f"{source_port} → {destination_port}")
        record.layers.append(layer)
        record.protocol = application
        record.info = f"{application} | {record.info}"

    @staticmethod
    def _add_payload_layer(record: PacketRecord, payload: bytes, name: str = "Data") -> None:
        layer = ProtocolLayer(name)
        layer.add("Length", f"{len(payload)} bytes")
        layer.add("Printable Preview", format_payload_summary(payload))
        record.layers.append(layer)


__all__ = ["PacketParser"]
