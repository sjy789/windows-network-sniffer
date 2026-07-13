"""Defensive, byte-oriented parsers for the protocols used by the project.

Scapy is intentionally absent from this module.  It is useful for capturing
and saving packets, but protocol fields below are decoded directly from the
wire bytes with :mod:`struct` so the course project demonstrates the actual
packet formats.
"""

from __future__ import annotations

import socket
import struct
import time
from typing import Any

from .formatting import format_payload_summary
from .application import decode_application
from .models import IPv4Fragment, PacketRecord, ProtocolLayer


_VLAN_ETHERTYPES = {0x8100, 0x88A8, 0x9100}
_ETHERTYPE_NAMES = {
    0x0800: "IPv4",
    0x0806: "ARP",
    0x86DD: "IPv6",
    0x8100: "802.1Q VLAN",
    0x88A8: "802.1ad VLAN",
}
_IP_PROTOCOL_NAMES = {
    1: "ICMP",
    2: "IGMP",
    6: "TCP",
    17: "UDP",
    41: "IPv6",
    47: "GRE",
    50: "ESP",
    51: "AH",
    89: "OSPF",
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
        known_ipv4 = {2}  # AF_INET. Windows AF_INET6 is 23 and is out of scope.
        family = family_le if family_le in known_ipv4 else family_be
        layer = ProtocolLayer("Loopback")
        layer.add("Address Family", family)
        record.layers.append(layer)
        if family in known_ipv4:
            self._parse_ipv4(record, 4, record.raw[:4])
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
        record.info = (
            f"{source_port} → {destination_port} [{flag_text}] "
            f"Seq={sequence} Ack={acknowledgment} Len={len(payload)}"
        )
        self._identify_application(record, "TCP", source_port, destination_port)
        if payload:
            self._decode_application_payload(record, "TCP", source_port, destination_port, payload)
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
        layer.add("Length", udp_length)
        layer.add("Checksum", f"0x{checksum:04X}")
        record.layers.append(layer)

        available = end - offset
        if udp_length < 8:
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
        record.info = f"{source_port} → {destination_port} Len={udp_length}"
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
