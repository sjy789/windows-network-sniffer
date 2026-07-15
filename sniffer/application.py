"""Defensive, bounded decoders for common clear-text application metadata."""

from __future__ import annotations

import struct

from .models import ProtocolLayer
from .tls import parse_client_hello


def decode_application(transport: str, source_port: int, destination_port: int, payload: bytes) -> ProtocolLayer | None:
    ports = {source_port, destination_port}
    try:
        if 53 in ports:
            return _dns(payload[2:] if transport == "TCP" and len(payload) >= 2 else payload)
        if transport == "TCP" and ports & {80, 8080}:
            return _http(payload)
        if transport == "TCP" and ports & {443, 8443}:
            return _tls(payload)
        if transport == "UDP" and ports & {67, 68}:
            return _dhcp(payload)
    except (IndexError, UnicodeError, ValueError, struct.error):
        return None
    return None


def _dns(data: bytes) -> ProtocolLayer | None:
    if len(data) < 12:
        return None
    transaction, flags, questions, answers, authority, additional = struct.unpack_from("!HHHHHH", data)
    layer = ProtocolLayer("Domain Name System")
    layer.add("Transaction ID", f"0x{transaction:04X}")
    layer.add("Message", "Response" if flags & 0x8000 else "Query")
    layer.add("Opcode", (flags >> 11) & 0xF)
    layer.add("Response Code", flags & 0xF)
    layer.add("Questions", questions)
    layer.add("Answers", answers)
    layer.add("Authority RRs", authority)
    layer.add("Additional RRs", additional)
    if questions:
        name, cursor = _dns_name(data, 12)
        if cursor + 4 <= len(data):
            query_type, query_class = struct.unpack_from("!HH", data, cursor)
            layer.add("Query Name", name)
            layer.add("Query Type", _DNS_TYPES.get(query_type, query_type))
            layer.add("Query Class", query_class)
    return layer


def _dns_name(data: bytes, cursor: int) -> tuple[str, int]:
    labels: list[str] = []
    consumed = cursor
    jumped = False
    visited: set[int] = set()
    while cursor < len(data) and len(labels) < 64:
        length = data[cursor]
        if length == 0:
            cursor += 1
            return ".".join(labels) or ".", consumed if jumped else cursor
        if length & 0xC0 == 0xC0:
            if cursor + 1 >= len(data):
                raise ValueError("truncated DNS pointer")
            pointer = ((length & 0x3F) << 8) | data[cursor + 1]
            if pointer in visited or pointer >= len(data):
                raise ValueError("invalid DNS pointer")
            visited.add(pointer)
            if not jumped:
                consumed = cursor + 2
            cursor = pointer
            jumped = True
            continue
        if length > 63 or cursor + 1 + length > len(data):
            raise ValueError("invalid DNS label")
        labels.append(data[cursor + 1 : cursor + 1 + length].decode("idna"))
        cursor += 1 + length
    raise ValueError("unterminated DNS name")


def _http(data: bytes) -> ProtocolLayer | None:
    if not data:
        return None
    head = data[:16_384].split(b"\r\n\r\n", 1)[0]
    lines = head.split(b"\r\n")
    first = lines[0].decode("iso-8859-1", errors="replace")
    if not (first.startswith("HTTP/") or first.split(" ", 1)[0] in {"GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH", "CONNECT", "TRACE"}):
        return None
    layer = ProtocolLayer("Hypertext Transfer Protocol")
    layer.add("Start Line", first)
    headers: dict[str, str] = {}
    for raw in lines[1:101]:
        if b":" not in raw:
            continue
        name, value = raw.split(b":", 1)
        headers[name.decode("ascii", errors="ignore").casefold()] = value.strip().decode("iso-8859-1", errors="replace")
    for key, label in (("host", "Host"), ("user-agent", "User Agent"), ("content-type", "Content Type"), ("content-length", "Content Length"), ("server", "Server")):
        if key in headers:
            layer.add(label, headers[key][:512])
    return layer


def _tls(data: bytes) -> ProtocolLayer | None:
    if len(data) < 5 or data[0] not in {20, 21, 22, 23}:
        return None
    content_type, major, minor, length = struct.unpack_from("!BBBH", data)
    if major != 3 or 5 + length > len(data):
        return None
    layer = ProtocolLayer("Transport Layer Security")
    layer.add("Record Type", {20: "Change Cipher Spec", 21: "Alert", 22: "Handshake", 23: "Application Data"}.get(content_type, content_type))
    layer.add("Legacy Version", f"TLS {major}.{minor}")
    layer.add("Record Length", length)
    if content_type == 22 and length >= 4:
        handshake = data[5]
        layer.add("Handshake Type", {1: "Client Hello", 2: "Server Hello", 11: "Certificate"}.get(handshake, handshake))
        if handshake == 1:
            parsed = parse_client_hello(data)
            if parsed.status == "complete" and parsed.hello is not None:
                layer.add("Server Name (SNI)", parsed.hello.server_name or "未提供")
                layer.add("ALPN", ", ".join(parsed.hello.alpn_protocols) or "未提供")
    return layer


def _client_hello_extensions(body: bytes) -> tuple[str, list[str]]:
    if len(body) < 35:
        return "", []
    cursor = 34 + body[34]
    if cursor + 2 > len(body):
        return "", []
    cipher_length = int.from_bytes(body[cursor : cursor + 2], "big")
    cursor += 2 + cipher_length
    if cursor >= len(body):
        return "", []
    cursor += 1 + body[cursor]
    if cursor + 2 > len(body):
        return "", []
    end = min(len(body), cursor + 2 + int.from_bytes(body[cursor : cursor + 2], "big"))
    cursor += 2
    sni = ""
    alpn: list[str] = []
    while cursor + 4 <= end:
        kind, size = struct.unpack_from("!HH", body, cursor)
        value = body[cursor + 4 : cursor + 4 + size]
        cursor += 4 + size
        if kind == 0 and len(value) >= 5:
            name_size = int.from_bytes(value[3:5], "big")
            sni = value[5 : 5 + name_size].decode("idna", errors="replace")
        elif kind == 16 and len(value) >= 3:
            pos = 2
            while pos < len(value):
                item_size = value[pos]
                pos += 1
                alpn.append(value[pos : pos + item_size].decode("ascii", errors="replace"))
                pos += item_size
    return sni, alpn


def _dhcp(data: bytes) -> ProtocolLayer | None:
    if len(data) < 240 or data[236:240] != b"\x63\x82\x53\x63":
        return None
    operation, hardware_type, hardware_length, _hops, transaction = struct.unpack_from("!BBBBI", data)
    layer = ProtocolLayer("Dynamic Host Configuration Protocol")
    layer.add("Operation", "Boot Reply" if operation == 2 else "Boot Request")
    layer.add("Transaction ID", f"0x{transaction:08X}")
    if hardware_type == 1 and hardware_length:
        layer.add("Client MAC", ":".join(f"{byte:02X}" for byte in data[28 : 28 + min(hardware_length, 16)]))
    cursor = 240
    while cursor < len(data):
        kind = data[cursor]
        cursor += 1
        if kind == 255:
            break
        if kind == 0:
            continue
        if cursor >= len(data):
            break
        size = data[cursor]
        value = data[cursor + 1 : cursor + 1 + size]
        cursor += 1 + size
        if kind == 53 and value:
            layer.add("Message Type", _DHCP_TYPES.get(value[0], value[0]))
        elif kind == 50 and len(value) == 4:
            layer.add("Requested IP", ".".join(map(str, value)))
        elif kind == 51 and len(value) == 4:
            layer.add("Lease Time", f"{int.from_bytes(value, 'big')} seconds")
        elif kind == 12:
            layer.add("Host Name", value.decode("utf-8", errors="replace"))
    return layer


_DNS_TYPES = {1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR", 15: "MX", 16: "TXT", 28: "AAAA", 33: "SRV", 65: "HTTPS"}
_DHCP_TYPES = {1: "Discover", 2: "Offer", 3: "Request", 4: "Decline", 5: "ACK", 6: "NAK", 7: "Release", 8: "Inform"}


__all__ = ["decode_application"]
