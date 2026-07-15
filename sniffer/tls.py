"""Bounded TLS ClientHello decoding and TCP stream assembly.

Only clear-text ClientHello metadata is decoded.  The implementation does not
decrypt TLS traffic and deliberately keeps a small, expiring per-flow buffer.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import time

from .models import PacketRecord, ProtocolLayer


TLS_PORTS = frozenset({443, 8443})
_MAX_TLS_RECORD = 2**14 + 2048


@dataclass(slots=True, frozen=True)
class TLSClientHello:
    server_name: str | None
    alpn_protocols: tuple[str, ...]
    legacy_version: str


@dataclass(slots=True, frozen=True)
class TLSParseResult:
    status: str
    hello: TLSClientHello | None = None
    error: str | None = None


class _NeedMoreData(Exception):
    pass


class _MalformedHello(ValueError):
    pass


def parse_client_hello(data: bytes) -> TLSParseResult:
    """Decode a ClientHello from one or more complete TLS handshake records.

    ``status`` is one of ``not_tls``, ``incomplete``, ``complete`` or
    ``malformed``.  Incomplete TCP/TLS fragments are not reported as malformed.
    """

    if not data:
        return TLSParseResult("not_tls")
    if data[0] != 22:
        return TLSParseResult("not_tls")

    handshake = bytearray()
    cursor = 0
    expected_handshake_size: int | None = None
    try:
        while cursor < len(data):
            if len(data) - cursor < 5:
                raise _NeedMoreData
            content_type = data[cursor]
            major = data[cursor + 1]
            record_length = int.from_bytes(data[cursor + 3 : cursor + 5], "big")
            if major != 3:
                raise _MalformedHello("TLS record version is invalid")
            if record_length > _MAX_TLS_RECORD:
                raise _MalformedHello("TLS record length exceeds the supported limit")
            record_end = cursor + 5 + record_length
            if record_end > len(data):
                raise _NeedMoreData
            if content_type != 22:
                if not handshake:
                    return TLSParseResult("not_tls")
                raise _MalformedHello("ClientHello is interrupted by a non-handshake TLS record")
            handshake.extend(data[cursor + 5 : record_end])
            cursor = record_end

            if expected_handshake_size is None and len(handshake) >= 4:
                if handshake[0] != 1:
                    return TLSParseResult("not_tls")
                expected_handshake_size = 4 + int.from_bytes(handshake[1:4], "big")
            if expected_handshake_size is not None and len(handshake) >= expected_handshake_size:
                body = bytes(handshake[4:expected_handshake_size])
                return TLSParseResult("complete", hello=_decode_client_hello_body(body))
    except _NeedMoreData:
        return TLSParseResult("incomplete")
    except _MalformedHello as exc:
        return TLSParseResult("malformed", error=str(exc))

    return TLSParseResult("incomplete")


def _decode_client_hello_body(body: bytes) -> TLSClientHello:
    if len(body) < 35:
        raise _MalformedHello("TLS ClientHello fixed fields are truncated")
    legacy_version = f"{body[0]}.{body[1]}"
    cursor = 34  # legacy_version (2) + random (32)

    session_id_length = body[cursor]
    cursor += 1
    cursor = _skip(body, cursor, session_id_length, "session id")

    cipher_suites_length, cursor = _read_u16(body, cursor, "cipher suites length")
    if cipher_suites_length < 2 or cipher_suites_length % 2:
        raise _MalformedHello("TLS ClientHello cipher suites length is invalid")
    cursor = _skip(body, cursor, cipher_suites_length, "cipher suites")

    compression_length, cursor = _read_u8(body, cursor, "compression methods length")
    if compression_length < 1:
        raise _MalformedHello("TLS ClientHello has no compression method")
    cursor = _skip(body, cursor, compression_length, "compression methods")

    # TLS 1.2 permits the extensions vector to be absent.  SNI and ALPN are
    # optional, so represent this explicitly instead of leaving blank fields.
    if cursor == len(body):
        return TLSClientHello(None, (), legacy_version)

    extensions_length, cursor = _read_u16(body, cursor, "extensions length")
    extensions_end = cursor + extensions_length
    if extensions_end != len(body):
        raise _MalformedHello("TLS ClientHello extensions length does not match the handshake")

    server_name: str | None = None
    alpn_protocols: tuple[str, ...] = ()
    seen_extensions: set[int] = set()
    while cursor < extensions_end:
        extension_type, cursor = _read_u16(body, cursor, "extension type")
        extension_length, cursor = _read_u16(body, cursor, "extension length")
        extension_end = cursor + extension_length
        if extension_end > extensions_end:
            raise _MalformedHello("TLS extension exceeds the ClientHello extensions vector")
        if extension_type in seen_extensions:
            raise _MalformedHello(f"TLS ClientHello repeats extension {extension_type}")
        seen_extensions.add(extension_type)
        value = body[cursor:extension_end]
        if extension_type == 0:
            server_name = _decode_server_name(value)
        elif extension_type == 16:
            alpn_protocols = _decode_alpn(value)
        cursor = extension_end

    return TLSClientHello(server_name, alpn_protocols, legacy_version)


def _decode_server_name(value: bytes) -> str | None:
    list_length, cursor = _read_u16(value, 0, "SNI list length")
    if list_length != len(value) - 2:
        raise _MalformedHello("TLS SNI list length is invalid")
    server_name: str | None = None
    while cursor < len(value):
        name_type, cursor = _read_u8(value, cursor, "SNI name type")
        name_length, cursor = _read_u16(value, cursor, "SNI name length")
        name_end = cursor + name_length
        if name_end > len(value):
            raise _MalformedHello("TLS SNI name is truncated")
        if name_type == 0:
            if server_name is not None:
                raise _MalformedHello("TLS SNI contains more than one host_name")
            raw_name = value[cursor:name_end]
            if not raw_name or b"\x00" in raw_name:
                raise _MalformedHello("TLS SNI host_name is empty or contains NUL")
            try:
                server_name = raw_name.decode("ascii")
            except UnicodeDecodeError as exc:
                raise _MalformedHello("TLS SNI host_name is not ASCII") from exc
        cursor = name_end
    return server_name


def _decode_alpn(value: bytes) -> tuple[str, ...]:
    list_length, cursor = _read_u16(value, 0, "ALPN list length")
    if list_length != len(value) - 2 or list_length == 0:
        raise _MalformedHello("TLS ALPN protocol list length is invalid")
    protocols: list[str] = []
    while cursor < len(value):
        protocol_length, cursor = _read_u8(value, cursor, "ALPN protocol length")
        if protocol_length == 0:
            raise _MalformedHello("TLS ALPN contains an empty protocol name")
        protocol_end = cursor + protocol_length
        if protocol_end > len(value):
            raise _MalformedHello("TLS ALPN protocol name is truncated")
        protocols.append(value[cursor:protocol_end].decode("ascii", errors="backslashreplace"))
        cursor = protocol_end
    return tuple(protocols)


def apply_client_hello(record: PacketRecord, result: TLSParseResult, *, reassembled: bool = False) -> bool:
    """Attach a decoded ClientHello to a packet record, returning success."""

    if result.status != "complete" or result.hello is None:
        return False
    hello = result.hello
    # A single-segment parse may already have attached this layer.
    record.layers = [layer for layer in record.layers if layer.name != "TLS ClientHello"]
    layer = ProtocolLayer("TLS ClientHello")
    layer.add("Handshake Type", "ClientHello (1)")
    layer.add("Legacy Version", hello.legacy_version)
    layer.add("Server Name (SNI)", hello.server_name or "未提供（可能使用 IP、会话恢复或 ECH）")
    layer.add("ALPN Protocols", ", ".join(hello.alpn_protocols) or "未提供")
    layer.add("TCP Reassembly", "是" if reassembled else "否（单个 TCP 段完整）")
    record.layers.append(layer)
    record.protocol = "TLS"
    details = []
    if hello.server_name:
        details.append(f"SNI={hello.server_name}")
    if hello.alpn_protocols:
        details.append(f"ALPN={','.join(hello.alpn_protocols)}")
    prefix = "TLS ClientHello"
    record.info = f"{prefix} | {' '.join(details)}" if details else prefix
    return True


@dataclass(slots=True)
class _TCPFlow:
    anchor_sequence: int
    segments: dict[int, bytes] = field(default_factory=dict)
    updated_at: float = 0.0


class TLSStreamReassembler:
    """Reassemble bounded, in-order client-to-server TLS handshake bytes."""

    def __init__(self, *, timeout: float = 15.0, max_flows: int = 256, max_bytes_per_flow: int = 256 * 1024) -> None:
        self.timeout = float(timeout)
        self.max_flows = int(max_flows)
        self.max_bytes_per_flow = int(max_bytes_per_flow)
        self._flows: dict[tuple[str, int, str, int], _TCPFlow] = {}

    def clear(self) -> None:
        self._flows.clear()

    def process(self, record: PacketRecord) -> TLSParseResult:
        self.expire(record.timestamp)
        if (
            record.tcp_sequence is None
            or record.destination_port not in TLS_PORTS
            or record.source_port is None
            or not record.transport_payload
        ):
            return TLSParseResult("not_tls")

        payload = record.transport_payload
        sequence = record.tcp_sequence
        key = (record.source, record.source_port, record.destination, record.destination_port)
        flow = self._flows.get(key)
        if flow is None:
            self._make_room()
            flow = _TCPFlow(anchor_sequence=sequence, updated_at=record.timestamp)
            self._flows[key] = flow

        self._insert(flow, sequence, payload)
        flow.updated_at = record.timestamp
        if sum(len(segment) for segment in flow.segments.values()) > self.max_bytes_per_flow:
            self._flows.pop(key, None)
            return TLSParseResult("malformed", error="TLS ClientHello exceeds reassembly buffer limit")

        assembled = self._contiguous_data(flow)
        if not assembled or assembled[0] != 22:
            # The first observed TCP segment may arrive out of order.  Keep it
            # briefly so an earlier segment containing the record header can
            # establish the stream start.
            return TLSParseResult("incomplete")
        result = parse_client_hello(assembled)
        if result.status in {"complete", "malformed", "not_tls"}:
            self._flows.pop(key, None)
        if result.status == "complete":
            apply_client_hello(record, result, reassembled=len(flow.segments) > 1)
        return result

    def expire(self, now: float | None = None) -> None:
        current = time.time() if now is None else float(now)
        for key, flow in list(self._flows.items()):
            if current - flow.updated_at >= self.timeout:
                self._flows.pop(key, None)

    def _insert(self, flow: _TCPFlow, sequence: int, payload: bytes) -> None:
        offset = (sequence - flow.anchor_sequence) & 0xFFFFFFFF
        if offset >= 0x80000000:
            offset -= 0x100000000
        existing = flow.segments.get(offset)
        if existing is None or len(payload) > len(existing):
            flow.segments[offset] = payload

    @staticmethod
    def _contiguous_data(flow: _TCPFlow) -> bytes:
        if not flow.segments:
            return b""
        ordered = sorted(flow.segments.items())
        start, first = ordered[0]
        data = bytearray(first)
        end = start + len(first)
        for sequence, payload in ordered[1:]:
            if sequence > end:
                break
            overlap = max(0, end - sequence)
            if overlap < len(payload):
                data.extend(payload[overlap:])
                end += len(payload) - overlap
        return bytes(data)

    def _make_room(self) -> None:
        while len(self._flows) >= self.max_flows:
            oldest = min(self._flows, key=lambda key: self._flows[key].updated_at)
            self._flows.pop(oldest, None)


def _skip(data: bytes, cursor: int, length: int, label: str) -> int:
    end = cursor + length
    if end > len(data):
        raise _MalformedHello(f"TLS ClientHello {label} is truncated")
    return end


def _read_u8(data: bytes, cursor: int, label: str) -> tuple[int, int]:
    if cursor >= len(data):
        raise _MalformedHello(f"TLS ClientHello {label} is truncated")
    return data[cursor], cursor + 1


def _read_u16(data: bytes, cursor: int, label: str) -> tuple[int, int]:
    if cursor + 2 > len(data):
        raise _MalformedHello(f"TLS ClientHello {label} is truncated")
    return int.from_bytes(data[cursor : cursor + 2], "big"), cursor + 2


__all__ = [
    "TLS_PORTS",
    "TLSClientHello",
    "TLSParseResult",
    "TLSStreamReassembler",
    "apply_client_hello",
    "parse_client_hello",
]
