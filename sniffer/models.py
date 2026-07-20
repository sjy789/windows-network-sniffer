"""跨模块共享的数据模型。

核心解析器只接收原始字节，不依赖 Scapy 的协议字段。Scapy 对象仅保存在
``PacketRecord.original_packet`` 中，供 PCAP 写出使用。
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, TypeAlias


# (source IPv4, destination IPv4, IP protocol number, Identification)
FragmentKey: TypeAlias = tuple[str, str, int, int]


@dataclass(slots=True)
class ProtocolLayer:
    """一个协议层及其适合 GUI 展示的字段。"""

    name: str
    fields: list[tuple[str, str]] = field(default_factory=list)

    def add(self, name: str, value: object) -> None:
        self.fields.append((name, str(value)))


@dataclass(slots=True)
class IPv4Fragment:
    """从 IPv4 包中提取的重组输入。"""

    key: FragmentKey
    identification: int
    offset_bytes: int
    more_fragments: bool
    payload: bytes
    ip_header: bytes
    link_header: bytes
    timestamp: float


@dataclass(slots=True)
class PacketRecord:
    """一个捕获帧或重组后虚拟包的展示模型。"""

    timestamp: float
    raw: bytes
    length: int
    source: str = ""
    destination: str = ""
    protocol: str = "UNKNOWN"
    source_port: int | None = None
    destination_port: int | None = None
    info: str = ""
    layers: list[ProtocolLayer] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    fragment: IPv4Fragment | None = None
    is_reassembled: bool = False
    reassembly_note: str = ""
    link_type: str = "ethernet"
    original_packet: Any = field(default=None, repr=False, compare=False)
    sequence: int = 0
    transport_payload: bytes = field(default=b"", repr=False, compare=False)
    tcp_sequence: int | None = field(default=None, repr=False, compare=False)
    tcp_flags: int = field(default=0, repr=False, compare=False)

    @property
    def timestamp_text(self) -> str:
        return datetime.fromtimestamp(self.timestamp).strftime("%H:%M:%S.%f")[:-3]

    @property
    def is_fragment(self) -> bool:
        return self.fragment is not None


@dataclass(slots=True, frozen=True)
class InterfaceInfo:
    """Npcap 可捕获接口。"""

    name: str
    description: str
    pcap_name: str
    addresses: tuple[str, ...] = ()
    is_loopback: bool = False
    is_virtual: bool = False

    @property
    def display_name(self) -> str:
        description = self.description.strip()
        label = self.name if not description or description == self.name else f"{self.name} — {description}"
        if self.addresses:
            label += f"  ({', '.join(self.addresses)})"
        return label


@dataclass(slots=True)
class ReassemblyResult:
    """IPv4 重组器返回的结果。"""

    key: FragmentKey
    complete: bool = False
    ip_packet: bytes | None = None
    link_header: bytes = b""
    fragment_count: int = 0
    status: str = "cached"
    error: str | None = None


@dataclass(slots=True)
class CaptureStats:
    captured: int = 0
    queued: int = 0
    dropped: int = 0
    parse_errors: int = 0
    reassembled: int = 0
