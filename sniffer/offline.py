"""Offline PCAP/PCAPNG loading through the normal parser pipeline."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from scapy.all import Ether, IP
try:
    from scapy.utils import PcapReader
except ImportError:  # pragma: no cover - depends on Scapy build
    PcapReader = None  # type: ignore[assignment]
try:
    from scapy.utils import PcapNgReader
except ImportError:  # pragma: no cover - depends on Scapy build
    PcapNgReader = None  # type: ignore[assignment]

from .models import CaptureStats, PacketRecord, ReassemblyResult
from .parser import PacketParser
from .reassembly import IPv4Reassembler


class OfflineCaptureError(RuntimeError):
    """A user-facing failure while loading a capture file."""


@dataclass(slots=True)
class OfflineLoadResult:
    """Records and counters produced by an offline capture import."""

    records: list[PacketRecord] = field(default_factory=list)
    stats: CaptureStats = field(default_factory=CaptureStats)
    expired_fragments: int = 0


def load_capture_file(
    path: str | Path,
    *,
    parser: PacketParser | None = None,
    reassembler: IPv4Reassembler | None = None,
    max_packets: int | None = None,
) -> OfflineLoadResult:
    """Read a PCAP/PCAPNG file and return parsed packet records.

    The loader deliberately reuses the live-capture parser and IPv4
    reassembler.  Reassembled datagrams are emitted as virtual records with no
    ``original_packet`` so later PCAP export still writes only real frames.
    """

    target = Path(path)
    if not target.exists():
        raise OfflineCaptureError(f"文件不存在：{target}")
    if target.is_dir():
        raise OfflineCaptureError(f"路径是文件夹而不是抓包文件：{target}")
    if max_packets is not None and max_packets <= 0:
        raise ValueError("max_packets must be greater than zero")

    parser = parser or PacketParser()
    reassembler = reassembler or IPv4Reassembler()
    result = OfflineLoadResult()

    try:
        with _open_reader(target) as reader:
            for index, packet in enumerate(reader, start=1):
                if max_packets is not None and index > max_packets:
                    break
                _handle_packet(packet, parser, reassembler, result)
    except OfflineCaptureError:
        raise
    except Exception as exc:  # noqa: BLE001 - convert parser/reader failures for GUI
        raise OfflineCaptureError(f"读取抓包文件失败：{exc}") from exc

    try:
        expired = reassembler.expire(now=float("inf"))
    except Exception:
        expired = []
    result.expired_fragments += len(expired)
    result.stats.queued = len(result.records)
    return result


def _open_reader(path: Path):  # noqa: ANN202 - Scapy reader types are version-specific
    suffix = path.suffix.casefold()
    try:
        if suffix == ".pcapng":
            if PcapNgReader is None:
                raise OfflineCaptureError("当前 Scapy 版本不支持 PCAPNG 读取")
            return PcapNgReader(str(path))
        if PcapReader is None:
            raise OfflineCaptureError("当前 Scapy 版本不支持 PCAP 读取")
        return PcapReader(str(path))
    except Exception as exc:
        raise OfflineCaptureError(f"无法打开抓包文件：{exc}") from exc


def _handle_packet(
    packet: Any,
    parser: PacketParser,
    reassembler: IPv4Reassembler,
    result: OfflineLoadResult,
) -> None:
    result.stats.captured += 1
    timestamp = _timestamp(packet)
    try:
        raw, link_type, unsupported_error = _packet_data(packet)
        if unsupported_error is not None:
            record = PacketRecord(
                timestamp=timestamp,
                raw=raw,
                length=len(raw),
                protocol="UNKNOWN",
                info=unsupported_error,
                errors=[unsupported_error],
                link_type=link_type,
                original_packet=packet,
            )
        else:
            record = parser.parse(
                raw,
                timestamp=timestamp,
                original_packet=packet,
                link_type=link_type,
            )
            record.original_packet = packet
            record.link_type = link_type
    except Exception as exc:  # noqa: BLE001
        raw = _safe_bytes(packet)
        record = PacketRecord(
            timestamp=timestamp,
            raw=raw,
            length=len(raw),
            protocol="MALFORMED",
            info=f"离线数据包解析失败：{exc}",
            errors=[f"离线数据包解析失败：{exc}"],
            link_type="unknown",
            original_packet=packet,
        )

    if record.errors:
        result.stats.parse_errors += 1
    result.records.append(record)
    _handle_fragment(record, parser, reassembler, result)


def _handle_fragment(
    record: PacketRecord,
    parser: PacketParser,
    reassembler: IPv4Reassembler,
    result: OfflineLoadResult,
) -> None:
    fragment = record.fragment
    if fragment is None:
        return

    try:
        reassembly: ReassemblyResult = reassembler.add(fragment)
    except Exception as exc:  # noqa: BLE001
        error = f"IPv4 分片重组失败：{exc}"
        record.errors.append(error)
        record.reassembly_note = error
        result.stats.parse_errors += 1
        return

    note = _reassembly_note(reassembly)
    if note:
        record.reassembly_note = note
    if reassembly.error:
        record.errors.append(reassembly.error)
        result.stats.parse_errors += 1
    if not reassembly.complete or reassembly.ip_packet is None:
        return

    link_header = reassembly.link_header or fragment.link_header
    virtual_raw = link_header + reassembly.ip_packet if link_header else reassembly.ip_packet
    virtual_link_type = "ethernet" if link_header else "raw_ipv4"
    try:
        virtual = parser.parse(
            virtual_raw,
            timestamp=record.timestamp,
            original_packet=None,
            link_type=virtual_link_type,
        )
        virtual.original_packet = None
        virtual.is_reassembled = True
        virtual.reassembly_note = note or f"由 {reassembly.fragment_count} 个 IPv4 分片重组"
        virtual.link_type = virtual_link_type
    except Exception as exc:  # noqa: BLE001
        error = f"重组数据包解析失败：{exc}"
        virtual = PacketRecord(
            timestamp=record.timestamp,
            raw=virtual_raw,
            length=len(virtual_raw),
            protocol="MALFORMED",
            info=error,
            errors=[error],
            is_reassembled=True,
            reassembly_note=note,
            link_type=virtual_link_type,
            original_packet=None,
        )
        result.stats.parse_errors += 1

    result.stats.reassembled += 1
    result.records.append(virtual)


def _packet_data(packet: Any) -> tuple[bytes, str, str | None]:
    try:
        if callable(getattr(packet, "haslayer", None)) and packet.haslayer(Ether):
            return bytes(packet[Ether]), "ethernet", None
        if callable(getattr(packet, "haslayer", None)) and packet.haslayer(IP):
            return bytes(packet[IP]), "raw_ipv4", None
        raw = bytes(packet)
    except Exception as exc:
        raise ValueError(f"无法读取数据包原始字节：{exc}") from exc

    layer_name = packet.__class__.__name__
    return raw, "unknown", f"暂不支持链路层类型：{layer_name}"


def _timestamp(packet: Any) -> float:
    try:
        return float(packet.time)
    except (AttributeError, TypeError, ValueError):
        return 0.0


def _safe_bytes(packet: Any) -> bytes:
    try:
        return bytes(packet)
    except Exception:
        return b""


def _reassembly_note(result: ReassemblyResult) -> str:
    if result.error:
        return f"重组异常：{result.error}"
    if result.complete:
        return f"由 {result.fragment_count} 个 IPv4 分片重组完成"
    if result.status and result.status != "cached":
        return result.status
    return ""


__all__ = ["OfflineCaptureError", "OfflineLoadResult", "load_capture_file"]
