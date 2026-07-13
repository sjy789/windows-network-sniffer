"""PCAP and human-readable summary export."""

from __future__ import annotations

import csv
from collections.abc import Iterable
from datetime import datetime
from pathlib import Path
from typing import Any

from scapy.all import wrpcap

from .models import PacketRecord


class StorageError(RuntimeError):
    """A user-facing export failure."""


CSV_HEADERS = (
    "序号",
    "时间",
    "源地址",
    "目的地址",
    "协议",
    "源端口",
    "目的端口",
    "长度",
    "信息",
    "是否重组",
    "错误",
)


def _prepare_path(path: str | Path) -> Path:
    if isinstance(path, str) and not path.strip():
        raise ValueError("保存路径不能为空")
    target = Path(path).expanduser()
    if target.exists() and target.is_dir():
        raise StorageError(f"保存路径是文件夹而不是文件：{target}")
    try:
        target.parent.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        raise StorageError(f"无法创建保存目录“{target.parent}”：{exc}") from exc
    return target


def save_pcap(path: str | Path, records: Iterable[PacketRecord]) -> int:
    """Write original, non-reassembled Scapy packets to a PCAP file.

    Virtual records created by IPv4 reassembly intentionally have no original
    packet and are excluded.  The return value is the number of frames written.
    """

    target = _prepare_path(path)
    packets: list[Any] = [
        record.original_packet
        for record in records
        if not record.is_reassembled and record.original_packet is not None
    ]
    if not packets:
        raise StorageError("没有可保存到 PCAP 的原始数据包")

    try:
        wrpcap(str(target), packets)
    except Exception as exc:
        raise StorageError(f"保存 PCAP 文件失败：{exc}") from exc
    return len(packets)


def _timestamp_text(timestamp: float) -> str:
    try:
        return datetime.fromtimestamp(timestamp).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
    except (OSError, OverflowError, ValueError):
        return str(timestamp)


def _excel_safe(value: object) -> object:
    """Prevent captured text from becoming a spreadsheet formula."""

    if not isinstance(value, str):
        return value
    if value.startswith(("=", "+", "-", "@")):
        return "'" + value
    return value


def export_csv(path: str | Path, records: Iterable[PacketRecord]) -> int:
    """Export packet summaries as an Excel-friendly UTF-8-BOM CSV file."""

    target = _prepare_path(path)
    count = 0
    try:
        with target.open("w", encoding="utf-8-sig", newline="") as stream:
            writer = csv.writer(stream)
            writer.writerow(CSV_HEADERS)
            for fallback_sequence, record in enumerate(records, start=1):
                sequence = record.sequence if record.sequence > 0 else fallback_sequence
                writer.writerow(
                    (
                        sequence,
                        _timestamp_text(record.timestamp),
                        _excel_safe(record.source),
                        _excel_safe(record.destination),
                        _excel_safe(record.protocol),
                        "" if record.source_port is None else record.source_port,
                        "" if record.destination_port is None else record.destination_port,
                        record.length,
                        _excel_safe(record.info),
                        "是" if record.is_reassembled else "否",
                        _excel_safe("; ".join(record.errors)),
                    )
                )
                count += 1
    except (OSError, csv.Error) as exc:
        raise StorageError(f"导出 CSV 文件失败：{exc}") from exc
    return count


__all__ = ["CSV_HEADERS", "StorageError", "export_csv", "save_pcap"]
