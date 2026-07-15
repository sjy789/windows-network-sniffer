"""Threaded packet capture with a GUI-safe, bounded hand-off queue."""

from __future__ import annotations

from queue import Empty, Full, Queue
from threading import Event, RLock
from time import time
from typing import TYPE_CHECKING, Any

from scapy.all import AsyncSniffer, Ether, IP, IPv6

from .models import CaptureStats, InterfaceInfo, PacketRecord, ReassemblyResult

if TYPE_CHECKING:
    from .parser import PacketParser
    from .reassembly import IPv4Reassembler


class CaptureError(RuntimeError):
    """A user-facing failure to start or stop packet capture."""


class CaptureSession:
    """Own one Scapy ``AsyncSniffer`` and feed parsed records to a queue.

    The Scapy callback runs on its worker thread.  It only parses and enqueues
    records; it never invokes GUI objects.  Consumers should call :meth:`drain`
    periodically from their own (for example, Qt GUI) thread.
    """

    def __init__(
        self,
        queue_size: int = 5000,
        parser: PacketParser | None = None,
        reassembler: IPv4Reassembler | None = None,
    ) -> None:
        if isinstance(queue_size, bool) or not isinstance(queue_size, int) or queue_size <= 0:
            raise ValueError("queue_size 必须是正整数")

        if parser is None:
            from .parser import PacketParser

            parser = PacketParser()
        if reassembler is None:
            from .reassembly import IPv4Reassembler

            reassembler = IPv4Reassembler()

        self._parser = parser
        self._reassembler = reassembler
        self._queue: Queue[PacketRecord] = Queue(maxsize=queue_size)
        self._lock = RLock()
        self._sniffer: AsyncSniffer | None = None
        self._running = False
        self._started = Event()
        self._stats = CaptureStats()
        self._sequence = 0
        self.last_error: str | None = None
        self.last_warning: str | None = None

    @property
    def running(self) -> bool:
        """Whether the current capture worker is still alive."""

        with self._lock:
            sniffer = self._sniffer
            if sniffer is None:
                self._running = False
                return False

            sniffer_running = bool(getattr(sniffer, "running", False))
            thread = getattr(sniffer, "thread", None)
            thread_alive = bool(thread is not None and thread.is_alive())
            alive = sniffer_running or thread_alive
            self._running = alive
            if alive:
                return True

            exception = getattr(sniffer, "exception", None)
            if exception is not None:
                self.last_error = f"抓包线程已停止：{exception}"
            return False

    @property
    def stats(self) -> CaptureStats:
        """Return a stable snapshot of counters and current queue depth."""

        with self._lock:
            return CaptureStats(
                captured=self._stats.captured,
                queued=self._queue.qsize(),
                dropped=self._stats.dropped,
                parse_errors=self._stats.parse_errors,
                reassembled=self._stats.reassembled,
            )

    @property
    def queue_capacity(self) -> int:
        """Maximum number of parsed packets waiting for the GUI.

        The dashboard uses this read-only value for its queue health meter;
        exposing it avoids coupling the interface to ``Queue`` internals.
        """

        return self._queue.maxsize

    def start(self, interface: InterfaceInfo, capture_filter: str = "") -> None:
        """Start asynchronous capture on ``interface``.

        ``capture_filter`` is a libpcap/BPF capture filter.  Calling ``start``
        while this session is running is rejected to prevent two workers from
        writing into the same queue and statistics object.
        """

        if not isinstance(interface, InterfaceInfo):
            raise TypeError("interface 必须是 InterfaceInfo")
        if not interface.pcap_name.strip():
            raise ValueError("所选网卡缺少 Npcap 设备名")

        with self._lock:
            if self.running:
                raise CaptureError("抓包已在运行，请先停止当前会话")

            self._discard_pending()
            self._stats = CaptureStats()
            self._sequence = 0
            self.last_error = None
            self.last_warning = None
            self._started.clear()
            clear = getattr(self._reassembler, "clear", None)
            if callable(clear):
                clear()

            options: dict[str, Any] = {
                "iface": interface.pcap_name,
                "prn": self._handle_packet,
                "store": False,
                "started_callback": self._started.set,
            }
            normalized_filter = capture_filter.strip()
            if normalized_filter:
                options["filter"] = normalized_filter

            sniffer = AsyncSniffer(**options)
            self._sniffer = sniffer
            self._running = True
            try:
                sniffer.start()
            except Exception as exc:
                self._running = False
                self._sniffer = None
                self.last_error = f"无法在“{interface.name}”上开始抓包：{exc}"
                raise CaptureError(self.last_error) from exc

            # AsyncSniffer opens its socket in the worker thread. Surface an
            # invalid interface/BPF error at Start time instead of leaving the
            # GUI looking active while the worker has already exited.
            self._started.wait(timeout=2.0)
            exception = getattr(sniffer, "exception", None)
            thread = getattr(sniffer, "thread", None)
            if exception is not None and not bool(thread is not None and thread.is_alive()):
                self._running = False
                self._sniffer = None
                self.last_error = f"无法在“{interface.name}”上开始抓包：{exception}"
                raise CaptureError(self.last_error) from exception

    def stop(self) -> None:
        """Stop capture; calling it for an already stopped session is safe."""

        with self._lock:
            sniffer = self._sniffer

        if sniffer is None:
            return

        # Socket setup occurs in Scapy's worker.  A very quick stop should give
        # its started callback a brief chance instead of raising "Not running".
        if not bool(getattr(sniffer, "running", False)):
            self._started.wait(timeout=1.0)

        try:
            if bool(getattr(sniffer, "running", False)):
                # Ask Scapy to close the capture socket, then apply our own
                # bounded join so closing the GUI cannot hang indefinitely.
                sniffer.stop(join=False)
                thread = getattr(sniffer, "thread", None)
                if thread is not None and thread.is_alive():
                    thread.join(timeout=3.0)
                    if thread.is_alive():
                        raise TimeoutError("抓包线程未在 3 秒内停止")
            else:
                thread = getattr(sniffer, "thread", None)
                if thread is not None and thread.is_alive():
                    thread.join(timeout=1.0)
                    if thread.is_alive():
                        raise TimeoutError("抓包线程未在 1 秒内停止")
                exception = getattr(sniffer, "exception", None)
                if exception is not None:
                    raise exception
        except Exception as exc:
            with self._lock:
                # The worker may still be alive after a failed stop.  Preserve
                # that state so start() cannot create a second capture worker.
                thread = getattr(sniffer, "thread", None)
                self._running = bool(getattr(sniffer, "running", False)) or bool(
                    thread is not None and thread.is_alive()
                )
                self.last_error = f"停止抓包时发生错误：{exc}"
            raise CaptureError(self.last_error) from exc
        else:
            with self._lock:
                self._running = False
                self._sniffer = None

    def drain(self, max_items: int = 200) -> list[PacketRecord]:
        """Remove and return at most ``max_items`` records without blocking."""

        if isinstance(max_items, bool) or not isinstance(max_items, int) or max_items <= 0:
            raise ValueError("max_items 必须是正整数")

        records: list[PacketRecord] = []
        for _ in range(max_items):
            try:
                records.append(self._queue.get_nowait())
            except Empty:
                break
        return records

    def _discard_pending(self) -> None:
        while True:
            try:
                self._queue.get_nowait()
            except Empty:
                return

    @staticmethod
    def _packet_data(packet: Any) -> tuple[bytes, str, str | None]:
        """Normalize supported Scapy frames for the hand-written parser."""

        try:
            if callable(getattr(packet, "haslayer", None)) and packet.haslayer(Ether):
                return bytes(packet[Ether]), "ethernet", None
            if callable(getattr(packet, "haslayer", None)) and packet.haslayer(IP):
                return bytes(packet[IP]), "raw_ipv4", None
            if callable(getattr(packet, "haslayer", None)) and packet.haslayer(IPv6):
                return bytes(packet[IPv6]), "raw_ipv6", None
            raw = bytes(packet)
        except Exception as exc:
            raise ValueError(f"无法读取数据包原始字节：{exc}") from exc

        layer_name = packet.__class__.__name__
        return raw, "unknown", f"暂不支持链路层类型：{layer_name}"

    def _handle_packet(self, packet: Any) -> None:
        """Scapy worker callback.  Never let malformed traffic kill capture."""

        timestamp = self._timestamp(packet)
        expire = getattr(self._reassembler, "expire", None)
        if callable(expire):
            try:
                expire(now=timestamp)
            except Exception as exc:  # Cache cleanup must never kill capture.
                with self._lock:
                    self.last_warning = f"清理 IPv4 分片缓存失败：{exc}"
        with self._lock:
            self._stats.captured += 1

        parse_failure_counted = False
        try:
            raw, link_type, unsupported_error = self._packet_data(packet)
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
                record = self._parser.parse(
                    raw,
                    timestamp=timestamp,
                    original_packet=packet,
                    link_type=link_type,
                )
                # The original Scapy packet is deliberately retained only on
                # real captures so storage can reproduce the exact frame.
                record.original_packet = packet
                record.link_type = link_type
            if record.errors:
                with self._lock:
                    self._stats.parse_errors += 1
                    self.last_warning = f"数据包解析警告：{record.errors[0]}"
                parse_failure_counted = True
        except Exception as exc:
            error = f"数据包解析失败：{exc}"
            try:
                raw = bytes(packet)
            except Exception:
                raw = b""
            record = PacketRecord(
                timestamp=timestamp,
                raw=raw,
                length=len(raw),
                protocol="MALFORMED",
                info=error,
                errors=[error],
                link_type="unknown",
                original_packet=packet,
            )
            with self._lock:
                self._stats.parse_errors += 1
                self.last_warning = error
            parse_failure_counted = True

        self._enqueue(record)
        self._handle_fragment(record, timestamp, parse_failure_counted=parse_failure_counted)

    @staticmethod
    def _timestamp(packet: Any) -> float:
        try:
            return float(packet.time)
        except (AttributeError, TypeError, ValueError):
            return time()

    def _handle_fragment(
        self,
        record: PacketRecord,
        timestamp: float,
        *,
        parse_failure_counted: bool,
    ) -> None:
        fragment = record.fragment
        if fragment is None or self._reassembler is None:
            return

        try:
            result: ReassemblyResult = self._reassembler.add(fragment)
        except Exception as exc:
            error = f"IPv4 分片重组失败：{exc}"
            record.errors.append(error)
            record.reassembly_note = error
            with self._lock:
                if not parse_failure_counted:
                    self._stats.parse_errors += 1
                self.last_warning = error
            return

        note = self._reassembly_note(result)
        if note:
            record.reassembly_note = note
        if result.error:
            record.errors.append(result.error)
            with self._lock:
                # ``parse_errors`` counts affected packets, not the number of
                # warning strings attached to one packet.
                if not parse_failure_counted:
                    self._stats.parse_errors += 1
                self.last_warning = f"IPv4 分片重组失败：{result.error}"
        if not result.complete or result.ip_packet is None:
            return

        link_header = result.link_header or fragment.link_header
        virtual_raw = link_header + result.ip_packet if link_header else result.ip_packet
        virtual_link_type = "ethernet" if link_header else "raw_ipv4"
        try:
            virtual = self._parser.parse(
                virtual_raw,
                timestamp=timestamp,
                original_packet=None,
                link_type=virtual_link_type,
            )
            virtual.original_packet = None
            virtual.is_reassembled = True
            virtual.reassembly_note = note or f"由 {result.fragment_count} 个 IPv4 分片重组"
            virtual.link_type = virtual_link_type
        except Exception as exc:
            error = f"重组数据包解析失败：{exc}"
            virtual = PacketRecord(
                timestamp=timestamp,
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
            with self._lock:
                self._stats.parse_errors += 1
                self.last_warning = error

        with self._lock:
            self._stats.reassembled += 1
        self._enqueue(virtual)

    @staticmethod
    def _reassembly_note(result: ReassemblyResult) -> str:
        if result.error:
            return f"重组异常：{result.error}"
        if result.complete:
            return f"由 {result.fragment_count} 个 IPv4 分片重组完成"
        if result.status and result.status != "cached":
            return result.status
        return ""

    def _enqueue(self, record: PacketRecord) -> None:
        with self._lock:
            self._sequence += 1
            record.sequence = self._sequence
        try:
            self._queue.put_nowait(record)
        except Full:
            with self._lock:
                self._stats.dropped += 1


__all__ = ["CaptureError", "CaptureSession"]
