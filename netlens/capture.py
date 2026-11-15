"""Streaming capture I/O and an interruptible live-capture lifecycle."""

import signal
import struct
import threading
import time
from collections import deque
from pathlib import Path

from scapy.all import AsyncSniffer, PcapNgReader, PcapReader, PcapWriter, conf
from scapy.error import Scapy_Exception

from .analysis import Analyzer

MAX_RECORD_BYTES = 16 * 1024 * 1024


def _next_ng_packet(reader):
    """Validate block framing without treating a truncated block as normal EOF."""
    stream, start, endian = reader.f, reader.f.tell(), reader.endian
    while True:
        position = stream.tell()
        header = stream.read(8)
        if not header:
            return False
        if len(header) != 8:
            raise ValueError("Truncated PCAPNG block header")
        if header[:4] == b"\x0a\x0d\x0d\x0a":
            magic = stream.read(4)
            if magic not in (b"\x1a\x2b\x3c\x4d", b"\x4d\x3c\x2b\x1a"):
                raise ValueError("Invalid PCAPNG byte order")
            endian = ">" if magic == b"\x1a\x2b\x3c\x4d" else "<"
        kind, length = struct.unpack(endian + "II", header)
        if length < 12 or length % 4 or length > MAX_RECORD_BYTES:
            raise ValueError("Invalid or oversized PCAPNG block")
        stream.seek(position + length - 4)
        tail = stream.read(4)
        if len(tail) != 4 or struct.unpack(endian + "I", tail)[0] != length:
            raise ValueError("Truncated or inconsistent PCAPNG block")
        if kind in (2, 3, 6):
            stream.seek(start)
            return True


def iter_packets(reader):
    """Use Scapy for decoding, checking record boundaries before each read."""
    classic_pcap = not isinstance(reader, PcapNgReader)
    while True:
        if classic_pcap:
            position = reader.f.tell()
            header = reader.f.read(16)
            if not header:
                return
            if len(header) != 16:
                raise ValueError("Truncated PCAP packet header")
            captured_length = struct.unpack(reader.endian + "IIII", header)[2]
            if captured_length > MAX_RECORD_BYTES:
                raise ValueError("PCAP packet exceeds the 16 MiB record limit")
            reader.f.seek(position)
        elif not _next_ng_packet(reader):
            return
        try:
            packet = reader.read_packet(size=MAX_RECORD_BYTES)
        except EOFError as exc:
            raise ValueError("Truncated or invalid capture record") from exc
        if classic_pcap and reader.f.tell() != position + 16 + captured_length:
            raise ValueError("Truncated PCAP packet data")
        yield packet


class PCAPWriter:
    """Flush each packet; rotate in the requested directory without overwriting files."""

    def __init__(self, filename, max_size_mb=100):
        self.path = Path(filename)
        self.max_size_bytes = int(max_size_mb * 1024 * 1024)
        if self.max_size_bytes < 24:
            raise ValueError("PCAP size limit must be at least 24 bytes")
        self.lock = threading.Lock()
        self.writer = None
        self.file_count = 0
        self.current_size = 0
        self.current_linktype = None
        self.files = []
        self.closed = False
        # Reserve the output before capture so path/permission errors fail immediately.
        self.stream = self.path.open("xb")

    def _open(self, packet):
        linktype = conf.l2types.layer2num.get(type(packet))
        if linktype is None:
            raise ValueError(f"Unsupported PCAP link type: {type(packet).__name__}")
        if self.stream is None:
            path = self.path.with_name(f"{self.path.stem}_{self.file_count}{self.path.suffix}")
            self.stream = path.open("xb")
        else:
            path = self.path
        self.writer = PcapWriter(self.stream, linktype=linktype, sync=True)
        self.writer.write_header(packet)
        self.current_linktype = linktype
        self.current_size = 24
        self.files.append(str(path))

    def write(self, packet):
        with self.lock:
            if self.closed:
                raise ValueError("PCAP writer is closed")
            record_size = 16 + len(packet)
            linktype = conf.l2types.layer2num.get(type(packet))
            if self.writer and (
                self.current_size + record_size > self.max_size_bytes
                or self.current_linktype != linktype
            ):
                self.writer.close()
                self.writer = None
                self.stream = None
                self.file_count += 1
            if self.writer is None:
                self._open(packet)
            self.writer.write(packet)
            self.current_size += record_size

    def close(self):
        with self.lock:
            if self.closed:
                return
            self.closed = True
            if self.writer:
                self.writer.close()
            elif self.stream:
                # An empty capture is still a valid Ethernet PCAP.
                writer = PcapWriter(self.stream, linktype=1, sync=True)
                writer.write_header(None)
                writer.close()
                self.files.append(str(self.path))

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()


class NetLens:
    def __init__(
        self,
        interface=None,
        bpf_filter=None,
        count=0,
        timeout=None,
        pcap_out=None,
        max_size_mb=100,
        analyzer=None,
        on_packet=None,
        on_stats=None,
        store_limit=0,
    ):
        self.interface = interface
        self.bpf_filter = bpf_filter
        self.count = count
        self.timeout = timeout
        self.pcap_out = pcap_out
        self.max_size_mb = max_size_mb
        self.analyzer = analyzer or Analyzer()
        self.on_packet = on_packet
        self.on_stats = on_stats
        self.packet_buffer = deque(maxlen=store_limit)
        self.stopped = threading.Event()
        self.ready = threading.Event()
        self.pcap_writer = None
        self.capture = None
        self.error = None
        self.started = False

    def _process_packet(self, packet):
        if self.error is not None:
            return
        try:
            if self.pcap_writer:
                self.pcap_writer.write(packet)
            info = self.analyzer.process(packet)
            if self.packet_buffer.maxlen:
                self.packet_buffer.append(info)
            if self.on_packet:
                self.on_packet(info)
        except Exception as exc:
            # Scapy normally logs and swallows callback errors. Relay to the main thread.
            self.error = exc
            self.stopped.set()

    def stop(self):
        """Request shutdown; safe from a signal handler or another thread."""
        self.stopped.set()

    def _prepare(self):
        if self.started:
            raise RuntimeError("Create a new NetLens instance for each capture")
        self.started = True
        if self.pcap_out:
            self.pcap_writer = PCAPWriter(self.pcap_out, self.max_size_mb)

    def _finish(self):
        self.stopped.set()
        if self.pcap_writer:
            self.pcap_writer.close()

    def summary(self, reference_time=None):
        result = self.analyzer.summary(reference_time)
        result["pcap_files"] = list(self.pcap_writer.files) if self.pcap_writer else []
        if self.packet_buffer.maxlen:
            result["stored_packets"] = list(self.packet_buffer)
            result["store_limit"] = self.packet_buffer.maxlen
        return result

    def analyze(self, filepath):
        with PcapReader(str(filepath)) as packets:
            self._prepare()
            try:
                for packet in iter_packets(packets):
                    if self.stopped.is_set():
                        break
                    self._process_packet(packet)
                    if self.error is not None:
                        raise self.error
                    if self.count and self.analyzer.stats.total_packets >= self.count:
                        break
            finally:
                self._finish()
        return self.summary()

    def start(self):
        self._prepare()
        previous_handlers = {}
        started_at = time.monotonic()
        try:
            if threading.current_thread() is threading.main_thread():
                for sig in (signal.SIGINT, signal.SIGTERM):
                    previous_handlers[sig] = signal.signal(sig, lambda *_: self.stop())
            self.capture = AsyncSniffer(
                iface=self.interface,
                filter=self.bpf_filter,
                count=self.count,
                store=False,
                prn=self._process_packet,
                started_callback=self.ready.set,
            )
            self.capture.start()
            next_stats = time.monotonic() + 5
            while self.capture.thread.is_alive():
                if self.timeout is not None and time.monotonic() - started_at >= self.timeout:
                    self.stop()
                if self.stopped.is_set() and self.ready.is_set():
                    self._stop_capture()
                    break
                self.capture.join(timeout=0.1)
                if self.on_stats and time.monotonic() >= next_stats:
                    self.on_stats(self.summary(time.time()))
                    next_stats = time.monotonic() + 5
            self.capture.join()
            if self.error is not None:
                raise self.error
        finally:
            try:
                if self.capture and self.capture.thread and self.capture.thread.is_alive():
                    # Wait for initialization before calling Scapy's stop callback.
                    while self.capture.thread.is_alive() and not self.ready.wait(0.1):
                        continue
                    self._stop_capture()
                    self.capture.join()
            finally:
                for sig, handler in previous_handlers.items():
                    signal.signal(sig, handler)
                self._finish()
        result = self.summary(time.time())
        result["wall_seconds"] = round(time.monotonic() - started_at, 6)
        return result

    def _stop_capture(self):
        if self.capture.running:
            try:
                self.capture.stop(join=False)
            except Scapy_Exception:
                # Count or timeout can finish between the check and stop().
                if self.capture.running:
                    raise
