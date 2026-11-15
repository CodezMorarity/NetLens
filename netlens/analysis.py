"""Shared analysis for live captures and streaming offline files."""

import math
import threading
from collections import Counter, OrderedDict, deque

from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.inet6 import IPv6, _ICMPv6
from scapy.layers.l2 import ARP, Ether

from .detection import SYNScanDetector, analyze_payload
from .protocols import (
    network_layer,
    packet_info,
    packet_timestamp,
    payload_bytes,
    transport_layer,
)


class PacketStats:
    def __init__(self):
        self.total_packets = 0
        self.total_bytes = 0
        self.ipv4_packets = 0
        self.ipv6_packets = 0
        self.protocols = Counter()
        self.top_talkers_ip = Counter()
        self.top_talkers_mac = Counter()
        self.ports = Counter()
        self.first_timestamp = None
        self.last_timestamp = None
        self.bandwidth_buckets = {}

    def update(self, packet, pkt_len, timestamp):
        self.total_packets += 1
        self.total_bytes += pkt_len
        self.first_timestamp = (
            timestamp if self.first_timestamp is None else min(self.first_timestamp, timestamp)
        )
        self.last_timestamp = (
            timestamp if self.last_timestamp is None else max(self.last_timestamp, timestamp)
        )
        # Ten 100 ms bins: all packets count, including simultaneous high-rate arrivals.
        bucket = math.floor(timestamp * 10)
        size, count = self.bandwidth_buckets.get(bucket, (0, 0))
        self.bandwidth_buckets[bucket] = (size + pkt_len, count + 1)
        cutoff = math.floor(self.last_timestamp * 10) - 9
        self.bandwidth_buckets = {k: v for k, v in self.bandwidth_buckets.items() if k >= cutoff}
        if Ether in packet:
            self.top_talkers_mac[packet[Ether].src] += 1
        ip = network_layer(packet)
        transport = transport_layer(packet)
        if ip is not None:
            self.ipv4_packets += isinstance(ip, IP)
            self.ipv6_packets += isinstance(ip, IPv6)
            self.top_talkers_ip.update(dict.fromkeys((ip.src, ip.dst)).keys())
        if isinstance(transport, (TCP, UDP)):
            proto = "TCP" if isinstance(transport, TCP) else "UDP"
            self.ports.update(dict.fromkeys((transport.sport, transport.dport)).keys())
        elif isinstance(transport, ICMP):
            proto = "ICMP"
        elif isinstance(transport, _ICMPv6):
            proto = "ICMPv6"
        elif ARP in packet:
            proto = "ARP"
        else:
            proto = "Other"
        self.protocols[proto] += 1

    def get_summary(self, reference_time=None):
        reference = self.last_timestamp if reference_time is None else reference_time
        cutoff = math.floor(reference * 10) - 9 if reference is not None else 0
        recent = [v for k, v in self.bandwidth_buckets.items() if k >= cutoff]
        elapsed = (self.last_timestamp - self.first_timestamp) if self.total_packets else 0.0
        return {
            "total_packets": self.total_packets,
            "total_bytes": self.total_bytes,
            "ipv4_packets": self.ipv4_packets,
            "ipv6_packets": self.ipv6_packets,
            "first_timestamp": self.first_timestamp,
            "last_timestamp": self.last_timestamp,
            "elapsed_seconds": round(elapsed, 6),
            "current_bps": sum(size for size, _ in recent) * 8,
            "current_pps": sum(count for _, count in recent),
            "average_bps": round(self.total_bytes * 8 / elapsed, 2) if elapsed > 0 else 0,
            "top_protocols": self.protocols.most_common(10),
            "top_talkers_ip": self.top_talkers_ip.most_common(10),
            "top_talkers_mac": self.top_talkers_mac.most_common(10),
            "top_ports": self.ports.most_common(10),
        }


class ConnectionTracker:
    """Bidirectional TCP/UDP flow sessions, expired in capture time."""

    def __init__(self, timeout=60, max_connections=10000):
        self.timeout = timeout
        self.max_connections = max_connections
        self.connections = OrderedDict()
        self.total_connections = 0
        self.evicted_connections = 0
        self.watermark = float("-inf")

    def update(self, packet, timestamp=None):
        timestamp = packet_timestamp(packet) if timestamp is None else timestamp
        self.watermark = max(self.watermark, timestamp)
        self._expire(self.watermark)
        ip, transport = network_layer(packet), transport_layer(packet)
        if ip is None or not isinstance(transport, (TCP, UDP)):
            return None
        if timestamp < self.watermark - self.timeout:
            return None
        proto = "TCP" if isinstance(transport, TCP) else "UDP"
        endpoints = tuple(sorted(((ip.src, transport.sport), (ip.dst, transport.dport))))
        key = (proto, *endpoints)
        entry = self.connections.get(key)
        if entry is not None and self.watermark - entry["last_seen"] >= self.timeout:
            del self.connections[key]
            entry = None
        if entry is None:
            self.total_connections += 1
            entry = {
                "src": ip.src,
                "dst": ip.dst,
                "sport": transport.sport,
                "dport": transport.dport,
                "proto": proto,
                "packets": 0,
                "bytes": 0,
                "start": timestamp,
                "last_seen": timestamp,
                "bidirectional": False,
            }
            self.connections[key] = entry
        elif (ip.src, transport.sport) == (entry["dst"], entry["dport"]):
            entry["bidirectional"] = True
        entry["packets"] += 1
        entry["bytes"] += len(packet)
        entry["last_seen"] = max(entry["last_seen"], timestamp)
        entry["start"] = min(entry["start"], timestamp)
        self.connections.move_to_end(key)
        if len(self.connections) > self.max_connections:
            self.connections.popitem(last=False)
            self.evicted_connections += 1
        return entry

    def _expire(self, reference):
        # Access order usually matches time; out-of-order captures are handled by get_active.
        while self.connections:
            key = next(iter(self.connections))
            if reference - self.connections[key]["last_seen"] < self.timeout:
                break
            del self.connections[key]

    def get_active(self, reference_time=None):
        reference = self.watermark if reference_time is None else reference_time
        return {
            k: dict(v)
            for k, v in self.connections.items()
            if reference - v["last_seen"] < self.timeout
        }

    def get_summary(self, reference_time=None):
        return {
            "total_connections": self.total_connections,
            "active_connections": len(self.get_active(reference_time)),
            "evicted_connections": self.evicted_connections,
        }


class Analyzer:
    def __init__(self, show_sensitive=False, show_raw=False, hex_dump=False):
        self.stats = PacketStats()
        self.conn_tracker = ConnectionTracker()
        self.syn_detector = SYNScanDetector()
        self.finding_counts = Counter()
        self.findings = deque(maxlen=100)
        self.processing_errors = 0
        self.show_sensitive = show_sensitive
        self.show_raw = show_raw
        self.hex_dump = hex_dump
        self.lock = threading.RLock()

    def process(self, packet):
        with self.lock:
            timestamp = packet_timestamp(packet)
            self.stats.update(packet, len(packet), timestamp)
            self.conn_tracker.update(packet, timestamp)
            info = packet_info(packet, self.show_sensitive, self.show_raw, self.hex_dump)
            info["number"] = self.stats.total_packets
            findings = analyze_payload(payload_bytes(packet), self.show_sensitive)
            ip, tcp = network_layer(packet), transport_layer(packet)
            if ip is not None and isinstance(tcp, TCP) and int(tcp.flags) & 0x12 == 0x02:
                alert = self.syn_detector.check(ip.src, tcp.sport, ip.dst, tcp.dport, timestamp)
                if alert:
                    findings.append(
                        {
                            "type": "syn_scan",
                            "pattern": "Possible SYN scan",
                            "severity": "high",
                            "context": "Unique SYN targets exceeded threshold",
                            **alert,
                        }
                    )
            info["security_findings"] = findings
            for finding in findings:
                self.finding_counts[finding["pattern"]] += 1
                self.findings.append(
                    {"packet_number": info["number"], "timestamp": info["timestamp"], **finding}
                )
            return info

    def summary(self, reference_time=None):
        with self.lock:
            return {
                **self.stats.get_summary(reference_time),
                **self.conn_tracker.get_summary(reference_time),
                "processing_errors": self.processing_errors,
                "security_findings": {
                    "total": sum(self.finding_counts.values()),
                    "by_type": dict(self.finding_counts),
                    "recent": list(self.findings),
                },
            }
