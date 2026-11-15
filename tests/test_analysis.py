import json

import pytest
from scapy.all import ICMP, IP, TCP, UDP, Ether, IPv6, Raw

from netlens.analysis import Analyzer, ConnectionTracker, PacketStats
from netlens.detection import SYNScanDetector, analyze_payload


def test_identical_timestamps_and_more_than_1000_packets():
    stats = PacketStats()
    packet = Ether() / IP() / TCP()
    for _ in range(2001):
        stats.update(packet, len(packet), 100.0)
    data = stats.get_summary()
    assert data["total_packets"] == 2001
    assert data["current_pps"] == 2001
    assert data["current_bps"] == len(packet) * 2001 * 8
    assert data["elapsed_seconds"] == 0
    assert stats.get_summary(102)["current_bps"] == 0


def test_packet_time_not_processing_time(packets):
    analyzer = Analyzer()
    for packet in packets:
        analyzer.process(packet)
    data = analyzer.summary()
    assert data["elapsed_seconds"] == pytest.approx(1.6)
    assert data["ipv6_packets"] == 2
    assert data["total_packets"] == 33
    assert data["total_connections"] == 28
    assert data["security_findings"]["by_type"] == {"Password": 1, "Possible SYN scan": 1}


def test_out_of_order_timestamps():
    stats = PacketStats()
    packet = IP() / TCP()
    for timestamp in (20, 10, 21):
        stats.update(packet, 40, timestamp)
    assert stats.get_summary()["elapsed_seconds"] == 11
    assert stats.get_summary()["current_bps"] == 320


@pytest.mark.parametrize("ip", [IP, IPv6])
def test_bidirectional_flows_and_transport_separation(ip):
    src, dst = ("192.0.2.1", "192.0.2.2") if ip is IP else ("2001:db8::1", "2001:db8::2")
    tracker = ConnectionTracker()
    tracker.update(ip(src=src, dst=dst) / TCP(sport=50000, dport=80), 100)
    tracker.update(ip(src=dst, dst=src) / TCP(sport=80, dport=50000), 101)
    tracker.update(ip(src=src, dst=dst) / UDP(sport=50000, dport=80), 102)
    assert tracker.get_summary()["total_connections"] == 2
    assert any(v["bidirectional"] and v["packets"] == 2 for v in tracker.get_active().values())
    assert tracker.get_summary(200)["active_connections"] == 0


def test_connection_expiration_and_limit():
    tracker = ConnectionTracker(timeout=5, max_connections=2)
    packet = IP() / TCP(dport=80)
    tracker.update(packet, 0)
    tracker.update(packet, 10)
    assert tracker.total_connections == 2
    for port in range(81, 90):
        tracker.update(IP() / TCP(dport=port), 11)
    assert len(tracker.connections) == 2
    assert tracker.evicted_connections > 0


def test_icmp_does_not_create_flow_for_quoted_packet():
    tracker = ConnectionTracker()
    tracker.update(IP() / ICMP(type=3) / IP() / TCP(), 100)
    assert tracker.total_connections == 0


def test_slow_syn_packets_are_not_a_scan():
    detector = SYNScanDetector()
    assert all(
        detector.check("192.0.2.1", 10000, "192.0.2.2", port, port * 3) is None
        for port in range(30)
    )


def test_syn_retransmissions_not_unique_targets():
    detector = SYNScanDetector()
    assert all(
        detector.check("192.0.2.1", 10000 + i, "192.0.2.2", 80, i * 0.01) is None for i in range(50)
    )


def test_syn_cooldown_and_bounded_sources():
    detector = SYNScanDetector(max_sources=2)
    alerts = [
        detector.check("192.0.2.1", 10000, "192.0.2.2", 20000 + i, i * 0.01) for i in range(50)
    ]
    assert sum(alert is not None for alert in alerts) == 1
    for i in range(10):
        detector.check(f"192.0.2.{i + 1}", 10000, "192.0.2.2", 80, 1)
    assert len(detector.syn_tracker) == 2


@pytest.mark.parametrize(
    "payload,label",
    [
        (b"PASSWORD=hunter2", "Password"),
        (b'{"password": "hunter2"}', "Password"),
        (b"X-API-Key: a-private-key", "Secret or token"),
        (b"Authorization: Basic dXNlcjpwYXNz", "Authorization header"),
        (b"AKIAABCDEFGHIJKLMNOP", "AWS access key"),
        (b"-----BEGIN RSA PRIVATE KEY-----", "Private key"),
        (b"card=4111 1111 1111 1111", "Possible payment card"),
        (b"card=378282246310005", "Possible payment card"),
        (b"card=4222222222222", "Possible payment card"),
        (b"ssn=123-45-6789", "Possible SSN"),
    ],
)
def test_sensitive_patterns_redacted(payload, label):
    findings = analyze_payload(payload)
    assert label in {finding["pattern"] for finding in findings}
    assert all(finding["context"] == "[redacted]" for finding in findings)
    assert any(finding["context"] != "[redacted]" for finding in analyze_payload(payload, True))


def test_plain_words_and_invalid_pii_do_not_alert():
    assert (
        analyze_payload(
            b"login authentication token password documentation 000-12-3456 4111111111111112"
        )
        == []
    )


def test_findings_sample_is_bounded():
    analyzer = Analyzer()
    packet = IP() / TCP() / Raw(b"password=private")
    for i in range(110):
        packet.time = i
        analyzer.process(packet)
    data = analyzer.summary()
    assert data["security_findings"]["total"] == 110
    assert len(data["security_findings"]["recent"]) == 100
    assert "private" not in json.dumps(data)
