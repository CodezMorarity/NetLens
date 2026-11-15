import json

import pytest
from scapy.all import DNS, DNSQR, DNSRR, ICMP, IP, TCP, UDP, Ether, IPv6, Raw
from scapy.layers.inet6 import ICMPv6EchoRequest, IPv6ExtHdrHopByHop

from netlens.protocols import (
    classify_packet,
    packet_info,
    parse_dns,
    parse_ethernet,
    parse_http,
    parse_ip,
    payload_bytes,
    transport_layer,
)


def test_ip_and_dns_ids_do_not_overwrite_each_other():
    packet = Ether() / IP(id=123) / UDP() / DNS(id=456, qd=DNSQR(qname="example.test"))
    info = packet_info(packet)
    assert info["ip"]["id"] == 123
    assert info["dns"]["id"] == 456
    json.dumps(info)


def test_raw_ip_does_not_invent_mac_addresses():
    assert parse_ethernet(IP(src="192.0.2.1")) == {}


def test_ipv6_extension_headers():
    packet = IPv6(src="2001:db8::1", dst="2001:db8::2") / IPv6ExtHdrHopByHop() / TCP(dport=443)
    assert parse_ip(packet)["version"] == 6
    assert classify_packet(packet) == "HTTPS/TLS"
    assert isinstance(transport_layer(packet), TCP)


def test_icmp_quoted_tcp_is_not_a_tcp_flow():
    packet = IP() / ICMP(type=3) / IP() / TCP(dport=80)
    assert classify_packet(packet) == "ICMP"
    assert "tcp" not in packet_info(packet)
    assert payload_bytes(packet) == b""


def test_dns_multiple_answers_and_tcp():
    packet = (
        IP()
        / TCP(dport=53)
        / DNS(
            qr=1,
            qd=DNSQR(qname="example.test"),
            an=[
                DNSRR(rrname="example.test", rdata="192.0.2.1"),
                DNSRR(rrname="example.test", rdata="192.0.2.2"),
            ],
        )
    )
    assert classify_packet(packet) == "DNS"
    assert [answer["data"] for answer in parse_dns(packet)["answers"]] == ["192.0.2.1", "192.0.2.2"]


def test_http_user_agent_header_whitespace_and_redaction():
    packet = (
        IP()
        / TCP(dport=80)
        / Raw(
            b"GET /?token=private HTTP/1.1\r\nHost:example.test\r\nUser-Agent: test-agent\r\n"
            b"Authorization: Bearer private\r\nCookie: session=private\r\n\r\n"
        )
    )
    info = parse_http(packet)
    assert info["user_agent"] == "test-agent"
    assert info["host"] == "example.test"
    assert "private" not in json.dumps(info)
    assert "private" in json.dumps(parse_http(packet, show_sensitive=True))


def test_http_still_works_with_scapy_http_dissection():
    from scapy.layers.http import HTTP, HTTPRequest

    packet = IP() / TCP(dport=80) / HTTP() / HTTPRequest(Host=b"example.test", User_Agent=b"demo")
    assert parse_http(packet)["user_agent"] == "demo"
    assert b"Host: example.test" in payload_bytes(packet)


def test_hex_dump_does_not_require_show_raw():
    info = packet_info(IP() / UDP() / Raw(b"sample"), hex_dump=True)
    assert "packet_hex" in info
    assert "raw_preview" not in info


@pytest.mark.parametrize(
    "packet,expected",
    [
        (IPv6() / ICMPv6EchoRequest(), "ICMPv6"),
        (IP() / UDP(sport=67, dport=50000), "DHCP"),
        (IP() / TCP(sport=30000, dport=30001, flags="S"), "TCP-SYN"),
        (IP() / TCP(sport=30000, dport=30001, flags="SA"), "TCP"),
    ],
)
def test_protocol_classification(packet, expected):
    assert classify_packet(packet) == expected
