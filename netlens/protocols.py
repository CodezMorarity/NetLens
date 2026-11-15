"""Packet-local protocol decoding; no DNS lookups or network requests."""

import math
from datetime import datetime, timezone

from scapy.layers.dns import DNS
from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.inet6 import IPv6, IPv6ExtHdrFragment, _ICMPv6
from scapy.layers.l2 import ARP, Ether


def network_layer(packet):
    # Walk from the outside so an ICMP error's quoted packet isn't treated as a flow.
    layer = packet
    while layer:
        if isinstance(layer, (IP, IPv6)):
            return layer
        layer = layer.payload
    return None


def transport_layer(packet):
    ip = network_layer(packet)
    if ip is None or (isinstance(ip, IP) and ip.frag):
        return None
    layer = ip.payload
    while layer and layer.__class__.__name__.startswith("IPv6ExtHdr"):
        if isinstance(layer, IPv6ExtHdrFragment) and layer.offset:
            return None
        layer = layer.payload
    return layer if isinstance(layer, (TCP, UDP, ICMP, _ICMPv6)) else None


def payload_bytes(packet):
    transport = transport_layer(packet)
    if isinstance(transport, (TCP, UDP)):
        return bytes(transport.payload)
    return b""


def packet_timestamp(packet):
    timestamp = float(packet.time)
    if not math.isfinite(timestamp):
        raise ValueError("Packet timestamp must be finite")
    return timestamp


def iso_timestamp(timestamp):
    try:
        return datetime.fromtimestamp(timestamp, timezone.utc).isoformat()
    except (OverflowError, OSError, ValueError):
        return str(timestamp)


def parse_ethernet(packet):
    if Ether not in packet:
        return {}
    eth = packet[Ether]
    return {"mac_src": eth.src, "mac_dst": eth.dst, "eth_type": hex(eth.type)}


def parse_ip(packet):
    ip = network_layer(packet)
    if ip is None:
        return {}
    info = {"src": ip.src, "dst": ip.dst, "version": ip.version}
    if isinstance(ip, IP):
        info.update(
            ttl=ip.ttl,
            length=ip.len,
            id=ip.id,
            protocol=ip.proto,
            flags=str(ip.flags),
            fragment_offset=ip.frag,
        )
    else:
        info.update(hop_limit=ip.hlim, payload_length=ip.plen, next_header=ip.nh)
    return info


def parse_tcp(packet):
    tcp = transport_layer(packet)
    if not isinstance(tcp, TCP):
        return {}
    return {
        "sport": tcp.sport,
        "dport": tcp.dport,
        "seq": tcp.seq,
        "ack": tcp.ack,
        "flags": str(tcp.flags),
        "window": tcp.window,
        "options": str(tcp.options),
    }


def parse_udp(packet):
    udp = transport_layer(packet)
    if not isinstance(udp, UDP):
        return {}
    return {"sport": udp.sport, "dport": udp.dport, "length": udp.len}


def parse_icmp(packet):
    icmp = transport_layer(packet)
    if not isinstance(icmp, (ICMP, _ICMPv6)):
        return {}
    return {"type": icmp.type, "code": icmp.code, "description": icmp.name}


def parse_arp(packet):
    if ARP not in packet:
        return {}
    arp = packet[ARP]
    return {
        "op": arp.op,
        "op_name": {1: "Request", 2: "Reply"}.get(arp.op, str(arp.op)),
        "psrc": arp.psrc,
        "pdst": arp.pdst,
        "hwsrc": arp.hwsrc,
        "hwdst": arp.hwdst,
    }


def _text(value):
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return str(value)


def parse_dns(packet):
    transport = transport_layer(packet)
    if not isinstance(transport, (TCP, UDP)) or DNS not in transport:
        return {}
    dns = transport[DNS]
    info = {"id": dns.id, "qr": "Response" if dns.qr else "Query", "rcode": dns.rcode}
    if dns.qd:
        info.update(query=_text(dns.qd[0].qname), qtype=dns.qd[0].qtype)
    info["answers"] = [
        {"name": _text(rr.rrname), "type": rr.type, "data": _text(rr.rdata)}
        for rr in dns.an[:10]
        if hasattr(rr, "rdata")
    ]
    return info


def parse_http(packet, show_sensitive=False):
    if not isinstance(transport_layer(packet), TCP):
        return {}
    raw = payload_bytes(packet)[:16384]
    lines = raw.split(b"\r\n\r\n", 1)[0].split(b"\r\n")
    if not lines:
        return {}
    first = _text(lines[0])
    request = (
        first.startswith(
            (
                "GET ",
                "POST ",
                "PUT ",
                "DELETE ",
                "PATCH ",
                "HEAD ",
                "OPTIONS ",
                "CONNECT ",
                "TRACE ",
            )
        )
        and " HTTP/" in first
    )
    response = first.startswith("HTTP/")
    if not (request or response):
        return {}
    if request and not show_sensitive and "?" in first:
        target, _, version = first.rpartition(" ")
        first = target.split("?", 1)[0] + "?[redacted] " + version
    info = {"request_line" if request else "status_line": first}
    allowed = {
        "host",
        "user-agent",
        "content-type",
        "server",
        "authorization",
        "proxy-authorization",
        "cookie",
        "set-cookie",
        "x-api-key",
        "x-auth-token",
    }
    sensitive = {
        "authorization",
        "proxy-authorization",
        "cookie",
        "set-cookie",
        "x-api-key",
        "x-auth-token",
    }
    for line in lines[1:]:
        key, sep, value = line.partition(b":")
        name = _text(key).lower().strip()
        if sep and name in allowed:
            info[name.replace("-", "_")] = (
                "[redacted]" if name in sensitive and not show_sensitive else _text(value.strip())
            )
    return info


TCP_SERVICES = {
    21: "FTP",
    22: "SSH",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS/TLS",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5900: "VNC",
    6379: "Redis",
    8080: "HTTP",
    27017: "MongoDB",
}
UDP_SERVICES = {
    53: "DNS",
    67: "DHCP",
    68: "DHCP",
    123: "NTP",
    161: "SNMP",
    443: "QUIC/DTLS",
    1900: "SSDP",
    5353: "mDNS",
}


def classify_packet(packet):
    transport = transport_layer(packet)
    if isinstance(transport, (TCP, UDP)):
        if DNS in transport:
            return "mDNS" if 5353 in (transport.sport, transport.dport) else "DNS"
        services = TCP_SERVICES if isinstance(transport, TCP) else UDP_SERVICES
        for port in (transport.dport, transport.sport):
            if port in services:
                return services[port]
        if isinstance(transport, TCP):
            if parse_http(packet):
                return "HTTP"
            return "TCP-SYN" if int(transport.flags) & 0x12 == 0x02 else "TCP"
        return "UDP"
    if isinstance(transport, ICMP):
        return "ICMP"
    if isinstance(transport, _ICMPv6):
        return "ICMPv6"
    if ARP in packet:
        return "ARP"
    return "Other"


def packet_info(packet, show_sensitive=False, show_raw=False, hex_dump=False):
    timestamp = packet_timestamp(packet)
    info = {
        "event": "packet",
        "timestamp": iso_timestamp(timestamp),
        "epoch": timestamp,
        "length": len(packet),
        "classification": classify_packet(packet),
    }
    for name, parser in (
        ("ethernet", parse_ethernet),
        ("ip", parse_ip),
        ("tcp", parse_tcp),
        ("udp", parse_udp),
        ("icmp", parse_icmp),
        ("arp", parse_arp),
        ("dns", parse_dns),
    ):
        layer = parser(packet)
        if layer:
            info[name] = layer
    http = parse_http(packet, show_sensitive=show_sensitive)
    if http:
        info["http"] = http
    if show_raw:
        info["raw_preview"] = payload_bytes(packet)[:200].hex()
    if hex_dump:
        info["packet_hex"] = bytes(packet)[:512].hex()
    return info
