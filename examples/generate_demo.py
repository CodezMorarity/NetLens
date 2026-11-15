"""Generate synthetic documentation traffic locally; sends no packets."""

import argparse
from pathlib import Path

from scapy.all import ARP, DNS, DNSQR, DNSRR, ICMP, IP, TCP, UDP, Ether, IPv6, Raw, wrpcap
from scapy.layers.inet6 import ICMPv6EchoRequest


def demo_packets():
    client, server = "192.0.2.10", "198.51.100.20"
    layer2 = Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02")
    packets = [
        layer2 / ARP(psrc=client, pdst=server, hwsrc=layer2.src, hwdst=layer2.dst),
        layer2
        / IP(src=client, dst=server)
        / UDP(sport=50000, dport=53)
        / DNS(id=1, qd=DNSQR(qname="example.test")),
        layer2
        / IP(src=server, dst=client)
        / UDP(sport=53, dport=50000)
        / DNS(
            id=1,
            qr=1,
            qd=DNSQR(qname="example.test"),
            an=DNSRR(rrname="example.test", rdata=server),
        ),
        layer2
        / IP(src=client, dst=server)
        / TCP(sport=50001, dport=80, flags="PA")
        / Raw(
            b"POST /login HTTP/1.1\r\nHost: example.test\r\nUser-Agent: NetLens-demo\r\n"
            b"Content-Type: application/x-www-form-urlencoded\r\n\r\nusername=demo&password=demo-only"
        ),
        layer2
        / IP(src=server, dst=client)
        / TCP(sport=80, dport=50001, flags="PA")
        / Raw(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK"),
        layer2 / IP(src=client, dst=server) / ICMP(),
        layer2 / IPv6(src="2001:db8::1", dst="2001:db8::2") / ICMPv6EchoRequest(),
        layer2 / IPv6(src="2001:db8::1", dst="2001:db8::2") / TCP(sport=50002, dport=443),
    ]
    packets.extend(
        layer2 / IP(src="192.0.2.99", dst=server) / TCP(sport=40000, dport=20000 + i, flags="S")
        for i in range(25)
    )
    for index, packet in enumerate(packets):
        packet.time = 1700000000 + index * 0.05
    return packets


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", nargs="?", default="demo.pcap")
    args = parser.parse_args()
    packets = demo_packets()
    with Path(args.output).open("xb") as stream:
        wrpcap(stream, packets)
    print(f"Wrote {len(packets)} synthetic packets to {args.output}")


if __name__ == "__main__":
    main()
