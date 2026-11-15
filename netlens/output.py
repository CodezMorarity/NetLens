"""Human and machine-readable output. Packet text cannot emit terminal controls."""

import json
import unicodedata


def safe_text(value):
    return "".join(
        f"\\u{ord(char):04x}" if unicodedata.category(char) in {"Cc", "Cf", "Cs"} else char
        for char in str(value)
    )


def format_bps(value):
    for unit in ("bps", "Kbps", "Mbps", "Gbps"):
        if value < 1000 or unit == "Gbps":
            return f"{value:.1f} {unit}"
        value /= 1000


def _endpoint(address, port=None):
    if port is None:
        return str(address)
    return f"[{address}]:{port}" if ":" in address else f"{address}:{port}"


class Output:
    def __init__(self, stdout, stderr, json_output=False, verbose=False, no_color=False):
        self.stdout, self.stderr = stdout, stderr
        self.json_output, self.verbose = json_output, verbose
        self.color = not no_color and not json_output and stdout.isatty()
        if self.color:
            try:
                from colorama import AnsiToWin32

                self.stdout = AnsiToWin32(stdout, strip=False).stream
            except ImportError:
                pass

    def message(self, message):
        print(safe_text(message), file=self.stderr, flush=True)

    def json(self, data):
        print(json.dumps(data, ensure_ascii=True, allow_nan=False), file=self.stdout, flush=True)

    def packet(self, info):
        if self.json_output:
            self.json(info)
            return
        network = info.get("ip", info.get("arp", info.get("ethernet", {})))
        src = network.get("src", network.get("psrc", network.get("mac_src", "?")))
        dst = network.get("dst", network.get("pdst", network.get("mac_dst", "?")))
        transport = info.get("tcp", info.get("udp", {}))
        flow = (
            f"{_endpoint(src, transport.get('sport'))} -> {_endpoint(dst, transport.get('dport'))}"
        )
        detail = info.get("dns", {}).get("query", "")
        http = info.get("http", {})
        detail = http.get("request_line", http.get("status_line", detail))
        line = safe_text(
            f"{info['number']:>6}  {info['timestamp']}  {info['classification']:<10} "
            f"{flow}  {info['length']} B  {detail}"
        )
        if self.color:
            line = f"\033[36m{line}\033[0m"
        print(line, file=self.stdout, flush=True)
        if self.verbose:
            for key in ("ethernet", "ip", "tcp", "udp", "icmp", "arp", "dns", "http"):
                if key in info:
                    print(f"        {key.upper():<8} {safe_text(info[key])}", file=self.stdout)
        for finding in info.get("security_findings", []):
            print(
                safe_text(
                    f"        ! {finding['severity'].upper()}: {finding['pattern']} "
                    f"{finding['context']}"
                ),
                file=self.stdout,
            )
        if "raw_preview" in info:
            print(f"        PAYLOAD  {info['raw_preview']}", file=self.stdout)
        if "packet_hex" in info:
            data = bytes.fromhex(info["packet_hex"])
            for offset in range(0, len(data), 16):
                row = data[offset : offset + 16]
                ascii_text = "".join(chr(c) if 32 <= c < 127 else "." for c in row)
                print(f"        {offset:04x}  {row.hex(' '):<47}  {ascii_text}", file=self.stdout)

    def stats(self, data):
        self.message(
            f"Packets: {data['total_packets']:,} | "
            f"Bandwidth: {format_bps(data['current_bps'])} | "
            f"Packets/s: {data['current_pps']:,}"
        )

    def summary(self, data, stream=False):
        if self.json_output:
            self.json({"event": "summary", **data} if stream else data)
            return
        print("\nNetLens capture summary", file=self.stdout)
        for label, value in (
            ("Packets", f"{data['total_packets']:,}"),
            ("Captured bytes", f"{data['total_bytes']:,}"),
            ("Capture span", f"{data['elapsed_seconds']:.3f} s"),
            ("IPv4 / IPv6", f"{data['ipv4_packets']} / {data['ipv6_packets']}"),
            ("Average bandwidth", format_bps(data["average_bps"])),
            ("Flow sessions", data["total_connections"]),
            ("Active at end", data["active_connections"]),
            ("Findings", data["security_findings"]["total"]),
        ):
            print(f"  {label:<20} {value}", file=self.stdout)
        for label, items in (
            ("Protocols", data["top_protocols"]),
            ("IP endpoints", data["top_talkers_ip"][:5]),
            ("Ports", data["top_ports"][:5]),
            ("Finding types", data["security_findings"]["by_type"].items()),
        ):
            text = ", ".join(f"{name} ({count})" for name, count in items) or "none"
            print(f"  {label:<20} {safe_text(text)}", file=self.stdout)
        for path in data.get("pcap_files", []):
            print(f"  PCAP saved           {safe_text(path)}", file=self.stdout)
