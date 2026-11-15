"""NetLens CLI; help and version work without capture dependencies installed."""

import argparse
import json
import math
import sys
from contextlib import ExitStack, contextmanager
from pathlib import Path

from . import __version__
from .output import Output, safe_text


def nonnegative_int(value):
    number = int(value)
    if number < 0:
        raise argparse.ArgumentTypeError("must be zero or greater")
    return number


def positive_int(value):
    number = int(value)
    if number <= 0:
        raise argparse.ArgumentTypeError("must be greater than zero")
    return number


def positive_float(value):
    number = float(value)
    if not math.isfinite(number) or number <= 0:
        raise argparse.ArgumentTypeError("must be a finite number greater than zero")
    return number


def build_parser():
    parser = argparse.ArgumentParser(
        description="NetLens — live packet capture and offline network analysis.",
        epilog="Capture only traffic you are authorized to inspect. Created by Tejas Chandola.",
    )
    parser.add_argument("--version", action="version", version=f"NetLens {__version__}")
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument(
        "--analyze", metavar="FILE", help="Analyze PCAP/PCAPNG without capture privileges"
    )
    mode.add_argument(
        "--list-interfaces", action="store_true", help="List capture interfaces and exit"
    )
    parser.add_argument("-i", "--interface", help="Interface name or index from --list-interfaces")
    parser.add_argument("-f", "--filter", help="Live-capture BPF filter, e.g. 'tcp port 443'")
    parser.add_argument(
        "-c",
        "--count",
        type=nonnegative_int,
        default=0,
        help="Process at most N packets (0 = unlimited)",
    )
    parser.add_argument(
        "-t", "--timeout", type=positive_float, help="Stop live capture after N seconds"
    )
    parser.add_argument("-o", "--output", help="Write packets to a new PCAP file")
    parser.add_argument(
        "--max-pcap-mb",
        type=positive_float,
        default=100,
        help="Rotate PCAP output after N MiB (default: 100)",
    )
    parser.add_argument(
        "--report", metavar="FILE", help="Write the final JSON report to a new file"
    )
    output = parser.add_mutually_exclusive_group()
    output.add_argument("-j", "--json", action="store_true", help="Machine-readable JSON output")
    output.add_argument(
        "-v", "--verbose", action="store_true", help="Show each packet's protocol fields"
    )
    parser.add_argument(
        "--packets", action="store_true", help="Also emit individual packets in offline mode"
    )
    parser.add_argument("--no-color", action="store_true", help="Disable terminal colors")
    parser.add_argument(
        "--no-stats", action="store_true", help="Disable periodic statistics and final live summary"
    )
    parser.add_argument(
        "--hex-dump",
        action="store_true",
        help="Show up to 512 packet bytes as hex (may include secrets)",
    )
    parser.add_argument(
        "--show-raw",
        action="store_true",
        help="Show up to 200 payload bytes as hex (may include secrets)",
    )
    parser.add_argument(
        "--show-sensitive",
        action="store_true",
        help="Show detected secret values and sensitive HTTP fields",
    )
    parser.add_argument(
        "--store", action="store_true", help="Include recent packet records in --report"
    )
    parser.add_argument(
        "--store-limit",
        type=positive_int,
        default=1000,
        help="Maximum records retained with --store (default: 1000)",
    )
    return parser


def list_interfaces():
    from scapy.all import conf

    interfaces = []
    for index, iface in enumerate(conf.ifaces.values()):
        addresses = iface.ips.values() if isinstance(iface.ips, dict) else [iface.ips]
        ips = [
            str(address)
            for group in addresses
            for address in (group if isinstance(group, (list, tuple)) else [group])
        ]
        interfaces.append(
            {
                "index": index,
                "name": iface.name,
                "capture_name": iface.network_name,
                "description": iface.description,
                "addresses": ips,
            }
        )
    return interfaces


def resolve_interface(value):
    if value is None:
        return None
    interfaces = list_interfaces()
    if value.isdecimal():
        index = int(value)
        if index < len(interfaces):
            return interfaces[index]["capture_name"]
    for iface in interfaces:
        if value in (iface["name"], iface["capture_name"]):
            return iface["capture_name"]
    raise ValueError(f"Unknown interface {value!r}. Run --list-interfaces to see available names.")


@contextmanager
def new_report(path):
    """Reserve a new output early; remove only our incomplete report on failure."""
    report = open(path, "x", encoding="utf-8")
    try:
        with report:
            yield report
    except BaseException:
        Path(path).unlink(missing_ok=True)
        raise


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.analyze and (args.interface or args.filter or args.timeout):
        parser.error("--interface, --filter, and --timeout apply only to live capture")
    if args.store and not args.report:
        parser.error("--store requires --report FILE")
    if args.max_pcap_mb * 1024 * 1024 < 24:
        parser.error("--max-pcap-mb must allow at least a 24-byte PCAP header")
    if args.list_interfaces and (
        args.output
        or args.report
        or args.store
        or args.interface
        or args.filter
        or args.timeout
        or args.count
    ):
        parser.error("capture and report options cannot be used with --list-interfaces")
    paths = [Path(p).resolve() for p in (args.analyze, args.output, args.report) if p]
    if len(set(paths)) != len(paths):
        parser.error("input, PCAP output, and JSON report must be different files")
    output = Output(sys.stdout, sys.stderr, args.json, args.verbose, args.no_color)
    try:
        from scapy.error import Scapy_Exception

        from .analysis import Analyzer
        from .capture import NetLens
    except ImportError as exc:
        output.message(
            f"NetLens dependency missing: {exc}. Install with: python -m pip install -r requirements.txt"
        )
        return 1
    except OSError as exc:
        output.message(f"Cannot initialize network interfaces: {exc}")
        return 1
    try:
        if args.list_interfaces:
            interfaces = list_interfaces()
            if args.json:
                output.json({"interfaces": interfaces})
            else:
                print("Available network interfaces:")
                for iface in interfaces:
                    print(
                        safe_text(
                            f"  [{iface['index']}] {iface['name']}  "
                            f"{', '.join(iface['addresses'])}  {iface['description']}"
                        )
                    )
            return 0
        if args.analyze and not Path(args.analyze).is_file():
            raise FileNotFoundError(f"Capture file not found: {args.analyze}")
        interface = resolve_interface(args.interface)
        analyzer = Analyzer(args.show_sensitive, args.show_raw, args.hex_dump)
        emit_packets = (
            not args.analyze or args.packets or args.verbose or args.hex_dump or args.show_raw
        )
        sniffer = NetLens(
            interface=interface,
            bpf_filter=args.filter,
            count=args.count,
            timeout=args.timeout,
            pcap_out=args.output,
            max_size_mb=args.max_pcap_mb,
            analyzer=analyzer,
            on_packet=output.packet if emit_packets else None,
            on_stats=output.stats if not args.no_stats and not args.json else None,
            store_limit=args.store_limit if args.store else 0,
        )
        with ExitStack() as stack:
            report = stack.enter_context(new_report(args.report)) if args.report else None
            if args.analyze:
                data = sniffer.analyze(args.analyze)
            else:
                output.message(
                    f"NetLens {__version__} | Capturing on {interface or 'default interface'}. Ctrl+C stops capture."
                )
                data = sniffer.start()
            data.update(
                schema_version=1,
                netlens_version=__version__,
                source={
                    "mode": "offline" if args.analyze else "live",
                    "file": args.analyze,
                    "interface": interface,
                    "filter": args.filter,
                },
            )
            if report:
                json.dump(data, report, indent=2, ensure_ascii=True, allow_nan=False)
                report.write("\n")
                report.flush()
                output.message(f"Report saved: {args.report}")
        if args.analyze or not args.no_stats:
            output.summary(data, stream=emit_packets)
        return 0
    except BrokenPipeError:
        try:
            sys.stdout.close()
        except OSError:
            pass
        return 0
    except KeyboardInterrupt:
        output.message("Analysis interrupted.")
        return 130
    except PermissionError as exc:
        output.message(
            f"Permission denied: {exc}. Live capture may require root/Administrator; check file permissions too."
        )
        return 1
    except FileExistsError as exc:
        output.message(f"Output file already exists: {exc.filename}. Choose a new filename.")
        return 1
    except (OSError, ValueError, RuntimeError, Scapy_Exception) as exc:
        output.message(f"NetLens error: {exc}")
        if not args.analyze:
            output.message(
                "Check the interface and BPF filter. Filters require libpcap; Windows capture requires Npcap."
            )
        return 1
