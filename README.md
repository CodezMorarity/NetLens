# NetLens

A **command-line network packet analyzer**. Capture live traffic,
inspect saved PCAP/PCAPNG files, follow bidirectional flows, and flag possible
cleartext secrets or SYN scans. Use it only on traffic you are authorized to inspect.

## Install

Requires Python **3.10+**. Run these commands in the project directory.

### Linux / macOS

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install .
netlens --help
```

If the checkout is on an exFAT/FAT drive that cannot create symlinks, put the
environment on your home filesystem instead:

```bash
python3 -m venv "$HOME/.venvs/netlens"
source "$HOME/.venvs/netlens/bin/activate"
python -m pip install .
```

Live capture normally needs root or appropriate capture permissions. BPF filters
require libpcap (e.g. `libpcap0.8` on Debian/Ubuntu or `libpcap` on Arch Linux).
macOS includes libpcap. Offline analysis needs neither root nor capture permissions.

### Windows (PowerShell)

```powershell
py -3 -m venv .venv
.\.venv\Scripts\python.exe -m pip install .
.\.venv\Scripts\netlens.exe --list-interfaces
```

Install [Npcap](https://npcap.com/#download) for live capture and use an elevated
terminal if your Npcap configuration requires it. Select an interface by its displayed
index, friendly name, or capture name. No Windows-only modules are imported on Linux/macOS.

The existing `venv/` directory, if present, is an old Windows environment; recreate
an environment on your own OS rather than copying it across machines.

For source checkout usage, `python -m pip install -r requirements.txt` followed by
`python main.py ...` works too. `python -m netlens ...` is equivalent.

## Try the demo without capturing traffic

```bash
python examples/generate_demo.py demo.pcap
netlens --analyze demo.pcap
netlens --analyze demo.pcap --json
netlens --analyze demo.pcap --packets --verbose
```

The generator writes **33 synthetic packets** using documentation addresses and
`example.test`; it sends nothing onto the network. Expected summary:

```text
NetLens capture summary
  Packets              33
  Captured bytes       2,041
  Capture span         1.600 s
  IPv4 / IPv6          30 / 2
  Average bandwidth    10.2 Kbps
  Flow sessions        28
  Active at end        28
  Findings             2
```

The findings are one demo password and one possible SYN scan. Output files must
have new names; existing files are never overwritten.

## Capture and analyze

```bash
# Discover interfaces. JSON is also supported.
netlens --list-interfaces

# Linux/macOS: use the Python executable from the installed environment.
sudo .venv/bin/python -m netlens -i eth0 -t 30

# Filter and save at most 100 packets; stop after 60 seconds even if idle.
sudo .venv/bin/python -m netlens -i eth0 -f 'tcp port 80 or tcp port 443' \
  -c 100 -t 60 -o capture.pcap --report capture-report.json

# Inspect an existing capture, including packet details and a hex dump.
netlens --analyze capture.pcap -v --hex-dump

# Export a JSON summary and retain only the most recent 50 packet records.
netlens --analyze capture.pcap --report analysis.json --store --store-limit 50

# Copy the first 100 packets from a saved capture into a new PCAP.
netlens --analyze capture.pcap -c 100 -o excerpt.pcap
```

Replace `eth0` with an interface listed on your machine. If the environment is in
your home directory, replace `.venv/bin/python` with that environment's Python path.
`-i`, `-f`, and `-t` apply to live capture; offline use of these options is rejected.
Ctrl+C and SIGTERM stop live capture, close output files, and emit one final summary.

## Output formats

| Mode | Standard output |
| --- | --- |
| Live capture | One line per packet, alerts, then a summary |
| Live `--json` | JSON Lines: `packet` records followed by one `summary` record |
| Offline `--analyze FILE` | One human-readable summary |
| Offline `--analyze FILE --json` | One JSON summary document |
| Offline `--packets --json` | JSON Lines: packet records and a final summary |
| `--report FILE` | Writes a separate, indented JSON summary file |

Status messages and errors go to stderr. JSON stdout never contains banners,
ANSI color codes, or plain-text alerts. `--verbose`, `--hex-dump`, and `--show-raw`
also enable packet output offline. `--no-stats` disables periodic statistics and
the final **live** summary; offline analysis still prints its result. Color is used
only on an interactive terminal and can be disabled with `--no-color`.

Reports have `schema_version: 1`. Packet records contain `event`, `number`,
`timestamp` (UTC), `epoch`, `length`, `classification`, protocol objects such as
`ip`, `tcp`, `dns`, `http`, and `security_findings`. Nested protocol objects keep
fields such as IP and DNS IDs distinct. Summary fields include packet/byte counts,
capture timestamps, bit rates, flow counts, top endpoints/ports, and finding counts
with the most recent 100 findings.

```bash
netlens --analyze demo.pcap --json > summary.json
netlens --analyze demo.pcap --packets --json > packets.jsonl
```

Exit codes: **0** success, **1** capture/file/dependency failure, **2** invalid CLI
arguments, **130** interrupted offline analysis.

## Analysis behavior and limits

- Parses Ethernet, IPv4, IPv6 (including common extension headers), TCP, UDP,
  ICMP/ICMPv6, ARP, DNS, and packet-local HTTP/1.x headers. Common service labels
  such as HTTPS, SSH, and QUIC are port-based hints, not verified application identities.
- Offline duration, flow expiration, and scan detection use **capture timestamps**.
  The summary's capture span is the last timestamp minus the first; a live capture
  also reports `wall_seconds`. Rates use captured bytes converted to bits. Current
  rates use ten 100 ms buckets; average rate is zero for a zero-duration capture.
- IP endpoint and port counts count packets involving that endpoint/port, once
  per packet. TCP/UDP flow sessions combine both directions, expire after 60 seconds
  of inactivity, and keep up to 10,000 active entries. Reused endpoints after expiration
  start a new session. `evicted_connections` reports capacity evictions.
- SYN detection flags at least 20 distinct destination IP/port pairs from one
  source within two seconds, with a two-second alert cooldown. Retransmissions to
  one target do not count as distinct targets. State is limited to 10,000 sources
  and 4,096 SYN events per source. Alerts are indicators for investigation, not proof.
- Detects password assignments, authorization/session headers, several common key
  formats, possible SSNs, and Luhn-valid payment-card-like numbers. Values are
  **redacted by default** in findings and sensitive HTTP fields. `--show-sensitive`
  reveals detected values. HTTP query strings are redacted by default.
- Raw PCAP exports preserve original traffic. `--show-raw` and `--hex-dump` explicitly
  expose bytes and may include secrets even when normal fields are redacted. Treat
  captures and reports as sensitive; default redaction is not a general-purpose data scrubber.
- Payload inspection is per packet: no TCP stream reassembly, IP defragmentation,
  TLS decryption, HTTP/2 decoding, or guaranteed detection of secrets split across
  packets. Binary/encrypted traffic and heuristic matches can produce false results.
- Files are read incrementally rather than loaded into memory. Full packets are
  not retained during capture. `--store` retains only the configured number of
  parsed records; aggregate counters still grow with distinct addresses and ports.
  NetLens is a Python inspection tool, not a lossless high-throughput capture system.
  Malformed record boundaries are rejected; individual PCAP records and PCAPNG
  blocks are limited to 16 MiB.

PCAP output flushes each packet and rotates at `--max-pcap-mb` (default 100 MiB),
including file and record headers. Rotated files stay beside the original as
`capture_1.pcap`, `capture_2.pcap`, etc. A single packet can exceed the requested
limit. Mixed link-layer types use separate files. Empty captures produce a valid
empty Ethernet PCAP. Write failures stop capture and return an error.

## Development and verification

```bash
python -m pip install -e '.[dev]'
python -m pytest -q
python -m ruff check .
python -m ruff format --check .
python -m build
```

Tests use synthetic captures and Scapy's asynchronous sniffer with an in-memory
socket. They cover protocol parsing, timing, scan heuristics, redaction, statistics,
PCAP/PCAPNG I/O, rotation, CLI output, invalid arguments, capture errors, and idle
shutdown. They require no root privileges and do not capture or send network traffic.
Scapy enumerates local interfaces at import time, so highly restricted sandboxes
may need permission to read interface metadata even for these offline tests.

```text
main.py                 Source-checkout launcher
netlens/cli.py          Arguments, interfaces, reports, exit codes
netlens/protocols.py    Packet decoding and classification
netlens/detection.py    Cleartext exposure and SYN scan heuristics
netlens/analysis.py     Statistics and bidirectional flow sessions
netlens/capture.py      Streaming PCAP I/O and capture lifecycle
netlens/output.py       Human and JSON output
examples/generate_demo.py
tests/
```

Scapy references: [capture and async sniffing](https://scapy.readthedocs.io/en/stable/usage.html#asynchronous-sniffing),
[PCAP readers and writers](https://scapy.readthedocs.io/en/stable/api/scapy.utils.html).
