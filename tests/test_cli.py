import io
import json
import subprocess
import sys
from pathlib import Path

import pytest

from netlens.cli import main, resolve_interface
from netlens.output import Output, safe_text

ROOT = Path(__file__).resolve().parents[1]


def run_cli(*args):
    return subprocess.run(
        [sys.executable, str(ROOT / "main.py"), *map(str, args)],
        capture_output=True,
        text=True,
        timeout=15,
    )


def test_help_and_version():
    assert run_cli("--help").returncode == 0
    result = run_cli("--version")
    assert result.stdout.strip() == "NetLens 1.0.0"
    assert result.returncode == 0


def test_offline_json_is_one_parseable_document(pcap):
    result = run_cli("--analyze", pcap, "--json")
    assert result.returncode == 0, result.stderr
    data = json.loads(result.stdout)
    assert data["total_packets"] == 33
    assert data["schema_version"] == 1
    assert "demo-only" not in result.stdout
    assert "\x1b" not in result.stdout


def test_packet_json_stream_includes_final_summary(pcap):
    result = run_cli("--analyze", pcap, "--json", "--packets", "-c", 4)
    assert result.returncode == 0, result.stderr
    records = [json.loads(line) for line in result.stdout.splitlines()]
    assert [row["event"] for row in records] == ["packet"] * 4 + ["summary"]
    assert records[-1]["total_packets"] == 4


def test_report_and_store_are_complete_and_bounded(pcap, tmp_path):
    report = tmp_path / "report.json"
    result = run_cli("--analyze", pcap, "--report", report, "--store", "--store-limit", 2)
    assert result.returncode == 0, result.stderr
    data = json.loads(report.read_text())
    assert data["total_packets"] == 33
    assert len(data["stored_packets"]) == 2
    assert "Report saved:" in result.stderr


def test_invalid_files_exit_nonzero_with_clean_stdout(tmp_path):
    missing = run_cli("--analyze", tmp_path / "missing.pcap", "--json")
    assert missing.returncode == 1
    assert missing.stdout == ""
    invalid = tmp_path / "invalid.pcap"
    invalid.write_bytes(b"This is not a capture file")
    result = run_cli("--analyze", invalid, "--json")
    assert result.returncode == 1
    assert result.stdout == ""
    assert "Traceback" not in result.stderr


@pytest.mark.parametrize(
    "args",
    [
        ["--count", "-1"],
        ["--timeout", "0"],
        ["--timeout", "nan"],
        ["--timeout", "inf"],
        ["--max-pcap-mb", "-1"],
        ["--store-limit", "0"],
        ["--store"],
        ["--analyze", "x", "--filter", "tcp"],
        ["--analyze", "x", "--timeout", "1"],
        ["--analyze", "x", "-o", "x"],
        ["--list-interfaces", "--report", "x"],
    ],
)
def test_invalid_options(args):
    result = run_cli(*args)
    assert result.returncode == 2
    assert result.stdout == ""


def test_existing_report_is_not_overwritten(pcap, tmp_path):
    report = tmp_path / "report.json"
    report.write_text("keep")
    result = run_cli("--analyze", pcap, "--report", report)
    assert result.returncode == 1
    assert report.read_text() == "keep"


def test_failed_analysis_removes_incomplete_report(tmp_path):
    invalid = tmp_path / "invalid.pcap"
    invalid.write_bytes(b"not a pcap")
    report = tmp_path / "report.json"
    result = run_cli("--analyze", invalid, "--report", report)
    assert result.returncode == 1
    assert not report.exists()


def test_hex_dump_works_without_verbose_or_show_raw(pcap):
    result = run_cli("--analyze", pcap, "--hex-dump", "-c", 1)
    assert result.returncode == 0
    assert "0000" in result.stdout
    assert "\x1b" not in result.stdout


def test_interfaces_json_is_valid():
    result = run_cli("--list-interfaces", "--json")
    assert result.returncode == 0, result.stderr
    assert isinstance(json.loads(result.stdout)["interfaces"], list)


def test_windows_interface_names_and_index(monkeypatch):
    monkeypatch.setattr(
        "netlens.cli.list_interfaces",
        lambda: [
            {"index": 0, "name": "Ethernet", "capture_name": r"\Device\NPF_{example}"},
        ],
    )
    assert resolve_interface("0") == r"\Device\NPF_{example}"
    assert resolve_interface("Ethernet") == r"\Device\NPF_{example}"
    with pytest.raises(ValueError, match="Unknown interface"):
        resolve_interface("99")


def test_terminal_controls_are_escaped():
    text = safe_text("Host: example.test\x1b[2J\n\u202eevil")
    assert "\x1b" not in text
    assert "\n" not in text
    assert "\u202e" not in text


def test_live_cli_json_remains_clean_with_alerts(monkeypatch, packets, capsys):
    def fake_start(sniffer):
        for packet in packets:
            sniffer._process_packet(packet)
        if sniffer.error:
            raise sniffer.error
        return sniffer.summary()

    monkeypatch.setattr("netlens.capture.NetLens.start", fake_start)
    assert main(["--json"]) == 0
    captured = capsys.readouterr()
    rows = [json.loads(line) for line in captured.out.splitlines()]
    assert len(rows) == 34
    assert rows[-1]["event"] == "summary"
    assert "Capturing on" in captured.err


def test_no_stats_disables_live_summary(monkeypatch, capsys):
    monkeypatch.setattr("netlens.capture.NetLens.start", lambda sniffer: sniffer.summary())
    assert main(["--json", "--no-stats"]) == 0
    assert capsys.readouterr().out == ""


def test_output_uses_ipv6_endpoint_brackets():
    stdout = io.StringIO()
    output = Output(stdout, io.StringIO())
    output.packet(
        {
            "number": 1,
            "timestamp": "now",
            "classification": "TCP",
            "length": 60,
            "ip": {"src": "2001:db8::1", "dst": "2001:db8::2"},
            "tcp": {"sport": 0, "dport": 443},
        }
    )
    assert "[2001:db8::1]:0 -> [2001:db8::2]:443" in stdout.getvalue()
