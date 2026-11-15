"""Heuristic cleartext exposure and SYN sweep detection."""

import re
from collections import OrderedDict, deque

SYN_THRESHOLD = 20
SYN_WINDOW = 2.0

_RULES = [
    (rb"\b(?:password|passwd|pwd)\s*[\"']?\s*[:=]\s*[\"']?[^\s&;\"']+", "Password", "high"),
    (
        rb"\b(?:api[_-]?key|x-api-key|client_secret|secret|access_token|refresh_token|token|x-auth-token)"
        rb"\s*[\"']?\s*[:=]\s*[\"']?[^\s&;\"']+",
        "Secret or token",
        "high",
    ),
    (rb"\b(?:proxy-)?authorization\s*:\s*[^\r\n]+", "Authorization header", "high"),
    (rb"\b(?:set-)?cookie\s*:\s*[^\r\n]+", "Session cookie", "medium"),
    (rb"\bAKIA[A-Z0-9]{16}\b", "AWS access key", "high"),
    (rb"\bgh[pousr]_[A-Za-z0-9]{20,}\b", "GitHub token", "high"),
    (rb"\bgithub_pat_[A-Za-z0-9_]{20,}\b", "GitHub token", "high"),
    (rb"\bxox[baprs]-[A-Za-z0-9-]{10,}\b", "Slack token", "high"),
    (rb"\bsk_(?:live|test)_[A-Za-z0-9]{16,}\b", "Stripe secret key", "high"),
    (rb"-----BEGIN (?:RSA |EC |OPENSSH |DSA |ENCRYPTED )?PRIVATE KEY-----", "Private key", "high"),
]
CREDENTIAL_PATTERNS = [(re.compile(p, re.I), label, severity) for p, label, severity in _RULES]
_SSN = re.compile(rb"\b(\d{3})-(\d{2})-(\d{4})\b")
_CARD = re.compile(rb"(?<!\d)(?:\d[ -]?){12,18}\d(?!\d)")


def _luhn(digits):
    values = [int(n) for n in digits.decode("ascii")]
    return (
        len(set(values)) > 1
        and sum(
            n if i % 2 == 0 else (2 * n - 9 if n > 4 else 2 * n)
            for i, n in enumerate(reversed(values))
        )
        % 10
        == 0
    )


def analyze_payload(raw_bytes, show_sensitive=False):
    """Return indicators, with no surrounding payload or secret values by default."""
    findings = []
    seen = set()

    def add(match, label, severity, kind="credential"):
        if label in seen:
            return
        seen.add(label)
        context = (
            match.group().decode("utf-8", errors="replace") if show_sensitive else "[redacted]"
        )
        findings.append(
            {"type": kind, "pattern": label, "severity": severity, "context": context[:200]}
        )

    for pattern, label, severity in CREDENTIAL_PATTERNS:
        match = pattern.search(raw_bytes)
        if match:
            add(match, label, severity)
    for match in _SSN.finditer(raw_bytes):
        area, group, serial = (int(part) for part in match.groups())
        if 0 < area < 900 and area != 666 and group and serial:
            add(match, "Possible SSN", "medium", "pii")
    for match in _CARD.finditer(raw_bytes):
        digits = re.sub(rb"\D", b"", match.group())
        if 13 <= len(digits) <= 19 and _luhn(digits):
            add(match, "Possible payment card", "medium", "pii")
    return findings


class SYNScanDetector:
    """Detect unique targets in capture time, with cooldown and bounded state."""

    def __init__(self, threshold=SYN_THRESHOLD, window=SYN_WINDOW, max_sources=10000):
        self.threshold = threshold
        self.window = window
        self.max_sources = max_sources
        self.syn_tracker = OrderedDict()
        self.last_alert = {}
        self.watermark = float("-inf")
        self.last_cleanup = float("-inf")

    def check(self, src_ip, src_port, dst_ip, dst_port, timestamp):
        self.watermark = max(timestamp, self.watermark)
        cutoff = self.watermark - self.window
        if timestamp < cutoff:
            return None
        if self.watermark - self.last_cleanup >= self.window:
            for source, entries in list(self.syn_tracker.items()):
                if not entries or max(t for t, _, _ in entries) < cutoff:
                    del self.syn_tracker[source]
                    self.last_alert.pop(source, None)
            self.last_cleanup = self.watermark
        entries = self.syn_tracker.setdefault(src_ip, deque(maxlen=4096))
        self.syn_tracker.move_to_end(src_ip)
        while len(self.syn_tracker) > self.max_sources:
            source, _ = self.syn_tracker.popitem(last=False)
            self.last_alert.pop(source, None)
        entries.append((timestamp, dst_ip, dst_port))
        # Filter rather than pop from the left: PCAP timestamps can arrive out of order.
        entries = deque((entry for entry in entries if entry[0] >= cutoff), maxlen=4096)
        self.syn_tracker[src_ip] = entries
        targets = {(dst, port) for _, dst, port in entries}
        if len(targets) < self.threshold:
            return None
        if self.watermark - self.last_alert.get(src_ip, float("-inf")) < self.window:
            return None
        self.last_alert[src_ip] = self.watermark
        return {
            "source": src_ip,
            "unique_targets": len(targets),
            "total_syn": len(entries),
            "window_seconds": self.window,
        }
