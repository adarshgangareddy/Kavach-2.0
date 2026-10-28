"""Kavach telemetry for Flask apps: report suspicious requests to the Kavach dashboard.

Copy this file into your Flask project, then:

    from kavach_telemetry import init_kavach_telemetry
    init_kavach_telemetry(app,
                          kavach_url="http://localhost:8080/api",
                          app_key=os.environ["KAVACH_APP_KEY"])

Get the app key from the Monitoring page in Kavach. Standard library only.
Alerts are sent from a background thread, so a slow or offline Kavach never slows your app.

What it checks on every request:
- bodies over 5 MB: always rejected with 400
- SQL injection and path traversal patterns in the path, query string, form fields and JSON values:
  reported to Kavach; rejected with 403 only when block_attacks=True

Pattern matching is a tripwire, not a fix. Attackers can phrase payloads to dodge it, and ordinary
text can trip it, which is why attacks are only reported by default. The real fix is in the code:
parameterised queries and safe path handling, which Kavach's scanner checks for.
"""
from __future__ import annotations

import json
import logging
import queue
import re
import threading
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Iterable, Iterator
from urllib.parse import unquote_plus

MAX_BODY_BYTES = 5 * 1024 * 1024  # 5 MB
SEND_TIMEOUT = 2.0
QUEUE_SIZE = 500  # alerts waiting to be sent; extra ones are dropped, never blocking a request
MAX_FIELDS = 200  # inputs inspected per request
MAX_VALUE_CHARS = 4096  # characters inspected per input
SAMPLE_CHARS = 120  # characters of the matching input sent to Kavach

log = logging.getLogger("kavach_telemetry")

SQL = "sql_injection"
PATH = "path_traversal"

# (category, label, pattern), matched against normalised input: decoded, lower case, SQL comments removed.
RULES = [
    (SQL, "UNION SELECT", r"\bunion\s+(all\s+|distinct\s+)?select\b"),
    (SQL, "SELECT ... FROM", r"\bselect\s+[\w*,.()@`\" ]{1,80}?\s+from\s+[\w.`\"\[]+"),
    (SQL, "quote then OR/AND comparison", r"['\"]\s*\)?\s*(or|and)\s+['\"]?[\w]+['\"]?\s*(=|<|>|like\b)"),
    (SQL, "stacked query", r";\s*(drop\s+(table|database)\b|delete\s+from\b|insert\s+into\b"
                           r"|update\s+[\w.`\"]+\s+set\b|alter\s+table\b|truncate\s+table\b"
                           r"|exec(ute)?\s*(\(|@|xp_|sp_|master\.)|create\s+table\b)"),
    (SQL, "quote then comment", r"['\"]\s*\)?\s*(--|#)"),
    (SQL, "time delay function", r"\b(sleep|pg_sleep|benchmark)\s*\(|\bwaitfor\s+delay\b"),
    (PATH, "../ sequence", r"(^|[/\\])\.\.([/\\]|$)"),
    (PATH, "sensitive system file", r"/etc/(passwd|shadow|hosts)\b|/proc/self/|\bwin\.ini\b|\bboot\.ini\b"),
    (PATH, "null byte", r"\x00"),
]
_COMPILED = [(category, label, re.compile(pattern)) for category, label, pattern in RULES]
_SQL_COMMENT = re.compile(r"/\*.*?\*/", re.S)


@dataclass(frozen=True)
class Match:
    category: str
    label: str
    field: str
    sample: str


def normalize(value: str) -> list[str]:
    """Undo the disguises payloads use: extra URL encoding, inline SQL comments, odd case and spacing.

    Two readings, because a comment can split a keyword (UN/**/ION) or stand in for a space (UNION/**/SELECT).
    """
    text = value[:MAX_VALUE_CHARS]
    for _ in range(2):  # Flask decoded once already; this catches %252e%252e and friends
        decoded = unquote_plus(text)
        if decoded == text:
            break
        text = decoded
    text = text.lower()
    return [" ".join(_SQL_COMMENT.sub(gap, text).split()) for gap in ("", " ")]


def find_attack(fields: Iterable[tuple[str, str]]) -> Match | None:
    """The first rule that matches any (field name, value) pair, or None."""
    for count, (name, value) in enumerate(fields):
        if count >= MAX_FIELDS:
            return None
        texts = normalize(value)
        for category, label, pattern in _COMPILED:
            if any(pattern.search(text) for text in texts):
                return Match(category, label, name, value[:SAMPLE_CHARS])
    return None


def _json_values(data, prefix: str = "json", depth: int = 0) -> Iterator[tuple[str, str]]:
    if depth > 5:
        return
    if isinstance(data, dict):
        for key, value in data.items():
            yield from _json_values(value, f"{prefix}.{key}", depth + 1)
    elif isinstance(data, list):
        for index, value in enumerate(data):
            yield from _json_values(value, f"{prefix}[{index}]", depth + 1)
    elif isinstance(data, str):
        yield prefix, data


def request_fields(req) -> Iterator[tuple[str, str]]:
    """Every user-controlled input worth checking: path, query string, form fields, JSON strings."""
    yield "path", req.path
    for key, value in req.args.items(multi=True):
        yield f"query.{key}", value
    for key, value in req.form.items(multi=True):
        yield f"form.{key}", value
    if req.is_json:
        yield from _json_values(req.get_json(silent=True))


class KavachReporter:
    """Sends alerts to Kavach's /alerts intake, one at a time, off the request path."""

    def __init__(self, kavach_url: str, app_key: str):
        self.endpoint = kavach_url.rstrip("/") + "/alerts"
        self.app_key = app_key
        self._queue: queue.Queue[dict] = queue.Queue(maxsize=QUEUE_SIZE)
        threading.Thread(target=self._worker, name="kavach-telemetry", daemon=True).start()

    def report(self, reason: str, endpoint: str, method: str, client_ip: str | None = None,
               size_bytes: int | None = None, match: Match | None = None) -> None:
        alert = {"timestamp": datetime.now(timezone.utc).isoformat(), "endpoint": endpoint[:512],
                 "method": method[:16], "reason": reason[:200], "client_ip": client_ip,
                 "size_bytes": size_bytes}
        if match:
            alert |= {"category": match.category, "field": match.field[:128], "sample": match.sample}
        try:
            self._queue.put_nowait(alert)
        except queue.Full:
            log.warning("Kavach alert queue full; dropped an alert")

    def _worker(self) -> None:
        while True:
            self._send(self._queue.get())

    def _send(self, alert: dict) -> None:
        request = urllib.request.Request(
            self.endpoint, data=json.dumps(alert).encode(), method="POST",
            headers={"Content-Type": "application/json", "X-Kavach-Key": self.app_key})
        try:
            with urllib.request.urlopen(request, timeout=SEND_TIMEOUT):
                pass
        except Exception as error:  # Kavach being down must never break the monitored app
            log.warning("Could not send alert to Kavach: %s", error)


def init_kavach_telemetry(app, kavach_url: str, app_key: str, max_body_bytes: int = MAX_BODY_BYTES,
                          block_attacks: bool = False) -> KavachReporter:
    """Reject oversized bodies, and report (optionally block) injection and traversal patterns."""
    from flask import jsonify, request

    reporter = KavachReporter(kavach_url, app_key)

    @app.before_request
    def _kavach_check():
        size = request.content_length
        if size is not None and size > max_body_bytes:
            reporter.report("Payload too large", request.path, request.method,
                            client_ip=request.remote_addr, size_bytes=size)
            return jsonify(error="Request body too large"), 400
        match = find_attack(request_fields(request))
        if match is None:
            return None
        reporter.report(f"{'SQL injection' if match.category == SQL else 'Path traversal'} pattern: {match.label}",
                        request.path, request.method, client_ip=request.remote_addr, match=match)
        if block_attacks:
            return jsonify(error="Request blocked"), 403
        return None

    app.extensions["kavach"] = reporter  # other code can call app.extensions["kavach"].report(...)
    return reporter
