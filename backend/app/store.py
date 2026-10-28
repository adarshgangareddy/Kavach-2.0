"""SQLite persistence for scans and findings."""

import sqlite3
import threading
from contextlib import contextmanager
from pathlib import Path

from app.models import Scan
from app.rank.priority import sort_by_priority
from app.schema import Finding, Status

_SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    id TEXT PRIMARY KEY,
    created_at REAL NOT NULL,
    data TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS findings (
    id TEXT PRIMARY KEY,
    scan_id TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    status TEXT NOT NULL,
    severity REAL NOT NULL,
    cwe TEXT NOT NULL,
    data TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_findings_scan ON findings(scan_id, severity DESC);
"""


class Store:
    def __init__(self, path: Path):
        path.parent.mkdir(parents=True, exist_ok=True)
        self.path = path
        self._lock = threading.Lock()
        with self._conn() as conn:
            conn.executescript(_SCHEMA)

    @contextmanager
    def _conn(self):
        with self._lock:
            conn = sqlite3.connect(self.path)
            conn.execute("PRAGMA foreign_keys = ON")
            try:
                yield conn
                conn.commit()
            finally:
                conn.close()

    def save_scan(self, scan: Scan) -> None:
        with self._conn() as conn:
            conn.execute(
                "INSERT INTO scans (id, created_at, data) VALUES (?, ?, ?) "
                "ON CONFLICT(id) DO UPDATE SET data = excluded.data",
                (scan.id, scan.created_at, scan.model_dump_json()),
            )

    def get_scan(self, scan_id: str) -> Scan | None:
        with self._conn() as conn:
            row = conn.execute("SELECT data FROM scans WHERE id = ?", (scan_id,)).fetchone()
        return Scan.model_validate_json(row[0]) if row else None

    def list_scans(self, limit: int = 50) -> list[Scan]:
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT data FROM scans ORDER BY created_at DESC LIMIT ?", (limit,)
            ).fetchall()
        return [Scan.model_validate_json(r[0]) for r in rows]

    def replace_findings(self, scan_id: str, findings: list[Finding]) -> None:
        with self._conn() as conn:
            conn.execute("DELETE FROM findings WHERE scan_id = ?", (scan_id,))
            conn.executemany(
                "INSERT INTO findings (id, scan_id, status, severity, cwe, data) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                [(f.id, f.scan_id, f.status.value, f.severity, f.cwe, f.model_dump_json())
                 for f in findings],
            )

    def list_findings(self, scan_id: str, *, status: Status | None = None,
                      cwe: str | None = None, min_severity: float | None = None) -> list[Finding]:
        sql = "SELECT data FROM findings WHERE scan_id = ?"
        args: list = [scan_id]
        if status is not None:
            sql += " AND status = ?"
            args.append(status.value)
        if cwe:
            sql += " AND cwe = ?"
            args.append(cwe)
        if min_severity is not None:
            sql += " AND severity >= ?"
            args.append(min_severity)
        sql += " ORDER BY id"
        with self._conn() as conn:
            rows = conn.execute(sql, args).fetchall()
        return sort_by_priority(Finding.model_validate_json(r[0]) for r in rows)

    def get_finding(self, finding_id: str) -> Finding | None:
        with self._conn() as conn:
            row = conn.execute("SELECT data FROM findings WHERE id = ?", (finding_id,)).fetchone()
        return Finding.model_validate_json(row[0]) if row else None

    def update_status(self, finding_id: str, status: Status) -> Finding | None:
        finding = self.get_finding(finding_id)
        if finding is None:
            return None
        finding = finding.model_copy(update={"status": status})
        with self._conn() as conn:
            conn.execute(
                "UPDATE findings SET status = ?, data = ? WHERE id = ?",
                (status.value, finding.model_dump_json(), finding_id),
            )
        return finding


def summary(findings: list[Finding]) -> dict:
    by_cwe: dict[str, int] = {}
    by_status: dict[str, int] = {}
    for f in findings:
        by_cwe[f.cwe] = by_cwe.get(f.cwe, 0) + 1
        by_status[f.status.value] = by_status.get(f.status.value, 0) + 1
    return {"total": len(findings), "by_cwe": by_cwe, "by_status": by_status}
