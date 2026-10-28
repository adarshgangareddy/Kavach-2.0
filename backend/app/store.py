"""SQLite persistence for users, scans and findings. Scans and findings belong to one user."""

import sqlite3
import threading
import time
import uuid
from contextlib import contextmanager
from pathlib import Path

from app.auth import User
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
CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    email TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL,
    created_at REAL NOT NULL
);
"""


class Store:
    def __init__(self, path: Path):
        path.parent.mkdir(parents=True, exist_ok=True)
        self.path = path
        self._lock = threading.Lock()
        with self._conn() as conn:
            conn.executescript(_SCHEMA)
            columns = {row[1] for row in conn.execute("PRAGMA table_info(scans)")}
            if "owner_id" not in columns:  # databases from before user accounts
                conn.execute("ALTER TABLE scans ADD COLUMN owner_id TEXT")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_scans_owner ON scans(owner_id, created_at)")

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

    # users

    @staticmethod
    def _user(row) -> User | None:
        return User(row[0], row[1], row[2]) if row else None

    def create_user(self, email: str, password_hash: str, role: str = "user") -> User:
        user = User(f"U-{uuid.uuid4().hex[:12]}", email, role)
        with self._conn() as conn:
            conn.execute("INSERT INTO users (id, email, password_hash, role, created_at) "
                         "VALUES (?, ?, ?, ?, ?)", (user.id, email, password_hash, role, time.time()))
        return user

    def get_user(self, user_id: str) -> User | None:
        with self._conn() as conn:
            row = conn.execute("SELECT id, email, role FROM users WHERE id = ?", (user_id,)).fetchone()
        return self._user(row)

    def get_user_by_email(self, email: str) -> tuple[User, str] | tuple[None, None]:
        """(user, password hash) or (None, None)."""
        with self._conn() as conn:
            row = conn.execute("SELECT id, email, role, password_hash FROM users WHERE email = ?",
                               (email,)).fetchone()
        return (self._user(row[:3]), row[3]) if row else (None, None)

    def set_password_hash(self, user_id: str, password_hash: str) -> None:
        with self._conn() as conn:
            conn.execute("UPDATE users SET password_hash = ? WHERE id = ?", (password_hash, user_id))

    def assign_unowned_scans(self, owner_id: str) -> int:
        """Give scans from before user accounts to `owner_id` (the seeded admin)."""
        with self._conn() as conn:
            return conn.execute("UPDATE scans SET owner_id = ? WHERE owner_id IS NULL",
                                (owner_id,)).rowcount

    # scans: every read takes the caller's user id; None means internal, unscoped access

    def save_scan(self, scan: Scan) -> None:
        with self._conn() as conn:
            conn.execute(
                "INSERT INTO scans (id, created_at, data, owner_id) VALUES (?, ?, ?, ?) "
                "ON CONFLICT(id) DO UPDATE SET data = excluded.data",
                (scan.id, scan.created_at, scan.model_dump_json(), scan.owner_id),
            )

    def _scan(self, row) -> Scan | None:
        if not row:
            return None
        scan = Scan.model_validate_json(row[0])
        scan.owner_id = row[1]
        return scan

    def get_scan(self, scan_id: str, owner_id: str | None = None) -> Scan | None:
        sql, args = "SELECT data, owner_id FROM scans WHERE id = ?", [scan_id]
        if owner_id is not None:
            sql += " AND owner_id = ?"
            args.append(owner_id)
        with self._conn() as conn:
            return self._scan(conn.execute(sql, args).fetchone())

    def list_scans(self, owner_id: str, limit: int = 50) -> list[Scan]:
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT data, owner_id FROM scans WHERE owner_id = ? ORDER BY created_at DESC LIMIT ?",
                (owner_id, limit),
            ).fetchall()
        return [self._scan(r) for r in rows]

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

    def get_finding(self, finding_id: str, owner_id: str | None = None) -> Finding | None:
        sql = "SELECT f.data FROM findings f JOIN scans s ON s.id = f.scan_id WHERE f.id = ?"
        args = [finding_id]
        if owner_id is not None:
            sql += " AND s.owner_id = ?"
            args.append(owner_id)
        with self._conn() as conn:
            row = conn.execute(sql, args).fetchone()
        return Finding.model_validate_json(row[0]) if row else None

    def update_status(self, finding_id: str, status: Status,
                      owner_id: str | None = None) -> Finding | None:
        finding = self.get_finding(finding_id, owner_id)
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
