"""Known vulnerabilities for pinned packages, from OSV (osv.dev) or an offline OSV export.

Online mode sends only package names and versions to api.osv.dev, never project code.
"""
from __future__ import annotations

import json
import re
import ssl
import time
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from functools import lru_cache
from dataclasses import dataclass, field
from pathlib import Path

from app.fixwatch.deps import Dependency, normalise

OSV_API = "https://api.osv.dev/v1"
ECOSYSTEM = "PyPI"
TIMEOUT_S = 8
MAX_DETAILS = 80  # advisory lookups per scan; keeps a huge lockfile from stalling the scan
WORKERS = 8       # advisory details fetched side by side
CACHE_S = 3600    # an answer for a package version is reused for an hour
_cache: dict[tuple[str, str], tuple[float, list]] = {}


class AdvisoryError(RuntimeError):
    pass


@dataclass
class Advisory:
    id: str
    summary: str
    fixed: list[str] = field(default_factory=list)  # versions that contain the fix
    cwes: list[str] = field(default_factory=list)
    aliases: list[str] = field(default_factory=list)

    @property
    def url(self) -> str:
        return f"https://osv.dev/vulnerability/{self.id}"


def version_key(version: str) -> tuple:
    """Good-enough ordering for PyPI versions: 2.10 > 2.9, 1.0 > 1.0rc1."""
    parts = []
    for piece in re.split(r"[.+!-]", version):
        num = re.match(r"\d+", piece)
        parts.append((1, int(num[0]), piece[num.end():]) if num else (0, 0, piece))
    return tuple(parts)


def parse_vuln(data: dict, package: str) -> Advisory:
    fixed = sorted({e["fixed"] for a in data.get("affected", [])
                    if normalise(a.get("package", {}).get("name", "")) == package
                    for r in a.get("ranges", []) for e in r.get("events", []) if "fixed" in e}, key=version_key)
    summary = data.get("summary") or (data.get("details") or "").strip().split("\n")[0][:200]
    cwes = list(data.get("database_specific", {}).get("cwe_ids", []))
    return Advisory(data["id"], summary or "No summary published.", fixed, cwes, list(data.get("aliases", [])))


def _affects(data: dict, dep: Dependency) -> bool:
    """Offline matching: the listed versions, or a range between introduced and fixed."""
    for affected in data.get("affected", []):
        if normalise(affected.get("package", {}).get("name", "")) != dep.name:
            continue
        if dep.version in affected.get("versions", []):
            return True
        for rng in affected.get("ranges", []):
            start, mine = None, version_key(dep.version)
            for event in rng.get("events", []):
                if "introduced" in event:
                    start = version_key(event["introduced"]) if event["introduced"] != "0" else ()
                if "fixed" in event and start is not None:
                    if start <= mine < version_key(event["fixed"]):
                        return True
                    start = None
            if start is not None and start <= mine:
                return True
    return False


@lru_cache(maxsize=1)
def _tls() -> ssl.SSLContext:
    """Verified TLS. Uses certifi's CA bundle when installed: python.org builds on macOS ship
    without system certificates, so the default context there cannot verify any site."""
    try:
        import certifi
    except ImportError:
        return ssl.create_default_context()
    return ssl.create_default_context(cafile=certifi.where())


def _post(url: str, payload: dict) -> dict:
    req = urllib.request.Request(url, data=json.dumps(payload).encode(), method="POST",
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=TIMEOUT_S, context=_tls()) as resp:
        return json.load(resp)


def _get(url: str) -> dict:
    with urllib.request.urlopen(url, timeout=TIMEOUT_S, context=_tls()) as resp:
        return json.load(resp)


def _fresh(dep: Dependency) -> list[Advisory] | None:
    hit = _cache.get((dep.name, dep.version))
    return hit[1] if hit and time.monotonic() - hit[0] < CACHE_S else None


def lookup_online(deps: list[Dependency]) -> dict[str, list[Advisory]]:
    """{package name: advisories affecting its pinned version}, from api.osv.dev.

    One batch query finds which versions are affected; the details of each advisory are then
    fetched in parallel. Answers are cached for an hour, so re-scans do not ask again.
    """
    out = {d.name: cached for d in deps if (cached := _fresh(d)) is not None}
    todo = [d for d in deps if d.name not in out]
    if not todo:
        return {name: found for name, found in out.items() if found}
    queries = [{"package": {"name": d.name, "ecosystem": ECOSYSTEM}, "version": d.version} for d in todo]
    try:
        results = _post(f"{OSV_API}/querybatch", {"queries": queries}).get("results", [])
        wanted = [(dep, v["id"]) for dep, r in zip(todo, results) for v in (r.get("vulns") or [])][:MAX_DETAILS]
        with ThreadPoolExecutor(max_workers=WORKERS) as pool:
            details = list(pool.map(lambda pair: _get(f"{OSV_API}/vulns/{pair[1]}"), wanted))
    except (OSError, ValueError, KeyError) as exc:
        raise AdvisoryError(f"could not reach the OSV advisory database: {exc}") from exc
    for dep in todo:
        out[dep.name] = []
    for (dep, _), data in zip(wanted, details):
        out[dep.name].append(parse_vuln(data, dep.name))
    for dep in todo:
        _cache[(dep.name, dep.version)] = (time.monotonic(), out[dep.name])
    return {name: found for name, found in out.items() if found}


def lookup_offline(deps: list[Dependency], path: Path) -> dict[str, list[Advisory]]:
    """Same answer from a local file: a JSON list of OSV records (or {"vulns": [...]})."""
    try:
        data = json.loads(path.read_text())
    except (OSError, ValueError) as exc:
        raise AdvisoryError(f"could not read the advisory file {path}: {exc}") from exc
    records = data.get("vulns", []) if isinstance(data, dict) else data
    out: dict[str, list[Advisory]] = {}
    for dep in deps:
        for record in records:
            if _affects(record, dep):
                out.setdefault(dep.name, []).append(parse_vuln(record, dep.name))
    return out
