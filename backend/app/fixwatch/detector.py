"""Fix-watcher detector: pinned dependencies with published security fixes, where the code uses them.

Off unless SENTINEL_FIXWATCH is set, so scans, the CLI and the commit hook stay offline by default:
    SENTINEL_FIXWATCH=osv              ask api.osv.dev (sends package names and versions, never code)
    SENTINEL_FIXWATCH=/path/vulns.json use a downloaded OSV export instead, fully offline

One finding per vulnerable package, on the first line of project code that imports it. Packages the
code never imports are left out: their fixes cannot affect this project's code paths.
"""
from __future__ import annotations

import os
from pathlib import Path

from app.detect.base import Candidate
from app.fixwatch.advisories import Advisory, lookup_offline, lookup_online, version_key
from app.fixwatch.deps import Dependency, find_dependencies
from app.fixwatch.usage import Use, find_uses
from app.schema import ConfidenceTier

CWE = "CWE-1395"  # dependency on a vulnerable third-party component
ENV = "SENTINEL_FIXWATCH"
LISTED = 5        # advisories spelled out in the fix advice; the rest are counted


def mode() -> str:
    """"off", "osv", or the path of an offline advisory file."""
    value = os.environ.get(ENV, "").strip()
    return value if value and value.lower() not in {"0", "off", "false", "no"} else "off"


def upgrade_to(advisories: list[Advisory]) -> str | None:
    """The lowest version that fixes every advisory, when each one names a fix."""
    if not advisories or any(not a.fixed for a in advisories):
        return None
    return max((min(a.fixed, key=version_key) for a in advisories), key=version_key)


def advice(dep: Dependency, advisories: list[Advisory]) -> str:
    target = upgrade_to(advisories)
    head = (f"Upgrade {dep.name} from {dep.version} to {target} or later in {dep.file} (line {dep.line}), "
            "then run your tests." if target else
            f"Upgrade {dep.name} past {dep.version} in {dep.file} (line {dep.line}); some advisories list no "
            "fixed version yet, so read them for a workaround.")
    listed = "; ".join(f"{a.id}: {a.summary} ({a.url})" for a in advisories[:LISTED])
    more = f"; and {len(advisories) - LISTED} more" if len(advisories) > LISTED else ""
    return f"{head} Fixes: {listed}{more}."


def to_candidate(dep: Dependency, advisories: list[Advisory], use: Use) -> Candidate:
    count = len(advisories)
    return Candidate(
        file=use.file, line=use.line, cwe=CWE, detector=FixWatchDetector.name,
        source=f"{dep.file}:{dep.line} {dep.spec}",
        sink=f"{dep.name} {dep.version} has {count} published security {'fix' if count == 1 else 'fixes'} "
             "you do not have",
        path=[f"import {use.module}"],
        confidence_tier=ConfidenceTier.PATTERN_MATCH,
        confidence=0.7,
        fix_suggestion=advice(dep, advisories),
    )


class FixWatchDetector:
    name = "fixwatch"
    version = "fixwatch-1"
    whole_program = True  # reads dependency files at the project root, not one Python file

    def available(self) -> bool:
        return mode() != "off"

    def lookup(self, deps: list[Dependency]) -> dict[str, list[Advisory]]:
        source = mode()
        return lookup_online(deps) if source == "osv" else lookup_offline(deps, Path(source))

    def scan(self, root: Path, files: list[str], timeout_s: float) -> list[Candidate]:
        deps = find_dependencies(root)
        found = self.lookup(deps) if deps else {}
        out = []
        for dep in deps:
            advisories = found.get(dep.name)
            uses = find_uses(root, files, dep.name) if advisories else []
            if uses:
                out.append(to_candidate(dep, advisories, uses[0]))
        return out
