"""Scan orchestration shared by the API: ingest -> filter -> detect -> score -> store."""

import time
from collections.abc import Callable
from pathlib import Path

from app.config import Settings
from app.detect.registry import active_detectors
from app.ingest import IngestError, github, upload
from app.ingest.filter import filter_project
from app.ingest.workspace import workspace_for
from app.models import Scan, ScanStatus
from app.pipeline import build_findings, run_detectors, severity_counts
from app.store import Store

NO_DETECTOR_NOTE = ("No detectors are installed or enabled, so no findings can be produced. "
                    "Install bandit or semgrep, or register the team detector.")


def source_root(scan_id: str, settings: Settings) -> Path:
    """Directory the scan's relative file paths are resolved against."""
    src = workspace_for(scan_id, settings) / "src"
    return upload.project_root(src) if src.exists() and any(src.iterdir()) else src


def analyse(scan: Scan, root: Path, store: Store, settings: Settings) -> Scan:
    started = time.monotonic()
    filtered = filter_project(root, settings.max_file_bytes)
    detectors = active_detectors()
    scan.notes.extend(filtered.notes)
    if not detectors:
        scan.notes.append(NO_DETECTOR_NOTE)
    candidates, det_notes = run_detectors(root, filtered.files, detectors,
                                          settings.detector_timeout_s)
    scan.notes.extend(det_notes)
    findings = build_findings(scan.id, candidates, started=started)
    store.replace_findings(scan.id, findings)
    scan.files_scanned = len(filtered.files)
    scan.detectors = [d.name for d in detectors]
    scan.finding_count = len(findings)
    scan.severity_counts = severity_counts(findings)
    scan.status = ScanStatus.DONE
    scan.finished_at = time.time()
    store.save_scan(scan)
    return scan


def _run(scan: Scan, store: Store, settings: Settings, prepare: Callable[[Path], None]) -> None:
    scan.status = ScanStatus.RUNNING
    store.save_scan(scan)
    src = workspace_for(scan.id, settings) / "src"
    try:
        prepare(src)
        analyse(scan, upload.project_root(src), store, settings)
    except IngestError as exc:
        _fail(scan, store, str(exc))
    except Exception as exc:  # noqa: BLE001 - background job: record, never crash the worker
        _fail(scan, store, f"Internal error: {type(exc).__name__}")
        raise


def _fail(scan: Scan, store: Store, message: str) -> None:
    scan.status = ScanStatus.FAILED
    scan.error = message
    scan.finished_at = time.time()
    store.save_scan(scan)


def run_zip_scan(scan: Scan, data: bytes, store: Store, settings: Settings) -> None:
    def prepare(src: Path) -> None:
        scan.notes.extend(upload.extract_zip(data, src, settings))
    _run(scan, store, settings, prepare)


def run_github_scan(scan: Scan, url: str, store: Store, settings: Settings) -> None:
    def prepare(src: Path) -> None:
        src.rmdir()  # git clone needs a missing or empty target
        github.clone(url, src, settings)
    _run(scan, store, settings, prepare)
