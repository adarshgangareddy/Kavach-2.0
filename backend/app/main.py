"""FastAPI application (PRD section 8, L5 API)."""

import logging
from contextlib import asynccontextmanager
from functools import lru_cache
from pathlib import Path
from typing import Annotated, Literal

from fastapi import (BackgroundTasks, Depends, FastAPI, File, Form, HTTPException,
                     Path as PathParam, Query, Request, UploadFile)
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, PlainTextResponse, Response

from app import __version__, service
from app.config import Settings, get_settings
from app.detect.registry import all_detectors
from app.ingest import IngestError, github, upload
from app.ingest.snippet import write_snippet
from app.ingest.workspace import fresh_workspace, resolve_source_file
from app.models import SCAN_ID_PATTERN, Scan, SnippetRequest, StatusUpdate
from app.rank.model import load_model
from app.report import owasp, sarif
from app.report.export import json_report, pdf_report
from app.schema import Finding, Status
from app.store import Store
from app import vault

log = logging.getLogger("zeroday_sentinel")


@asynccontextmanager
async def lifespan(_: FastAPI):
    """Encrypt any workspace still in plaintext (scans from before encryption at rest)."""
    if sealed := vault.seal_existing(get_settings()):
        log.warning("Encrypted %d plaintext scan workspaces at rest", sealed)
    yield


app = FastAPI(title="ZeroDay Sentinel", version=__version__, lifespan=lifespan)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"],
    allow_methods=["GET", "POST", "PATCH"],
    allow_headers=["Content-Type"],
)

def ranker_status() -> str:
    return load_model()[1]


ScanId = Annotated[str, PathParam(pattern=SCAN_ID_PATTERN)]
FindingId = Annotated[str, PathParam(pattern=r"^F-[0-9a-f]{8}-\d{3,}$")]


@lru_cache
def _store_for(db_path: str) -> Store:
    return Store(Path(db_path))


def settings_dep() -> Settings:
    return get_settings()


def store_dep(settings: Annotated[Settings, Depends(settings_dep)]) -> Store:
    return _store_for(str(settings.db_path))


SettingsDep = Annotated[Settings, Depends(settings_dep)]
StoreDep = Annotated[Store, Depends(store_dep)]


@app.exception_handler(IngestError)
async def _ingest_error(_: Request, exc: IngestError) -> JSONResponse:
    return JSONResponse(status_code=exc.status_code, content={"detail": str(exc)})


def _scan_or_404(store: Store, scan_id: str) -> Scan:
    scan = store.get_scan(scan_id)
    if scan is None:
        raise HTTPException(404, "Scan not found")
    return scan


@app.get("/health")
def health() -> dict:
    return {"status": "ok", "version": __version__, "ranker": ranker_status()}


@app.get("/detectors")
def detectors() -> list[dict]:
    return [{"name": d.name, "version": d.version, "available": d.available()}
            for d in all_detectors()]


@app.get("/cwe")
def cwe_catalog() -> dict[str, dict[str, str]]:
    return {cwe: {"title": title, "owasp": owasp.owasp_for(cwe)}
            for cwe, title in owasp.CWE_TITLES.items()}


@app.post("/scans", status_code=202, response_model=Scan)
async def create_scan(
    background: BackgroundTasks, store: StoreDep, settings: SettingsDep,
    file: UploadFile | None = File(None), github_url: str | None = Form(None),
) -> Scan:
    if (file is None) == (not github_url):
        raise HTTPException(422, "Provide exactly one of: a zip file or github_url.")
    if file is not None:
        if file.filename and not file.filename.lower().endswith(".zip"):
            raise IngestError("Only .zip uploads are supported.")
        data = upload.read_limited(file.file, settings.max_upload_bytes)
        scan = Scan(source_kind="zip", source_ref=file.filename or "upload.zip")
        task, arg = service.run_zip_scan, data
    else:
        github.parse_github_url(github_url)
        scan = Scan(source_kind="github", source_ref=github_url.strip())
        task, arg = service.run_github_scan, github_url.strip()
    fresh_workspace(scan.id, settings)
    store.save_scan(scan)
    background.add_task(task, scan, arg, store, settings)
    return scan


@app.post("/snippet")
def scan_snippet(body: SnippetRequest, store: StoreDep, settings: SettingsDep) -> dict:
    scan = Scan(source_kind="snippet", source_ref=body.filename)
    src = fresh_workspace(scan.id, settings) / "src"
    _, notes = write_snippet(body.code, body.filename, src, settings)
    scan.notes.extend(notes)
    store.save_scan(scan)
    scan = service.analyse(scan, src, store, settings)
    return {"scan": scan, "findings": store.list_findings(scan.id)}


@app.get("/scans", response_model=list[Scan])
def list_scans(store: StoreDep, limit: int = Query(50, ge=1, le=200)) -> list[Scan]:
    return store.list_scans(limit)


@app.get("/scans/{scan_id}", response_model=Scan)
def get_scan(scan_id: ScanId, store: StoreDep) -> Scan:
    return _scan_or_404(store, scan_id)


@app.get("/scans/{scan_id}/findings", response_model=list[Finding])
def list_findings(
    scan_id: ScanId, store: StoreDep,
    status: Status | None = None, cwe: str | None = None,
    min_severity: float | None = Query(None, ge=0, le=10),
) -> list[Finding]:
    _scan_or_404(store, scan_id)
    return store.list_findings(scan_id, status=status, cwe=cwe, min_severity=min_severity)


@app.get("/findings/{finding_id}", response_model=Finding)
def get_finding(finding_id: FindingId, store: StoreDep) -> Finding:
    finding = store.get_finding(finding_id)
    if finding is None:
        raise HTTPException(404, "Finding not found")
    return finding


@app.patch("/findings/{finding_id}", response_model=Finding)
def update_finding(finding_id: FindingId, body: StatusUpdate, store: StoreDep) -> Finding:
    finding = store.update_status(finding_id, body.status)
    if finding is None:
        raise HTTPException(404, "Finding not found")
    return finding


@app.get("/scans/{scan_id}/report")
def report(scan_id: ScanId, store: StoreDep,
           format: Literal["json", "pdf"] = "json") -> Response:
    scan = _scan_or_404(store, scan_id)
    findings = store.list_findings(scan_id)
    if format == "pdf":
        return Response(pdf_report(scan, findings), media_type="application/pdf",
                        headers={"Content-Disposition": f'attachment; filename="{scan_id}.pdf"'})
    return JSONResponse(json_report(scan, findings),
                        headers={"Content-Disposition": f'attachment; filename="{scan_id}.json"'})


@app.get("/scans/{scan_id}/sarif")
def sarif_export(scan_id: ScanId, store: StoreDep) -> JSONResponse:
    scan = _scan_or_404(store, scan_id)
    doc = sarif.to_sarif(scan, store.list_findings(scan_id))
    return JSONResponse(doc, media_type="application/sarif+json",
                        headers={"Content-Disposition": f'attachment; filename="{scan_id}.sarif"'})


@app.get("/scans/{scan_id}/source", response_class=PlainTextResponse)
def source_file(scan_id: ScanId, store: StoreDep, settings: SettingsDep,
                path: str = Query(..., min_length=1, max_length=512)) -> str:
    _scan_or_404(store, scan_id)
    if vault.is_sealed(scan_id, settings):  # decrypted in memory, never written back to disk
        try:
            text = vault.read_file(scan_id, path, settings)
        except vault.VaultError as exc:
            raise HTTPException(409, f"Source unavailable: {exc}") from exc
        if text is None:
            raise HTTPException(404, "File not found in this scan")
        return text
    target = resolve_source_file(service.source_root(scan_id, settings), path)  # scan still running
    if target is None:
        raise HTTPException(404, "File not found in this scan")
    return target.read_text(encoding="utf-8", errors="replace")
