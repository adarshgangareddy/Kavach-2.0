"""FastAPI application (PRD section 8, L5 API).

Every route except /health and /auth/login needs a signed-in user (session cookie),
and every scan and finding is visible only to the user who created it. Another
user's record answers 404, the same as a missing one, so ids leak nothing.
"""

import hashlib
import logging
import os
import secrets
import shutil
import sqlite3
from contextlib import asynccontextmanager
from functools import lru_cache
from pathlib import Path
from typing import Annotated, Literal

from fastapi import (BackgroundTasks, Depends, FastAPI, File, Form, HTTPException,
                     Path as PathParam, Query, Request, UploadFile)
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, PlainTextResponse, Response
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address

from app import __version__, auth, service, vault
from app.auth import User
from app.config import Settings, get_settings
from app.detect.registry import all_detectors
from app.ingest import IngestError, github, upload
from app.ingest.snippet import write_snippet
from app.ingest.workspace import fresh_workspace, resolve_source_file, workspace_for
from app.models import (SCAN_ID_PATTERN, AlertIn, AppCreate, LoginRequest, RegisterRequest, Scan, ScanStatus,
                        SnippetRequest, StatusUpdate)
from app.rank.model import load_model
from app.report import owasp, sarif
from app.report.export import json_report, pdf_report
from app.schema import Finding, Status
from app.store import Store

log = logging.getLogger("zeroday_sentinel")
LOGIN_RATE = "5/minute"
SIGNUP_RATE = "3/minute"
ALERT_RATE = "120/minute"
APP_KEY_HEADER = "X-Kavach-Key"
SIGNUP_REFUSED = "Could not create an account with these details"
DEFAULT_ORIGINS = "http://localhost:5173,http://127.0.0.1:5173,http://localhost:3000"


@asynccontextmanager
async def lifespan(_: FastAPI):
    """Seed the admin account, then encrypt any workspace still in plaintext."""
    _store_for(str(get_settings().db_path))
    if sealed := vault.seal_existing(get_settings()):
        log.warning("Encrypted %d plaintext scan workspaces at rest", sealed)
    yield


app = FastAPI(title="Kavach", version=__version__, lifespan=lifespan)
app.add_middleware(
    CORSMiddleware,
    allow_origins=[o.strip() for o in os.environ.get("SENTINEL_CORS_ORIGINS", DEFAULT_ORIGINS).split(",")
                   if o.strip()],
    allow_credentials=True,  # the session cookie; origins must be listed explicitly, never "*"
    allow_methods=["GET", "POST", "PATCH", "DELETE"],
    allow_headers=["Content-Type"],
)
limiter = Limiter(key_func=get_remote_address)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)


def ranker_status() -> str:
    return load_model()[1]


ScanId = Annotated[str, PathParam(pattern=SCAN_ID_PATTERN)]
FindingId = Annotated[str, PathParam(pattern=r"^F-[0-9a-f]{8}-\d{3,}$")]


def _seed_admin(store: Store) -> None:
    """Create or update the admin account from SENTINEL_ADMIN_EMAIL / _PASSWORD."""
    email = auth.normalize_email(os.environ.get("SENTINEL_ADMIN_EMAIL", ""))
    password = os.environ.get("SENTINEL_ADMIN_PASSWORD", "")
    if not email or not password:
        log.warning("SENTINEL_ADMIN_EMAIL / SENTINEL_ADMIN_PASSWORD not set: no admin account")
        return
    user, stored = store.get_user_by_email(email)
    if user is None:
        user = store.create_user(email, auth.hash_password(password), role="admin")
    elif not auth.verify_password(stored, password) or auth.needs_rehash(stored):
        store.set_password_hash(user.id, auth.hash_password(password))  # .env is the source of truth
    if moved := store.assign_unowned_scans(user.id):
        log.warning("Assigned %d scans from before user accounts to %s", moved, email)


@lru_cache
def _store_for(db_path: str) -> Store:
    store = Store(Path(db_path))
    _seed_admin(store)
    return store


def settings_dep() -> Settings:
    return get_settings()


def store_dep(settings: Annotated[Settings, Depends(settings_dep)]) -> Store:
    return _store_for(str(settings.db_path))


SettingsDep = Annotated[Settings, Depends(settings_dep)]
StoreDep = Annotated[Store, Depends(store_dep)]


def get_current_user(request: Request, store: StoreDep) -> User:
    token = request.cookies.get(auth.COOKIE_NAME)
    claims = auth.decode_token(token) if token else None
    user = store.get_user(claims["sub"]) if claims else None
    if user is None:
        raise HTTPException(401, "Not signed in")
    return user


CurrentUser = Annotated[User, Depends(get_current_user)]


@app.exception_handler(IngestError)
async def _ingest_error(_: Request, exc: IngestError) -> JSONResponse:
    return JSONResponse(status_code=exc.status_code, content={"detail": str(exc)})


def _scan_or_404(store: Store, scan_id: str, user: User) -> Scan:
    scan = store.get_scan(scan_id, owner_id=user.id)
    if scan is None:
        raise HTTPException(404, "Scan not found")
    return scan


# --- public -----------------------------------------------------------------

@app.get("/health")
def health() -> dict:
    return {"status": "ok", "version": __version__, "ranker": ranker_status(),
            "signup": auth.signup_enabled()}


@app.post("/auth/login")
@limiter.limit(LOGIN_RATE)
def login(request: Request, body: LoginRequest, store: StoreDep) -> JSONResponse:
    user, stored = store.get_user_by_email(auth.normalize_email(body.email))
    if not auth.verify_password(stored, body.password):  # same work and message either way
        raise HTTPException(401, auth.GENERIC_LOGIN_ERROR)
    if auth.needs_rehash(stored):
        store.set_password_hash(user.id, auth.hash_password(body.password))
    response = JSONResponse({"email": user.email, "role": user.role})
    auth.set_session_cookie(response, auth.issue_token(user))
    return response


@app.post("/auth/register", status_code=201)
@limiter.limit(SIGNUP_RATE)
def register(request: Request, body: RegisterRequest, store: StoreDep) -> JSONResponse:
    """Create a normal user account and sign it in. New accounts never get the admin role."""
    if not auth.signup_enabled():
        raise HTTPException(403, "Sign-up is turned off on this server")
    if store.get_user_by_email(body.email)[0] is not None:
        raise HTTPException(409, SIGNUP_REFUSED)
    try:
        user = store.create_user(body.email, auth.hash_password(body.password), role="user")
    except sqlite3.IntegrityError as exc:  # the same email registered concurrently
        raise HTTPException(409, SIGNUP_REFUSED) from exc
    response = JSONResponse({"email": user.email, "role": user.role}, status_code=201)
    auth.set_session_cookie(response, auth.issue_token(user))
    return response


@app.post("/auth/logout")
def logout() -> JSONResponse:
    response = JSONResponse({"ok": True})
    auth.clear_session_cookie(response)
    return response


# --- signed in ---------------------------------------------------------------

@app.get("/auth/me")
def me(user: CurrentUser) -> dict:
    return {"email": user.email, "role": user.role}


@app.get("/detectors")
def detectors(_: CurrentUser) -> list[dict]:
    return [{"name": d.name, "version": d.version, "available": d.available()}
            for d in all_detectors()]


@app.get("/cwe")
def cwe_catalog(_: CurrentUser) -> dict[str, dict[str, str]]:
    return {cwe: {"title": title, "owasp": owasp.owasp_for(cwe)}
            for cwe, title in owasp.CWE_TITLES.items()}


@app.post("/scans", status_code=202, response_model=Scan)
async def create_scan(
    background: BackgroundTasks, store: StoreDep, settings: SettingsDep, user: CurrentUser,
    file: UploadFile | None = File(None), github_url: str | None = Form(None),
) -> Scan:
    if (file is None) == (not github_url):
        raise HTTPException(422, "Provide exactly one of: a zip file or github_url.")
    if file is not None:
        if file.filename and not file.filename.lower().endswith(".zip"):
            raise IngestError("Only .zip uploads are supported.")
        data = upload.read_limited(file.file, settings.max_upload_bytes)
        scan = Scan(source_kind="zip", source_ref=file.filename or "upload.zip", owner_id=user.id)
        task, arg = service.run_zip_scan, data
    else:
        github.parse_github_url(github_url)
        scan = Scan(source_kind="github", source_ref=github_url.strip(), owner_id=user.id)
        task, arg = service.run_github_scan, github_url.strip()
    fresh_workspace(scan.id, settings)
    store.save_scan(scan)
    background.add_task(task, scan, arg, store, settings)
    return scan


@app.post("/snippet")
def scan_snippet(body: SnippetRequest, store: StoreDep, settings: SettingsDep,
                 user: CurrentUser) -> dict:
    scan = Scan(source_kind="snippet", source_ref=body.filename, owner_id=user.id)
    src = fresh_workspace(scan.id, settings) / "src"
    _, notes = write_snippet(body.code, body.filename, src, settings)
    scan.notes.extend(notes)
    store.save_scan(scan)
    scan = service.analyse(scan, src, store, settings)
    return {"scan": scan, "findings": store.list_findings(scan.id)}


def _key_hash(key: str) -> str:
    """App keys are long random tokens, so a plain SHA-256 is enough to store them safely."""
    return hashlib.sha256(key.encode()).hexdigest()


@app.post("/apps", status_code=201)
def create_app(body: AppCreate, store: StoreDep, user: CurrentUser) -> dict:
    """Register a monitored app. The key is shown once; Kavach keeps only its hash."""
    key = "kv_" + secrets.token_urlsafe(32)
    return store.create_app(user.id, body.name.strip(), _key_hash(key)) | {"key": key}


@app.get("/apps")
def list_apps(store: StoreDep, user: CurrentUser) -> list[dict]:
    return store.list_apps(user.id)


@app.delete("/apps/{app_id}", status_code=204)
def delete_app(app_id: Annotated[str, PathParam(pattern=r"^A-[0-9a-f]{10}$")],
               store: StoreDep, user: CurrentUser) -> Response:
    if not store.delete_app(app_id, user.id):
        raise HTTPException(404, "App not found")
    return Response(status_code=204)


@app.post("/alerts", status_code=202)
@limiter.limit(ALERT_RATE)
def receive_alert(request: Request, alert: AlertIn, store: StoreDep) -> dict:
    """Intake for monitored apps: authenticated by the app key, not a user session."""
    key = request.headers.get(APP_KEY_HEADER, "")
    found = store.app_for_key(_key_hash(key)) if key else None
    if found is None:
        raise HTTPException(401, "Unknown app key")
    app_id, owner_id, _ = found
    record = store.add_alert(app_id, owner_id, alert.model_dump())
    return {"id": record["id"]}


@app.get("/alerts")
def list_alerts(store: StoreDep, user: CurrentUser,
                limit: int = Query(100, ge=1, le=500)) -> list[dict]:
    return store.list_alerts(user.id, limit)


@app.delete("/alerts", status_code=204)
def clear_alerts(store: StoreDep, user: CurrentUser) -> Response:
    store.clear_alerts(user.id)
    return Response(status_code=204)


@app.get("/scans", response_model=list[Scan])
def list_scans(store: StoreDep, user: CurrentUser,
               limit: int = Query(50, ge=1, le=200)) -> list[Scan]:
    return store.list_scans(user.id, limit)


@app.delete("/scans/{scan_id}", status_code=204)
def delete_scan(scan_id: ScanId, store: StoreDep, settings: SettingsDep, user: CurrentUser) -> Response:
    """Delete a scan for good: its findings, its record and its encrypted source on disk."""
    scan = _scan_or_404(store, scan_id, user)
    if scan.status in (ScanStatus.QUEUED, ScanStatus.RUNNING):
        raise HTTPException(409, "This scan is still running; delete it when it has finished")
    store.delete_scan(scan_id, user.id)
    shutil.rmtree(workspace_for(scan_id, settings), ignore_errors=True)
    return Response(status_code=204)


@app.get("/scans/{scan_id}", response_model=Scan)
def get_scan(scan_id: ScanId, store: StoreDep, user: CurrentUser) -> Scan:
    return _scan_or_404(store, scan_id, user)


@app.get("/scans/{scan_id}/findings", response_model=list[Finding])
def list_findings(
    scan_id: ScanId, store: StoreDep, user: CurrentUser,
    status: Status | None = None, cwe: str | None = None,
    min_severity: float | None = Query(None, ge=0, le=10),
) -> list[Finding]:
    _scan_or_404(store, scan_id, user)
    return store.list_findings(scan_id, status=status, cwe=cwe, min_severity=min_severity)


@app.get("/findings/{finding_id}", response_model=Finding)
def get_finding(finding_id: FindingId, store: StoreDep, user: CurrentUser) -> Finding:
    finding = store.get_finding(finding_id, owner_id=user.id)
    if finding is None:
        raise HTTPException(404, "Finding not found")
    return finding


@app.patch("/findings/{finding_id}", response_model=Finding)
def update_finding(finding_id: FindingId, body: StatusUpdate, store: StoreDep,
                   user: CurrentUser) -> Finding:
    finding = store.update_status(finding_id, body.status, owner_id=user.id)
    if finding is None:
        raise HTTPException(404, "Finding not found")
    return finding


@app.get("/scans/{scan_id}/report")
def report(scan_id: ScanId, store: StoreDep, user: CurrentUser,
           format: Literal["json", "pdf"] = "json") -> Response:
    scan = _scan_or_404(store, scan_id, user)
    findings = store.list_findings(scan_id)
    if format == "pdf":
        return Response(pdf_report(scan, findings), media_type="application/pdf",
                        headers={"Content-Disposition": f'attachment; filename="{scan_id}.pdf"'})
    return JSONResponse(json_report(scan, findings),
                        headers={"Content-Disposition": f'attachment; filename="{scan_id}.json"'})


@app.get("/scans/{scan_id}/sarif")
def sarif_export(scan_id: ScanId, store: StoreDep, user: CurrentUser) -> JSONResponse:
    scan = _scan_or_404(store, scan_id, user)
    doc = sarif.to_sarif(scan, store.list_findings(scan_id))
    return JSONResponse(doc, media_type="application/sarif+json",
                        headers={"Content-Disposition": f'attachment; filename="{scan_id}.sarif"'})


@app.get("/scans/{scan_id}/source", response_class=PlainTextResponse)
def source_file(scan_id: ScanId, store: StoreDep, settings: SettingsDep, user: CurrentUser,
                path: str = Query(..., min_length=1, max_length=512)) -> str:
    _scan_or_404(store, scan_id, user)
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
