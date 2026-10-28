# ZeroDay Sentinel

Flask vulnerability scanner for Hack Fest 2026 PS-01. Read docs/prd.md first.

## Rules
- Every layer reads and writes the Finding record in backend/app/schema.py. Do not change it without asking.
- Scope: Python and Flask only. Bug classes: command injection, SQL injection, path traversal.
- Defensive only. Detectors analyse code statically and must never execute project code.
- Write a pytest test for every component before calling it done. Run tests after each change.
- Tests use the marker-comment `MarkerDetector` in backend/tests/conftest.py, not real vulnerable code.
- Keep functions small. No new dependencies without asking.

## Commands
- Setup: cd backend && python3 -m venv .venv && .venv/bin/pip install -e ".[dev]" bandit
- Backend: cd backend && .venv/bin/uvicorn app.main:app --reload
- Tests: cd backend && .venv/bin/pytest -q
- Frontend: cd frontend && npm install && npm run dev  (proxies /api to :8000)
- CLI: sentinel scan PATH [--diff-base REF] [--format text|json|sarif]
- Hook: scripts/install-hook.sh

## Where things live
- L1 ingestion: backend/app/ingest/
- L2 detection plug-in point: backend/app/detect/base.py (Detector, Candidate), registry.py
- L2 taint: backend/app/detect/propagation.py (ast tracer), taint.py (detector), rules in backend/sentinel-rules.toml
- L3 early detection: backend/app/early/ (incremental.py, hook.py, scope.py), backend/app/cli.py
- L5 reporting: backend/app/report/ (severity, owasp, sarif, export), backend/app/main.py
- Dashboard: frontend/src/
