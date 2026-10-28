# ZeroDay Sentinel

Flask vulnerability scanner for Hack Fest 2026 PS-01. Read docs/prd.md first.
Track progress in docs/CHECKLIST.md: update it whenever a feature is finished or started.

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
- Affected tests only: cd backend && .venv/bin/python -m app.devtools.regress [--base origin/main] [--dry-run]
- Update target baselines: cd backend && SENTINEL_UPDATE_BASELINE=1 .venv/bin/pytest tests/test_targets_regression.py
- Frontend: cd frontend && npm install && npm run dev  (proxies /api to :8000)
- CLI: sentinel scan PATH [--diff-base REF] [--format text|json|sarif]
- Hook: scripts/install-hook.sh
- Watch: sentinel watch [--scan] [--once]  (writes .git/sentinel-status.json)
- Eval: backend/.venv/bin/python eval/run.py  (writes eval/results.md and results.json)
- Semgrep: install with `uv tool install semgrep`, never into backend/.venv (it breaks FastAPI's opentelemetry pin)

## Where things live
- L1 ingestion: backend/app/ingest/
- L2 detection plug-in point: backend/app/detect/base.py (Detector, Candidate), registry.py
- L2 taint: backend/app/detect/propagation.py (ast tracer), taint.py (detector), rules in backend/sentinel-rules.toml
- L2 ranking: backend/app/rank/ (features, JSON model, train.py, priority sort)
- L3 early detection: backend/app/early/ (incremental.py, hook.py, scope.py), backend/app/cli.py
- Auth: backend/app/auth.py (Argon2id, JWT cookie), get_current_user in main.py, users + owner scoping in store.py; secrets in backend/.env (see .env.example)
- Encryption at rest: backend/app/vault.py (AES-256-GCM workspaces; key from SENTINEL_DATA_KEY or .sentinel-data/vault.key)
- L5 reporting: backend/app/report/ (severity, owasp, sarif, export), backend/app/main.py
- Dashboard: frontend/src/
