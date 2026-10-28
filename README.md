# pocketrocket-t2-04
Official HackFest 2026 repository for team PocketRocket (T2-04).

## Kavach

A security scanner for Python Flask apps. It takes in code, runs detectors, scores and
classifies the findings, catches issues at commit and PR time, and tracks everything on a
dashboard. See [docs/prd.md](docs/prd.md) for the design and
[docs/CHECKLIST.md](docs/CHECKLIST.md) for what is done and what remains.

### Run with Docker (one command)

```bash
cp backend/.env.example backend/.env    # fill in SENTINEL_JWT_SECRET and the admin password
docker compose up --build
```

Open http://localhost:8080 and sign in with the admin email and password from `backend/.env`.
The API is not published to the host; only the dashboard (bound to 127.0.0.1) talks to it. Scans,
the database and the encryption key live in the `kavach-data` volume (`docker compose down -v`
deletes them). Build without Semgrep for a smaller image:
`docker compose build --build-arg WITH_SEMGREP=false`.

### Quick start (without Docker)

First copy `backend/.env.example` to `backend/.env` and fill in `SENTINEL_JWT_SECRET` and the admin
email and password. The admin account is created on startup; sign in with it on the dashboard.

```bash
cd backend
python3 -m venv .venv
.venv/bin/pip install -e ".[dev]" bandit
.venv/bin/pytest -q
.venv/bin/uvicorn app.main:app --reload        # API on :8000
```

```bash
cd frontend
npm install
npm run dev                                     # dashboard on :5173
```

### Tests

```bash
cd backend
.venv/bin/pytest -q                                  # full suite
.venv/bin/python -m app.devtools.regress             # only tests affected by your changes
.venv/bin/python -m app.devtools.regress --base origin/main --dry-run
```

`app.devtools.regress` reads the import graph of `app/` and `tests/` and runs only the tests that
depend on changed files. It runs the full suite whenever narrowing would be unsafe, for example
when `conftest.py` or packaging changes. `tests/test_targets_regression.py` re-scans every seeded app in
`targets/` and fails if a bug it used to catch is now missed, or if false positives go up.

### Evaluation

```bash
backend/.venv/bin/python eval/run.py
```

Runs Bandit, Semgrep (`p/python` registry rules) and Kavach on every app in `targets/`, and
writes `eval/results.md` (head-to-head, per app, missed bugs, ablation, early-detection timing,
caveats) and `eval/results.json`. Targets are scanned statically and never run.

Install Semgrep as an isolated tool, not into `backend/.venv`: it pins library versions that
conflict with FastAPI. Its rules download at run time, so it needs internet access.

```bash
uv tool install semgrep        # or: pipx install semgrep
```

### Early detection

```bash
scripts/install-hook.sh                         # blocks commits with severity >= 7
SENTINEL_SKIP=1 git commit -m "..."             # bypass once
sentinel watch --scan                           # as you save: changed functions + findings
sentinel scan . --diff-base origin/main --format sarif --out sentinel.sarif
```

`.github/workflows/scan.yml` runs the diff scan on every pull request and uploads SARIF to
GitHub code scanning, so findings appear on the changed lines.

### API

| Method | Path | Purpose |
|---|---|---|
| POST | `/scans` | Zip upload (`file`) or `github_url` form field |
| POST | `/snippet` | Scan pasted code (`{"code": "..."}`) |
| GET | `/scans`, `/scans/{id}` | Scan list and status |
| GET | `/scans/{id}/findings` | Filters: `status`, `cwe`, `min_severity` |
| GET/PATCH | `/findings/{id}` | Detail; status workflow (`open`, `fixed`, `accepted`) |
| GET | `/scans/{id}/report?format=json\|pdf` | Reports |
| GET | `/scans/{id}/sarif` | SARIF 2.1.0 |

### Security notes

- Sign-in: passwords are hashed with Argon2id (argon2-cffi, random salt per hash). A successful
  login sets a short-lived (30 min) HS256 JWT in an `HttpOnly`, `SameSite=Lax` cookie, `Secure`
  unless `SENTINEL_COOKIE_SECURE=false`. Failed logins always answer "Invalid email or password",
  and unknown emails cost the same Argon2 work. Logins are limited to 5 per minute per IP (slowapi).
- Every route except `/health` and `/auth/login` needs a session. Scans and findings belong to the
  user who created them; another user's record answers 404, exactly like a missing one.
- Sign-up creates normal (non-admin) accounts: 12-128 character passwords, 3 sign-ups per minute
  per IP, and `SENTINEL_ALLOW_SIGNUP=false` turns it off for admin-created accounts only.
- Secrets come from the environment or `backend/.env` (git-ignored); nothing is hard-coded.
- Zip uploads are capped at 50 MB and 200 MB unpacked. Paths that escape the folder
  (zip slip), absolute paths and symlinks are rejected.
- GitHub ingestion accepts only `https://github.com/owner/repo` URLs. Clones are shallow,
  non-interactive, time-limited and do not create symlinks.
- Detectors run static analysis only, and no scanned code is ever executed.
- Uploaded code is encrypted at rest. After each scan, only the Python files the code viewer
  needs are kept, encrypted with AES-256-GCM into `src.enc`, bound to the scan ID; every plaintext
  file (including `.env` and other non-Python files) is deleted. The viewer decrypts in memory.
  Set the key with `SENTINEL_DATA_KEY` (32 bytes, url-safe base64; generate one with
  `python -c "from app.vault import generate_key; print(generate_key())"`). Without it, a key file
  is created once at `backend/.sentinel-data/vault.key` with permissions 0600.
