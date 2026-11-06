# Kavach 2.0
Built at HackFest 2026 by team PocketRocket (T2-04).

## Kavach

A security scanner for Python Flask apps. It takes in code, runs detectors, scores and
classifies the findings, catches issues at commit and PR time, and tracks everything on a
dashboard. See [docs/prd.md](docs/prd.md) for the design and
[docs/CHECKLIST.md](docs/CHECKLIST.md) for what is done and what remains.

### Project structure

| Folder | What is in it |
|---|---|
| `backend/` | The API and scanner (Python, FastAPI): `app/detect` (detectors), `app/fix` (patch suggester), `app/fixwatch` (dependency advisories), `app/rank` (ML ranker), `app/report` (scores, SARIF, PDF), `tests/` |
| `frontend/` | The dashboard (React, Vite, three.js): `src/pages`, `src/components`, `src/three` (3D views) |
| `telemetry/` | `kavach_telemetry.py`, the file a Flask app adds to send attack alerts to Kavach |
| `demo/` | `monitored-app/`, a small safe Flask shop for the Monitoring demo |
| `targets/` | Deliberately vulnerable test apps used for evaluation (see `targets/README.md`); never deploy them |
| `eval/` | `run.py` and the results: Kavach vs Bandit and Semgrep, ablation, patch re-test |
| `scripts/` | `install-hook.sh`, the pre-commit hook installer |
| `docs/` | The design (`prd.md`) and the progress checklist |
| `.github/` | CI: tests on every pull request and the PR security scan |

`CLAUDE.md` and `.claude/` hold notes and settings for the AI coding assistant used to build this; you can ignore them.

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

Dashboard tests (the 3D views' 2D fallbacks):

```bash
cd frontend && npm test
```

### Fix-watcher (dependency security fixes)

Kavach can check the exact pins in `requirements*.txt` and `pyproject.toml` against published
security advisories (OSV). A package gets a finding only when your code imports it, placed on that
import line, with the version to upgrade to and a link to each advisory. Packages your code never
imports are left out.

It is off unless `SENTINEL_FIXWATCH` is set: `osv` asks api.osv.dev (package names and versions only,
never code; answers are cached for an hour), or give a path to a downloaded OSV export to stay offline.
Docker turns it on (`docker-compose.yml`); local runs, the CLI and the commit hook stay offline.

### 3D effects and how to turn them off

The dashboard draws a few views in 3D (three.js, loaded lazily in its own file). Each has a plain 2D
version that shows the same information, and Kavach switches to it on its own when:

- you click **Reduce effects** in the header (remembered in this browser);
- your system asks for reduced motion (macOS: Settings > Accessibility > Display > Reduce motion);
- WebGL is not available, a 3D view throws an error, or the WebGL context is lost;
- the frame rate stays under 40 fps for 2 seconds;
- the screen is narrower than 768px (except the sign-in background).

To clear the saved choice, run `localStorage.removeItem('kavach.reduceEffects')` in the browser console.
The 3D code is in `frontend/src/three/`; the 2D versions and the switch are in `frontend/src/components/`.

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
