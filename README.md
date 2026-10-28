# pocketrocket-t2-04
Official HackFest 2026 repository for team PocketRocket (T2-04).

## ZeroDay Sentinel

A security scanner for Python Flask apps. It takes in code, runs detectors, scores and
classifies the findings, catches issues at commit and PR time, and tracks everything on a
dashboard. See [docs/prd.md](docs/prd.md) for the design and build status.

### Quick start

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

### Early detection

```bash
scripts/install-hook.sh                         # blocks commits with severity >= 7
SENTINEL_SKIP=1 git commit -m "..."             # bypass once
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
- Zip uploads are capped at 50 MB and 200 MB unpacked. Paths that escape the folder
  (zip slip), absolute paths and symlinks are rejected.
- GitHub ingestion accepts only `https://github.com/owner/repo` URLs. Clones are shallow,
  non-interactive, time-limited and do not create symlinks.
- Detectors run static analysis only, and no scanned code is ever executed.
