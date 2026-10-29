# Kavach: feature checklist

Tracks every feature in the PRD (`docs/prd.md`). Updated whenever a feature is finished or started.

**Legend:** ✅ done · 🟡 partly done · ⬜ not started · 👥 needs the team (content Claude cannot write)

**Last updated:** 2026-10-28

## Overall

| Layer | PRD priority | Done | Status |
|---|---|---|---|
| L1 Ingestion | Must | 4 / 4 | ✅ Complete |
| L2 Detection | Must | 6 / 7 | ✅ Taint detector on, ML ranker trained; only custom secret/crypto checks remain |
| L3 Early detection | Must (fix-watcher: Stretch) | 4 / 5 | ✅ Must-haves complete, plus a write-time watcher |
| L4 Verification and mitigation | Should | 1 / 4 | 🟡 Confidence tiers only |
| L5 Reporting and dashboard | Must | 5 / 5 | ✅ Complete |
| Evaluation | Must for demo | 4 / 4 | ✅ Bandit and Semgrep compared, ablation and early-detection numbers recorded |
| **Total** | | **24 / 29** | **About 83%. All Must layers work end to end; evaluation complete; ranker trained** |

## L1 Ingestion: "Bring your code"

- [x] ✅ **Zip upload:** 50 MB limit, 200 MB unpacked, zip-slip, symlink and zip-bomb protection, 30 s limit
- [x] ✅ **GitHub URL:** `https://github.com/owner/repo` only; shallow, non-interactive, time-limited clone
- [x] ✅ **Snippet scan:** paste one function; re-indents and reports parse errors gracefully
- [x] ✅ **File filter:** skips venv, tests, vendored and non-Python files with a clear note
- [x] ✅ **Diff reader:** maps changed lines in a git diff to function names

## L2 Detection: "Find the hidden risk"

- [x] ✅ **Parser and call graph:** functions, methods and imports across files (`detect/propagation.py`)
- [x] ✅ **Taint engine:** assignments, f-strings, branches, loops, return values, sanitizers
- [x] ✅ **Wrapper discovery:** finds project functions whose parameter reaches a sink
- [x] ✅ **Rule layer, baseline:** Bandit and Semgrep adapters
- [x] ✅ **Sink lists:** filled in by the team in `backend/sentinel-rules.toml`; the taint detector is on
- [x] ✅ **Argument-aware sinks:** sink tables in `sentinel-rules.toml` (`args`, `kwargs`, `when`): `execute` only counts the SQL text, `subprocess` only with `shell=True`. Removed the parameterized-query false alarm in app2
- [x] ✅ **Rule layer, custom AST checks** (`rules` detector): hard-coded secrets (named secrets, 8 token formats, passwords in connection URLs, `os.getenv` fallbacks, hard-coded JWT/HMAC keys) and weak crypto (MD5/SHA-1, fast hash on passwords, DES/RC4/Blowfish, ECB, old TLS, short RSA/DSA keys, certificate checks off, `random` for tokens). Word-based name matching avoids Bandit's false alarms (`token_type`, `password_field`, env names); secret values never stored; merges with Bandit (CWE-259/798 treated as one); 0 findings on Kavach's own code
- [x] ✅ **ML ranker:** trained on the seeded targets (`python -m app.rank.train targets`), saved as `backend/sentinel-model.json` (JSON weights, no pickle). Held out by app: false positives read before 90% recall 5 → 0, precision@k 62% → 100%. Only 23 findings from 3 apps: present as indicative, not as a 100% claim. Labelling now matches the closest line first
- [x] ✅ **Priority sort:** open first, then severity band, then `ml_rank` or confidence, then tier and location (`app/rank/priority.py`); used by scans and the API

## L3 Early detection: "Catch it before it ships"

- [x] ✅ **Pre-commit hook:** checks staged code, blocks on severity ≥ 7 in changed code, bypass with `SENTINEL_SKIP=1` (`scripts/install-hook.sh`)
- [x] ✅ **Incremental cache:** re-scans only changed files; the whole-program taint detector always sees every file
- [x] ✅ **PR scan (GitHub Action):** scans the PR diff, annotates changed lines, keeps SARIF as an artifact, uploads to code scanning when available
- [x] ✅ **Write-time watcher (`sentinel watch`):** polls git every second, records added/modified/removed functions vs HEAD in `.git/sentinel-status.json`; `--scan` prints findings in changed functions as you save (`detected_at: write`)
- [x] ✅ **Fix-watcher (`app/fixwatch/`):** exact pins from requirements*.txt / pyproject.toml checked against OSV (online, parallel, cached 1 h) or an offline OSV export; a finding (CWE-1395, `detected_at: watch`) only when the code imports the package, on that import line, with the upgrade target and advisory links. Off unless SENTINEL_FIXWATCH is set; on in Docker. Dashboard: Advisory label, clickable advisory links, dependency → used-here path, kept out of the call graph

## L4 Verification and mitigation: "Prove it, then fix it"

- [x] ✅ **Confidence tiers:** `pattern-match` and `reachable` assigned; findings never dropped
- [x] ✅ **Patch suggester:** code diffs for CWE-89 (placeholders + parameters; +, f-string, %, .format, query in a variable; sqlite3 `?` / psycopg `%s`), CWE-78 (argument list, no shell; os.system → subprocess.run; refuses shell features and user-chosen programs) and CWE-22 (`_kavach_safe_path` helper, registered as a sanitizer). Each patch is re-checked by tracing the whole project in memory; dashboard shows the diff with Apply / Copy / Download .diff (`git apply`). All 13 seeded bugs get a patch confirmed fixed. Rule-layer findings get patches too (`app/fix/rule_patches.py`): secrets → `os.environ[...]`, MD5/SHA-1 → SHA-256, certificate checks back on, `random` → `secrets`, 1024 → 3072-bit keys, old TLS → `PROTOCOL_TLS_CLIENT`; 28/36 benchmark cases, all confirmed; cipher swaps, slow password hashes and hard-coded password checks stay advice-only with the reason shown. Patches are written only when Kavach's own rule layer also reports the line, so other tools' false alarms are not 'fixed'. Import-only lines explain there is nothing to rewrite. The editor's re-scan judges the patched lines and counts other issues in the file separately
- [ ] 👥 **Proof runner:** harmless marker test in Docker with no network, against the team's own targets
- [ ] ⬜ **Patch re-test:** apply the suggested fix to a copy and re-run the proof (depends on the proof runner)

## L5 Reporting and dashboard: "See it, rate it, track it"

- [x] ✅ **Severity scoring:** PRD formula, with each factor shown in the UI
- [x] ✅ **OWASP and CWE tagging:** every finding tagged, with links to CWE pages
- [x] ✅ **API (FastAPI + SQLite):** every endpoint in the PRD, plus `/detectors`, `/cwe` and `/scans/{id}/source`
- [x] ✅ **React dashboard:** scan page, charts, filterable findings table, finding detail with highlighted code, path and severity breakdown, status workflow, light/dark mode, phone layout
- [x] ✅ **Exports:** JSON, PDF and SARIF 2.1.0 (structure checked by `sentinel validate-sarif`)

## Evaluation (PRD section 9)

- [x] ✅ **Seeded target apps:** app1, app2, app3 in `targets/`: 13 seeded bugs (9 wrapper, 4 direct) and safe decoys. First result: taint 13/13, Bandit 6/13. Spec in `targets/README.md`
- [x] ✅ **Head-to-head (`eval/run.py`):** writes `eval/results.md`. Taint 13/13 (precision 76%), Semgrep `p/python` 7/13 (70%), Bandit 6/13 (46%). On wrapper bugs: taint 9/9, Bandit 4/9, Semgrep 3/9
- [x] ✅ **Ablation (`eval/run.py`):** Bandit only 6/13, taint only 13/13 (76%), Bandit + taint 13/13 (59%), Kavach engines (taint + rule layer) 13/13 (76%, rule layer adds no noise), full Kavach 13/13 (57%), 0 extra findings at severity ≥ 7 in any setup; ML ranker held-out FP 5 → 0; proof runner row stated honestly (not built)
- [x] ✅ **Patch re-test (static):** every seeded bug patched (13/13), confirmed by re-trace (13/13), patched copy re-scanned by all four detectors: 0 serious reports left
- [x] ✅ **Rule-layer benchmark (`eval/rules_corpus/`):** 36 labelled problems + 25 decoys. Kavach rule layer 36/36, 0 decoys flagged, 0 reports on our own code; Bandit 21/36, 10 decoys flagged, 2 false alarms on our own code; Semgrep 9/36
- [x] ✅ **Early-detection numbers:** 3/3 vulnerable commits blocked by the real hook, median 0.03 s

## Engineering and delivery

- [x] ✅ Authentication: Argon2id passwords, 30-minute JWT in an HttpOnly/SameSite=Lax cookie, 5/min login rate limit, generic login errors, sign-up (3/min, 12+ character passwords, turn off with SENTINEL_ALLOW_SIGNUP=false), per-user scoping of scans and findings, React sign-in/sign-up page and protected routes
- [x] ✅ Encryption at rest: scan workspaces stored as AES-256-GCM archives bound to the scan ID; plaintext deleted after each scan (and on failure); existing workspaces migrated at startup (`app/vault.py`)
- [x] ✅ CI: backend tests (Python 3.11) and frontend build on every PR
- [x] ✅ One-command Docker setup: `docker compose up --build` (API container not published, dashboard on 127.0.0.1:8080 via nginx with security headers, data in a volume, unprivileged users, Semgrep in its own venv)
- [x] ✅ Runtime alerts (Monitoring page): Flask apps add `telemetry/kavach_telemetry.py`, which blocks request bodies over 5 MB and checks the path, query, form and JSON inputs for SQL injection and path traversal patterns (decodes double URL encoding and SQL comments; report-only by default, `block_attacks=True` returns 403), reporting each to Kavach from a background thread; per-app keys (shown once, stored as SHA-256), `POST /alerts` intake rate-limited, alerts private per user
- [x] ✅ "Found only by Kavach" panel on each scan: Kavach-only / both / Bandit-or-Semgrep-only groups that filter the list, and an "Only Kavach" tag on issues the other tools missed
- [x] ✅ Regression test runner: runs only the tests affected by changed files, using the import graph (`python -m app.devtools.regress`)
- [x] ✅ Detection regression suite: compares each target with `targets/<app>/baseline.json` and fails on missed bugs or more false positives. Active for app1, app2 and app3
- [x] ✅ 221 backend tests, passing on Python 3.11 and 3.14, with no vulnerable code (marker comments, made-up sinks, synthetic ranker data)
- [x] ✅ Docs: `README.md`, `CLAUDE.md`, `docs/prd.md`, this checklist
- [x] ✅ PR [#1](https://github.com/Hackfest-X-Saividya/pocketrocket-t2-04/pull/1) opened, with Auto-fix watching CI
- [x] ✅ PR #1 and PR #2 merged into `main`

## Demo prep (PRD section 16)

- [x] ✅ All seeded wrapper bugs found (9/9), with Bandit and Semgrep results recorded
- [x] ✅ Results table states the small sample size (`eval/results.md`, Caveats)
- [x] ✅ Vulnerable commit flagged by the hook in under 5 seconds (0.03 s on each seeded app)
- [ ] ⬜ Proof test fails before the patch and passes after
- [ ] ⬜ Demo results cached and a backup video recorded
- [ ] ⬜ Limitations and ethics slide ready

## Suggested next steps

1. 👥 Proof runner for 2–3 findings (Docker, no network), then patch re-test.
2. ⬜ Custom AST checks for secrets and weak crypto.
