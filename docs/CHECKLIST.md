# ZeroDay Sentinel: feature checklist

Tracks every feature in the PRD (`docs/prd.md`). Updated whenever a feature is finished or started.

**Legend:** ✅ done · 🟡 partly done · ⬜ not started · 👥 needs the team (content Claude cannot write)

**Last updated:** 2026-10-28

## Overall

| Layer | PRD priority | Done | Status |
|---|---|---|---|
| L1 Ingestion | Must | 4 / 4 | ✅ Complete |
| L2 Detection | Must | 5 / 7 | 🟡 Taint detector on; ML ranker built but needs real training data; extra rules remain |
| L3 Early detection | Must (fix-watcher: Stretch) | 3 / 4 | ✅ Must-haves complete |
| L4 Verification and mitigation | Should | 1 / 4 | 🟡 Confidence tiers only |
| L5 Reporting and dashboard | Must | 5 / 5 | ✅ Complete |
| Evaluation | Must for demo | 0 / 4 | ⬜ Not started |
| **Total** | | **18 / 28** | **About 64%. All Must layers work end to end** |

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
- [ ] ⬜ **Rule layer, custom AST checks:** hard-coded secrets and weak crypto (Bandit covers these for now)
- [ ] 🟡 **ML ranker:** built (`app/rank/`): features, project-level cross-validation, false-positive-reduction report, model saved as JSON weights (no pickle), scans score without scikit-learn. **Needs real labelled findings from the seeded targets to train**; until a model file exists, `ml_rank` is the detector confidence
- [x] ✅ **Priority sort:** open first, then severity band, then `ml_rank` or confidence, then tier and location (`app/rank/priority.py`); used by scans and the API

## L3 Early detection: "Catch it before it ships"

- [x] ✅ **Pre-commit hook:** checks staged code, blocks on severity ≥ 7 in changed code, bypass with `SENTINEL_SKIP=1` (`scripts/install-hook.sh`)
- [x] ✅ **Incremental cache:** re-scans only changed files; the whole-program taint detector always sees every file
- [x] ✅ **PR scan (GitHub Action):** scans the PR diff, annotates changed lines, keeps SARIF as an artifact, uploads to code scanning when available
- [ ] ⬜ **Fix-watcher (stretch):** watch dependency fixes for patterns that may apply to the project

## L4 Verification and mitigation: "Prove it, then fix it"

- [x] ✅ **Confidence tiers:** `pattern-match` and `reachable` assigned; findings never dropped
- [ ] 🟡 **Patch suggester:** written fix guidance per bug type; no code diff yet
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
- [ ] ⬜ **Head-to-head (`eval/run.py`):** Bandit vs default Semgrep vs ZeroDay Sentinel, with caught, missed and precision
- [ ] ⬜ **Ablation:** rules only, taint only, taint plus ML, taint plus proof
- [ ] ⬜ **Early-detection numbers:** median diff-scan time and percent of seeded commits flagged before merge

## Engineering and delivery

- [x] ✅ CI: backend tests (Python 3.11) and frontend build on every PR
- [x] ✅ Regression test runner: runs only the tests affected by changed files, using the import graph (`python -m app.devtools.regress`)
- [x] ✅ Detection regression suite: compares each target with `targets/<app>/baseline.json` and fails on missed bugs or more false positives. Active for app1, app2 and app3
- [x] ✅ 158 backend tests, passing on Python 3.11 and 3.14, with no vulnerable code (marker comments, made-up sinks, synthetic ranker data)
- [x] ✅ Docs: `README.md`, `CLAUDE.md`, `docs/prd.md`, this checklist
- [x] ✅ PR [#1](https://github.com/Hackfest-X-Saividya/pocketrocket-t2-04/pull/1) opened, with Auto-fix watching CI
- [ ] ⬜ PR #1 reviewed and merged into `main`

## Demo prep (PRD section 16)

- [ ] ⬜ All seeded wrapper bugs found, with Bandit and Semgrep results recorded
- [ ] ⬜ Results table states the small sample size
- [ ] ⬜ Vulnerable commit flagged by the hook in under 5 seconds (works in tests; needs the sink lists and a demo repo)
- [ ] ⬜ Proof test fails before the patch and passes after
- [ ] ⬜ Demo results cached and a backup video recorded
- [ ] ⬜ Limitations and ethics slide ready

## Suggested next steps

1. ⬜ Build `eval/run.py` for the head-to-head results table across `targets/`.
2. ⬜ Train the ML ranker on the three seeded apps (`python -m app.rank.train label`, then `fit`). The data is tiny, so present it as illustrative.
3. 👥 Proof runner for 2–3 findings (Docker, no network), then patch re-test.
4. ⬜ Custom AST checks for secrets and weak crypto.
