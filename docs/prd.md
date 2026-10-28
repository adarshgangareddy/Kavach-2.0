# Kavach: PRD summary and build status

Source: "ZeroDay Sentinel – PRDs by Layer and Feature Component, with Claude Code Plan" (Oct 28, 2026).
The product was later renamed Kavach; the PRD keeps its original name.

Kavach scans Python Flask apps for hidden dangerous paths, including ones that
no rule list names. It catches them early (commit and PR), proves and rates them, suggests
fixes and tracks them on a dashboard.

**Scope:** Flask and Python only. Three bug classes: command injection (CWE-78),
SQL injection (CWE-89) and path traversal (CWE-22).

## Layers and status

| Layer | Components | Status |
|---|---|---|
| L1 Ingestion | Zip/GitHub upload, snippet scan, diff reader, file filter | Built |
| L2 Detection | Call graph, taint engine, wrapper discovery | Built (`detect/propagation.py`, `detect/taint.py`). **Sink lists in `backend/sentinel-rules.toml` still to be filled in by the team** |
| L2 ML ranker | Rank findings by likelihood of being real | Built (`app/rank/`); needs labelled data from the seeded targets to train |
| L2 Rule layer | Baseline rules | Bandit and Semgrep adapters built |
| L3 Early detection | Pre-commit hook, PR scan Action, incremental cache | Built. Fix-watcher (stretch) not started |
| L4 Verification | Confidence tiers, fix suggestions | Tiers and remediation guidance built. Proof runner, patch diff and re-test not built |
| L5 Reporting | Severity, OWASP/CWE tagging, API, dashboard, PDF/JSON/SARIF | Built |

## Shared contract

`backend/app/schema.py` `Finding` matches the PRD record exactly. Detectors return
`Candidate` objects (`backend/app/detect/base.py`), and the pipeline turns them into Findings
with an id, severity, OWASP label and fix suggestion.

## Severity formula

```
severity = min(10, base(CWE) + 1.5*reachable + 1.0*public_route
                   + 1.0*confidence - 2.0*sanitizer_present)
```

Bases are in `backend/app/report/severity.py`. Each term is stored in `severity_factors`
and shown in the dashboard.

## Taint detector

`backend/app/detect/propagation.py` is the tracer, built on the standard `ast` module. It covers
assignments, f-strings, branches, loops, return values, methods and imports across files.
`backend/app/detect/taint.py` runs it once per `[[rule]]` in `backend/sentinel-rules.toml`:

- `sources`: request expressions (pre-filled with Flask's `request.*`)
- `entry_decorators`: route decorators. Only route parameters and sources start a flow.
- per rule: `cwe`, `sinks` (empty, so **fill these in**), and `sanitizers`

A rule with no sinks is skipped. Until any rule has sinks, the detector shows as unavailable
under `/detectors`. Findings are tagged `taint` (direct) or `taint-wrapper` (through
project helpers), with tier `reachable`. Sanitized paths are kept with `sanitizer_present`
and low confidence. The detector is whole-program: the commit hook and the PR scan give it
every project file, and keep a finding when its path passes through changed code.

Try the tracer on its own: `python -m app.detect.propagation app --sink '*.write_text'`

## ML ranker

`backend/app/rank/` scores each finding with the probability that it is a real issue, stored in
`ml_rank`. It never changes `severity`: findings are sorted by severity band first, and the
ranker orders findings within a band (`priority.py`).

Quickest: `cd backend && .venv/bin/python -m app.rank.train targets --out sentinel-model.json`
scans every app in `targets/` with taint, Bandit and Semgrep, labels the findings and trains.

Or step by step:

1. Scan a target app, export the JSON report, and label it against the target's ground truth:
   `python -m app.rank.train label --report scan.json --truth truth.json --project app1 >> labeled.jsonl`
2. Train: `python -m app.rank.train fit --data labeled.jsonl --out backend/sentinel-model.json`.
   It prints the false-positive reduction measured on held-out projects.

Training needs `pip install -e "backend[ml]"` (scikit-learn). The model is saved as JSON weights,
not a pickle, because loading a pickle can run code. Scans read the JSON with plain Python. Without
a model file, `ml_rank` is the detector's confidence. `GET /health` reports which mode is active.

## Adding another detector

1. Implement a class with `name`, `version`, `available()` and
   `scan(root, files, timeout_s) -> list[Candidate]`.
2. Fill `source`, `sink`, `path`, `confidence_tier`, `reachable`, `public_route`,
   `sanitizer_present` and `confidence`. These drive the severity score and the path view.
3. Call `register(YourDetector())` in `backend/app/detect/registry.py`.
4. For incremental re-analysis, use `function_hashes`, `changed_since` and
   `affected_functions` in `backend/app/early/incremental.py`, together with your call graph's
   caller map.

## Honest limits
- The `ml_rank` field currently holds detector confidence, until the ranker is trained.
- `proof-confirmed` is never assigned until a proof runner exists.
- "Zero-day" means unknown vulnerable paths that no signature covers.
