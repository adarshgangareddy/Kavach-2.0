# Seeded target apps

Small, deliberately vulnerable Flask apps used to evaluate ZeroDay Sentinel against Bandit and
Semgrep, and to train the ML ranker. They are our own code, scanned statically, and never deployed
or exposed to a network.

## Layout

One folder per app:

```
targets/
  app1/
    app.py            # Flask app and routes
    helpers.py        # project helpers the bugs pass through (optional, recommended)
    truth.json        # ground truth: every seeded bug
  app2/
    ...
```

At least **3 apps** are needed: the ML ranker is evaluated on apps it did not train on, and the
results table should cover more than one codebase.

## What each app should contain

- **Routes** declared with `@app.route(...)` (or `@app.get` / `@app.post`), reading input from
  `request.args`, `request.form`, `request.json`, and so on, as listed in `backend/sentinel-rules.toml`.
- **Seeded bugs** in the PRD's bug classes: CWE-78, CWE-89, CWE-22 (and optionally CWE-502).
- **Wrapper bugs:** most seeded bugs should reach the risky call through one or more of the app's
  own helper functions, ideally in a different file. This is what Bandit and default Semgrep miss
  and what the results table needs to show.
- **A few direct bugs** (risky call written in the route itself), as a control: every tool should
  catch these.
- **Safe decoys** that must **not** be reported: the same patterns, but with the sanitizer from the
  rules file applied, or with only constant data reaching the call. These measure false positives.

## truth.json

A JSON list with one entry per seeded bug, and nothing else. Decoys are **not** listed: anything a
tool reports that is not in this list counts as a false positive.

```json
[
  {"file": "helpers.py", "line": 14, "cwe": "CWE-89",
   "kind": "wrapper", "note": "route search() -> run_query()"},
  {"file": "app.py", "line": 31, "cwe": "CWE-78",
   "kind": "direct"}
]
```

| Field | Required | Meaning |
|---|---|---|
| `file` | yes | Path relative to the app folder, with forward slashes |
| `line` | yes | Line of the risky call (the sink). A tool's finding matches within ±2 lines |
| `cwe` | yes | `"CWE-78"`, `"CWE-89"`, `"CWE-22"` or `"CWE-502"` |
| `kind` | no | `"wrapper"` (through a helper) or `"direct"`, used to break down the results table |
| `note` | no | Free text for humans |

Check a file with:

```bash
cd backend && .venv/bin/python -m app.rank.truth ../targets/app1
```

## Rules

- Keep the apps small (a few hundred lines each). They are test fixtures, not products.
- No real secrets, no network calls, and nothing that runs on import.
- Don't run the apps on a network. Scanning is static and never executes them.
- When you move code around, update the `line` numbers in `truth.json` and re-run the check.
