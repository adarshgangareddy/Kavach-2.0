# ZeroDay Sentinel evaluation

Seeded targets: 3 apps, 13 bugs (9 through project helpers, 4 direct). Generated 2026-10-28 16:39 by `eval/run.py`.

## Head-to-head

| Tool | Caught | Recall | Wrapper bugs | Direct bugs | Extra findings | Precision | Extra at severity ≥ 7 | Scan time |
|---|---|---|---|---|---|---|---|---|
| Bandit | 6/13 | 46% | 4/9 | 2/4 | 7 | 46% | 0 | 0.21s |
| Semgrep (default rules) | not run (semgrep not installed) | | | | | | | |
| ZeroDay Sentinel (taint) | 13/13 | 100% | 9/9 | 4/4 | 4 | 76% | 0 | 0.01s |

## Per app

| App | Bugs | Bandit | ZeroDay Sentinel (taint) |
|---|---|---|---|
| app1 | 4 | 2/4 | 4/4 |
| app2 | 5 | 3/5 | 5/5 |
| app3 | 4 | 1/4 | 4/4 |

## Missed bugs

- **Bandit:** app1/helpers.py:11 CWE-22 (wrapper), app1/helpers.py:21 CWE-89 (wrapper), app2/helpers.py:12 CWE-89 (wrapper), app2/app.py:36 CWE-22 (direct), app3/helpers.py:7 CWE-22 (wrapper), app3/helpers.py:16 CWE-89 (wrapper), app3/app.py:36 CWE-22 (direct)
- **ZeroDay Sentinel (taint):** none

## Ablation

| Configuration | Caught | Precision | Note |
|---|---|---|---|
| Rules only (Bandit) | 6/13 | 46% | |
| Taint only | 13/13 | 76% | |
| Rules + taint | 13/13 | 59% | |
| Taint + ML ranker | same as taint | same as taint | Reorders findings, does not add or remove them. Ranker: heuristic (no model file; ml_rank = detector confidence) |
| Taint + proof runner | | | Not built yet |

## Early detection (pre-commit hook)

Each app: helpers committed first, then a commit adding the routes, run through the real hook with the taint detector.

| App | Commit blocked | Hook time |
|---|---|---|
| app1 | yes | 0.03s |
| app2 | yes | 0.03s |
| app3 | yes | 0.03s |

Vulnerable commits blocked before merge: 3/3 (100%). Median hook time: 0.03s.

## Caveats

- Small sample: 3 apps and 13 seeded bugs. These numbers are indicative, not conclusive.
- The targets were written by our own team, with the bug classes our rules cover. Results on real-world code will be lower.
- A finding matches a seeded bug when file and CWE agree and the line is within ±2. Anything else counts as an extra finding, including low-severity reports of the safe decoys.
- Semgrep (default rules) was not run: semgrep not installed.
