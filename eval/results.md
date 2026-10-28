# Kavach evaluation

Seeded targets: 3 apps, 13 bugs (9 through project helpers, 4 direct). Generated 2026-10-29 02:17 by `eval/run.py`.

## Head-to-head

| Tool | Caught | Recall | Wrapper bugs | Direct bugs | Extra findings | Precision | Extra at severity ≥ 7 | Scan time |
|---|---|---|---|---|---|---|---|---|
| Bandit | 6/13 | 46% | 4/9 | 2/4 | 7 | 46% | 0 | 0.21s |
| Semgrep (p/python rules) | 7/13 | 54% | 3/9 | 4/4 | 3 | 70% | 0 | 2.82s |
| Kavach (taint) | 13/13 | 100% | 9/9 | 4/4 | 4 | 76% | 0 | 0.01s |

## Per app

| App | Bugs | Bandit | Semgrep (p/python rules) | Kavach (taint) |
|---|---|---|---|---|
| app1 | 4 | 2/4 | 2/4 | 4/4 |
| app2 | 5 | 3/5 | 3/5 | 5/5 |
| app3 | 4 | 1/4 | 2/4 | 4/4 |

## Missed bugs

- **Bandit:** app1/helpers.py:11 CWE-22 (wrapper), app1/helpers.py:21 CWE-89 (wrapper), app2/helpers.py:12 CWE-89 (wrapper), app2/app.py:36 CWE-22 (direct), app3/helpers.py:7 CWE-22 (wrapper), app3/helpers.py:16 CWE-89 (wrapper), app3/app.py:36 CWE-22 (direct)
- **Semgrep (p/python rules):** app1/helpers.py:11 CWE-22 (wrapper), app1/helpers.py:21 CWE-89 (wrapper), app2/helpers.py:12 CWE-89 (wrapper), app2/helpers.py:16 CWE-78 (wrapper), app3/helpers.py:7 CWE-22 (wrapper), app3/helpers.py:16 CWE-89 (wrapper)
- **Kavach (taint):** none

## Ablation

Seeded bugs only. Extra reports include low-severity notes; none of them would block a commit unless the last column says so.

| Configuration | Caught | Wrapper bugs | Precision | Extra reports | Extra at severity ≥ 7 | Note |
|---|---|---|---|---|---|---|
| Pattern rules only (Bandit) | 6/13 | 4/9 | 46% | 7 | 0 | |
| Taint only | 13/13 | 9/9 | 76% | 4 | 0 | |
| Pattern rules + taint | 13/13 | 9/9 | 59% | 9 | 0 | |
| Kavach engines (taint + rule layer) | 13/13 | 9/9 | 76% | 4 | 0 | |
| Full Kavach (taint + rule layer + Bandit + Semgrep) | 13/13 | 9/9 | 57% | 10 | 0 | |
| + ML ranker | same | same | same | same | same | Reorders findings, does not add or remove them. On held-out apps, false positives read before 90% recall: 5 -> 0 (100% fewer); model v1 trained on 23 findings from 3 projects |
| + patch suggester | same | same | same | same | same | Adds a checked fix per finding; see Patch suggester below. |
| + proof runner | | | | | | Not built: planned as a sandboxed check with no network. Patches are re-tested statically instead (below). |

## Patch suggester

For each seeded bug: the suggested patch, Kavach's whole-project re-trace of it, and a re-scan of a patched copy of the app by every detector (taint, rule layer, Bandit, Semgrep). This is a static re-test; no code is run.

| Bug | Patch | Re-trace | Left at the patched lines after a full re-scan |
|---|---|---|---|
| app1/helpers.py:7 CWE-78 | Run the program with an argument list, without a shell | fixed | 1 report(s), highest severity 6.9 (bandit) |
| app1/helpers.py:11 CWE-22 | Check the path stays inside the allowed folder | fixed | nothing |
| app1/helpers.py:21 CWE-89 | Use a parameterised query | fixed | nothing |
| app1/app.py:30 CWE-78 | Run the program with an argument list, without a shell | fixed | 1 report(s), highest severity 6.9 (bandit) |
| app2/helpers.py:7 CWE-78 | Run the program with an argument list, without a shell | fixed | 1 report(s), highest severity 6.9 (bandit) |
| app2/helpers.py:12 CWE-89 | Use a parameterised query | fixed | nothing |
| app2/app.py:26 CWE-78 | Run the program with an argument list, without a shell | fixed | 2 report(s), highest severity 6.9 (bandit) |
| app2/helpers.py:16 CWE-78 | Run the program with an argument list, without a shell | fixed | 1 report(s), highest severity 6.9 (bandit) |
| app2/app.py:36 CWE-22 | Check the path stays inside the allowed folder | fixed | nothing |
| app3/helpers.py:7 CWE-22 | Check the path stays inside the allowed folder | fixed | nothing |
| app3/helpers.py:11 CWE-78 | Run the program with an argument list, without a shell | fixed | 1 report(s), highest severity 6.9 (bandit) |
| app3/helpers.py:16 CWE-89 | Use a parameterised query | fixed | nothing |
| app3/app.py:36 CWE-22 | Check the path stays inside the allowed folder | fixed | nothing |

Patches written: 13/13. Confirmed fixed by the re-trace: 13/13. Serious reports (severity ≥ 7) left after patching: 0.
Lower-severity reports left on 6 patched line(s), none serious, from bandit: pattern tools that flag any use of a call, safe or not (for example Bandit's general warning on every subprocess call).

## Secrets and weak crypto (rule layer)

Labelled cases in `eval/rules_corpus/`: 36 problems to find and 25 decoys that look similar but are fine. Matching is on the exact line; tools that number a problem differently (Bandit calls every secret CWE-259) are counted as the same problem.

| Tool | Caught | Recall | Decoys flagged | Extra reports | Precision | Reports on our own real code | Scan time |
|---|---|---|---|---|---|---|---|
| Kavach rule layer | 36/36 | 100% | 0/25 | 0 | 100% | 0 | 0.00s |
| Bandit | 21/36 | 58% | 10/25 | 12 | 64% | 3 | 0.07s |
| Semgrep (p/python rules) | 9/36 | 25% | 0/25 | 1 | 90% | 0 | 0.91s |

| Problem | Cases | Kavach rule layer | Bandit | Semgrep (p/python rules) |
|---|---|---|---|---|
| Hard-coded credentials (CWE-798) | 18 | 18/18 | 8/18 | 0/18 |
| Broken or risky cryptographic algorithm (CWE-327) | 9 | 9/9 | 7/9 | 6/9 |
| Password hash too fast (CWE-916) | 1 | 1/1 | 0/1 | 0/1 |
| Key too short (CWE-326) | 2 | 2/2 | 2/2 | 2/2 |
| Certificate checks turned off (CWE-295) | 4 | 4/4 | 2/4 | 1/4 |
| Insufficiently random values (CWE-330) | 2 | 2/2 | 2/2 | 0/2 |

Our own real code is `backend/app`, `telemetry`, `demo`: it has no hard-coded secrets or weak crypto, so reports there are noise.
- Missed by Bandit: crypto_cases.py:17 CWE-916, crypto_cases.py:20 CWE-327, crypto_cases.py:27 CWE-295, crypto_cases.py:28 CWE-295, crypto_cases.py:29 CWE-327, secrets_cases.py:16 CWE-798, secrets_cases.py:20 CWE-798, secrets_cases.py:21 CWE-798, secrets_cases.py:22 CWE-798, secrets_cases.py:23 CWE-798, secrets_cases.py:24 CWE-798, secrets_cases.py:25 CWE-798, secrets_cases.py:26 CWE-798, secrets_cases.py:27 CWE-798, secrets_cases.py:28 CWE-798
- Missed by Semgrep (p/python rules): crypto_cases.py:17 CWE-916, crypto_cases.py:20 CWE-327, crypto_cases.py:21 CWE-327, crypto_cases.py:25 CWE-295, crypto_cases.py:27 CWE-295, crypto_cases.py:28 CWE-295, crypto_cases.py:29 CWE-327, crypto_cases.py:34 CWE-330, crypto_cases.py:35 CWE-330, secrets_cases.py:13 CWE-798, secrets_cases.py:14 CWE-798, secrets_cases.py:15 CWE-798, secrets_cases.py:16 CWE-798, secrets_cases.py:17 CWE-798, secrets_cases.py:18 CWE-798, secrets_cases.py:19 CWE-798, secrets_cases.py:20 CWE-798, secrets_cases.py:21 CWE-798, secrets_cases.py:22 CWE-798, secrets_cases.py:23 CWE-798, secrets_cases.py:24 CWE-798, secrets_cases.py:25 CWE-798, secrets_cases.py:26 CWE-798, secrets_cases.py:27 CWE-798, secrets_cases.py:28 CWE-798, secrets_cases.py:31 CWE-798, secrets_cases.py:32 CWE-798

Patches for these cases: 28/36 get one, 28 confirmed by re-reading the patched file. The rest are advice-only on purpose: a new cipher, a slow password hash or a hard-coded password check changes stored data or needs a design decision.

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
- The secrets and crypto cases were written by our team to cover what the rule layer checks, so they favour it. The 'own real code' column is the fairer comparison of noise.
- Semgrep uses its public registry ruleset (`p/python` unless SENTINEL_SEMGREP_CONFIG is set), downloaded at run time with metrics off. `--config auto` is not used because it requires sending metrics.
