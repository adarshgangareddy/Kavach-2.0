"""Detection regression suite over the seeded targets in targets/<app>/.

Skipped until the targets exist. See app/devtools/baseline.py for how baselines
are created and updated.
"""

import os
import warnings
from pathlib import Path

import pytest

from app.devtools import baseline

REPO = Path(__file__).resolve().parents[2]
RULES = REPO / "backend" / "sentinel-rules.toml"
APPS = sorted(p.parent for p in (REPO / "targets").glob("*/truth.json"))


@pytest.mark.parametrize(
    "app_dir",
    APPS or [pytest.param(None, marks=pytest.mark.skip(reason="no seeded targets in targets/ yet"))],
    ids=[p.name for p in APPS] or ["no-targets"],
)
def test_detection_does_not_regress(app_dir):
    current = baseline.summarize(app_dir, RULES)
    saved = baseline.load_baseline(app_dir)
    if saved is None or os.environ.get("SENTINEL_UPDATE_BASELINE") == "1":
        path = baseline.write_baseline(app_dir, current)
        pytest.skip(f"baseline written to {path.relative_to(REPO)}: "
                    f"{len(current['caught'])}/{current['truth']} caught, "
                    f"{current['false_positives']} false positives. Commit it.")
    regressions, improvements = baseline.compare(saved, current)
    assert not regressions, (
        f"{app_dir.name}: detection regressed:\n  " + "\n  ".join(regressions)
        + "\nIf this change is intended, update the baseline with SENTINEL_UPDATE_BASELINE=1."
    )
    if improvements:
        warnings.warn(f"{app_dir.name} improved ({'; '.join(improvements)}); "
                      "update the baseline with SENTINEL_UPDATE_BASELINE=1 to lock it in")
