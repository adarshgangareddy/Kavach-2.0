"""Runtime scoring for the ML ranker. Pure Python, no scikit-learn needed.

The trained model is a standardized logistic regression stored as JSON
weights (see train.py). JSON rather than pickle/joblib: loading a pickle can
execute code, which a security tool should never do with a file on disk.
"""

import json
import math
import os
from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from app.rank.features import FEATURES, extract
from app.schema import Finding

MODEL_VERSION = 1
DEFAULT_MODEL = Path(__file__).resolve().parents[2] / "sentinel-model.json"


class ModelError(ValueError):
    pass


def _finite_list(data: dict, key: str, length: int) -> list[float]:
    values = data.get(key)
    if not isinstance(values, list) or len(values) != length:
        raise ModelError(f"'{key}' must be a list of {length} numbers")
    out = []
    for v in values:
        if isinstance(v, bool) or not isinstance(v, (int, float)) or not math.isfinite(v):
            raise ModelError(f"'{key}' contains a non-finite or non-numeric value")
        out.append(float(v))
    return out


def _sigmoid(z: float) -> float:
    if z >= 0:
        return 1.0 / (1.0 + math.exp(-z))
    ez = math.exp(z)
    return ez / (1.0 + ez)


@dataclass(frozen=True)
class LinearModel:
    mean: tuple[float, ...]
    scale: tuple[float, ...]
    coef: tuple[float, ...]
    intercept: float
    meta: dict = field(default_factory=dict, compare=False)

    @classmethod
    def from_dict(cls, data: Any) -> "LinearModel":
        if not isinstance(data, dict) or data.get("version") != MODEL_VERSION:
            raise ModelError(f"unsupported model format (expected version {MODEL_VERSION})")
        if tuple(data.get("features", ())) != FEATURES:
            raise ModelError("model was trained on a different feature set; retrain it")
        n = len(FEATURES)
        scale = _finite_list(data, "scale", n)
        if any(s <= 0 for s in scale):
            raise ModelError("'scale' values must be positive")
        intercept = data.get("intercept")
        if isinstance(intercept, bool) or not isinstance(intercept, (int, float)) \
                or not math.isfinite(intercept):
            raise ModelError("'intercept' must be a finite number")
        return cls(tuple(_finite_list(data, "mean", n)), tuple(scale),
                   tuple(_finite_list(data, "coef", n)), float(intercept),
                   dict(data.get("meta", {})))

    def to_dict(self) -> dict:
        return {"version": MODEL_VERSION, "features": list(FEATURES), "mean": list(self.mean),
                "scale": list(self.scale), "coef": list(self.coef),
                "intercept": self.intercept, "meta": self.meta}

    def score_vector(self, x: Sequence[float]) -> float:
        z = self.intercept + sum(c * (v - m) / s
                                 for c, v, m, s in zip(self.coef, x, self.mean, self.scale))
        return _sigmoid(z)

    def score(self, item: Any) -> float:
        """Estimated probability that the finding is a real issue."""
        return self.score_vector(extract(item))


def model_path() -> Path:
    return Path(os.environ.get("SENTINEL_MODEL", DEFAULT_MODEL))


_cache: dict[str, tuple[float, LinearModel | None, str]] = {}


def load_model(path: Path | None = None) -> tuple[LinearModel | None, str]:
    """(model or None, human-readable status). Reloads when the file changes."""
    path = path or model_path()
    try:
        mtime = path.stat().st_mtime
    except FileNotFoundError:
        return None, "heuristic (no model file; ml_rank = detector confidence)"
    cached = _cache.get(str(path))
    if cached and cached[0] == mtime:
        return cached[1], cached[2]
    try:
        model = LinearModel.from_dict(json.loads(path.read_text()))
        meta = model.meta
        status = (f"model v{MODEL_VERSION} trained on {meta.get('findings', '?')} findings "
                  f"from {meta.get('projects', '?')} projects")
    except (OSError, ValueError) as exc:  # ModelError and JSONDecodeError are ValueErrors
        model, status = None, f"heuristic (model file rejected: {exc})"
    _cache[str(path)] = (mtime, model, status)
    return model, status


def apply(findings: list[Finding]) -> list[Finding]:
    """Replace ml_rank with the model's score; unchanged when no valid model exists."""
    model, _ = load_model()
    if model is None:
        return findings
    return [f.model_copy(update={"ml_rank": round(model.score(f), 4)}) for f in findings]
