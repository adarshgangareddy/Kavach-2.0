"""Detector registry. SENTINEL_DETECTORS=name1,name2 picks which ones run."""

import os
from collections.abc import Iterator
from contextlib import contextmanager

from app.detect.adapters import BanditDetector, SemgrepDetector
from app.detect.base import Detector
from app.detect.taint import TaintDetector

_registry: dict[str, Detector] = {}
_override: list[Detector] | None = None


def register(detector: Detector) -> None:
    _registry[detector.name] = detector


def all_detectors() -> list[Detector]:
    return list(_override if _override is not None else _registry.values())


def active_detectors() -> list[Detector]:
    wanted = os.environ.get("SENTINEL_DETECTORS")
    chosen = all_detectors()
    if wanted and _override is None:
        names = {n.strip() for n in wanted.split(",") if n.strip()}
        chosen = [d for d in chosen if d.name in names]
    return [d for d in chosen if d.available()]


@contextmanager
def use_detectors(detectors: list[Detector]) -> Iterator[None]:
    """Temporarily replace the registry (tests, evaluation runs)."""
    global _override
    previous, _override = _override, detectors
    try:
        yield
    finally:
        _override = previous


register(TaintDetector())
register(BanditDetector())
register(SemgrepDetector())
