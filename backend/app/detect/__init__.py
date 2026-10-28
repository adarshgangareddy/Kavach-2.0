"""L2 Detection: plug-in interface.

The team's own engine (call graph, taint, wrapper discovery) implements the
`Detector` protocol in `base.py` and registers itself in `registry.py`.
Bandit and Semgrep adapters are included so the pipeline works end to end
before the engine lands.
"""
