"""Taint detector: runs the propagation tracer once per rule in sentinel-rules.toml."""

import hashlib
import os
import tomllib
from dataclasses import dataclass
from pathlib import Path

from app.detect.base import Candidate
from app.detect.propagation import Config, Flow, Project, SinkSpec
from app.schema import ConfidenceTier

DEFAULT_RULES = Path(__file__).resolve().parents[2] / "sentinel-rules.toml"

# Confidence feeds the severity formula. A sanitized path is probably safe,
# so it is reported with low confidence rather than dropped.
CONFIDENCE = 0.8
SANITIZED_CONFIDENCE = 0.3


class RulesError(ValueError):
    pass


@dataclass(frozen=True)
class Rule:
    id: str
    cwe: str
    sinks: tuple[str | SinkSpec, ...]
    sanitizers: tuple[str, ...]


@dataclass(frozen=True)
class Rules:
    rules: tuple[Rule, ...]
    sources: tuple[str, ...]
    entry_decorators: tuple[str, ...]
    digest: str

    def active(self) -> tuple[Rule, ...]:
        return tuple(r for r in self.rules if r.sinks)


def _strings(table: dict, key: str, where: str) -> tuple[str, ...]:
    value = table.get(key, [])
    if not isinstance(value, list) or not all(isinstance(v, str) and v for v in value):
        raise RulesError(f"{where}: '{key}' must be a list of non-empty strings")
    return tuple(value)


_SINK_KEYS = {"call", "args", "kwargs", "when"}


def _sink(value, where: str) -> str | SinkSpec:
    """A sink is a call pattern string, or a table narrowing which arguments count:
    { call = "*.execute", args = [0], kwargs = ["sql"], when = { shell = true } }
    """
    if isinstance(value, str) and value:
        return value
    if not isinstance(value, dict):
        raise RulesError(f"{where}: each sink must be a string or a table")
    if unknown := set(value) - _SINK_KEYS:
        raise RulesError(f"{where}: unknown sink keys {sorted(unknown)}")
    call = value.get("call")
    if not isinstance(call, str) or not call:
        raise RulesError(f"{where}: a sink table needs 'call'")
    args = value.get("args")
    if args is not None and (not isinstance(args, list) or not all(
            isinstance(i, int) and not isinstance(i, bool) and i >= 0 for i in args)):
        raise RulesError(f"{where}: sink 'args' must be a list of argument positions (0, 1, ...)")
    kwargs = value.get("kwargs", [])
    if not isinstance(kwargs, list) or not all(isinstance(k, str) and k for k in kwargs):
        raise RulesError(f"{where}: sink 'kwargs' must be a list of keyword names")
    when = value.get("when", {})
    if not isinstance(when, dict) or not all(
            isinstance(v, (str, int, float, bool)) for v in when.values()):
        raise RulesError(f"{where}: sink 'when' must map keyword names to literal values")
    if args is None and kwargs:
        args = []  # naming keywords means "only these", not "everything"
    return SinkSpec(call, tuple(args) if args is not None else None, tuple(kwargs),
                    tuple(sorted(when.items())))


def _sinks(table: dict, where: str) -> tuple[str | SinkSpec, ...]:
    value = table.get("sinks", [])
    if not isinstance(value, list):
        raise RulesError(f"{where}: 'sinks' must be a list")
    return tuple(_sink(v, f"{where} sink #{n + 1}") for n, v in enumerate(value))


def load_rules(path: Path) -> Rules:
    try:
        raw = path.read_bytes()
        data = tomllib.loads(raw.decode())
    except FileNotFoundError as exc:
        raise RulesError(f"rules file not found: {path}") from exc
    except (tomllib.TOMLDecodeError, UnicodeDecodeError) as exc:
        raise RulesError(f"{path.name}: {exc}") from exc

    rules = []
    for i, table in enumerate(data.get("rule", [])):
        where = f"{path.name} rule #{i + 1}"
        if not isinstance(table.get("id"), str) or not str(table.get("cwe", "")).startswith("CWE-"):
            raise RulesError(f"{where}: needs 'id' and a 'cwe' like \"CWE-78\"")
        rules.append(Rule(table["id"], table["cwe"], _sinks(table, where),
                          _strings(table, "sanitizers", where)))
    return Rules(tuple(rules), _strings(data, "sources", path.name),
                 _strings(data, "entry_decorators", path.name),
                 hashlib.sha256(raw).hexdigest()[:12])


def rules_path() -> Path:
    return Path(os.environ.get("SENTINEL_RULES", DEFAULT_RULES))


def _describe_origin(flow: Flow) -> str:
    kind, _, name = flow.origin.partition(":")
    return name if kind == "source" else f"{flow.entry}({name})"


def to_candidate(flow: Flow, rule: Rule, public: bool) -> Candidate:
    return Candidate(
        file=flow.file,
        line=flow.line,
        cwe=rule.cwe,
        # More than "entry -> sink" means the path went through project helpers.
        detector="taint-wrapper" if len(flow.path) > 2 else "taint",
        source=_describe_origin(flow),
        sink=flow.sink,
        path=list(flow.path),
        confidence_tier=ConfidenceTier.REACHABLE,
        confidence=SANITIZED_CONFIDENCE if flow.sanitized else CONFIDENCE,
        reachable=True,
        public_route=public,
        sanitizer_present=flow.sanitized,
    )


class TaintDetector:
    name = "taint"
    whole_program = True

    def __init__(self, path: Path | None = None):
        self._path = path

    @property
    def path(self) -> Path:
        return self._path or rules_path()

    @property
    def version(self) -> str:
        """Changes whenever the rules file changes, so cached results are invalidated."""
        try:
            return f"tracer-1+{load_rules(self.path).digest}"
        except RulesError:
            return "tracer-1+invalid"

    def available(self) -> bool:
        """False until the rules file lists at least one sink. A broken file stays
        'available' so scan() can report the error instead of hiding it."""
        try:
            return bool(load_rules(self.path).active())
        except RulesError:
            return self.path.exists()

    def scan(self, root: Path, files: list[str], timeout_s: float) -> list[Candidate]:
        return self.scan_project(Project.from_directory(root, files))

    def scan_sources(self, sources: dict[str, str]) -> list[Candidate]:
        """Same analysis on source text held in memory: {relative/path.py: text}."""
        return self.scan_project(Project.from_sources(sources))

    def scan_project(self, project: Project) -> list[Candidate]:
        rules = load_rules(self.path)
        out: list[Candidate] = []
        for rule in rules.active():
            config = Config(sinks=rule.sinks, sources=rules.sources,
                            sanitizers=rule.sanitizers,
                            entry_decorators=rules.entry_decorators)
            result = project.analyse(config)
            public = set(result.entries) if rules.entry_decorators else set()
            out.extend(to_candidate(f, rule, f"{f.entry_file}::{f.entry}" in public)
                       for f in result.flows)
        return out
