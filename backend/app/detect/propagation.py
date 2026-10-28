"""Inter-procedural variable propagation with the standard `ast` module.

Answers: "which function parameters (or configured source expressions) can
flow into which configured sink calls, and through which functions?"

Everything security-specific is configuration. Callers supply:
- sinks:       call-name patterns (fnmatch), e.g. "pkg.store" or "*.write"
- sources:     dotted expression prefixes that produce untrusted data
- sanitizers:  call-name patterns whose result is considered cleaned
- entry_decorators: decorator patterns marking entry points (e.g. "*.route")

Labels: "param:x" (parameter x of the current function), "source:<prefix>",
and a leading "~" for a label that passed through a sanitizer.

Analysis model:
- Intra-procedural: strong updates on straight-line assignment, union at
  branch merges, fixpoint over loop bodies.
- Function summaries: which parameters flow to the return value.
- Inter-procedural: summaries iterated to a fixpoint (handles recursion);
  then "parameter reaches sink" facts propagate up the call graph, which
  is how project-specific wrapper functions are discovered.

Known limits: object fields are not tracked across methods, nested
functions and lambdas are not analysed, and calls through dynamic
expressions are reported as unresolved rather than followed.
"""

from __future__ import annotations

import argparse
import ast
import fnmatch
import json
import sys
from dataclasses import asdict, dataclass, field
from pathlib import Path

Label = str
Env = dict[str, frozenset[Label]]

MAX_ROUNDS = 50
MAX_LOOP_ITER = 10
_EMPTY: frozenset[Label] = frozenset()


@dataclass(frozen=True)
class Config:
    sinks: tuple[str, ...]
    sources: tuple[str, ...] = ()
    sanitizers: tuple[str, ...] = ()
    entry_decorators: tuple[str, ...] = ()
    propagate_unknown_calls: bool = True
    # obj.method(...) with an unknown obj type: follow it if exactly one class defines `method`.
    resolve_unique_methods: bool = True


@dataclass
class FunctionInfo:
    key: str
    file: str
    qualname: str
    cls: str | None
    node: ast.FunctionDef | ast.AsyncFunctionDef
    module: ModuleInfo
    positional: list[str]
    kwonly: list[str]
    vararg: str | None
    kwarg: str | None

    @property
    def params(self) -> list[str]:
        extra = [p for p in (self.vararg, self.kwarg) if p]
        return self.positional + self.kwonly + extra

    @property
    def display(self) -> str:
        return f"{self.qualname}()"


@dataclass
class ModuleInfo:
    file: str
    name: str
    is_package: bool
    aliases: dict[str, str] = field(default_factory=dict)
    functions: dict[str, FunctionInfo] = field(default_factory=dict)


@dataclass
class CallSite:
    raw: str
    callee: str
    line: int
    receiver: frozenset[Label]
    args: list[frozenset[Label]]
    kwargs: dict[str, frozenset[Label]]
    spread: frozenset[Label]
    via_attribute: bool
    target: str | None = None

    def labels(self) -> frozenset[Label]:
        out = set(self.receiver) | self.spread
        for group in (*self.args, *self.kwargs.values()):
            out |= group
        return frozenset(out)

    def merge(self, other: CallSite) -> CallSite:
        width = max(len(self.args), len(other.args))
        pad = lambda a: a + [_EMPTY] * (width - len(a))  # noqa: E731
        self.args = [x | y for x, y in zip(pad(self.args), pad(other.args))]
        for k, v in other.kwargs.items():
            self.kwargs[k] = self.kwargs.get(k, _EMPTY) | v
        self.receiver |= other.receiver
        self.spread |= other.spread
        return self


@dataclass
class Summary:
    returns: frozenset[Label] = _EMPTY
    calls: list[CallSite] = field(default_factory=list)
    unresolved: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class Hit:
    sink: str
    file: str
    line: int
    path: tuple[str, ...]


@dataclass(frozen=True)
class Flow:
    entry: str
    entry_file: str
    origin: str
    sink: str
    file: str
    line: int
    path: tuple[str, ...]
    sanitized: bool


@dataclass
class Result:
    flows: list[Flow]
    wrappers: dict[str, dict[str, str]]
    unresolved: list[str]
    parse_errors: list[str]
    entries: list[str] = field(default_factory=list)  # "file::qualname" of entry points


# --- helpers -----------------------------------------------------------------

def dotted(node: ast.AST) -> str | None:
    """'a.b.c' for Name/Attribute chains, 'f().attr' through calls; None if dynamic."""
    parts: list[str] = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
    elif isinstance(node, ast.Call) and (inner := dotted(node.func)):
        parts.append(f"{inner}()")
    else:
        return None
    return ".".join(reversed(parts))


def call_name(func: ast.expr) -> str | None:
    """Name of a called expression. Methods on computed receivers become '<expr>.method'."""
    if (name := dotted(func)) is not None:
        return name
    attrs: list[str] = []
    while isinstance(func, ast.Attribute):
        attrs.append(func.attr)
        func = func.value
    return "<expr>." + ".".join(reversed(attrs)) if attrs else None


def _matches(patterns: tuple[str, ...], *names: str) -> str | None:
    for pat in patterns:
        for name in names:
            if name and fnmatch.fnmatchcase(name, pat):
                return pat
    return None


def _sanitize(label: Label) -> Label:
    return label if label.startswith("~") else f"~{label}"


def _merge(*envs: Env) -> Env:
    out: Env = {}
    for env in envs:
        for name, labels in env.items():
            out[name] = out.get(name, _EMPTY) | labels
    return out


def bind(fn: FunctionInfo, site: CallSite) -> dict[str, frozenset[Label]]:
    """Map a call's argument labels onto the callee's parameter names."""
    params = list(fn.positional)
    bound: dict[str, frozenset[Label]] = {}
    is_method = fn.cls is not None and params and params[0] in ("self", "cls")
    if is_method and site.via_attribute and site.raw.split(".")[0] != fn.cls:
        bound[params[0]] = site.receiver
        params = params[1:]
    for i, labels in enumerate(site.args):
        name = params[i] if i < len(params) else fn.vararg
        if name:
            bound[name] = bound.get(name, _EMPTY) | labels
    for key, labels in site.kwargs.items():
        name = key if key in fn.params else fn.kwarg
        if name:
            bound[name] = bound.get(name, _EMPTY) | labels
    if site.spread:
        for name in fn.params:
            bound.setdefault(name, site.spread)
    return bound


def substitute(labels: frozenset[Label], binding: dict[str, frozenset[Label]],
               params_only: bool = False) -> frozenset[Label]:
    """Rewrite callee-side labels into caller-side labels."""
    out: set[Label] = set()
    for label in labels:
        sanitized = label.startswith("~")
        base = label.lstrip("~")
        if base.startswith("param:"):
            for b in binding.get(base[6:], _EMPTY):
                out.add(_sanitize(b) if sanitized else b)
        elif not params_only:
            out.add(label)
    return frozenset(out)


# --- intra-procedural analysis ----------------------------------------------

class _FunctionAnalysis:
    def __init__(self, project: Project, fn: FunctionInfo, config: Config):
        self.project, self.fn, self.config = project, fn, config
        self.calls: dict[tuple[int, int], CallSite] = {}
        self.returns: set[Label] = set()
        self.unresolved: dict[int, str] = {}

    def run(self) -> Summary:
        env: Env = {p: frozenset({f"param:{p}"}) for p in self.fn.params}
        self._block(self.fn.node.body, env)
        return Summary(frozenset(self.returns), list(self.calls.values()),
                       [f"{self.fn.file}:{ln} {txt}" for ln, txt in sorted(self.unresolved.items())])

    # statements

    def _block(self, stmts: list[ast.stmt], env: Env) -> Env:
        for stmt in stmts:
            env = self._stmt(stmt, env)
        return env

    def _stmt(self, s: ast.stmt, env: Env) -> Env:
        if isinstance(s, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            return env
        if isinstance(s, ast.Assign):
            labels = self._expr(s.value, env)
            for target in s.targets:
                self._assign(target, labels, env)
        elif isinstance(s, ast.AnnAssign) and s.value is not None:
            self._assign(s.target, self._expr(s.value, env), env)
        elif isinstance(s, ast.AugAssign):
            self._assign(s.target, self._expr(s.value, env) | self._expr(s.target, env), env)
        elif isinstance(s, ast.Return):
            self.returns |= self._expr(s.value, env)
        elif isinstance(s, ast.If):
            self._expr(s.test, env)
            return _merge(self._block(s.body, dict(env)), self._block(s.orelse, dict(env)))
        elif isinstance(s, (ast.For, ast.AsyncFor)):
            labels = self._expr(s.iter, env)
            return self._loop(s, env, lambda e: self._assign(s.target, labels, e))
        elif isinstance(s, ast.While):
            return self._loop(s, env, lambda e: self._expr(s.test, e))
        elif isinstance(s, (ast.With, ast.AsyncWith)):
            for item in s.items:
                labels = self._expr(item.context_expr, env)
                if item.optional_vars is not None:
                    self._assign(item.optional_vars, labels, env)
            return self._block(s.body, env)
        elif isinstance(s, (ast.Try, getattr(ast, "TryStar", ast.Try))):
            after = self._block(s.body, dict(env))
            entered = _merge(env, after)  # an exception can happen anywhere in the body
            outs = [self._block(s.orelse, dict(after))]
            outs += [self._block(h.body, dict(entered)) for h in s.handlers]
            return self._block(s.finalbody, _merge(*outs))
        elif isinstance(s, ast.Match):
            self._expr(s.subject, env)
            return _merge(env, *(self._block(c.body, dict(env)) for c in s.cases))
        else:
            for child in ast.iter_child_nodes(s):
                if isinstance(child, ast.expr):
                    self._expr(child, env)
        return env

    def _loop(self, s: ast.For | ast.AsyncFor | ast.While, env: Env, head) -> Env:
        current = dict(env)
        for _ in range(MAX_LOOP_ITER):
            body_env = dict(current)
            head(body_env)
            merged = _merge(current, self._block(s.body, body_env))
            if merged == current:
                break
            current = merged
        return self._block(s.orelse, current)

    def _assign(self, target: ast.expr, labels: frozenset[Label], env: Env) -> None:
        if isinstance(target, ast.Name):
            env[target.id] = labels  # strong update
        elif isinstance(target, (ast.Tuple, ast.List)):
            for elt in target.elts:
                self._assign(elt, labels, env)
        elif isinstance(target, ast.Starred):
            self._assign(target.value, labels, env)
        elif isinstance(target, (ast.Attribute, ast.Subscript)):
            root = target
            while isinstance(root, (ast.Attribute, ast.Subscript)):
                if isinstance(root, ast.Subscript):
                    self._expr(root.slice, env)
                root = root.value
            if isinstance(root, ast.Name):  # weak update of the containing object
                env[root.id] = env.get(root.id, _EMPTY) | labels

    # expressions

    def _source(self, node: ast.AST) -> frozenset[Label]:
        if not self.config.sources or (raw := dotted(node)) is None:
            return _EMPTY
        canon = self.project.canonical(self.fn.module, raw)
        for prefix in self.config.sources:
            if any(n == prefix or n.startswith(prefix + ".") for n in (raw, canon)):
                return frozenset({f"source:{prefix}"})
        return _EMPTY

    def _expr(self, node: ast.expr | None, env: Env) -> frozenset[Label]:
        if node is None:
            return _EMPTY
        if isinstance(node, ast.Name):
            return env.get(node.id, _EMPTY) | self._source(node)
        if isinstance(node, ast.Attribute):
            return self._expr(node.value, env) | self._source(node)
        if isinstance(node, ast.Subscript):
            self._expr(node.slice, env)  # an index does not taint the element
            return self._expr(node.value, env) | self._source(node.value)
        if isinstance(node, ast.Call):
            return self._call(node, env)
        if isinstance(node, ast.NamedExpr):
            labels = self._expr(node.value, env)
            self._assign(node.target, labels, env)
            return labels
        if isinstance(node, (ast.ListComp, ast.SetComp, ast.GeneratorExp, ast.DictComp)):
            return self._comprehension(node, env)
        if isinstance(node, ast.Lambda):
            return _EMPTY
        if isinstance(node, ast.Compare):
            for child in (node.left, *node.comparators):
                self._expr(child, env)
            return _EMPTY  # booleans carry no data
        out: frozenset[Label] = _EMPTY
        for child in ast.iter_child_nodes(node):
            if isinstance(child, ast.expr):
                out |= self._expr(child, env)
        return out

    def _comprehension(self, node, env: Env) -> frozenset[Label]:
        local = dict(env)
        for gen in node.generators:
            self._assign(gen.target, self._expr(gen.iter, local), local)
            for cond in gen.ifs:
                self._expr(cond, local)
        if isinstance(node, ast.DictComp):
            return self._expr(node.key, local) | self._expr(node.value, local)
        return self._expr(node.elt, local)

    def _call(self, node: ast.Call, env: Env) -> frozenset[Label]:
        args: list[frozenset[Label]] = []
        spread: frozenset[Label] = _EMPTY
        for arg in node.args:
            if isinstance(arg, ast.Starred):
                spread |= self._expr(arg.value, env)
            else:
                args.append(self._expr(arg, env))
        kwargs: dict[str, frozenset[Label]] = {}
        for kw in node.keywords:
            labels = self._expr(kw.value, env)
            if kw.arg is None:
                spread |= labels
            else:
                kwargs[kw.arg] = labels

        via_attribute = isinstance(node.func, ast.Attribute)
        receiver = self._expr(node.func.value, env) if via_attribute else _EMPTY
        raw = call_name(node.func)
        if raw is None:
            self._expr(node.func, env)
            self.unresolved[node.lineno] = ast.unparse(node.func)[:80]
            raw = "<dynamic>"
        callee = self.project.canonical(self.fn.module, raw)
        site = CallSite(raw, callee, node.lineno, receiver, args, kwargs, spread, via_attribute)
        key = (node.lineno, node.col_offset)
        site = self.calls[key].merge(site) if key in self.calls else site
        self.calls[key] = site

        if _matches(self.config.sanitizers, callee, raw):
            return frozenset(_sanitize(lbl) for lbl in site.labels())
        target = self.project.resolve(self.fn, raw)
        if target is not None:
            site.target = target.key
            returns = self.project.summaries[target.key].returns
            return substitute(returns, bind(target, site))
        return site.labels() if self.config.propagate_unknown_calls else _EMPTY


# --- project model and inter-procedural analysis -----------------------------

def _module_name(rel: str) -> tuple[str, bool]:
    parts = list(Path(rel).with_suffix("").parts)
    is_package = parts[-1] == "__init__"
    if is_package:
        parts = parts[:-1]
    return ".".join(parts), is_package


def _parameters(node: ast.FunctionDef | ast.AsyncFunctionDef):
    a = node.args
    positional = [p.arg for p in (*a.posonlyargs, *a.args)]
    return (positional, [p.arg for p in a.kwonlyargs],
            a.vararg.arg if a.vararg else None, a.kwarg.arg if a.kwarg else None)


class Project:
    def __init__(self) -> None:
        self.modules: dict[str, ModuleInfo] = {}
        self.functions: dict[str, FunctionInfo] = {}
        self.summaries: dict[str, Summary] = {}
        self.parse_errors: list[str] = []
        self.config: Config | None = None

    @classmethod
    def from_sources(cls, sources: dict[str, str]) -> Project:
        """sources: {relative/path.py: source text}"""
        project = cls()
        for rel, text in sorted(sources.items()):
            try:
                project._add_module(rel, ast.parse(text, filename=rel))
            except SyntaxError as exc:
                project.parse_errors.append(f"{rel}:{exc.lineno}: {exc.msg}")
        return project

    @classmethod
    def from_directory(cls, root: Path, files: list[str] | None = None) -> Project:
        if files is None:
            from app.ingest.filter import filter_project
            files = filter_project(root, max_file_bytes=2 * 1024 * 1024).files
        return cls.from_sources({rel: (root / rel).read_text(errors="replace") for rel in files})

    def _add_module(self, rel: str, tree: ast.Module) -> None:
        name, is_package = _module_name(rel)
        module = ModuleInfo(rel, name, is_package)
        self.modules[name] = module
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    local = alias.asname or alias.name.split(".")[0]
                    module.aliases[local] = alias.name if alias.asname else local
            elif isinstance(node, ast.ImportFrom):
                base = self._import_base(module, node)
                for alias in node.names:
                    full = f"{base}.{alias.name}" if base else alias.name
                    module.aliases[alias.asname or alias.name] = full
        for node in tree.body:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                self._add_function(module, node, None)
            elif isinstance(node, ast.ClassDef):
                for item in node.body:
                    if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
                        self._add_function(module, item, node.name)

    @staticmethod
    def _import_base(module: ModuleInfo, node: ast.ImportFrom) -> str:
        if not node.level:
            return node.module or ""
        parts = module.name.split(".") if module.name else []
        keep = len(parts) - node.level + (1 if module.is_package else 0)
        base = parts[:max(keep, 0)]
        return ".".join(base + ([node.module] if node.module else []))

    def _add_function(self, module: ModuleInfo, node, cls: str | None) -> None:
        qualname = f"{cls}.{node.name}" if cls else node.name
        positional, kwonly, vararg, kwarg = _parameters(node)
        fn = FunctionInfo(f"{module.file}::{qualname}", module.file, qualname, cls, node,
                          module, positional, kwonly, vararg, kwarg)
        module.functions[qualname] = fn
        self.functions[fn.key] = fn

    def canonical(self, module: ModuleInfo, raw: str) -> str:
        head, dot, rest = raw.partition(".")
        if head in module.aliases:
            return module.aliases[head] + (dot + rest if dot else "")
        return raw

    def _module_named(self, name: str) -> ModuleInfo | None:
        if name in self.modules:
            return self.modules[name]
        matches = [m for m in self.modules.values()
                   if m.name.endswith("." + name) or name.endswith("." + m.name)]
        return matches[0] if len(matches) == 1 else None

    def resolve(self, fn: FunctionInfo, raw: str) -> FunctionInfo | None:
        """Resolve a call written inside `fn` to a project function, if possible."""
        module = fn.module
        parts = raw.split(".")
        if parts[0] in ("self", "cls") and fn.cls and len(parts) == 2:
            return module.functions.get(f"{fn.cls}.{parts[1]}")
        if raw in module.functions and raw not in module.aliases:
            return module.functions[raw]
        canon = self.canonical(module, raw)
        owner, _, attr = canon.rpartition(".")
        if not owner:
            return None
        if (target := self._module_named(owner)) is not None:
            return target.functions.get(attr)
        owner_mod, _, cls = owner.rpartition(".")
        if owner_mod and (target := self._module_named(owner_mod)) is not None:
            if found := target.functions.get(f"{cls}.{attr}"):
                return found
        if self.config and self.config.resolve_unique_methods and len(parts) >= 2:
            methods = [f for f in self.functions.values() if f.cls and f.node.name == parts[-1]]
            if len(methods) == 1:
                return methods[0]
        return None

    # analysis

    def analyse(self, config: Config) -> Result:
        self.config = config
        self.summaries = {key: Summary() for key in self.functions}
        for _ in range(MAX_ROUNDS):
            changed = False
            for fn in self.functions.values():
                summary = _FunctionAnalysis(self, fn, config).run()
                changed |= summary.returns != self.summaries[fn.key].returns
                self.summaries[fn.key] = summary
            if not changed:
                break
        reach = self._reach(config)
        entries = self._entries(config)
        return Result(self._flows(reach, entries), self._wrappers(reach),
                      sorted({u for s in self.summaries.values() for u in s.unresolved}),
                      self.parse_errors, sorted(entries))

    def _reach(self, config: Config) -> dict[str, dict[Label, Hit]]:
        reach: dict[str, dict[Label, Hit]] = {key: {} for key in self.functions}

        def offer(key: str, label: Label, hit: Hit) -> bool:
            current = reach[key].get(label)
            if current is None or len(hit.path) < len(current.path):
                reach[key][label] = hit
                return True
            return False

        for fn in self.functions.values():
            for site in self.summaries[fn.key].calls:
                if _matches(config.sinks, site.callee, site.raw):
                    hit = Hit(site.callee, fn.file, site.line, (fn.display, site.callee))
                    for label in site.labels():
                        offer(fn.key, label, hit)

        for _ in range(MAX_ROUNDS):
            changed = False
            for fn in self.functions.values():
                for site in self.summaries[fn.key].calls:
                    if site.target is None or not reach[site.target]:
                        continue
                    binding = bind(self.functions[site.target], site)
                    for label, hit in list(reach[site.target].items()):
                        extended = Hit(hit.sink, hit.file, hit.line, (fn.display, *hit.path))
                        for mapped in substitute(frozenset({label}), binding, params_only=True):
                            changed |= offer(fn.key, mapped, extended)
            if not changed:
                break
        return reach

    def _entries(self, config: Config) -> set[str]:
        if config.entry_decorators:
            entries = set()
            for fn in self.functions.values():
                for dec in fn.node.decorator_list:
                    raw = dotted(dec.func if isinstance(dec, ast.Call) else dec) or ""
                    if _matches(config.entry_decorators, raw,
                                self.canonical(fn.module, raw)):
                        entries.add(fn.key)
            return entries
        called = {s.target for summ in self.summaries.values() for s in summ.calls if s.target}
        return set(self.functions) - called  # roots of the call graph

    def _flows(self, reach: dict[str, dict[Label, Hit]], entries: set[str]) -> list[Flow]:
        flows = []
        for key, facts in reach.items():
            fn = self.functions[key]
            for label, hit in facts.items():
                base = label.lstrip("~")
                if base.startswith("source:") or (base.startswith("param:") and key in entries):
                    flows.append(Flow(fn.qualname, fn.file, base, hit.sink, hit.file, hit.line,
                                      hit.path, label.startswith("~")))
        return sorted(flows, key=lambda f: (f.entry_file, f.entry, f.origin, f.sanitized))

    def _wrappers(self, reach: dict[str, dict[Label, Hit]]) -> dict[str, dict[str, str]]:
        """Functions whose parameter reaches a sink without sanitizing: project-specific sinks."""
        out: dict[str, dict[str, str]] = {}
        for key, facts in reach.items():
            params = {lbl[6:]: hit.sink for lbl, hit in facts.items() if lbl.startswith("param:")}
            if params:
                fn = self.functions[key]
                out[f"{fn.file}::{fn.qualname}"] = dict(sorted(params.items()))
        return dict(sorted(out.items()))


def trace(sources: dict[str, str], config: Config) -> Result:
    """Convenience entry point: analyse in-memory sources."""
    return Project.from_sources(sources).analyse(config)


# --- CLI ---------------------------------------------------------------------

def _print_text(result: Result) -> None:
    for flow in result.flows:
        tag = " (sanitized)" if flow.sanitized else ""
        print(f"{flow.entry_file}::{flow.entry}  {flow.origin} -> {flow.sink}"
              f"  at {flow.file}:{flow.line}{tag}")
        print(f"    path: {' -> '.join(flow.path)}")
    if result.wrappers:
        print("\nWrapper functions (parameter reaches a sink):")
        for name, params in result.wrappers.items():
            print(f"    {name}: " + ", ".join(f"{p} -> {s}" for p, s in params.items()))
    for item in result.unresolved:
        print(f"unresolved dynamic call: {item}", file=sys.stderr)
    for err in result.parse_errors:
        print(f"parse error: {err}", file=sys.stderr)
    print(f"\n{len(result.flows)} flows, {len(result.wrappers)} wrappers", file=sys.stderr)


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="python -m app.detect.propagation",
                                description="Trace variable propagation through functions.")
    p.add_argument("path", type=Path, help="project directory")
    p.add_argument("--sink", action="append", required=True, help="call pattern, repeatable")
    p.add_argument("--source", action="append", default=[], help="expression prefix, repeatable")
    p.add_argument("--sanitizer", action="append", default=[], help="call pattern, repeatable")
    p.add_argument("--entry-decorator", action="append", default=[],
                   help="decorator pattern marking entry points, e.g. '*.route'")
    p.add_argument("--json", action="store_true")
    args = p.parse_args(argv)
    config = Config(tuple(args.sink), tuple(args.source), tuple(args.sanitizer),
                    tuple(args.entry_decorator))
    result = Project.from_directory(args.path.resolve()).analyse(config)
    if args.json:
        print(json.dumps(asdict(result), indent=2))
    else:
        _print_text(result)
    return 0


if __name__ == "__main__":
    sys.exit(main())
