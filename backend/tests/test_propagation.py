"""Propagation tracer tests. Sinks, sources and sanitizers are neutral made-up names."""

import json
import textwrap

from app.detect import propagation
from app.detect.propagation import Config, trace

CFG = Config(sinks=("store", "*.store"), sources=("inbox.data",), sanitizers=("clean",))


def run(files: dict[str, str], config: Config = CFG):
    return trace({k: textwrap.dedent(v) for k, v in files.items()}, config)


def flows_of(result, entry):
    return [f for f in result.flows if f.entry == entry]


def test_direct_parameter_to_sink():
    result = run({"m.py": """
        def entry(q):
            a = q.strip()
            b = f"pre-{a}"
            store(b)
    """})
    [flow] = result.flows
    assert (flow.origin, flow.sink, flow.line) == ("param:q", "store", 5)
    assert flow.path == ("entry()", "store")


def test_through_helper_wrapper_and_return_values():
    result = run({"m.py": """
        def ident(x):
            return x

        def record(value):
            store(ident(value))

        def entry(q):
            record(q)

        def constant_only(q):
            store(ident("fixed"))
    """})
    assert [f.path for f in flows_of(result, "entry")] == [("entry()", "record()", "store")]
    assert flows_of(result, "constant_only") == []
    assert result.wrappers["m.py::record"] == {"value": "store"}


def test_strong_update_kills_old_value():
    result = run({"m.py": """
        def entry(q):
            x = q
            x = "constant"
            store(x)
    """})
    assert result.flows == []


def test_branches_merge_and_loops_reach_fixpoint():
    result = run({"m.py": """
        def branch(q, flag):
            if flag:
                x = q
            else:
                x = "c"
            store(x)

        def loop(q):
            y = ""
            for _ in range(3):
                store(y)
                y = q
    """})
    assert {f.entry for f in result.flows} == {"branch", "loop"}
    assert {f.origin for f in flows_of(result, "branch")} == {"param:q"}


def test_sanitizer_marks_flow_and_is_not_a_wrapper():
    result = run({"m.py": """
        def tidy(v):
            return clean(v)

        def entry(q):
            store(tidy(q))
    """})
    [flow] = result.flows
    assert flow.sanitized is True
    assert result.wrappers == {}


def test_methods_via_self_and_instances():
    result = run({"m.py": """
        class Box:
            def put(self, v):
                self.keep(v)

            def keep(self, v):
                store(v)

        def via_class(q, box):
            Box.put(box, q)

        def via_instance(q, box):
            box.put(q)
    """})
    expected = ("Box.put()", "Box.keep()", "store")
    assert flows_of(result, "via_class")[0].path == ("via_class()", *expected)
    assert flows_of(result, "via_instance")[0].path == ("via_instance()", *expected)
    assert result.wrappers["m.py::Box.keep"] == {"v": "store"}


def test_ambiguous_method_names_are_not_guessed():
    result = run({"m.py": """
        class A:
            def put(self, v):
                store(v)

        class B:
            def put(self, v):
                return v

        def entry(q, obj):
            obj.put(q)
    """})
    assert flows_of(result, "entry") == []


def test_cross_module_imports_and_aliases():
    result = run({
        "pkg/__init__.py": "",
        "pkg/helpers.py": """
            def record(value):
                store(value)
        """,
        "pkg/views.py": """
            from .helpers import record
            import pkg.helpers as hp

            def one(q):
                record(q)

            def two(q):
                hp.record(q)
        """,
    })
    assert {f.entry for f in result.flows} >= {"one", "two"}
    assert flows_of(result, "one")[0].file == "pkg/helpers.py"


def test_configured_source_expressions():
    result = run({"m.py": """
        def record(v):
            store(v)

        def handler():
            v = inbox.data.get("k")
            record(v)
    """})
    [flow] = flows_of(result, "handler")
    assert flow.origin == "source:inbox.data"
    assert flow.path == ("handler()", "record()", "store")


def test_entry_decorators_select_entry_points():
    config = Config(sinks=("store",), entry_decorators=("*.route",))
    result = run({"m.py": """
        @app.route("/x")
        def entry(q):
            helper(q)

        def helper(v):
            store(v)

        def not_an_entry(q):
            store(q)
    """}, config)
    assert {f.entry for f in result.flows} == {"entry"}


def test_containers_comprehensions_and_unpacking():
    result = run({"m.py": """
        def entry(q):
            items = [q, "x"]
            joined = ",".join(i.upper() for i in items)
            a, b = joined, 1
            data = {"k": a}
            store(data["k"])
    """})
    assert len(result.flows) == 1


def test_recursion_terminates_and_dynamic_calls_are_reported():
    result = run({"m.py": """
        def walk(v, n):
            if n:
                return walk(v, n - 1)
            return v

        def entry(q):
            store(walk(q, 3))
            handlers["x"](q)
    """})
    assert flows_of(result, "entry")
    assert any("handlers" in u for u in result.unresolved)


def test_methods_on_computed_receivers_match_sinks():
    result = run({"m.py": """
        def entry(q, base):
            (base / q).store()
            name = ", ".join([q])
    """})
    assert {(f.origin, f.sink) for f in result.flows} == {
        ("param:q", "<expr>.store"), ("param:base", "<expr>.store")}
    assert result.unresolved == []


def test_parse_errors_are_collected():
    result = run({"bad.py": "def broken(:\n", "ok.py": "def f(q):\n    store(q)\n"})
    assert result.parse_errors and result.flows


def test_cli_json(tmp_path, capsys):
    (tmp_path / "m.py").write_text("def entry(q):\n    store(q)\n")
    assert propagation.main([str(tmp_path), "--sink", "store", "--json"]) == 0
    data = json.loads(capsys.readouterr().out)
    assert data["flows"][0]["origin"] == "param:q"


def test_literal_dynamic_imports_resolve_for_sinks_and_sanitizers():
    result = run({"m.py": """
        import importlib

        def via_dunder(q):
            __import__("pkg").store(q)

        def via_importlib(q):
            importlib.import_module("pkg").store(q)

        def cleaned(q):
            store(__import__("tools").clean(q))

        def computed(q, name):
            __import__(name).store(q)
    """}, Config(sinks=("pkg.store", "store"), sanitizers=("tools.clean",)))
    by_entry = {f.entry: f for f in result.flows}
    assert by_entry["via_dunder"].sink == "pkg.store"
    assert by_entry["via_importlib"].sink == "pkg.store"
    assert by_entry["cleaned"].sanitized is True
    assert "computed" not in by_entry  # a non-literal module name is not guessed


def test_chained_calls_are_separate_call_sites():
    result = run({"m.py": """
        def entry(q):
            connect().store(q)

        def nested(q):
            connect(q).store("fixed")
    """}, Config(sinks=("*.store",)))
    flows = {f.entry: f for f in result.flows}
    assert flows["entry"].sink == "connect().store"
    assert flows["nested"].sink == "connect().store"  # q flows into the receiver


def test_one_input_reaching_several_sinks_reports_each():
    result = run({"m.py": """
        def helper(v):
            store(v)

        def entry(q):
            store(q)
            helper(q)
    """})
    flows = [(f.line, f.path) for f in result.flows if f.entry == "entry"]
    assert flows == [(3, ("entry()", "helper()", "store")), (6, ("entry()", "store"))]
