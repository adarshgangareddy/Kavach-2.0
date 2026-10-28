"""Patch suggester: rewrites, refusals, the whole-project re-check and the API.

The main cases use the team's seeded targets in targets/<app>/ (the same fixtures as the
detection regression suite). The short snippets below are one-line inputs for the parser:
they are only read with ast, never run.
"""

import io
import json
import shutil
import subprocess
import zipfile
from pathlib import Path

import pytest

from app.detect.registry import use_detectors
from app.detect.taint import TaintDetector
from app.fix.patch import HELPER_SOURCE, SAFE_PATH_HELPER, suggest_patch
from app.fix.verify import verify
from tests.conftest import signed_in_client

REPO = Path(__file__).resolve().parents[2]
APPS = sorted(p.parent for p in (REPO / "targets").glob("*/truth.json"))
TRUTH = [(app, bug) for app in APPS for bug in json.loads((app / "truth.json").read_text())]


def _sources(app: Path) -> dict[str, str]:
    return {p.name: p.read_text() for p in app.glob("*.py")}


def _added(patch) -> list[str]:
    return [l[1:] for l in patch.diff.splitlines() if l.startswith("+") and not l.startswith("+++")]


# every seeded bug gets a patch, and Kavach's re-trace confirms it --------------

@pytest.mark.parametrize("app, bug", TRUTH, ids=[f"{a.name}-{b['file']}:{b['line']}" for a, b in TRUTH])
def test_every_seeded_bug_gets_a_checked_patch(app, bug):
    sources = _sources(app)
    patch = suggest_patch(sources[bug["file"]], bug["file"], bug["line"], bug["cwe"])
    assert patch.available, patch.reason
    check = verify(sources, bug["file"], patch.patched_source, bug["cwe"], patch.changed_lines)
    assert check.status == "fixed", check.message
    assert check.paths_before >= 1


def test_patch_changes_only_what_it_must():
    app = REPO / "targets" / "app1"
    patch = suggest_patch((app / "helpers.py").read_text(), "helpers.py", 21, "CWE-89")
    removed = [l for l in patch.diff.splitlines() if l.startswith("-") and not l.startswith("---")]
    assert len(removed) == 1 and len(_added(patch)) == 1
    assert _added(patch)[0].strip() == """return db.execute("SELECT 'ok' WHERE tag = ?", (value,)).fetchone()"""


def test_diff_applies_with_git(tmp_path):
    if shutil.which("git") is None:
        pytest.skip("git not installed")
    shutil.copy(REPO / "targets" / "app2" / "helpers.py", tmp_path / "helpers.py")
    patch = suggest_patch((tmp_path / "helpers.py").read_text(), "helpers.py", 12, "CWE-89")
    (tmp_path / "fix.diff").write_text(patch.diff)
    subprocess.run(["git", "apply", "fix.diff"], cwd=tmp_path, check=True)
    assert (tmp_path / "helpers.py").read_text() == patch.patched_source


# SQL injection --------------------------------------------------------------

@pytest.mark.parametrize("call, expected", [
    ('db.execute(f"SELECT * FROM t WHERE id = {uid}")', 'db.execute("SELECT * FROM t WHERE id = ?", (uid,))'),
    ('db.execute("SELECT * FROM t WHERE n = \'{}\'".format(name))', 'db.execute("SELECT * FROM t WHERE n = ?", (name,))'),
    ('db.execute("SELECT * FROM t WHERE a = %s AND b = \'%s\'" % (a, b))',
     'db.execute("SELECT * FROM t WHERE a = ? AND b = ?", (a, b))'),
    ('db.execute(sql="SELECT * FROM t WHERE id = " + uid)', 'db.execute(sql="SELECT * FROM t WHERE id = ?", parameters=(uid,))'),
    ('db.execute("SELECT * FROM t WHERE n LIKE \'" + q + "%\'")', 'db.execute("SELECT * FROM t WHERE n LIKE ?", (f"{q}%",))'),
])
def test_sql_string_building_styles(call, expected):
    source = f"import sqlite3\n\ndef find(db, uid, name, a, b, q):\n    return {call}\n"
    patch = suggest_patch(source, "q.py", 4, "CWE-89")
    assert patch.available, patch.reason
    assert _added(patch) == [f"    return {expected}"]
    assert patch.notes == []  # sqlite3 is imported, so ? is known to be right


def test_sql_query_built_in_a_variable_first():
    source = 'def find(db, uid):\n    query = "SELECT * FROM t WHERE id = " + uid\n    return db.execute(query)\n'
    patch = suggest_patch(source, "q.py", 3, "CWE-89")
    assert _added(patch) == ['    query = "SELECT * FROM t WHERE id = ?"', "    return db.execute(query, (uid,))"]


def test_psycopg_gets_percent_placeholders_and_escaped_percent():
    source = "import psycopg\n\ndef find(cur, q):\n    cur.execute(\"SELECT * FROM t WHERE n LIKE '%\" + q + \"' AND r = '100%'\")\n"
    patch = suggest_patch(source, "q.py", 4, "CWE-89")
    assert _added(patch) == ['    cur.execute("SELECT * FROM t WHERE n LIKE %s AND r = \'100%%\'", (f"%{q}",))']


def test_unknown_driver_is_flagged_in_a_note():
    patch = suggest_patch('def f(db, uid):\n    db.execute("SELECT " + uid)\n', "q.py", 2, "CWE-89")
    assert patch.available and "placeholders" in patch.notes[0]


@pytest.mark.parametrize("source, reason", [
    ('def f(db, q):\n    db.execute(q)\n', "built elsewhere"),
    ('def f(db, a):\n    db.execute("SELECT * WHERE x = " + a, ())\n', "already passes parameters"),
    ('def f(db):\n    db.execute("SELECT 1")\n', "nothing to parameterise"),
    ('def f(db, a, b):\n    db.execute("SELECT * WHERE x = \'" + a + " " + b + "\'")\n', "more than one value"),
])
def test_sql_refuses_what_it_cannot_rewrite_safely(source, reason):
    patch = suggest_patch(source, "q.py", 2, "CWE-89")
    assert not patch.available and reason in patch.reason


# command injection ----------------------------------------------------------

def test_os_system_becomes_subprocess_run_with_returncode():
    source = '"""Doc."""\nimport os\n\ndef f(name):\n    return os.system("ls -l " + name)\n'
    patch = suggest_patch(source, "c.py", 5, "CWE-78")
    assert _added(patch) == ["import subprocess", '    return subprocess.run(["ls", "-l", name]).returncode']
    assert patch.patched_source.index("import subprocess") < patch.patched_source.index("import os")


def test_shell_true_with_list_just_drops_the_shell():
    source = 'import subprocess\n\ndef f(n):\n    subprocess.run(["ls", n], shell=True, check=True)\n'
    assert _added(suggest_patch(source, "c.py", 4, "CWE-78")) == ['    subprocess.run(["ls", n], check=True)']


def test_quoted_value_and_attached_flag_stay_one_argument():
    source = "import subprocess\n\ndef f(n):\n    subprocess.run(f\"grep --name={n} 'my file'\", shell=True)\n"
    assert _added(suggest_patch(source, "c.py", 4, "CWE-78")) == ['    subprocess.run(["grep", f"--name={n}", "my file"])']


@pytest.mark.parametrize("command, reason", [
    ('"ls " + n + " | wc -l"', "shell feature '|'"),
    ('n + " --help"', "chooses which program"),
    ('"echo \\"$HOME\\" " + n', "inside quotes"),
])
def test_command_refuses_shell_features_and_user_chosen_programs(command, reason):
    source = f"import subprocess\n\ndef f(n):\n    subprocess.run({command}, shell=True)\n"
    patch = suggest_patch(source, "c.py", 4, "CWE-78")
    assert not patch.available and reason in patch.reason


# path traversal -------------------------------------------------------------

def test_join_base_is_kept_as_the_allowed_folder():
    source = "import os\nBASE = 'files'\n\ndef f(name):\n    return open(os.path.join(BASE, name)).read()\n"
    patch = suggest_patch(source, "p.py", 5, "CWE-22")
    assert f"    return open({SAFE_PATH_HELPER}(BASE, name)).read()" in _added(patch)
    assert patch.notes == []  # the folder came from the code, no guess needed


def test_helper_is_added_once():
    source = "import os\n\ndef f(a, b):\n    open(a)\n    open(b)\n"
    first = suggest_patch(source, "p.py", 4, "CWE-22")
    second = suggest_patch(first.patched_source, "p.py", first.patched_source.splitlines().index("    open(b)") + 1,
                           "CWE-22")
    assert second.available and second.patched_source.count(f"def {SAFE_PATH_HELPER}") == 1


def test_safe_path_helper_refuses_escapes(tmp_path):
    namespace: dict = {}
    exec("import os\n" + HELPER_SOURCE, namespace)  # Kavach's own helper, not project code
    safe = namespace[SAFE_PATH_HELPER]
    (tmp_path / "files").mkdir()
    assert safe(tmp_path / "files", "a.txt") == str((tmp_path / "files" / "a.txt").resolve())
    for bad in ("../secret", "/etc/passwd", "sub/../../x"):
        with pytest.raises(ValueError):
            safe(tmp_path / "files", bad)


# general ----------------------------------------------------------------------

def test_unsupported_bug_type_has_no_patch():
    patch = suggest_patch("x = 1\n", "a.py", 1, "CWE-502")
    assert not patch.available and "written advice" in patch.reason


def test_broken_file_has_no_patch():
    patch = suggest_patch("def broken(:\n", "a.py", 1, "CWE-89")
    assert not patch.available and "does not parse" in patch.reason


def test_non_ascii_lines_are_patched_on_the_right_columns():
    source = 'def f(db, uid):\n    return db.execute("SELECT \'é\' WHERE id = " + uid)  # café\n'
    assert _added(suggest_patch(source, "q.py", 2, "CWE-89")) == [
        '    return db.execute("SELECT \'é\' WHERE id = ?", (uid,))  # café']


# API --------------------------------------------------------------------------

def _zip_app(app: Path) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for path in app.glob("*.py"):
            zf.writestr(f"{app.name}/{path.name}", path.read_text())
    return buf.getvalue()


def test_patch_endpoint_returns_a_checked_patch():
    client = signed_in_client()
    with use_detectors([TaintDetector()]):
        scan = client.post("/scans", files={"file": ("app3.zip", _zip_app(REPO / "targets" / "app3"),
                                                     "application/zip")}).json()
    findings = client.get(f"/scans/{scan['id']}/findings").json()
    sql = next(f for f in findings if f["cwe"] == "CWE-89")
    body = client.get(f"/findings/{sql['id']}/patch").json()
    assert body["available"] and body["verification"]["status"] == "fixed"
    assert body["diff"].startswith(f"--- a/{sql['file']}")


def test_patch_endpoint_is_private():
    client = signed_in_client()
    with use_detectors([TaintDetector()]):
        scan = client.post("/scans", files={"file": ("app1.zip", _zip_app(REPO / "targets" / "app1"),
                                                     "application/zip")}).json()
    finding = client.get(f"/scans/{scan['id']}/findings").json()[0]
    from fastapi.testclient import TestClient
    from app.main import app
    assert TestClient(app).get(f"/findings/{finding['id']}/patch").status_code == 401
