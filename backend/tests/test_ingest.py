import io
import stat
import zipfile

import pytest

from app.config import get_settings
from app.ingest import IngestError
from app.ingest.diff import changed_functions, function_spans, parse_unified_diff
from app.ingest.filter import filter_project, is_ignored
from app.ingest.github import parse_github_url
from app.ingest.snippet import normalize_snippet, write_snippet
from app.ingest.upload import extract_zip, project_root, read_limited
from app.ingest.workspace import resolve_source_file
from tests.conftest import write


def _zip(entries: dict[str, str], symlink: str | None = None) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for name, text in entries.items():
            zf.writestr(name, text)
        if symlink:
            info = zipfile.ZipInfo(symlink)
            info.external_attr = (stat.S_IFLNK | 0o777) << 16
            zf.writestr(info, "/etc/passwd")
    return buf.getvalue()


def test_extracts_zip_and_unwraps_single_folder(tmp_path):
    dest = tmp_path / "src"
    extract_zip(_zip({"proj/app.py": "x = 1\n", "proj/README.md": "hi"}), dest, get_settings())
    assert project_root(dest).name == "proj"
    assert (dest / "proj/app.py").read_text() == "x = 1\n"


def test_single_package_folder_is_not_unwrapped(tmp_path):
    dest = tmp_path / "src"
    extract_zip(_zip({"web/__init__.py": "", "web/views.py": "x = 1\n"}), dest, get_settings())
    assert project_root(dest) == dest


@pytest.mark.parametrize("name", ["../evil.py", "/abs/evil.py", "a/../../evil.py", "C:/evil.py"])
def test_rejects_zip_slip(tmp_path, name):
    with pytest.raises(IngestError, match="unsafe path"):
        extract_zip(_zip({name: "x"}), tmp_path / "src", get_settings())
    assert not (tmp_path / "evil.py").exists()


def test_skips_symlinks_in_zip(tmp_path):
    notes = extract_zip(_zip({"a.py": "x"}, symlink="link.py"), tmp_path / "src", get_settings())
    assert not (tmp_path / "src/link.py").exists()
    assert "symbolic links" in notes[0]


def test_rejects_zip_bomb_by_declared_size(tmp_path):
    settings = get_settings().__class__(data_dir=tmp_path, max_unpacked_bytes=10)
    with pytest.raises(IngestError, match="too large"):
        extract_zip(_zip({"a.py": "x" * 100}), tmp_path / "src", settings)


def test_rejects_non_zip(tmp_path):
    with pytest.raises(IngestError, match="not a valid zip"):
        extract_zip(b"not a zip", tmp_path / "src", get_settings())


def test_read_limited_enforces_size():
    assert read_limited(io.BytesIO(b"abc"), 3) == b"abc"
    with pytest.raises(IngestError) as exc:
        read_limited(io.BytesIO(b"abcd"), 3)
    assert exc.value.status_code == 413


def test_filter_skips_venv_tests_vendored_and_non_python(tmp_path):
    for rel in ["app/routes.py", "app/__init__.py", "tests/test_x.py", "app/test_y.py",
                "venv/lib/x.py", "node_modules/x.py", "static/app.js", "README.md"]:
        write(tmp_path, rel, "x = 1\n")
    write(tmp_path, "myenv/pyvenv.cfg", "")
    write(tmp_path, "myenv/lib/z.py", "")
    result = filter_project(tmp_path, max_file_bytes=1024)
    assert result.files == ["app/__init__.py", "app/routes.py"]
    assert any("non-Python" in n for n in result.notes)


def test_is_ignored():
    assert is_ignored("tests/test_a.py") and is_ignored("pkg/conftest.py")
    assert is_ignored("README.md")
    assert not is_ignored("app/views.py")


@pytest.mark.parametrize("url", ["https://github.com/pallets/flask",
                                 "https://github.com/pallets/flask.git",
                                 "https://github.com/a-b/c.d_e/"])
def test_accepts_github_urls(url):
    owner, repo = parse_github_url(url)
    assert owner and repo and not repo.endswith(".git")


@pytest.mark.parametrize("url", ["http://github.com/a/b", "https://gitlab.com/a/b",
                                 "https://github.com/a/b/tree/main", "https://github.com/a/..",
                                 "file:///etc", "https://github.com/a/b;rm", "--upload-pack=x"])
def test_rejects_bad_github_urls(url):
    with pytest.raises(IngestError):
        parse_github_url(url)


def test_snippet_dedents_and_writes(tmp_path):
    name, notes = write_snippet("    def f(x):\n        return x\n", "snippet.py",
                                tmp_path, get_settings())
    assert (tmp_path / name).read_text().startswith("def f")
    assert any("indentation" in n for n in notes)


def test_snippet_with_syntax_error_falls_back_gracefully():
    _, notes = normalize_snippet("def broken(:\n")
    assert "does not parse" in notes[0]


@pytest.mark.parametrize("bad", ["../x.py", "a/b.py", "x.txt", ".py"])
def test_snippet_rejects_bad_filenames(tmp_path, bad):
    with pytest.raises(IngestError):
        write_snippet("x = 1", bad, tmp_path, get_settings())


DIFF = """\
diff --git a/app/views.py b/app/views.py
--- a/app/views.py
+++ b/app/views.py
@@ -3,0 +4,2 @@ def a():
+    y = 2
+    z = 3
@@ -10 +11 @@ class C:
-        old
+        new
diff --git a/gone.py b/gone.py
--- a/gone.py
+++ /dev/null
@@ -1 +0,0 @@
-x
"""


def test_parse_unified_diff():
    assert parse_unified_diff(DIFF) == {"app/views.py": {4, 5, 11}}


SOURCE = """\
import os

@decorator
def a():
    x = 1
    y = 2
    z = 3

class C:
    def m(self):
        new
        def inner():
            pass
"""


def test_maps_changed_lines_to_functions():
    names = {s[0] for s in function_spans(SOURCE)}
    assert names == {"a", "C.m", "C.m.inner"}
    assert changed_functions(SOURCE, {3, 6}) == {"a"}
    assert changed_functions(SOURCE, {11}) == {"C.m"}
    assert changed_functions(SOURCE, {13}) == {"C.m.inner"}
    assert changed_functions(SOURCE, {1}) == {"<module>"}


def test_resolve_source_file_blocks_traversal(tmp_path):
    write(tmp_path, "root/app.py", "x")
    write(tmp_path, "secret.py", "x")
    root = tmp_path / "root"
    assert resolve_source_file(root, "app.py") is not None
    assert resolve_source_file(root, "../secret.py") is None
    assert resolve_source_file(root, str(tmp_path / "secret.py")) is None
