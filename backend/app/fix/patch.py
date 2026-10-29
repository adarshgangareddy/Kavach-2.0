"""Patch suggester: rewrite the dangerous call behind a finding into its safe form.

Reads the source with Python's ast and never runs it. Only the sink call (and the
line that builds its string, when that is a separate variable) changes, plus an
import or small helper when the fix needs one; every other line is left exactly
as it was. When the code is too unusual to rewrite safely, the patch says why,
and the written fix advice stays the guidance.

    SQL injection (CWE-89)      string-built query  -> placeholders + parameters
    Command injection (CWE-78)  shell command text  -> argument list, no shell
    Path traversal (CWE-22)     open(user path)     -> path checked against a folder
"""
from __future__ import annotations

import ast
import difflib
import re
import string
from dataclasses import dataclass, field

SQL, COMMAND, PATH = "CWE-89", "CWE-78", "CWE-22"
UPGRADE = "CWE-1395"  # fix-watcher leads point at an import on purpose: the fix is an upgrade

SQL_METHODS = {"execute", "executemany"}
SUBPROCESS = {"subprocess.run", "subprocess.call", "subprocess.check_call", "subprocess.check_output",
              "subprocess.Popen"}
SHELL_QUOTE = {"shlex.quote", "pipes.quote", "__import__('shlex').quote", "quote"}
OPEN_CALLS = {"open", "io.open"}
SHELL_ONLY = set("|&;<>`$*?~(){}[]\n\\")  # characters that mean something only to a shell
SAFE_PATH_HELPER = "_kavach_safe_path"
HELPER_SOURCE = f'''

def {SAFE_PATH_HELPER}(base, *parts):
    """Join parts onto base and refuse any path outside base (added by Kavach, CWE-22)."""
    root = os.path.realpath(base)
    path = os.path.realpath(os.path.join(root, *parts))
    if os.path.commonpath([root, path]) != root:
        raise ValueError("Refused a file path outside the allowed folder")
    return path
'''

Part = str | ast.expr  # a piece of a built string: literal text or an expression


def _helper_body(tree: ast.Module) -> str | None:
    """The safe-path helper's code (docstring left out) as ast text, if the module defines it."""
    for node in tree.body:
        if isinstance(node, ast.FunctionDef) and node.name == SAFE_PATH_HELPER:
            body = node.body[1:] if node.body and isinstance(node.body[0], ast.Expr) else node.body
            return ast.dump(ast.Module([*body], []), annotate_fields=False) + ast.dump(node.args)
    return None


_GENUINE_HELPER = _helper_body(ast.parse(HELPER_SOURCE))


def defines_genuine_helper(source: str) -> bool:
    """True when the file defines Kavach's safe-path helper unchanged, so a path passed through it
    is known to stay inside its folder. A function that only borrows the name does not count."""
    try:
        return _helper_body(ast.parse(source)) == _GENUINE_HELPER
    except SyntaxError:
        return False


class CannotPatch(Exception):
    """The code is too unusual to rewrite safely; the message says why."""


@dataclass
class Patch:
    available: bool
    cwe: str
    title: str = ""
    explanation: str = ""
    reason: str = ""  # why there is no patch, when available is False
    diff: str = ""
    patched_source: str = ""
    changed_lines: list[int] = field(default_factory=list)  # 1-based, in the patched file
    notes: list[str] = field(default_factory=list)


@dataclass
class _Edit:
    node: ast.AST  # the source span to replace
    text: str


@dataclass
class _Plan:
    title: str
    explanation: str
    edits: list[_Edit]
    notes: list[str] = field(default_factory=list)
    add_import: str | None = None  # module that must be imported, e.g. "os"
    add_helper: bool = False


# --- entry point -------------------------------------------------------------

def suggest_patch(source: str, file: str, line: int, cwe: str) -> Patch:
    if cwe not in PLANNERS:
        return Patch(False, cwe, reason=f"Automatic patches do not cover {cwe} yet; it has written advice only.")
    try:
        tree = ast.parse(source)
        if cwe != UPGRADE:
            _refuse_import_line(tree, line)
        plan = PLANNERS[cwe](tree, line, source)
        patched = _apply(source, tree, plan)
        ast.parse(patched)  # never hand back code that does not parse
    except CannotPatch as exc:
        return Patch(False, cwe, reason=str(exc))
    except SyntaxError as exc:
        return Patch(False, cwe, reason=f"The file does not parse as Python (line {exc.lineno}).")
    return Patch(True, cwe, title=plan.title, explanation=plan.explanation, notes=plan.notes,
                 diff=unified_diff(source, patched, file), patched_source=patched,
                 changed_lines=_changed_lines(source, patched))


def _refuse_import_line(tree: ast.Module, line: int) -> None:
    """Some tools flag `import subprocess` itself; an import has nothing to rewrite."""
    for node in ast.walk(tree):
        if isinstance(node, (ast.Import, ast.ImportFrom)) and node.lineno <= line <= node.end_lineno:
            raise CannotPatch("This line only imports a module, which Bandit flags as a reminder to use it "
                              "carefully. There is nothing to rewrite here: each call that uses it is checked "
                              "on its own line.")


def unified_diff(before: str, after: str, file: str) -> str:
    """A diff that `git apply` accepts from the project root."""
    return "".join(difflib.unified_diff(before.splitlines(keepends=True), after.splitlines(keepends=True),
                                        fromfile=f"a/{file}", tofile=f"b/{file}"))


def _changed_lines(before: str, after: str) -> list[int]:
    matcher = difflib.SequenceMatcher(a=before.splitlines(), b=after.splitlines(), autojunk=False)
    return [n + 1 for tag, _, _, j1, j2 in matcher.get_opcodes() if tag != "equal" for n in range(j1, j2)]


# --- finding the sink --------------------------------------------------------

def _name(node: ast.AST) -> str:
    return ast.unparse(node).replace('"', "'")


def _pick_call(tree: ast.Module, line: int, matches) -> ast.Call:
    """The matching call on the finding's line, else the only one in the same function."""
    calls = [n for n in ast.walk(tree) if isinstance(n, ast.Call) and matches(n)]
    on_line = [c for c in calls if c.lineno <= line <= c.end_lineno]
    if on_line:
        return min(on_line, key=lambda c: (c.end_lineno - c.lineno, c.end_col_offset - c.col_offset))
    scope = _enclosing_function(tree, line)
    nearby = [c for c in calls if scope and scope.lineno <= c.lineno <= scope.end_lineno]
    if len(nearby) == 1:
        return nearby[0]
    if nearby:  # some tools point at the line that reads the input, not the call it reaches
        lines = sorted({c.lineno for c in nearby})
        listed = ", ".join(map(str, lines[:-1])) + f" and {lines[-1]}" if len(lines) > 1 else str(lines[0])
        raise CannotPatch(f"Line {line} is where the input is read, not the dangerous call. This function has "
                          f"dangerous calls on lines {listed}: open those findings to patch them.")
    raise CannotPatch(f"Could not find the dangerous call at line {line}.")


def _enclosing_function(tree: ast.Module, line: int) -> ast.FunctionDef | ast.AsyncFunctionDef | None:
    found = None
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.lineno <= line <= node.end_lineno:
            if found is None or node.lineno >= found.lineno:
                found = node
    return found


def _first_arg(call: ast.Call, *keywords: str) -> tuple[ast.expr, ast.keyword | None]:
    if call.args:
        return call.args[0], None
    for kw in call.keywords:
        if kw.arg in keywords:
            return kw.value, kw
    raise CannotPatch("The call has no argument to rewrite.")


def _resolve(tree: ast.Module, call: ast.Call, value: ast.expr) -> tuple[ast.expr, ast.Assign | None]:
    """Follow `query = <built string>` when the call is given a variable set once in the same function."""
    if not isinstance(value, ast.Name):
        return value, None
    scope = _enclosing_function(tree, call.lineno) or tree
    assigns = [n for n in ast.walk(scope) if isinstance(n, (ast.Assign, ast.AugAssign, ast.AnnAssign))
               and any(isinstance(t, ast.Name) and t.id == value.id for t in _targets(n))]
    if len(assigns) == 1 and isinstance(assigns[0], ast.Assign) and len(assigns[0].targets) == 1 \
            and assigns[0].lineno < call.lineno:
        return assigns[0].value, assigns[0]
    raise CannotPatch(f"The string is built elsewhere in `{value.id}`; build it at the call to get a patch.")


def _targets(node: ast.AST) -> list[ast.expr]:
    return node.targets if isinstance(node, ast.Assign) else [node.target]


# --- taking a built string apart ---------------------------------------------

def _is_str(node: ast.AST) -> bool:
    return isinstance(node, ast.Constant) and isinstance(node.value, str)


def string_parts(node: ast.expr) -> list[Part] | None:
    """Literal text and expressions of a string built with +, an f-string, % or .format; None otherwise."""
    if isinstance(node, ast.JoinedStr):
        return _merge([_fstring_piece(v) for v in node.values])
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        left, right = string_parts(node.left), string_parts(node.right)
        if left is None and right is None:
            return None
        return _merge((left if left is not None else [node.left]) + (right if right is not None else [node.right]))
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Mod) and _is_str(node.left):
        return _merge(_percent_parts(node.left.value, node.right))
    if (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "format"
            and _is_str(node.func.value)):
        return _merge(_format_parts(node.func.value.value, node))
    if _is_str(node):
        return [node.value]
    return None


def _fstring_piece(value: ast.expr) -> Part:
    if isinstance(value, ast.Constant):
        return value.value
    if value.format_spec is not None:
        raise CannotPatch("The f-string formats a value with a format spec; rewrite it by hand.")
    return value.value


def _percent_parts(text: str, right: ast.expr) -> list[Part]:
    if isinstance(right, ast.Dict):
        raise CannotPatch("Named %-formatting is not rewritten automatically.")
    values = list(right.elts) if isinstance(right, ast.Tuple) else [right]
    parts: list[Part] = []
    for piece in re.split(r"(%%|%[sdifr])", text):
        if piece == "%%":
            parts.append("%")
        elif re.fullmatch(r"%[sdifr]", piece):
            if not values:
                raise CannotPatch("The %-format has more placeholders than values.")
            parts.append(values.pop(0))
        else:
            parts.append(piece)
    return parts


def _format_parts(text: str, call: ast.Call) -> list[Part]:
    keywords = {kw.arg: kw.value for kw in call.keywords if kw.arg}
    parts: list[Part] = []
    auto = 0
    for literal, field_name, spec, conversion in string.Formatter().parse(text):
        parts.append(literal)
        if field_name is None:
            continue
        if spec or conversion or not re.fullmatch(r"\w*", field_name):
            raise CannotPatch("The .format() call uses specs or attribute lookups; rewrite it by hand.")
        if field_name == "":
            field_name, auto = str(auto), auto + 1
        try:
            parts.append(call.args[int(field_name)] if field_name.isdigit() else keywords[field_name])
        except (IndexError, KeyError) as exc:
            raise CannotPatch("The .format() call does not match its placeholders.") from exc
    return parts


def _merge(parts: list[Part]) -> list[Part]:
    out: list[Part] = []
    for part in parts:
        if isinstance(part, str) and out and isinstance(out[-1], str):
            out[-1] += part
        elif part != "":
            out.append(part)
    return out


def _dynamic(parts: list[Part] | None) -> bool:
    return parts is not None and any(not isinstance(p, str) for p in parts)


def _joined(pieces: list[Part]) -> ast.expr:
    """One expression for literal text and values side by side: a constant, the value itself, or an f-string."""
    pieces = _merge(pieces)
    if len(pieces) == 1:
        return ast.Constant(pieces[0]) if isinstance(pieces[0], str) else pieces[0]
    return ast.JoinedStr([ast.Constant(p) if isinstance(p, str) else ast.FormattedValue(p, -1, None)
                          for p in pieces])


class _Writer:
    """Source text for new nodes. Parts that came from the file are copied exactly as written,
    so a patch changes the code's structure, not its quotes or spacing."""

    def __init__(self, source: str):
        self.source = source
        self.quote = '"' if source.count('"') >= source.count("'") else "'"

    def __call__(self, node: ast.AST) -> str:
        if getattr(node, "end_col_offset", None) is not None:
            segment = ast.get_source_segment(self.source, node)
            if segment is not None and "\n" not in segment:
                return segment
        method = getattr(self, f"_{type(node).__name__}", None)
        return method(node) if method else ast.unparse(node)

    def _Call(self, node: ast.Call) -> str:
        return f"{self(node.func)}({', '.join([*map(self, node.args), *map(self, node.keywords)])})"

    def _keyword(self, node: ast.keyword) -> str:
        return f"{node.arg}={self(node.value)}" if node.arg else f"**{self(node.value)}"

    def _Attribute(self, node: ast.Attribute) -> str:
        return f"{self(node.value)}.{node.attr}"

    def _Name(self, node: ast.Name) -> str:
        return node.id

    def _Subscript(self, node: ast.Subscript) -> str:
        return f"{self(node.value)}[{self(node.slice)}]"

    def _List(self, node: ast.List) -> str:
        return f"[{', '.join(map(self, node.elts))}]"

    def _Tuple(self, node: ast.Tuple) -> str:
        items = list(map(self, node.elts))
        return f"({items[0]},)" if len(items) == 1 else f"({', '.join(items)})"

    def _Constant(self, node: ast.Constant) -> str:
        text = repr(node.value)
        if isinstance(node.value, str) and self.quote == '"' and text.startswith("'") and '"' not in node.value:
            return f'"{text[1:-1]}"'
        return text

    def _JoinedStr(self, node: ast.JoinedStr) -> str:
        pieces = []
        for value in node.values:
            if isinstance(value, ast.Constant):
                pieces.append(value.value.replace("{", "{{").replace("}", "}}"))
            else:
                pieces.append("{" + self(value.value) + "}")
        body = "".join(pieces)
        for quote in (self.quote, "'" if self.quote == '"' else '"'):
            if quote not in body and "\\" not in body and "\n" not in body:
                return f"f{quote}{body}{quote}"
        return ast.unparse(node)


# --- SQL injection -----------------------------------------------------------

def _plan_sql(tree: ast.Module, line: int, source: str) -> _Plan:
    call = _pick_call(tree, line, lambda c: isinstance(c.func, ast.Attribute) and c.func.attr in SQL_METHODS)
    value, keyword = _first_arg(call, "sql", "operation")
    if len(call.args) > 1 or any(kw.arg in {"parameters", "params", "args"} for kw in call.keywords):
        raise CannotPatch("The call already passes parameters; move the remaining values into them by hand.")
    built, assign = _resolve(tree, call, value)
    parts = string_parts(built)
    if not _dynamic(parts):
        raise CannotPatch("The SQL text is not built from values here, so there is nothing to parameterise.")
    style = _placeholder_style(tree)
    query, params = _parameterise(parts, style)
    write = _Writer(source)
    query_node = ast.Constant(query)
    params_node = ast.Tuple(params, ast.Load())
    if assign is not None:  # query = "..." + x ; db.execute(query)  ->  query = "... ?" ; db.execute(query, (x,))
        edits = [_Edit(assign.value, write(query_node)), _Edit(call, _with_params(call, params_node, write))]
    else:
        new_call = _replace_first_arg(call, keyword, query_node)
        edits = [_Edit(call, _with_params(new_call, params_node, write))]
    notes = [] if style.known else ["Kavach could not tell which database driver this is. sqlite3 uses ? "
                                    "placeholders; psycopg, PyMySQL and MySQLdb use %s."]
    return _Plan("Use a parameterised query",
                 f"The values are now sent separately from the SQL text as parameters ({style.mark}), so the "
                 "database treats them as data and never as SQL, whatever they contain.",
                 edits, notes)


@dataclass(frozen=True)
class _Style:
    mark: str
    known: bool


def _placeholder_style(tree: ast.Module) -> _Style:
    modules = _imported_modules(tree)
    if modules & {"psycopg", "psycopg2", "pymysql", "MySQLdb", "mysql"}:
        return _Style("%s", True)
    return _Style("?", "sqlite3" in modules)


def _imported_modules(tree: ast.Module) -> set[str]:
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names |= {alias.name.split(".")[0] for alias in node.names}
        elif isinstance(node, ast.ImportFrom) and node.module:
            names.add(node.module.split(".")[0])
    return names


def _parameterise(parts: list[Part], style: _Style) -> tuple[str, list[ast.expr]]:
    """Replace each value with a placeholder; a value written inside quotes takes the quoted text with it."""
    parts = list(parts)
    text, params = "", []
    for i, part in enumerate(parts):
        if isinstance(part, str):
            text += part.replace("%", "%%") if style.mark == "%s" else part  # psycopg reads % itself
            continue
        opened = _open_quote(text)
        if opened is None:
            params.append(part)
        else:  # '...' + value + '...': the quoted text around the value becomes part of the parameter
            quote, start = opened
            after_text = parts[i + 1] if i + 1 < len(parts) and isinstance(parts[i + 1], str) else ""
            end = after_text.find(quote)
            if end < 0:
                raise CannotPatch("A quoted SQL string holds more than one value; rewrite it by hand.")
            prefix, suffix = _unescape(text[start + 1:], style), _unescape(after_text[:end], style)
            text, parts[i + 1] = text[:start], after_text[end + 1:]
            params.append(_joined([prefix, part, suffix]))
        text += style.mark
    return text, params


def _open_quote(sql: str) -> tuple[str, int] | None:
    """The quote character and position of a string literal still open at the end of the SQL text."""
    quote, start = None, -1
    for i, ch in enumerate(sql):
        if quote is None and ch in "'\"":
            quote, start = ch, i
        elif ch == quote:
            quote = None  # a doubled '' closes and reopens, which ends up the same
    return (quote, start) if quote else None


def _unescape(text: str, style: _Style) -> str:
    return text.replace("%%", "%") if style.mark == "%s" else text


def _replace_first_arg(call: ast.Call, keyword: ast.keyword | None, value: ast.expr) -> ast.Call:
    if keyword is None:
        return ast.Call(call.func, [value, *call.args[1:]], call.keywords)
    keywords = [ast.keyword(kw.arg, value) if kw is keyword else kw for kw in call.keywords]
    return ast.Call(call.func, call.args, keywords)


def _with_params(call: ast.Call, params: ast.Tuple, write: _Writer) -> str:
    if call.args:
        return write(ast.Call(call.func, [call.args[0], params], call.keywords))
    return write(ast.Call(call.func, [], [*call.keywords, ast.keyword("parameters", params)]))


# --- command injection -------------------------------------------------------

def _is_command(call: ast.Call) -> bool:
    return _name(call.func) in SUBPROCESS | {"os.system"}


def _plan_command(tree: ast.Module, line: int, source: str) -> _Plan:
    call = _pick_call(tree, line, _is_command)
    value, keyword = _first_arg(call, "args")
    notes: list[str] = []
    if isinstance(value, (ast.List, ast.Tuple)):
        argv = value
    else:
        built, _ = _resolve(tree, call, value)
        parts = string_parts(built)
        if not _dynamic(parts):
            raise CannotPatch("The command is fixed text, so user input cannot change it here.")
        argv = ast.List(_argv(parts, notes), ast.Load())
    keywords = [kw for kw in call.keywords if kw.arg != "shell" and kw is not keyword]
    if _name(call.func) == "os.system":  # same meaning: run it, give back the exit code
        new = ast.Attribute(ast.Call(_dotted("subprocess.run"), [argv], keywords), "returncode", ast.Load())
        add_import = "subprocess"
    else:
        new = ast.Call(call.func, [argv, *call.args[1:]], keywords)
        add_import = None
    return _Plan("Run the program with an argument list, without a shell",
                 "The command is now a list: the program name first, then each argument on its own. No shell "
                 "reads it, so characters like ; | & or $( ) in user input are passed as plain text and "
                 "cannot start another command.",
                 [_Edit(call, _Writer(source)(new))], notes, add_import=add_import)


def _argv(parts: list[Part], notes: list[str]) -> list[ast.expr]:
    tokens: list[list[Part]] = []
    current: list[Part] = []
    quote = None
    for part in parts:
        if not isinstance(part, str):
            current.append(_drop_shell_quote(part, notes))
            continue
        for ch in part:
            if quote:
                if ch == quote:
                    quote = None
                elif quote == '"' and ch in "$`\\":
                    raise CannotPatch(f"The command uses the shell feature {ch!r} inside quotes; rewrite it by hand.")
                else:
                    current.append(ch)
            elif ch in "'\"":
                quote = ch
            elif ch.isspace():
                if current:
                    tokens.append(current)
                    current = []
            elif ch in SHELL_ONLY:
                raise CannotPatch(f"The command uses the shell feature {ch!r}, so it cannot become a plain "
                                  "argument list; rewrite it by hand.")
            else:
                current.append(ch)
    if quote:
        raise CannotPatch("The command has an unclosed quote.")
    if current:
        tokens.append(current)
    if not tokens or not all(isinstance(p, str) for p in tokens[0]):
        raise CannotPatch("User input chooses which program runs; allow only a fixed list of programs instead.")
    return [_joined(token) for token in tokens]


def _drop_shell_quote(value: ast.expr, notes: list[str]) -> ast.expr:
    """shlex.quote(x) -> x: without a shell, quoting would put literal quote marks into the argument."""
    if isinstance(value, ast.Call) and _name(value.func) in SHELL_QUOTE and len(value.args) == 1:
        notes.append("Removed shlex.quote(): with no shell it is not needed, and it would add literal quote marks.")
        return value.args[0]
    return value


def _dotted(name: str) -> ast.expr:
    node: ast.expr = ast.Name(name.split(".")[0], ast.Load())
    for attr in name.split(".")[1:]:
        node = ast.Attribute(node, attr, ast.Load())
    return node


# --- path traversal ----------------------------------------------------------

def _plan_path(tree: ast.Module, line: int, source: str) -> _Plan:
    call = _pick_call(tree, line, lambda c: _name(c.func) in OPEN_CALLS)
    value, keyword = _first_arg(call, "file")
    if isinstance(value, ast.Call) and _name(value.func) == SAFE_PATH_HELPER:
        raise CannotPatch("This path is already checked by Kavach's safe-path helper.")
    notes: list[str] = []
    if isinstance(value, ast.Call) and _name(value.func) == "os.path.join" and len(value.args) >= 2:
        base, rest = value.args[0], value.args[1:]
    else:
        base, rest = ast.Constant("."), [value]
        notes.append("The allowed folder is set to '.', the folder the app runs from. Change it to the folder "
                     "your files really live in, for example os.path.join(app.root_path, 'files').")
    checked = ast.Call(ast.Name(SAFE_PATH_HELPER, ast.Load()), [base, *rest], [])
    return _Plan("Check the path stays inside the allowed folder",
                 "The file name is joined onto a fixed folder and fully resolved, following any ../ and "
                 "symlinks. If the result is outside that folder, the request is refused instead of reading "
                 "the file.",
                 [_Edit(call, _Writer(source)(_replace_first_arg(call, keyword, checked)))], notes,
                 add_import="os", add_helper=SAFE_PATH_HELPER not in _defined_functions(tree))


def _defined_functions(tree: ast.Module) -> set[str]:
    return {n.name for n in tree.body if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))}


# CWE -> function that plans the rewrite. app/fix/rule_patches.py adds the rule layer's bug types.
PLANNERS = {SQL: _plan_sql, COMMAND: _plan_command, PATH: _plan_path}


# --- applying the edits ------------------------------------------------------

def _apply(source: str, tree: ast.Module, plan: _Plan) -> str:
    lines = source.splitlines(keepends=True)
    for edit in sorted(plan.edits, key=lambda e: (e.node.lineno, e.node.col_offset), reverse=True):
        _replace_span(lines, edit.node, edit.text)
    header = []
    if plan.add_import and plan.add_import not in _top_level_imports(tree):
        header.append(f"import {plan.add_import}\n")
    insert_at = _after_imports(tree)
    if plan.add_helper:
        lines[insert_at:insert_at] = HELPER_SOURCE.splitlines(keepends=True)
    if header:
        at = _import_line(tree)
        lines[at:at] = header
    return "".join(lines)


def _replace_span(lines: list[str], node: ast.AST, text: str) -> None:
    """Swap one node's exact source span (ast offsets are UTF-8 bytes) for new text."""
    first, last = node.lineno - 1, node.end_lineno - 1
    head = lines[first].encode()[:node.col_offset].decode()
    tail = lines[last].encode()[node.end_col_offset:].decode()
    lines[first:last + 1] = [head + text + tail]


def _top_level_imports(tree: ast.Module) -> set[str]:
    return {alias.asname or alias.name for node in tree.body if isinstance(node, ast.Import) for alias in node.names}


def _imports(tree: ast.Module) -> list[ast.stmt]:
    return [n for n in tree.body if isinstance(n, (ast.Import, ast.ImportFrom))]


def _after_imports(tree: ast.Module) -> int:
    """Line index just after the last top-level import (or the docstring, or the top of the file)."""
    if imports := _imports(tree):
        return imports[-1].end_lineno
    if tree.body and isinstance(tree.body[0], ast.Expr) and _is_str(tree.body[0].value):
        return tree.body[0].end_lineno
    return 0


def _import_line(tree: ast.Module) -> int:
    """Where a new `import x` goes: with the existing imports, else after the docstring."""
    imports = _imports(tree)
    if imports:
        return imports[0].lineno - 1
    return _after_imports(tree)
