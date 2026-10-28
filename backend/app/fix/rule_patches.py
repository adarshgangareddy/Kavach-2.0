"""Patches for the rule layer's findings: hard-coded secrets and weak crypto.

Same approach as app/fix/patch.py: read with ast, rewrite only the reported expression,
never run the code. Where a safe rewrite would change stored data or needs a design
decision (a new cipher, a slow password hash), there is no patch and the reason says why.

    CWE-798/259  "literal"            -> os.environ["NAME"]
    CWE-327      hashlib.md5/sha1     -> hashlib.sha256;  old TLS constant -> PROTOCOL_TLS_CLIENT
    CWE-295      verify=False         -> removed;  CERT_NONE -> CERT_REQUIRED;  check_hostname -> True
    CWE-330      random.choice/...    -> secrets.choice/...
    CWE-326      1024-bit key         -> 3072-bit key
"""
from __future__ import annotations

import ast

from app.detect.rules import (ENV_LOOKUPS, KEY_ARGUMENT, OLD_TLS, WEAK_CIPHERS, WEAK_HASHES, _aliases, _literal,
                              check_module, is_secret_name, words)
from app.fix.patch import PLANNERS, CannotPatch, _Edit, _Plan, _Writer, _dotted

SECRET_CWES = ("CWE-798", "CWE-259")
SAFE_KEY_BITS = 3072
KEY_ENV = {"jwt.encode": "JWT_SECRET", "jwt.decode": "JWT_SECRET", "hmac.new": "HMAC_KEY", "hmac.digest": "HMAC_KEY",
           "cryptography.fernet.Fernet": "FERNET_KEY"}
LEAKED = ("The old value was in the code (and its history), so treat it as leaked: change it, then put the "
          "new value only in the environment.")


class _Names:
    """Resolves call and attribute names through the file's imports, like the rule layer does."""

    def __init__(self, tree: ast.Module):
        self.aliases = _aliases(tree)

    def __call__(self, node: ast.AST) -> str:
        dotted = _dotted_name(node)
        head, _, rest = dotted.partition(".")
        full = self.aliases.get(head, head)
        return f"{full}.{rest}" if rest else full


FALSE_ALARM = {
    "secret": "Kavach's rule layer does not see a secret here: the value looks like a label, a setting name or "
              "a placeholder. This report is probably a false alarm, so there is nothing to move out of the code.",
    "random": "Kavach's rule layer does not see a security value here (nothing is named like a token, password "
              "or key), so the random module is fine for this.",
    "other": "Kavach's rule layer does not report this line, so there is no patch for it. Check the other "
             "tool's message by hand.",
}


def _require_rule_hit(tree: ast.Module, line: int, kind: str) -> None:
    """Patch only what Kavach's own rule layer also reports, so another tool's false alarm is not 'fixed'."""
    if not any(c.line == line for c in check_module(tree, "patched.py")):
        raise CannotPatch(FALSE_ALARM[kind])


def _checked(kind: str, planner):
    def plan(tree: ast.Module, line: int, source: str) -> _Plan:
        _require_rule_hit(tree, line, kind)
        return planner(tree, line, source)
    return plan


def _dotted_name(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = _dotted_name(node.value)
        return f"{base}.{node.attr}" if base else ""
    return ""


def _on_line(tree: ast.Module, line: int, kind) -> list:
    return [n for n in ast.walk(tree) if isinstance(n, kind) and getattr(n, "lineno", 0) <= line
            <= getattr(n, "end_lineno", 0)]


def _env(name: str) -> str:
    """An environment variable name from an identifier: dbPassword -> DB_PASSWORD."""
    return "_".join(w.upper() for w in words(name)) or "SECRET"


def _from_env(var: str, original: ast.AST) -> ast.expr:
    value: ast.expr = ast.Subscript(_dotted("os.environ"), ast.Constant(var), ast.Load())
    if isinstance(original, ast.Constant) and isinstance(original.value, bytes):
        value = ast.Call(ast.Attribute(value, "encode", ast.Load()), [], [])
    return value


# --- hard-coded secrets ------------------------------------------------------------

def _plan_secret(tree: ast.Module, line: int, source: str) -> _Plan:
    names, write = _Names(tree), _Writer(source)
    target = _secret_target(tree, line, names)
    if target is None:
        raise CannotPatch("A hard-coded password check or default value needs a design change: compare "
                          "against a stored hash (for example with argon2-cffi) instead of a fixed value.")
    node, var = target
    new = _from_env(var, node)
    return _Plan("Read the secret from the environment",
                 f"The value now comes from the environment variable {var} when the app starts, so it is no "
                 "longer in the code, and os.environ[...] stops the app with a clear error if it is missing.",
                 [_Edit(node, write(new))],
                 [f"Set {var} in your environment or .env file before starting the app. {LEAKED}"],
                 add_import="os")


def _secret_target(tree: ast.Module, line: int, names: _Names) -> tuple[ast.AST, str] | None:
    """The literal (or env lookup with a fallback) to replace on this line, and the variable to read."""
    for call in _on_line(tree, line, ast.Call):
        name = names(call.func)
        if name in ENV_LOOKUPS and call.args and (var := _literal(call.args[0])):
            return call, var  # os.getenv("X", "fallback") -> os.environ["X"]
        if (position := KEY_ARGUMENT.get(name)) is not None and len(call.args) > position \
                and _literal(call.args[position]) is not None:
            return call.args[position], KEY_ENV.get(name, "SECRET_KEY")
        for kw in call.keywords:
            if kw.arg and is_secret_name(kw.arg) and _literal(kw.value) is not None and kw.value.lineno == line:
                return kw.value, _env(kw.arg)
    for d in _on_line(tree, line, ast.Dict):
        for key, value in zip(d.keys, d.values):
            if (name := _literal(key)) and is_secret_name(name) and _literal(value) is not None \
                    and value.lineno == line:
                return value, _env(name)
    for stmt in _on_line(tree, line, (ast.Assign, ast.AnnAssign)):
        value = stmt.value
        if _literal(value) is None:
            continue
        target = stmt.targets[0] if isinstance(stmt, ast.Assign) else stmt.target
        if isinstance(target, ast.Name):
            return value, _env(target.id)
        if isinstance(target, ast.Attribute):
            return value, _env(target.attr)
        if isinstance(target, ast.Subscript) and (key := _literal(target.slice)):
            return value, _env(key)
    return None


# --- weak crypto -----------------------------------------------------------------

def _plan_crypto(tree: ast.Module, line: int, source: str) -> _Plan:
    names, write = _Names(tree), _Writer(source)
    for call in _on_line(tree, line, ast.Call):
        name = names(call.func)
        if name in {"hashlib.md5", "hashlib.sha1"}:
            new = ast.Call(_dotted("hashlib.sha256"), call.args, call.keywords)
            return _hash_plan([_Edit(call, write(new))], add_import="hashlib")
        if name == "hashlib.new" and call.args and (_literal(call.args[0]) or "").lower() in {"md5", "sha1"}:
            return _hash_plan([_Edit(call.args[0], write(ast.Constant("sha256")))])
        if name in WEAK_HASHES:
            raise CannotPatch("This library's hash object is not rewritten automatically; use its SHA256 "
                              "class, or hashlib.sha256.")
        if name in WEAK_CIPHERS or any(isinstance(a, ast.Attribute) and a.attr == "MODE_ECB" for a in call.args) \
                or name.endswith("modes.ECB"):
            raise CannotPatch("Changing the cipher or mode changes the key, nonce and the format of anything "
                              "already encrypted, so it needs a planned change: use AES-GCM (see the advice).")
    for attr in _on_line(tree, line, ast.Attribute):
        name = names(attr)
        if name in OLD_TLS:
            new = "ssl.TLSVersion.TLSv1_2" if ".TLSVersion." in name else "ssl.PROTOCOL_TLS_CLIENT"
            return _Plan("Use a current TLS version",
                         "PROTOCOL_TLS_CLIENT negotiates the newest TLS both sides support and checks the "
                         "server's certificate and host name."
                         if "PROTOCOL" in new else "The lowest allowed version is now TLS 1.2.",
                         [_Edit(attr, new)], add_import="ssl")
    raise CannotPatch("Could not find the weak algorithm on this line.")


def _hash_plan(edits: list[_Edit], add_import: str | None = None) -> _Plan:
    return _Plan("Use SHA-256 instead of MD5 or SHA-1",
                 "SHA-256 has no known practical collisions, unlike MD5 and SHA-1.", edits,
                 ["SHA-256 gives different values than MD5 or SHA-1. If these hashes are stored or compared "
                  "with old ones, plan the change. If the hash is not for security (a cache key, an ETag), "
                  "keep it and add usedforsecurity=False instead."], add_import=add_import)


def _plan_cert(tree: ast.Module, line: int, source: str) -> _Plan:
    names, write = _Names(tree), _Writer(source)
    for call in _on_line(tree, line, ast.Call):
        if (verify := next((k for k in call.keywords if k.arg == "verify" and isinstance(k.value, ast.Constant)
                            and k.value.value is False), None)) is not None:
            new = ast.Call(call.func, call.args, [k for k in call.keywords if k is not verify])
            return _cert_plan(_Edit(call, write(new)), "verify=False is removed, so certificates are checked.")
        if names(call.func) in {"ssl._create_unverified_context", "ssl._create_stdlib_context"}:
            new = ast.Call(_dotted("ssl.create_default_context"), call.args, call.keywords)
            return _cert_plan(_Edit(call, write(new)), "create_default_context() checks certificates and "
                                                        "host names.", add_import="ssl")
    for attr in _on_line(tree, line, ast.Attribute):
        if names(attr) == "ssl.CERT_NONE":
            return _cert_plan(_Edit(attr, "ssl.CERT_REQUIRED"), "The server must now present a valid certificate.")
    for stmt in _on_line(tree, line, ast.Assign):
        target = stmt.targets[0]
        if isinstance(target, ast.Attribute) and target.attr == "check_hostname":
            return _cert_plan(_Edit(stmt.value, "True"), "The certificate must now match the host name.")
    raise CannotPatch("Could not find the turned-off certificate check on this line.")


def _cert_plan(edit: _Edit, what: str, add_import: str | None = None) -> _Plan:
    return _Plan("Turn certificate checks back on", f"{what} Without the check, anyone on the network can "
                 "pretend to be the server.", [edit],
                 ["If the server uses a private certificate authority, pass its bundle (verify='/path/ca.pem' "
                  "or ctx.load_verify_locations) instead of turning checks off."], add_import=add_import)


def _plan_random(tree: ast.Module, line: int, source: str) -> _Plan:
    names, write = _Names(tree), _Writer(source)
    edits = [edit for call in _on_line(tree, line, ast.Call) if (edit := _secrets_call(call, names(call.func), write))]
    if not edits:
        raise CannotPatch("This random call has no direct equivalent in the secrets module; use "
                          "secrets.token_urlsafe() or secrets.token_hex() for tokens.")
    return _Plan("Use the secrets module", "secrets draws from the operating system's secure random source, "
                 "so the value cannot be predicted from earlier ones.", edits, add_import="secrets")


def _secrets_call(call: ast.Call, name: str, write: _Writer) -> _Edit | None:
    args = call.args
    if call.keywords:
        return None
    if name == "random.choice" and len(args) == 1:
        return _Edit(call, f"secrets.choice({write(args[0])})")
    if name == "random.getrandbits" and len(args) == 1:
        return _Edit(call, f"secrets.randbits({write(args[0])})")
    if name == "random.randrange" and len(args) == 1:
        return _Edit(call, f"secrets.randbelow({write(args[0])})")
    if name == "random.randint" and len(args) == 2:
        low, high = write(args[0]), write(args[1])
        return _Edit(call, f"secrets.randbelow({high} - {low} + 1) + {low}")
    return None


def _plan_key_size(tree: ast.Module, line: int, source: str) -> _Plan:
    for call in _on_line(tree, line, ast.Call):
        size = next((k.value for k in call.keywords if k.arg in {"key_size", "bits"}), None)
        if size is None:
            size = next((a for a in call.args if isinstance(a, ast.Constant) and isinstance(a.value, int)
                         and a.value < 2048), None)
        if isinstance(size, ast.Constant) and isinstance(size.value, int):
            return _Plan(f"Use a {SAFE_KEY_BITS}-bit key", f"{size.value}-bit keys can be broken with enough "
                         f"computing power; {SAFE_KEY_BITS} bits is the current recommendation for new RSA keys.",
                         [_Edit(size, str(SAFE_KEY_BITS))],
                         ["Keys already issued stay weak: generate new ones and replace them."])
    return _plan_crypto(tree, line, source)  # Semgrep files old TLS versions under CWE-326 too


def _plan_password_hash(tree: ast.Module, line: int, source: str) -> _Plan:
    raise CannotPatch("Moving passwords to a slow hash changes how they are stored and checked, and needs a "
                      "library such as argon2-cffi. Old hashes have to be re-hashed when each user next logs in.")


PLANNERS.update({"CWE-798": _checked("secret", _plan_secret), "CWE-259": _checked("secret", _plan_secret),
                 "CWE-327": _checked("other", _plan_crypto), "CWE-295": _checked("other", _plan_cert),
                 "CWE-330": _checked("random", _plan_random), "CWE-326": _checked("other", _plan_key_size),
                 "CWE-916": _plan_password_hash})
