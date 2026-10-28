"""Kavach rule layer: AST checks for hard-coded secrets and weak cryptography.

Each file is read with ast and never run. Secret values never leave this module:
a finding names the variable and the kind of secret, never the value itself.

CWE numbers follow Bandit's where both report the same thing, so a line that
both flag merges into one finding ("bandit+rules") instead of showing twice.

    CWE-798  hard-coded credential (token formats, URLs with passwords, keys, env fallbacks)
    CWE-259  hard-coded password
    CWE-327  broken or risky crypto (MD5/SHA-1, DES/RC4/Blowfish, ECB mode, old TLS)
    CWE-916  fast hash used on a password
    CWE-326  key too short
    CWE-295  certificate checks turned off
    CWE-330  random module used for a token or password
"""
from __future__ import annotations

import ast
import re
from pathlib import Path

from app.detect.base import Candidate
from app.schema import ConfidenceTier

# --- names and values ----------------------------------------------------------

# Names are split into words ("db_password" -> db, password; "apiKey" -> api, key) and matched whole,
# so "bypass", "passed" and "tokenizer" are not mistaken for secrets.
PASSWORD_WORDS = {"password", "passwd", "passphrase", "pwd", "pass", "passcode"}
SECRET_WORDS = PASSWORD_WORDS | {"secret", "secrets", "token", "apikey", "credential", "credentials"}
SECRET_PAIRS = {("api", "key"), ("access", "key"), ("private", "key"), ("auth", "key"), ("signing", "key"),
                ("encryption", "key"), ("jwt", "key"), ("session", "key"), ("secret", "key"), ("client", "secret"),
                ("app", "secret"), ("master", "key")}
NOT_A_SECRET = {"url", "uri", "endpoint", "path", "file", "dir", "name", "header", "field", "type", "label", "prefix",
                "suffix", "len", "length", "min", "max", "policy", "regex", "pattern", "format", "hint", "prompt",
                "message", "msg", "error", "errors", "id", "count", "expiry", "expires", "ttl", "timeout", "reset",
                "forgot", "confirm", "placeholder", "env", "var", "param", "algorithm", "alg", "scheme", "location",
                "class", "cls", "validator", "strength", "rounds", "required", "enabled", "changed", "mismatch",
                "input", "form", "column", "table", "attr", "attribute", "kind", "mode", "size", "bytes", "chars"}
CONTEXT_WORDS = {"token", "secret", "password", "passwd", "otp", "nonce", "salt", "session", "csrf", "auth", "pin",
                 "apikey", "reset", "verification", "verify", "passcode", "invite"}
PLACEHOLDER = re.compile(r"\s*|\*+|x{3,}|\.{3}|<[^>]*>|\$\{[^}]*\}|\$[A-Z_]+|\{\{[^}]*\}\}|%\([^)]*\)s|%s|\{[^}]*\}"
                         r"|(your|my|example|sample|dummy|fake|placeholder|replace|insert|enter|put|change)[-_ ].*"
                         r"|.*_here|none|null|nil|todo|tbd|redacted|required|optional|secret|password|token"
                         r"|true|false|yes|no|on|off|enabled|disabled|[01]",  # switches, not secrets
                         re.I)
ENV_NAME = re.compile(r"[A-Z][A-Z0-9_]{2,}")  # "DB_PASSWORD": the name of an env variable, not a value
MIN_SECRET_CHARS = 3

TOKEN_FORMATS = [
    ("an AWS access key ID", re.compile(r"\b(AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("a GitHub token", re.compile(r"\b(gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{50,})\b")),
    ("a Slack token", re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}")),
    ("a Stripe live key", re.compile(r"\b[sr]k_live_[A-Za-z0-9]{20,}")),
    ("a Google API key", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b")),
    ("an Anthropic API key", re.compile(r"\bsk-ant-[A-Za-z0-9_-]{20,}")),
    ("an OpenAI project key", re.compile(r"\bsk-proj-[A-Za-z0-9_-]{20,}")),
    ("a private key", re.compile(r"-----BEGIN (RSA |EC |DSA |OPENSSH |ENCRYPTED |PGP )?PRIVATE KEY( BLOCK)?-----")),
]
URL_PASSWORD = re.compile(r"^[a-z][a-z0-9+.-]*://[^:/@\s]+:([^@\s/]+)@", re.I)

ENV_LOOKUPS = {"os.getenv", "os.environ.get", "os.environ.setdefault"}
KEY_ARGUMENT = {  # calls whose argument at this position is a secret key
    "jwt.encode": 1, "jwt.decode": 1, "hmac.new": 0, "hmac.digest": 0,
    "cryptography.fernet.Fernet": 0, "itsdangerous.URLSafeTimedSerializer": 0,
    "itsdangerous.URLSafeSerializer": 0, "itsdangerous.TimestampSigner": 0, "itsdangerous.Signer": 0,
}

# --- crypto ----------------------------------------------------------------------

WEAK_HASHES = {"hashlib.md5", "hashlib.sha1", "Crypto.Hash.MD5.new", "Crypto.Hash.SHA.new", "Crypto.Hash.SHA1.new",
               "Crypto.Hash.MD4.new", "Crypto.Hash.MD2.new", "Cryptodome.Hash.MD5.new", "Cryptodome.Hash.SHA1.new",
               "cryptography.hazmat.primitives.hashes.MD5", "cryptography.hazmat.primitives.hashes.SHA1"}
WEAK_HASH_NAMES = {"md5", "sha1", "md4", "md2"}
FAST_HASHES = WEAK_HASHES | {f"hashlib.{n}" for n in ("sha224", "sha256", "sha384", "sha512", "blake2b", "blake2s",
                                                       "sha3_256", "sha3_512")}
_CIPHER_MODULES = ("Crypto.Cipher", "Cryptodome.Cipher")
WEAK_CIPHERS = {f"{m}.{c}.new" for m in _CIPHER_MODULES for c in ("DES", "DES3", "ARC2", "ARC4", "Blowfish", "XOR",
                                                                   "CAST")} | {
    f"cryptography.hazmat.primitives.ciphers.algorithms.{c}"
    for c in ("TripleDES", "ARC4", "Blowfish", "IDEA", "CAST5", "SEED")}
ECB_MODES = {"cryptography.hazmat.primitives.ciphers.modes.ECB"}
OLD_TLS = {f"ssl.PROTOCOL_{v}" for v in ("SSLv2", "SSLv3", "SSLv23", "TLSv1", "TLSv1_1", "TLS")} | {
    f"ssl.TLSVersion.{v}" for v in ("SSLv3", "TLSv1", "TLSv1_1")}
NO_CERT_CHECK = {"ssl._create_unverified_context", "ssl._create_stdlib_context"}
HTTP_CLIENTS = ("requests.", "httpx.", "urllib3.")
KEY_GENERATORS = {  # call -> (keyword, position) holding the key size in bits
    "cryptography.hazmat.primitives.asymmetric.rsa.generate_private_key": ("key_size", 1),
    "cryptography.hazmat.primitives.asymmetric.dsa.generate_private_key": ("key_size", 0),
    "Crypto.PublicKey.RSA.generate": ("bits", 0), "Cryptodome.PublicKey.RSA.generate": ("bits", 0),
    "Crypto.PublicKey.DSA.generate": ("bits", 0),
}
MIN_KEY_BITS = 2048
RANDOM_CALLS = {f"random.{n}" for n in ("random", "randint", "randrange", "choice", "choices", "getrandbits",
                                         "sample", "uniform", "randbytes")}

FIX = {
    "secret": "Move this secret out of the code, into an environment variable or a secret manager, and read it "
              "with os.environ['NAME'] (no default). Treat the committed value as leaked: rotate it.",
    "fallback": "Remove the default value: os.environ['NAME'] fails loudly when the secret is missing, while a "
                "hard-coded fallback silently ships the same secret everywhere.",
    "weak_hash": "Use hashlib.sha256 or stronger. If this hash is not for security (a cache key, an ETag), "
                 "say so with hashlib.md5(data, usedforsecurity=False).",
    "password_hash": "Hash passwords with a slow, salted algorithm: Argon2 (argon2-cffi), bcrypt or "
                     "hashlib.scrypt. Fast hashes like SHA-256 can be guessed billions of times a second.",
    "cipher": "Use AES-GCM or ChaCha20-Poly1305 (cryptography's AESGCM / ChaCha20Poly1305, or Fernet).",
    "ecb": "Do not use ECB mode: identical blocks encrypt to identical output. Use AES-GCM.",
    "tls": "Allow TLS 1.2 or newer only: ctx = ssl.create_default_context(); "
           "ctx.minimum_version = ssl.TLSVersion.TLSv1_2.",
    "cert": "Keep certificate checks on (the default). For a private certificate authority, pass its "
            "bundle: verify='/path/to/ca.pem'.",
    "key_size": "Use at least 2048-bit RSA or DSA keys (3072 or more for new systems), or an elliptic curve key.",
    "random": "Use the secrets module for anything security-related: secrets.token_urlsafe(), "
              "secrets.token_hex() or secrets.choice(). The random module is predictable.",
}


class RulesDetector:
    """Hard-coded secrets and weak crypto, found by reading the AST of each file."""

    name = "rules"
    version = "rules-1"

    def available(self) -> bool:
        return True

    def scan(self, root: Path, files: list[str], timeout_s: float) -> list[Candidate]:
        out: list[Candidate] = []
        for rel in files:
            try:
                tree = ast.parse((root / rel).read_text(errors="replace"), filename=rel)
            except (SyntaxError, ValueError):
                continue  # other detectors report files that do not parse
            out.extend(check_module(tree, rel))
        return out


def check_module(tree: ast.Module, file: str) -> list[Candidate]:
    checker = _Checker(file, _aliases(tree))
    checker.visit(tree)
    return _one_per_line(checker.found)


def _one_per_line(found: list[Candidate]) -> list[Candidate]:
    """Several secret checks can fire on one line (a token named api_key): keep the most certain."""
    best: dict[tuple[int, str], Candidate] = {}
    for cand in found:
        key = (cand.line, "secret" if cand.cwe in {"CWE-259", "CWE-798"} else cand.cwe)
        if key not in best or cand.confidence > best[key].confidence:
            best[key] = cand
    return sorted(best.values(), key=lambda c: (c.line, c.cwe))


def _aliases(tree: ast.Module) -> dict[str, str]:
    """Local name -> full dotted name, from the file's imports."""
    names: dict[str, str] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                names[alias.asname or alias.name.split(".")[0]] = alias.name if alias.asname else alias.name.split(".")[0]
        elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
            for alias in node.names:
                names[alias.asname or alias.name] = f"{node.module}.{alias.name}"
    return names


def _dotted(node: ast.AST) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = _dotted(node.value)
        return f"{base}.{node.attr}" if base else None
    return None


def _literal(node: ast.AST | None) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, (str, bytes)):
        return node.value.decode("latin-1") if isinstance(node.value, bytes) else node.value
    return None


def is_real_secret(value: str, name: str = "") -> bool:
    """A literal that looks like an actual secret, not a placeholder, label or env variable name."""
    text = value.strip()
    return (len(text) >= MIN_SECRET_CHARS and not PLACEHOLDER.fullmatch(text) and not ENV_NAME.fullmatch(text)
            and text.lower() != name.lower() and text.count(" ") < 3)


def words(name: str) -> list[str]:
    """Identifier -> lower-case words: "dbPassword" and "DB_PASSWORD" both give ["db", "password"]."""
    spaced = re.sub(r"([a-z0-9])([A-Z])", r"\1 \2", name)
    return [w.lower() for w in re.split(r"[^A-Za-z0-9]+", spaced) if w]


def is_secret_name(name: str) -> bool:
    parts = words(name)
    if not parts or parts[-1] in NOT_A_SECRET:
        return False
    return bool(SECRET_WORDS & set(parts)) or any(pair in SECRET_PAIRS for pair in zip(parts, parts[1:]))


def is_password_name(name: str) -> bool:
    return bool(PASSWORD_WORDS & set(words(name)))


def is_security_context(name: str) -> bool:
    parts = words(name)
    return bool(CONTEXT_WORDS & set(parts)) or ("api" in parts and "key" in parts)


class _Checker(ast.NodeVisitor):
    def __init__(self, file: str, aliases: dict[str, str]):
        self.file, self.aliases = file, aliases
        self.found: list[Candidate] = []
        self.functions: list[str] = []

    # helpers ---------------------------------------------------------------

    def resolve(self, node: ast.AST) -> str:
        dotted = _dotted(node) or ""
        head, _, rest = dotted.partition(".")
        full = self.aliases.get(head, head)
        return f"{full}.{rest}" if rest else full

    def add(self, node: ast.AST, cwe: str, what: str, fix: str, confidence: float) -> None:
        self.found.append(Candidate(file=self.file, line=node.lineno, cwe=cwe, detector=RulesDetector.name,
                                    sink=what, confidence=confidence, fix_suggestion=FIX[fix],
                                    confidence_tier=ConfidenceTier.PATTERN_MATCH))

    def named_secret(self, node: ast.AST, name: str, value: ast.AST | None, where: str) -> None:
        text = _literal(value)
        if text is None or not is_secret_name(name) or not is_real_secret(text, name):
            return
        password = is_password_name(name)
        self.add(node, "CWE-259" if password else "CWE-798",
                 f"{where} `{name}` is set to a hard-coded {'password' if password else 'secret'}", "secret", 0.6)

    # secrets -----------------------------------------------------------------

    def visit_Constant(self, node: ast.Constant) -> None:
        text = _literal(node)
        if text is None:
            return
        for kind, pattern in TOKEN_FORMATS:
            if pattern.search(text):
                self.add(node, "CWE-798", f"String contains {kind}", "secret", 0.9)
                return
        if (m := URL_PASSWORD.match(text)) and is_real_secret(m[1]):
            self.add(node, "CWE-798", "Connection URL contains a hard-coded password", "secret", 0.8)

    def visit_Assign(self, node: ast.Assign) -> None:
        for target in node.targets:
            self._target(node, target, node.value)
        self._random(node, node.targets, node.value)
        self.generic_visit(node)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
        self._target(node, node.target, node.value)
        self.generic_visit(node)

    def _target(self, node: ast.AST, target: ast.AST, value: ast.AST | None) -> None:
        if isinstance(target, ast.Name):
            self.named_secret(node, target.id, value, "Variable")
        elif isinstance(target, ast.Attribute):
            self.named_secret(node, target.attr, value, "Attribute")
            if target.attr == "check_hostname" and isinstance(value, ast.Constant) and value.value is False:
                self.add(node, "CWE-295", "TLS hostname checking is turned off", "cert", 0.8)
        elif isinstance(target, ast.Subscript) and (key := _literal(target.slice)) is not None:
            self.named_secret(node, key, value, "Setting")

    def visit_Dict(self, node: ast.Dict) -> None:
        for key, value in zip(node.keys, node.values):
            if (name := _literal(key)) is not None:
                self.named_secret(value, name, value, "Key")
        self.generic_visit(node)

    def visit_Compare(self, node: ast.Compare) -> None:
        if isinstance(node.left, ast.Name) and len(node.comparators) == 1:
            self.named_secret(node, node.left.id, node.comparators[0], "Check of")
        self.generic_visit(node)

    def visit_FunctionDef(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        args = node.args.posonlyargs + node.args.args
        defaults = [None] * (len(args) - len(node.args.defaults)) + node.args.defaults
        for arg, default in [*zip(args, defaults), *zip(node.args.kwonlyargs, node.args.kw_defaults)]:
            self.named_secret(default or arg, arg.arg, default, "Default for")
        self.functions.append(node.name)
        self.generic_visit(node)
        self.functions.pop()

    visit_AsyncFunctionDef = visit_FunctionDef

    def visit_Call(self, node: ast.Call) -> None:
        name = self.resolve(node.func)
        for kw in node.keywords:
            if kw.arg:
                self.named_secret(kw.value, kw.arg, kw.value, "Argument")
        self._env_fallback(node, name)
        self._key_argument(node, name)
        self._crypto_call(node, name)
        self.generic_visit(node)

    def _env_fallback(self, node: ast.Call, name: str) -> None:
        if name not in ENV_LOOKUPS or not node.args:
            return
        var = _literal(node.args[0])
        default = node.args[1] if len(node.args) > 1 else next(
            (kw.value for kw in node.keywords if kw.arg in {"default", "value"}), None)
        text = _literal(default)
        if var and text and is_secret_name(var) and is_real_secret(text, var):
            self.add(node, "CWE-798", f"`{var}` falls back to a hard-coded value when the variable is not set",
                     "fallback", 0.8)

    def _key_argument(self, node: ast.Call, name: str) -> None:
        position = KEY_ARGUMENT.get(name)
        if position is None or len(node.args) <= position:
            return
        if (text := _literal(node.args[position])) is not None and is_real_secret(text):
            self.add(node, "CWE-798", f"{name.split('.')[-1]}() is given a hard-coded key", "secret", 0.8)

    # crypto ------------------------------------------------------------------

    def _crypto_call(self, node: ast.Call, name: str) -> None:
        if any(kw.arg == "usedforsecurity" and isinstance(kw.value, ast.Constant) and kw.value.value is False
               for kw in node.keywords):
            return
        if name in FAST_HASHES and _about_passwords(node):
            self.add(node, "CWE-916", f"{name}() is used on a password", "password_hash", 0.8)
        elif (algorithm := _weak_hash(node, name)) is not None:
            self.add(node, "CWE-327", f"Weak hash {algorithm}", "weak_hash", 0.6)
        elif name in WEAK_CIPHERS:
            self.add(node, "CWE-327", f"Weak cipher {name.split('.')[-2 if name.endswith('.new') else -1]}",
                     "cipher", 0.8)
        elif name in ECB_MODES or any(isinstance(a, ast.Attribute) and a.attr == "MODE_ECB" for a in node.args):
            self.add(node, "CWE-327", "Block cipher in ECB mode", "ecb", 0.8)
        elif name in NO_CERT_CHECK:
            self.add(node, "CWE-295", "SSL context that skips certificate checks", "cert", 0.8)
        elif name.startswith(HTTP_CLIENTS) and any(kw.arg == "verify" and isinstance(kw.value, ast.Constant)
                                                   and kw.value.value is False for kw in node.keywords):
            self.add(node, "CWE-295", "HTTPS request with certificate checks turned off", "cert", 0.8)
        elif name in KEY_GENERATORS and (bits := _key_bits(node, *KEY_GENERATORS[name])) and bits < MIN_KEY_BITS:
            self.add(node, "CWE-326", f"{bits}-bit key is too short", "key_size", 0.8)

    def visit_Attribute(self, node: ast.Attribute) -> None:
        name = self.resolve(node)
        if name in OLD_TLS:
            self.add(node, "CWE-327", f"Old protocol {name.split('.')[-1]}", "tls", 0.7)
        elif name == "ssl.CERT_NONE":
            self.add(node, "CWE-295", "Certificate checks set to CERT_NONE", "cert", 0.8)
        self.generic_visit(node)

    def _random(self, node: ast.Assign, targets: list[ast.AST], value: ast.AST) -> None:
        """random.* producing a value named like a token, or inside a function named like one."""
        calls = [c for c in ast.walk(value) if isinstance(c, ast.Call) and self.resolve(c.func) in RANDOM_CALLS]
        if not calls:
            return
        names = [t.id if isinstance(t, ast.Name) else t.attr if isinstance(t, ast.Attribute) else "" for t in targets]
        context = next((n for n in [*names, *self.functions[-1:]] if is_security_context(n)), None)
        if context:
            self.add(node, "CWE-330", f"{self.resolve(calls[0].func)}() makes `{context}`, which needs to be "
                     "unpredictable", "random", 0.6)


def _about_passwords(call: ast.Call) -> bool:
    """The hashed value is named like a password: hashlib.sha256(password.encode())."""
    return any(is_password_name(n.id if isinstance(n, ast.Name) else n.attr)
               for arg in call.args for n in ast.walk(arg) if isinstance(n, (ast.Name, ast.Attribute)))


def _weak_hash(call: ast.Call, name: str) -> str | None:
    """The algorithm name when this call makes an MD5/SHA-1 style hash, else None."""
    if name in WEAK_HASHES:
        return name.split(".")[-2 if name.endswith(".new") else -1].lower()
    algorithm = _literal(call.args[0]) if name == "hashlib.new" and call.args else None
    return algorithm.lower() if algorithm and algorithm.lower() in WEAK_HASH_NAMES else None


def _key_bits(call: ast.Call, keyword: str, position: int) -> int | None:
    value = next((kw.value for kw in call.keywords if kw.arg == keyword), None)
    if value is None and len(call.args) > position:
        value = call.args[position]
    return value.value if isinstance(value, ast.Constant) and isinstance(value.value, int) else None
