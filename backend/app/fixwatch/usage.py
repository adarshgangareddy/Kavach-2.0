"""Where the project's own code imports a package. A fix only matters for code that uses it."""
from __future__ import annotations

import ast
from dataclasses import dataclass
from pathlib import Path

# Packages whose import name differs from their PyPI name. Everything else imports as its
# name with - turned into _ (flask, jinja2, werkzeug, requests, ...).
IMPORT_NAMES = {
    "pyyaml": "yaml", "pillow": "PIL", "beautifulsoup4": "bs4", "pyjwt": "jwt", "python-jose": "jose",
    "scikit-learn": "sklearn", "python-dateutil": "dateutil", "opencv-python": "cv2",
    "opencv-python-headless": "cv2", "protobuf": "google.protobuf", "psycopg2-binary": "psycopg2",
    "python-dotenv": "dotenv", "pycryptodome": "Crypto", "pycryptodomex": "Cryptodome",
    "python-multipart": "multipart", "argon2-cffi": "argon2", "mysqlclient": "MySQLdb",
    "pymongo": "pymongo", "flask-sqlalchemy": "flask_sqlalchemy", "flask-login": "flask_login",
    "flask-cors": "flask_cors", "flask-wtf": "flask_wtf", "pyopenssl": "OpenSSL",
}


@dataclass(frozen=True)
class Use:
    file: str
    line: int
    module: str


def import_name(package: str) -> str:
    return IMPORT_NAMES.get(package, package.replace("-", "_"))


def _imports(tree: ast.Module) -> list[tuple[str, int]]:
    out = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            out += [(alias.name, node.lineno) for alias in node.names]
        elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
            out.append((node.module, node.lineno))
    return out


def find_uses(root: Path, files: list[str], package: str) -> list[Use]:
    """Every import of the package in the scanned Python files, in file and line order."""
    wanted = import_name(package)
    uses = []
    for rel in sorted(files):
        try:
            tree = ast.parse((root / rel).read_text(errors="replace"), filename=rel)
        except (SyntaxError, ValueError, OSError):
            continue
        for module, line in _imports(tree):
            if module == wanted or module.startswith(wanted + "."):
                uses.append(Use(rel, line, module))
    return sorted(uses, key=lambda u: (u.file, u.line))
