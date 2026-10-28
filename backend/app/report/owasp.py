"""CWE -> OWASP Top 10 (2021) tagging, CWE titles and generic remediation guidance."""

OWASP_BY_CWE: dict[str, str] = {
    "CWE-77": "A03:2021 Injection",
    "CWE-78": "A03:2021 Injection",
    "CWE-79": "A03:2021 Injection",
    "CWE-89": "A03:2021 Injection",
    "CWE-94": "A03:2021 Injection",
    "CWE-22": "A01:2021 Broken Access Control",
    "CWE-23": "A01:2021 Broken Access Control",
    "CWE-327": "A02:2021 Cryptographic Failures",
    "CWE-328": "A02:2021 Cryptographic Failures",
    "CWE-330": "A02:2021 Cryptographic Failures",
    "CWE-798": "A07:2021 Identification and Authentication Failures",
    "CWE-259": "A07:2021 Identification and Authentication Failures",
    "CWE-502": "A08:2021 Software and Data Integrity Failures",
    "CWE-605": "A05:2021 Security Misconfiguration",
    "CWE-703": "A05:2021 Security Misconfiguration",
}
UNMAPPED = "Unmapped"

CWE_TITLES: dict[str, str] = {
    "CWE-77": "Command injection",
    "CWE-78": "OS command injection",
    "CWE-79": "Cross-site scripting",
    "CWE-89": "SQL injection",
    "CWE-94": "Code injection",
    "CWE-22": "Path traversal",
    "CWE-23": "Relative path traversal",
    "CWE-259": "Hard-coded password",
    "CWE-327": "Broken or risky cryptographic algorithm",
    "CWE-328": "Weak hash",
    "CWE-330": "Insufficiently random values",
    "CWE-502": "Deserialization of untrusted data",
    "CWE-605": "Multiple binds to the same port",
    "CWE-703": "Improper check of exceptional conditions",
    "CWE-798": "Hard-coded credentials",
}

REMEDIATION: dict[str, str] = {
    "CWE-78": "Do not pass user input to a shell. Call subprocess.run with an argument list "
              "and shell=False, validate values against an allow-list, and use shlex.quote "
              "only when a shell is unavoidable.",
    "CWE-89": "Use parameterized queries (cursor.execute(sql, params)) or the ORM's query "
              "builder. Never build SQL with string formatting or concatenation.",
    "CWE-22": "Sanitize filenames with werkzeug.utils.secure_filename, resolve the final path "
              "with os.path.realpath and check it stays inside the allowed base directory.",
    "CWE-502": "Do not unpickle data from users. Use a data-only format such as JSON and "
               "validate it against a schema.",
    "CWE-798": "Move secrets to environment variables or a secret manager and rotate any "
               "value that was committed.",
    "CWE-327": "Use a current algorithm (for example AES-GCM from the cryptography package).",
    "CWE-328": "Use SHA-256 or stronger for integrity, and bcrypt, scrypt or Argon2 for passwords.",
    "CWE-79": "Rely on Jinja2 auto-escaping and avoid Markup()/|safe on user data.",
}
REMEDIATION["CWE-77"] = REMEDIATION["CWE-78"]
REMEDIATION["CWE-23"] = REMEDIATION["CWE-22"]
REMEDIATION["CWE-259"] = REMEDIATION["CWE-798"]


def owasp_for(cwe: str) -> str:
    return OWASP_BY_CWE.get(cwe, UNMAPPED)


def title_for(cwe: str) -> str:
    return CWE_TITLES.get(cwe, cwe)


def remediation_for(cwe: str) -> str:
    return REMEDIATION.get(cwe, "Review this location and validate untrusted input before use.")
