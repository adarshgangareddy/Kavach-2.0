"""Rule layer: hard-coded secrets and weak crypto (app/detect/rules.py).

Inputs are short lines that are only parsed with ast, never run. Values shaped like real
tokens are assembled at runtime, so this file holds nothing a secret scanner would flag.
"""

import ast

import pytest

from app.detect.base import Candidate
from app.detect.rules import RulesDetector, check_module, is_secret_name, words
from app.pipeline import deduplicate

AWS_ID = "AKIA" + "Q" * 16
GITHUB = "ghp_" + "a1" * 18
STRIPE = "sk_" + "live_" + "b2" * 12
PRIVATE_KEY = "-----BEGIN RSA " + "PRIVATE KEY-----"


def found(source: str) -> list[tuple[int, str]]:
    return [(c.line, c.cwe) for c in check_module(ast.parse(source), "f.py")]


def cwes(source: str) -> set[str]:
    return {cwe for _, cwe in found(source)}


# names --------------------------------------------------------------------------

@pytest.mark.parametrize("name, expected", [
    ("password", True), ("DB_PASSWORD", True), ("dbPassword", True), ("SECRET_KEY", True), ("apiKey", True),
    ("client_secret", True), ("auth_token", True), ("private_key", True),
    ("bypass", False), ("passed", False), ("tokenizer", False), ("token_type", False), ("password_field", False),
    ("PASSWORD_ENV", False), ("secret_name", False), ("sort_key", False), ("password_min_length", False),
])
def test_secret_names_are_matched_as_whole_words(name, expected):
    assert is_secret_name(name) is expected


def test_words_split_snake_and_camel_case():
    assert words("apiKey") == ["api", "key"]
    assert words("db_Password2") == ["db", "password2"]


# hard-coded secrets ---------------------------------------------------------------

@pytest.mark.parametrize("source, cwe", [
    ('DB_PASSWORD = "hunter2-staging"', "CWE-259"),
    ('app.secret_key = "dev-key-123"', "CWE-798"),
    ('app.config["SECRET_KEY"] = "dev"', "CWE-798"),
    ('settings = {"api_key": "k-29f8a7c1"}', "CWE-798"),
    ('connect(host="db", password="pw-for-db")', "CWE-259"),
    ('def login(user, password="admin123"):\n    pass', "CWE-259"),
    ('if password == "letmein":\n    pass', "CWE-259"),
    ('x = os.getenv("STRIPE_SECRET", "fallback-value")', "CWE-798"),
    ('x = os.environ.get("JWT_KEY", default="fallback-value")', "CWE-798"),
    ('t = jwt.encode(payload, "signing-secret", algorithm="HS256")', "CWE-798"),
    ('URL = "postgresql://admin:pa55word@db/shop"', "CWE-798"),
])
def test_hard_coded_secrets_are_found(source, cwe):
    source = "import os\nimport jwt\n" + source
    assert cwe in cwes(source)


@pytest.mark.parametrize("value", [AWS_ID, GITHUB, STRIPE, PRIVATE_KEY + "\nMIIE..."])
def test_known_token_formats_are_found_in_any_variable(value):
    assert found(f"config_blob = {value!r}") == [(1, "CWE-798")]


@pytest.mark.parametrize("source", [
    'token_type = "Bearer"',
    'password_field = "password"',
    'PASSWORD_ENV = "DB_PASSWORD"',
    'password = os.environ["DB_PASSWORD"]',
    'password = ""',
    'secret = "<your-secret-here>"',
    'api_key = "${API_KEY}"',
    'password = "your-password"',
    'bypass = "yes"',
    'headers = {"Access-Control-Allow-Credentials": "true"}',
    'msg = {"password": "Please enter your password below"}',
    'x = os.getenv("SECRET_KEY")',
    'x = os.getenv("DEBUG", "false")',
    'URL = "postgresql://admin:${DB_PASS}@db/shop"',
    'URL = "https://example.com/docs"',
])
def test_ordinary_code_is_not_flagged_as_a_secret(source):
    assert found("import os\n" + source) == []


def test_secret_values_never_appear_in_findings():
    source = f'DB_PASSWORD = "hunter2-staging"\nkey_blob = {AWS_ID!r}\nURL = "postgresql://a:pa55word@db/x"\n'
    for cand in check_module(ast.parse(source), "f.py"):
        text = cand.model_dump_json()
        assert "hunter2" not in text and AWS_ID not in text and "pa55word" not in text


def test_one_secret_finding_per_line():
    # named like a key *and* shaped like a token: one finding, the more certain one
    cands = check_module(ast.parse(f"api_key = {AWS_ID!r}"), "f.py")
    assert len(cands) == 1 and "AWS" in cands[0].sink


# weak crypto ------------------------------------------------------------------

@pytest.mark.parametrize("source, cwe", [
    ("hashlib.md5(data)", "CWE-327"),
    ("hashlib.sha1(data)", "CWE-327"),
    ('hashlib.new("MD5", data)', "CWE-327"),
    ("hashlib.sha256(password.encode())", "CWE-916"),
    ("hashlib.md5(user.password)", "CWE-916"),
    ("DES.new(key, DES.MODE_CBC)", "CWE-327"),
    ("AES.new(key, AES.MODE_ECB)", "CWE-327"),
    ("Cipher(algorithms.AES(key), modes.ECB())", "CWE-327"),
    ("Cipher(algorithms.TripleDES(key), modes.CBC(iv))", "CWE-327"),
    ("rsa.generate_private_key(public_exponent=65537, key_size=1024)", "CWE-326"),
    ("RSA.generate(1024)", "CWE-326"),
    ('requests.get("https://x", verify=False)', "CWE-295"),
    ("ssl._create_unverified_context()", "CWE-295"),
    ("ctx.check_hostname = False", "CWE-295"),
    ("ctx.verify_mode = ssl.CERT_NONE", "CWE-295"),
    ("ssl.SSLContext(ssl.PROTOCOL_TLSv1)", "CWE-327"),
])
def test_weak_crypto_is_found(source, cwe):
    imports = ("import hashlib, ssl, requests\nfrom Crypto.Cipher import AES, DES\nfrom Crypto.PublicKey import RSA\n"
               "from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes\n"
               "from cryptography.hazmat.primitives.asymmetric import rsa\n")
    assert cwe in cwes(imports + source)


@pytest.mark.parametrize("source", [
    "hashlib.md5(page, usedforsecurity=False)",
    "hashlib.sha256(data)",
    "AES.new(key, AES.MODE_GCM)",
    "rsa.generate_private_key(public_exponent=65537, key_size=3072)",
    'requests.get("https://x", timeout=5)',
    "ssl.create_default_context()",
    "dice = random.randint(1, 6)",
    "def shuffle_deck(deck):\n    pick = random.choice(deck)",
])
def test_modern_or_non_security_crypto_is_not_flagged(source):
    imports = ("import hashlib, random, ssl, requests\nfrom Crypto.Cipher import AES\n"
               "from cryptography.hazmat.primitives.asymmetric import rsa\n")
    assert found(imports + source) == []


@pytest.mark.parametrize("source", [
    'token = "".join(random.choice(ALPHABET) for _ in range(32))',
    "otp = random.randint(100000, 999999)",
    "def make_reset_link(user):\n    code = random.getrandbits(64)",
])
def test_random_module_for_security_values_is_found(source):
    assert "CWE-330" in cwes("import random\n" + source)


def test_aliased_imports_are_resolved():
    assert cwes("import hashlib as h\nh.md5(b'x')") == {"CWE-327"}
    assert cwes("from hashlib import sha1\nsha1(b'x')") == {"CWE-327"}


# detector and pipeline ----------------------------------------------------------

def test_detector_scans_files_and_skips_unparseable_ones(tmp_path):
    (tmp_path / "a.py").write_text('import hashlib\nhashlib.md5(b"x")\n')
    (tmp_path / "broken.py").write_text("def (:\n")
    cands = RulesDetector().scan(tmp_path, ["a.py", "broken.py"], 10)
    assert [(c.file, c.line, c.cwe, c.detector) for c in cands] == [("a.py", 2, "CWE-327", "rules")]
    assert cands[0].fix_suggestion.startswith("Use hashlib.sha256")


def test_bandit_password_and_rules_secret_merge_into_one_finding():
    bandit = Candidate(file="a.py", line=3, cwe="CWE-259", detector="bandit", confidence=0.5)
    rules = Candidate(file="a.py", line=3, cwe="CWE-798", detector="rules", confidence=0.6)
    merged = deduplicate([bandit, rules])
    assert len(merged) == 1 and merged[0].detector == "bandit+rules"


def test_merged_finding_keeps_the_plain_words_from_the_rules_check():
    bandit = Candidate(file="a.py", line=3, cwe="CWE-259", detector="bandit", confidence=0.9,
                       sink="B105:hardcoded_password_string", fix_suggestion="generic")
    rules = Candidate(file="a.py", line=3, cwe="CWE-259", detector="rules", confidence=0.6,
                      sink="Variable `DB_PASSWORD` is set to a hard-coded password", fix_suggestion="specific")
    merged = deduplicate([bandit, rules])[0]
    assert (merged.sink, merged.fix_suggestion, merged.confidence) == (rules.sink, "specific", 0.9)


def test_rules_detector_is_registered():
    from app.detect.registry import all_detectors
    assert "rules" in [d.name for d in all_detectors()]


def test_new_cwes_have_labels_and_scores():
    from app.report import owasp
    from app.report.severity import BASE_SCORE
    for cwe in ("CWE-916", "CWE-295", "CWE-326", "CWE-330"):
        assert owasp.owasp_for(cwe) != owasp.UNMAPPED and owasp.title_for(cwe) != cwe and cwe in BASE_SCORE
