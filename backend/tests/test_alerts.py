"""Monitored apps, app keys and the runtime alert intake."""

import importlib.util
import json
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app import auth
from app.main import _store_for, app
from app.config import get_settings
from tests.conftest import signed_in_client

ALERT = {"timestamp": "2026-10-28T10:00:00+00:00", "endpoint": "/upload", "method": "POST",
         "reason": "Payload too large", "client_ip": "203.0.113.7", "size_bytes": 6_000_000}
TELEMETRY = Path(__file__).resolve().parents[2] / "telemetry" / "kavach_telemetry.py"


def _register(client, name="shop-api"):
    res = client.post("/apps", json={"name": name})
    assert res.status_code == 201
    return res.json()


def _other_user_client():
    _store_for(str(get_settings().db_path)).create_user("watcher@example.test", auth.hash_password("watcher-password-1"))
    client = TestClient(app)
    assert client.post("/auth/login", json={"email": "watcher@example.test",
                                            "password": "watcher-password-1"}).status_code == 200
    return client


def test_app_key_is_shown_once_and_stored_hashed():
    client = signed_in_client()
    created = _register(client)
    assert created["key"].startswith("kv_") and len(created["key"]) > 40
    assert "key" not in client.get("/apps").json()[0]
    store = _store_for(str(get_settings().db_path))
    with store._conn() as conn:
        stored = conn.execute("SELECT key_hash FROM monitored_apps").fetchone()[0]
    assert created["key"] not in stored


def test_alert_with_valid_key_shows_on_the_dashboard():
    client = signed_in_client()
    key = _register(client)["key"]
    res = TestClient(app).post("/alerts", json=ALERT, headers={"X-Kavach-Key": key})
    assert res.status_code == 202
    alerts = client.get("/alerts").json()
    assert len(alerts) == 1
    assert alerts[0]["reason"] == "Payload too large" and alerts[0]["app"] == "shop-api"
    assert client.get("/apps").json()[0]["alert_count"] == 1


def test_alert_without_or_with_wrong_key_is_refused():
    anon = TestClient(app)
    assert anon.post("/alerts", json=ALERT).status_code == 401
    assert anon.post("/alerts", json=ALERT, headers={"X-Kavach-Key": "kv_wrong"}).status_code == 401


def test_oversized_alert_fields_are_rejected():
    key = _register(signed_in_client())["key"]
    res = TestClient(app).post("/alerts", json=ALERT | {"reason": "x" * 1000}, headers={"X-Kavach-Key": key})
    assert res.status_code == 422


def test_alerts_are_private_to_their_owner():
    key = _register(signed_in_client())["key"]
    TestClient(app).post("/alerts", json=ALERT, headers={"X-Kavach-Key": key})
    other = _other_user_client()
    assert other.get("/alerts").json() == []
    assert other.get("/apps").json() == []


def test_deleting_an_app_revokes_its_key_and_alerts():
    client = signed_in_client()
    created = _register(client)
    TestClient(app).post("/alerts", json=ALERT, headers={"X-Kavach-Key": created["key"]})
    assert client.delete(f"/apps/{created['id']}").status_code == 204
    assert client.get("/alerts").json() == []
    assert TestClient(app).post("/alerts", json=ALERT, headers={"X-Kavach-Key": created["key"]}).status_code == 401


def test_alert_pages_need_a_session():
    anon = TestClient(app)
    assert anon.get("/alerts").status_code == 401
    assert anon.post("/apps", json={"name": "x"}).status_code == 401


def _load_telemetry():
    spec = importlib.util.spec_from_file_location("kavach_telemetry", TELEMETRY)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module  # dataclasses look the module up by name
    spec.loader.exec_module(module)
    return module


def test_telemetry_client_sends_alert_in_background():
    received = []

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):
            body = self.rfile.read(int(self.headers["Content-Length"]))
            received.append((self.path, self.headers["X-Kavach-Key"], json.loads(body)))
            self.send_response(202)
            self.end_headers()

        def log_message(self, *_):
            pass

    server = HTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        reporter = _load_telemetry().KavachReporter(f"http://127.0.0.1:{server.server_port}/api", "kv_test")
        reporter.report("Payload too large", "/upload", "POST", size_bytes=6_000_000)
        deadline = time.time() + 3
        while not received and time.time() < deadline:
            time.sleep(0.02)
    finally:
        server.shutdown()
    path, key, alert = received[0]
    assert path == "/api/alerts" and key == "kv_test"
    assert alert["reason"] == "Payload too large" and alert["size_bytes"] == 6_000_000


def test_telemetry_client_never_raises_when_kavach_is_down():
    reporter = _load_telemetry().KavachReporter("http://127.0.0.1:9", "kv_test")
    reporter._send(dict(ALERT))  # connection refused is logged, not raised


# attack pattern checks in the telemetry middleware ---------------------------

@pytest.fixture(scope="module")
def telemetry():
    return _load_telemetry()


@pytest.mark.parametrize("value, category, label", [
    ("1 UNION SELECT password FROM users", "sql_injection", "UNION SELECT"),
    ("1 UN/**/ION SEL/**/ECT 1", "sql_injection", "UNION SELECT"),
    ("1/**/union/**/select/**/1", "sql_injection", "UNION SELECT"),
    ("1%2520UNION%2520SELECT%25201", "sql_injection", "UNION SELECT"),
    ("id, name FROM users WHERE 1 OR select name from users", "sql_injection", "SELECT ... FROM"),
    ("admin' OR '1'='1", "sql_injection", "quote then OR/AND comparison"),
    ("admin'--", "sql_injection", "quote then comment"),
    ("1; DROP TABLE users", "sql_injection", "stacked query"),
    ("1; exec xp_cmdshell", "sql_injection", "stacked query"),
    ("1 AND SLEEP(5)", "sql_injection", "time delay function"),
    ("../../app.py", "path_traversal", "../ sequence"),
    ("..\\..\\boot.ini", "path_traversal", "../ sequence"),
    ("..%2f..%2fsecret", "path_traversal", "../ sequence"),
    ("%252e%252e%252fsecret", "path_traversal", "../ sequence"),
    ("/etc/passwd", "path_traversal", "sensitive system file"),
    ("report.pdf%00.png", "path_traversal", "null byte"),
])
def test_attack_patterns_are_found(telemetry, value, category, label):
    match = telemetry.find_attack([("query.q", value)])
    assert match is not None and (match.category, match.label) == (category, label)
    assert match.field == "query.q" and match.sample == value[:telemetry.SAMPLE_CHARS]


@pytest.mark.parametrize("value", [
    "Union Station", "select a plan", "O'Reilly", "rock and roll", "hello...world", "v1.2..3",
    "path/to/file.txt", "I will drop by; update soon", "done; execute the plan", "it's fine -- really",
    "a; create a table for me", "50% off, 100%25 real",
])
def test_ordinary_text_is_not_flagged(telemetry, value):
    assert telemetry.find_attack([("form.comment", value)]) is None


def test_inspection_is_bounded(telemetry):
    many = [(f"query.f{i}", "ok") for i in range(telemetry.MAX_FIELDS)] + [("query.late", "' OR 1=1")]
    assert telemetry.find_attack(many) is None
    long_value = "a" * telemetry.MAX_VALUE_CHARS + " UNION SELECT 1"
    assert telemetry.find_attack([("query.q", long_value)]) is None


class _MultiDict(dict):
    def items(self, multi=False):
        return [(k, v) for k, values in super().items() for v in values]


class _Request:
    def __init__(self, path="/", args=None, form=None, body=None):
        self.path, self.args, self.form = path, _MultiDict(args or {}), _MultiDict(form or {})
        self.is_json, self._body = body is not None, body

    def get_json(self, silent=False):
        return self._body


def test_request_fields_cover_path_query_form_and_json(telemetry):
    req = _Request("/files/x", {"id": ["1", "2"]}, {"note": ["hi"]},
                   {"user": {"name": "a", "tags": ["b"]}, "age": 3})
    assert list(telemetry.request_fields(req)) == [
        ("path", "/files/x"), ("query.id", "1"), ("query.id", "2"), ("form.note", "hi"),
        ("json.user.name", "a"), ("json.user.tags[0]", "b")]


def test_traversal_in_a_nested_json_value_is_found(telemetry):
    req = _Request("/download", body={"file": {"path": "../../etc/passwd"}})
    match = telemetry.find_attack(telemetry.request_fields(req))
    assert match.category == "path_traversal" and match.field == "json.file.path"


def test_attack_alert_details_reach_the_dashboard():
    client = signed_in_client()
    key = _register(client)["key"]
    attack = ALERT | {"reason": "SQL injection pattern: UNION SELECT", "category": "sql_injection",
                      "field": "query.id", "sample": "1 UNION SELECT 1", "size_bytes": None}
    assert TestClient(app).post("/alerts", json=attack, headers={"X-Kavach-Key": key}).status_code == 202
    shown = client.get("/alerts").json()[0]
    assert (shown["category"], shown["field"], shown["sample"]) == ("sql_injection", "query.id", "1 UNION SELECT 1")


def test_unknown_alert_category_is_rejected():
    key = _register(signed_in_client())["key"]
    res = TestClient(app).post("/alerts", json=ALERT | {"category": "anything"}, headers={"X-Kavach-Key": key})
    assert res.status_code == 422


def test_flask_middleware_reports_and_optionally_blocks(telemetry):
    flask = pytest.importorskip("flask")  # Flask is the monitored app's dependency, not Kavach's
    for block, expected in ((False, 200), (True, 403)):
        web = flask.Flask(__name__)
        web.add_url_rule("/item", "item", lambda: "ok")
        reporter = telemetry.init_kavach_telemetry(web, "http://127.0.0.1:9", "kv_test", block_attacks=block)
        sent = []
        reporter.report = lambda *a, **kw: sent.append(kw.get("match"))
        assert web.test_client().get("/item?id=1 UNION SELECT 1").status_code == expected
        assert sent[0].category == "sql_injection"
        assert web.test_client().get("/item?id=7").status_code == 200 and len(sent) == 1
