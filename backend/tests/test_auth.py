"""Authentication, sessions, rate limiting and per-user data scoping."""

import io
import time
import zipfile

import jwt
import pytest
from fastapi.testclient import TestClient

from app import auth
from app.main import _store_for, app
from app.config import get_settings
from tests.conftest import ADMIN_EMAIL, ADMIN_PASSWORD, APP_SOURCE, signed_in_client

OTHER_EMAIL = "second.user@example.test"
OTHER_PASSWORD = "another-test-password"


def _store():
    return _store_for(str(get_settings().db_path))


def _add_user(email=OTHER_EMAIL, password=OTHER_PASSWORD):
    return _store().create_user(email, auth.hash_password(password))


def _zip() -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("demo/app/routes.py", APP_SOURCE)
    return buf.getvalue()


# a) successful login ---------------------------------------------------------

def test_login_sets_a_secure_session_cookie(monkeypatch):
    monkeypatch.setenv("SENTINEL_COOKIE_SECURE", "true")
    res = TestClient(app).post("/auth/login", json={"email": "  Admin@Example.TEST ", "password": ADMIN_PASSWORD})
    assert res.status_code == 200
    assert res.json() == {"email": ADMIN_EMAIL, "role": "admin"}
    cookie = res.headers["set-cookie"].lower()
    assert cookie.startswith(f"{auth.COOKIE_NAME}=")
    for flag in ("httponly", "secure", "samesite=lax", "max-age=1800", "path=/"):
        assert flag in cookie


def test_session_cookie_identifies_the_user():
    client = signed_in_client()
    assert client.get("/auth/me").json() == {"email": ADMIN_EMAIL, "role": "admin"}
    token = client.cookies.get(auth.COOKIE_NAME)
    claims = jwt.decode(token, options={"verify_signature": False})
    assert claims["iss"] == auth.ISSUER and claims["exp"] - claims["iat"] == 30 * 60


def test_password_is_stored_as_argon2id_with_unique_salts():
    _, admin_hash = _store().get_user_by_email(ADMIN_EMAIL)
    assert admin_hash.startswith("$argon2id$") and ADMIN_PASSWORD not in admin_hash
    assert auth.hash_password("same") != auth.hash_password("same")  # random salt per hash


# b) wrong password, generic error ---------------------------------------------

@pytest.mark.parametrize("email,password", [(ADMIN_EMAIL, "wrong-password"),
                                            ("nobody@example.test", ADMIN_PASSWORD)])
def test_failed_login_is_generic_and_sets_no_cookie(email, password):
    res = TestClient(app).post("/auth/login", json={"email": email, "password": password})
    assert res.status_code == 401
    assert res.json() == {"detail": "Invalid email or password"}
    assert "set-cookie" not in res.headers


# c) rate limiting --------------------------------------------------------------

def test_login_is_rate_limited_per_ip():
    client = TestClient(app)
    codes = [client.post("/auth/login", json={"email": ADMIN_EMAIL, "password": "nope"}).status_code
             for _ in range(6)]
    assert codes == [401, 401, 401, 401, 401, 429]
    # the correct password is refused too until the window passes
    assert client.post("/auth/login", json={"email": ADMIN_EMAIL, "password": ADMIN_PASSWORD}).status_code == 429


# d) protected routes need a valid session --------------------------------------

PROTECTED = [("get", "/auth/me"), ("get", "/scans"), ("get", "/detectors"), ("get", "/cwe"),
             ("get", "/scans/S-0000abcd"), ("get", "/scans/S-0000abcd/findings"),
             ("get", "/findings/F-0000abcd-001"), ("get", "/scans/S-0000abcd/sarif"),
             ("get", "/scans/S-0000abcd/report"), ("get", "/scans/S-0000abcd/source?path=a.py")]


@pytest.mark.parametrize("method,path", PROTECTED)
def test_protected_routes_reject_missing_cookie(method, path):
    assert getattr(TestClient(app), method)(path).status_code == 401


def test_writes_reject_missing_cookie():
    client = TestClient(app)
    assert client.post("/snippet", json={"code": "x = 1"}).status_code == 401
    assert client.post("/scans", files={"file": ("a.zip", _zip(), "application/zip")}).status_code == 401
    assert client.patch("/findings/F-0000abcd-001", json={"status": "fixed"}).status_code == 401


@pytest.mark.parametrize("token_kind", ["garbage", "wrong-key", "expired", "unknown-user"])
def test_invalid_tokens_are_rejected(token_kind):
    now = int(time.time())
    user = _store().get_user_by_email(ADMIN_EMAIL)[0]
    claims = {"sub": user.id, "iss": auth.ISSUER, "iat": now, "exp": now + 600}
    token = {
        "garbage": "not-a-jwt",
        "wrong-key": jwt.encode(claims, "x" * 40, algorithm="HS256"),
        "expired": jwt.encode(claims | {"iat": now - 7200, "exp": now - 3600}, auth.jwt_secret(), algorithm="HS256"),
        "unknown-user": jwt.encode(claims | {"sub": "U-missing"}, auth.jwt_secret(), algorithm="HS256"),
    }[token_kind]
    client = TestClient(app)
    client.cookies.set(auth.COOKIE_NAME, token)
    assert client.get("/scans").status_code == 401


def test_logout_clears_the_cookie():
    client = signed_in_client()
    res = client.post("/auth/logout")
    assert res.status_code == 200 and 'max-age=0' in res.headers["set-cookie"].lower()
    assert client.get("/scans").status_code == 401


def test_health_stays_public():
    assert TestClient(app).get("/health").status_code == 200


# e) users cannot see each other's records --------------------------------------

def test_users_cannot_access_each_others_scans_and_findings(marker):
    owner = signed_in_client()
    scan = owner.post("/scans", files={"file": ("demo.zip", _zip(), "application/zip")}).json()
    finding = owner.get(f"/scans/{scan['id']}/findings").json()[0]
    _add_user()
    other = signed_in_client(OTHER_EMAIL, OTHER_PASSWORD)

    assert other.get("/scans").json() == []
    sid, fid = scan["id"], finding["id"]
    for path in (f"/scans/{sid}", f"/scans/{sid}/findings", f"/scans/{sid}/report",
                 f"/scans/{sid}/sarif", f"/scans/{sid}/source?path=app/routes.py", f"/findings/{fid}"):
        assert other.get(path).status_code == 404, path  # same answer as a missing record
    assert other.patch(f"/findings/{fid}", json={"status": "accepted"}).status_code == 404
    assert owner.get(f"/findings/{fid}").json()["status"] == "open"  # unchanged

    mine = other.post("/snippet", json={"code": "x = 1\n"}).json()["scan"]["id"]
    assert [s["id"] for s in other.get("/scans").json()] == [mine]
    assert owner.get(f"/scans/{mine}").status_code == 404
    assert "owner_id" not in owner.get(f"/scans/{sid}").json()


def test_scans_from_before_accounts_go_to_the_admin():
    from app.models import Scan
    from app.store import Store
    db = get_settings().db_path
    legacy = Store(db)
    legacy.save_scan(Scan(source_kind="cli", source_ref="old"))  # no owner
    _store_for.cache_clear()
    client = signed_in_client()  # seeding assigns unowned scans to the admin
    assert [s["source_ref"] for s in client.get("/scans").json()] == ["old"]


# sign-up -------------------------------------------------------------------------

NEW_EMAIL = "new.person@example.test"
NEW_PASSWORD = "correct horse battery staple"


def test_register_creates_a_user_and_signs_in():
    client = TestClient(app)
    res = client.post("/auth/register", json={"email": "  New.Person@Example.TEST ", "password": NEW_PASSWORD})
    assert res.status_code == 201
    assert res.json() == {"email": NEW_EMAIL, "role": "user"}  # never admin
    assert "httponly" in res.headers["set-cookie"].lower()
    assert client.get("/auth/me").json()["email"] == NEW_EMAIL
    assert client.get("/scans").json() == []  # sees none of the admin's scans
    _, stored = _store().get_user_by_email(NEW_EMAIL)
    assert stored.startswith("$argon2id$")
    # and can sign in again later
    assert TestClient(app).post("/auth/login", json={"email": NEW_EMAIL, "password": NEW_PASSWORD}).status_code == 200


def test_register_refuses_an_existing_email():
    res = TestClient(app).post("/auth/register", json={"email": ADMIN_EMAIL, "password": NEW_PASSWORD})
    assert res.status_code == 409
    assert res.json() == {"detail": "Could not create an account with these details"}
    assert "set-cookie" not in res.headers


@pytest.mark.parametrize("email,password", [
    ("not-an-email", NEW_PASSWORD),
    (NEW_EMAIL, "short-pass"),                 # under 12 characters
    (NEW_EMAIL, "aaaaaaaaaaaaaaaa"),           # one repeated character
    (NEW_EMAIL, NEW_EMAIL),                    # the email itself
    (NEW_EMAIL, "x" * 129),                    # over the limit
])
def test_register_validates_email_and_password(email, password):
    res = TestClient(app).post("/auth/register", json={"email": email, "password": password})
    assert res.status_code == 422
    assert _store().get_user_by_email(NEW_EMAIL)[0] is None


def test_register_can_be_turned_off(monkeypatch):
    monkeypatch.setenv("SENTINEL_ALLOW_SIGNUP", "false")
    client = TestClient(app)
    assert client.get("/health").json()["signup"] is False
    assert client.post("/auth/register", json={"email": NEW_EMAIL, "password": NEW_PASSWORD}).status_code == 403


def test_register_is_rate_limited():
    client = TestClient(app)
    codes = [client.post("/auth/register", json={"email": f"user{i}@example.test", "password": NEW_PASSWORD}).status_code
             for i in range(4)]
    assert codes == [201, 201, 201, 429]
