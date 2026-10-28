"""Authentication: Argon2id password hashes and signed JWT sessions in an HttpOnly cookie.

No custom cryptography: hashing is argon2-cffi (Argon2id, a random 16-byte salt
per hash, parameters stored in the hash string), tokens are PyJWT HS256.

Environment (or backend/.env):
    SENTINEL_JWT_SECRET       signing key, at least 32 characters (required in production)
    SENTINEL_ADMIN_EMAIL      seeded admin account
    SENTINEL_ADMIN_PASSWORD
    SENTINEL_SESSION_MINUTES  token and cookie lifetime (default 30)
    SENTINEL_COOKIE_SECURE    "true" (default, HTTPS only) or "false" for local HTTP
    SENTINEL_ALLOW_SIGNUP     "true" (default) lets anyone create an account; "false" turns it off
"""

import logging
import os
import secrets
import time
from dataclasses import dataclass

import jwt
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError

COOKIE_NAME = "zds_session"
ALGORITHM = "HS256"
ISSUER = "zeroday-sentinel"
MIN_SECRET_CHARS = 32
GENERIC_LOGIN_ERROR = "Invalid email or password"

log = logging.getLogger("zeroday_sentinel.auth")
_hasher = PasswordHasher()  # Argon2id with library defaults (RFC 9106 low-memory profile)
# Verified against when the email is unknown, so both failure paths cost the same time.
_DUMMY_HASH = _hasher.hash(secrets.token_urlsafe(16))
_ephemeral_secret: str | None = None


@dataclass(frozen=True)
class User:
    id: str
    email: str
    role: str


def signup_enabled() -> bool:
    """Self-service sign-up. Turn off with SENTINEL_ALLOW_SIGNUP=false (admin-created accounts only)."""
    return os.environ.get("SENTINEL_ALLOW_SIGNUP", "true").strip().lower() not in {"0", "false", "no"}


def normalize_email(email: str) -> str:
    return email.strip().lower()


def hash_password(password: str) -> str:
    return _hasher.hash(password)


def verify_password(stored_hash: str | None, password: str) -> bool:
    """Constant-work check: an unknown user still pays for one Argon2 verification."""
    try:
        return _hasher.verify(stored_hash or _DUMMY_HASH, password) and stored_hash is not None
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False


def needs_rehash(stored_hash: str) -> bool:
    return _hasher.check_needs_rehash(stored_hash)


def jwt_secret() -> str:
    global _ephemeral_secret
    secret = os.environ.get("SENTINEL_JWT_SECRET", "")
    if secret:
        if len(secret) < MIN_SECRET_CHARS:
            raise RuntimeError(f"SENTINEL_JWT_SECRET must be at least {MIN_SECRET_CHARS} characters")
        return secret
    if _ephemeral_secret is None:  # never a hard-coded default
        _ephemeral_secret = secrets.token_urlsafe(48)
        log.warning("SENTINEL_JWT_SECRET is not set: using a random key; sessions end on restart")
    return _ephemeral_secret


def session_minutes() -> int:
    return max(1, int(os.environ.get("SENTINEL_SESSION_MINUTES", "30")))


def cookie_secure() -> bool:
    return os.environ.get("SENTINEL_COOKIE_SECURE", "true").strip().lower() not in {"0", "false", "no"}


def issue_token(user: User) -> str:
    now = int(time.time())
    claims = {"sub": user.id, "role": user.role, "iss": ISSUER, "iat": now,
              "exp": now + session_minutes() * 60, "jti": secrets.token_urlsafe(12)}
    return jwt.encode(claims, jwt_secret(), algorithm=ALGORITHM)


def decode_token(token: str) -> dict | None:
    """Claims of a valid, unexpired token from us; None for anything else."""
    try:
        return jwt.decode(token, jwt_secret(), algorithms=[ALGORITHM], issuer=ISSUER,
                          options={"require": ["sub", "exp", "iat", "iss"]})
    except jwt.PyJWTError:
        return None


def set_session_cookie(response, token: str) -> None:
    response.set_cookie(COOKIE_NAME, token, max_age=session_minutes() * 60, path="/",
                        httponly=True, secure=cookie_secure(), samesite="lax")


def clear_session_cookie(response) -> None:
    response.delete_cookie(COOKIE_NAME, path="/", httponly=True, secure=cookie_secure(),
                           samesite="lax")
