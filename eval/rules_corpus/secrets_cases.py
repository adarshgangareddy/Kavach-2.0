"""Hard-coded secrets: labelled cases. Never run."""
import hashlib
import hmac
import os

import jwt
from flask import Flask
from itsdangerous import URLSafeTimedSerializer

app = Flask(__name__)

# --- should be reported ---------------------------------------------------------
app.secret_key = "flask-dev-key-1"  # expect CWE-798
app.config["SECRET_KEY"] = "s3cret-config-value"  # expect CWE-798
DB_PASSWORD = "Winter2026!"  # expect CWE-798
API_KEY = "k_93f8e1c2d4b5a6"  # expect CWE-798
client_secret = "c1i3nt-s3cr3t-val"  # expect CWE-798
settings = {"auth_token": "tok-5b1e9c0a7d"}  # expect CWE-798
db = connect(host="db.internal", user="app", password="db-pass-77")  # expect CWE-798
DATABASE_URL = "postgresql://app:Sup3rS3cret@db.internal:5432/shop"  # expect CWE-798
REDIS_URL = "redis://cache:r3d1sPw@cache:6379/0"  # expect CWE-798
STRIPE = os.getenv("STRIPE_SECRET_KEY", "fallback-stripe-value")  # expect CWE-798
JWT_KEY = os.environ.get("JWT_SECRET", "jwt-fallback-value")  # expect CWE-798
signed = jwt.encode({"sub": 1}, "jwt-signing-secret", algorithm="HS256")  # expect CWE-798
mac = hmac.new(b"hmac-signing-key", b"msg", hashlib.sha256)  # expect CWE-798
serializer = URLSafeTimedSerializer("itsdangerous-key-1")  # expect CWE-798
CLOUD_ID = "AKIA" "Q7XW3LMNB2RTYUZP"  # expect CWE-798
PEM = "-----BEGIN RSA " "PRIVATE KEY-----\nMIIEfake\n"  # expect CWE-798


def login(user, password="admin123"):  # expect CWE-798
    if password == "letmein":  # expect CWE-798
        return True
    return False


# --- should not be reported -----------------------------------------------------
token_type = "Bearer"  # decoy
password_field = "password"  # decoy
PASSWORD_ENV = "DB_PASSWORD"  # decoy
password = os.environ["DB_PASSWORD"]  # decoy
SECRET_KEY = os.environ["SECRET_KEY"]  # decoy
secret = "<your-secret-here>"  # decoy
api_key = "${API_KEY}"  # decoy
password_min_length = "12"  # decoy
prompt = {"password": "Please enter your password"}  # decoy
bypass = "yes"  # decoy
headers = {"Access-Control-Allow-Credentials": "true"}  # decoy
DEBUG = os.getenv("DEBUG", "false")  # decoy
DOCS_URL = "https://example.com/docs/tokens"  # decoy
csrf_token_name = "csrf_token"  # decoy
empty_password = ""  # decoy
tokenizer = "whitespace"  # decoy
