"""A small shop API with Kavach runtime alerts, for the live Monitoring demo.

No security bugs on purpose: queries are parameterised and files are served with
send_from_directory, so attack attempts fail here and only show up as alerts in Kavach.
"""
import os
import sqlite3

from flask import Flask, jsonify, request, send_from_directory

from kavach_telemetry import init_kavach_telemetry

FILES_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "files")
PRODUCTS = [("Laptop stand", 45.0), ("USB-C cable", 9.5), ("Desk lamp", 30.0)]

app = Flask(__name__)
init_kavach_telemetry(app,
                      kavach_url=os.environ.get("KAVACH_URL", "http://host.docker.internal:8080/api"),
                      app_key=os.environ["KAVACH_APP_KEY"],
                      block_attacks=os.environ.get("KAVACH_BLOCK", "false").lower() == "true")


def _db() -> sqlite3.Connection:
    conn = sqlite3.connect(":memory:")
    conn.execute("CREATE TABLE products (name TEXT, price REAL)")
    conn.executemany("INSERT INTO products VALUES (?, ?)", PRODUCTS)
    return conn


@app.get("/")
def home():
    return jsonify(app="demo-shop", status="ok")


@app.get("/products")
def products():
    term = request.args.get("q", "")
    with _db() as conn:
        rows = conn.execute("SELECT name, price FROM products WHERE name LIKE ?", (f"%{term}%",)).fetchall()
    return jsonify([{"name": name, "price": price} for name, price in rows])


@app.get("/files")
def files():
    return send_from_directory(FILES_DIR, request.args.get("name", ""))


@app.post("/feedback")
def feedback():
    body = request.get_json(silent=True) or {}
    return jsonify(received=bool(body.get("message")))
