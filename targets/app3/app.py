from flask import Flask, request, jsonify
import sqlite3
import subprocess
from helpers import open_asset, run_preview, lookup_user, safe_asset

app = Flask(__name__)


@app.route("/asset")
def asset():
    name = request.args.get("name", "welcome.txt")
    if request.args.get("safe") == "1":
        return safe_asset(name)
    return open_asset(name)


@app.route("/preview", methods=["POST"])
def preview():
    return run_preview(request.form.get("text", ""))


@app.route("/user")
def user():
    return jsonify(lookup_user(request.args.get("id", "")))


@app.route("/preview-safe", methods=["POST"])
def preview_safe():
    value = request.form.get("text", "")
    result = subprocess.run("printf %s " + __import__("shlex").quote(value), shell=True, capture_output=True, text=True)
    return result.stdout


@app.route("/raw-asset")
def raw_asset():
    return open(request.args.get("name", "welcome.txt"), encoding="utf-8").read()

