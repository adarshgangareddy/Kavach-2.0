"""Fixed copy of targets/app3/app.py, for the fix-and-re-check demo.

Only /raw-asset changed: it served any file the user named (path traversal,
CWE-22). It now uses send_from_directory, which refuses ../ and absolute paths.
The original in targets/app3 keeps its bug on purpose: it is a test fixture.
"""

from flask import Flask, request, jsonify, send_from_directory
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
    name = request.args.get("name", "welcome.txt")
    return send_from_directory(app.root_path, name)  # FIXED: refuses ../ and absolute paths
