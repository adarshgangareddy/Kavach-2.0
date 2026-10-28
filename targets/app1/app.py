from flask import Flask, request, jsonify
import sqlite3
import subprocess
from helpers import run_report, find_document, unsafe_audit, safe_document

app = Flask(__name__)


@app.route("/report")
def report():
    return run_report(request.args.get("name", ""))


@app.route("/lookup")
def lookup():
    return jsonify(unsafe_audit(request.args.get("name", "")))


@app.route("/document")
def document():
    path = request.args.get("path", "README.txt")
    if request.args.get("safe") == "1":
        from helpers import safe_document
        return safe_document(path)
    return find_document(path)


@app.route("/shell")
def shell():
    return subprocess.run("echo " + request.args.get("text", ""), shell=True, capture_output=True, text=True).stdout


@app.route("/safe-report", methods=["POST"])
def safe_report():
    name = request.form.get("name", "")
    result = subprocess.run("printf %s " + __import__("shlex").quote(name), shell=True, capture_output=True, text=True)
    return result.stdout

