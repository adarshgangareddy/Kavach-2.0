import os
import sqlite3
import subprocess


def run_report(value):
    return subprocess.run("printf %s " + value, shell=True, capture_output=True, text=True).stdout


def find_document(value):
    return open(value, encoding="utf-8").read()


def safe_document(value):
    from werkzeug.utils import secure_filename
    return open(secure_filename(value), encoding="utf-8").read()


def unsafe_audit(value):
    db = sqlite3.connect(":memory:")
    return db.execute("SELECT 'ok' WHERE tag = '" + value + "'").fetchone()

