import os
import sqlite3
import subprocess


def open_asset(value):
    return open(value, encoding="utf-8").read()


def run_preview(value):
    return subprocess.run("echo " + value, shell=True, capture_output=True, text=True).stdout


def lookup_user(value):
    db = sqlite3.connect(":memory:")
    return db.execute("SELECT 'user' WHERE id = " + value).fetchone()


def safe_asset(value):
    from werkzeug.utils import secure_filename
    return open(secure_filename(value), encoding="utf-8").read()

