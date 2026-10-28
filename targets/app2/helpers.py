import os
import sqlite3
import subprocess


def archive_item(value):
    return subprocess.run("echo archive " + value, shell=True, capture_output=True, text=True).stdout


def search_notes(value):
    db = sqlite3.connect(":memory:")
    return db.execute("SELECT 'note' WHERE title LIKE '%" + value + "%'").fetchone()


def delete_preview(value):
    return os.system("echo " + value)


def safe_archive(value):
    from werkzeug.utils import secure_filename
    return open(secure_filename(value), encoding="utf-8").read()

