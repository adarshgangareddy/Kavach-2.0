from flask import Flask, request, jsonify
import os
import sqlite3
from helpers import archive_item, search_notes, delete_preview

app = Flask(__name__)


@app.route("/archive")
def archive():
    return archive_item(request.args.get("item", ""))


@app.route("/notes")
def notes():
    term = request.args.get("term", "")
    if request.args.get("safe") == "1":
        db = sqlite3.connect(":memory:")
        return jsonify(db.execute("SELECT ?", (term,)).fetchone())
    return jsonify(search_notes(term))


@app.route("/remove", methods=["POST"])
def remove():
    target = request.form.get("target", "")
    return str(os.system("echo removing " + target))


@app.route("/delete")
def delete():
    return str(delete_preview(request.args.get("item", "")))


@app.route("/file")
def file():
    return open(request.args.get("path", "README.txt"), encoding="utf-8").read()

