from __future__ import annotations

import sqlite3
import traceback
from pathlib import Path
from secrets import token_hex

from flask import Flask, Response, jsonify, request, session

BASE_DIR = Path(__file__).resolve().parent
DB_PATH = BASE_DIR / "lab.db"
app = Flask(__name__)
app.secret_key = "vulnaudit-local-secret"
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"

USERS = [
    (1, "alice", "alice@example.test", "Engineering"),
    (2, "bob", "bob@example.test", "Finance"),
    (3, "carol", "carol@example.test", "HR"),
    (4, "dave", "dave@example.test", "Sales"),
    (5, "erin", "erin@example.test", "Support"),
    (6, "frank", "frank@example.test", "QA"),
    (7, "gina", "gina@example.test", "Design"),
    (8, "henry", "henry@example.test", "Operations"),
    (9, "ivy", "ivy@example.test", "Legal"),
    (10, "jack", "jack@example.test", "Marketing"),
]


def init_db() -> None:
    with sqlite3.connect(DB_PATH) as db:
        db.execute(
            "CREATE TABLE IF NOT EXISTS users "
            "(id INTEGER PRIMARY KEY, "
            "username TEXT, "
            "email TEXT, "
            "department TEXT, "
            "password TEXT)"
        )

        db.execute(
            "CREATE TABLE IF NOT EXISTS accounts "
            "(username TEXT PRIMARY KEY, balance INTEGER)"
        )

        # Reset the synthetic training-lab data on startup.
        db.execute("DELETE FROM users")
        db.execute("DELETE FROM accounts")

        db.executemany(
            """
            INSERT INTO users (id, username, email, department, password)
            VALUES (?, ?, ?, ?, ?)
            """,
            [
                (u[0], u[1], u[2], u[3], "password")
                for u in USERS
            ],
        )

        db.executemany(
            """
            INSERT INTO accounts (username, balance)
            VALUES (?, ?)
            """,
            [
                (u[1], 1000)
                for u in USERS
            ],
        )

        db.commit()


def issue_weak_token(username: str) -> str:
    token = token_hex(2)
    session["username"] = username
    session["weak_token"] = token
    return token


@app.post("/login")
def login() -> Response:
    username = request.form.get("username", "")
    password = request.form.get("password", "")
    with sqlite3.connect(DB_PATH) as db:
        query = f"SELECT username FROM users WHERE username = '{username}' AND password = '{password}'"
        try:
            print("SQL QUERY:", query)
            row = db.execute(query).fetchone()
        except sqlite3.Error as exc:
            return Response(f"SQL error: {exc}", status=500, mimetype="text/plain")
    if row or (username == "admin" and password == "admin"):
        token = issue_weak_token(row[0] if row else "admin")
        return jsonify(authenticated=True, username=session["username"], token=token)
    return jsonify(authenticated=False), 401


@app.get("/search")
def search() -> Response:
    query = request.args.get("q", "")
    return Response(f"<html><body><h1>Search</h1><p>Results for: {query}</p></body></html>", mimetype="text/html")


@app.get("/user/<int:user_id>")
def user(user_id: int) -> Response:
    with sqlite3.connect(DB_PATH) as db:
        row = db.execute("SELECT id, username, email, department FROM users WHERE id = ?", (user_id,)).fetchone()
    if not row:
        return jsonify(error="not found"), 404
    return jsonify(id=row[0], username=row[1], email=row[2], department=row[3])


@app.get("/admin/debug")
def admin_debug() -> Response:
    try:
        raise RuntimeError("Synthetic debug failure for the local training lab")
    except Exception:
        body = "<html><body><h1>Debug Traceback</h1><pre>" + traceback.format_exc() + "</pre></body></html>"
        return Response(body, status=500, mimetype="text/html")


@app.get("/static/")
def static_listing() -> Response:
    static_dir = BASE_DIR / "static"
    static_dir.mkdir(exist_ok=True)
    (static_dir / "lab-notes.txt").write_text("Synthetic lab asset\n", encoding="utf-8")
    files = sorted(p.name for p in static_dir.iterdir() if p.is_file())
    return Response("<html><body><h1>Index of /static/</h1><ul>" + "".join(f'<li>{name}</li>' for name in files) + "</ul></body></html>", mimetype="text/html")


@app.post("/transfer")
def transfer() -> Response:
    username = request.form.get("username", "")
    amount = int(request.form.get("amount", "0"))
    if amount <= 0:
        return jsonify(error="amount must be positive"), 400
    with sqlite3.connect(DB_PATH) as db:
        row = db.execute("SELECT balance FROM accounts WHERE username = ?", (username,)).fetchone()
        if not row:
            return jsonify(error="unknown account"), 404
        new_balance = row[0] - amount
        db.execute("UPDATE accounts SET balance = ? WHERE username = ?", (new_balance, username))
        db.commit()
    return jsonify(success=True, username=username, amount=amount, balance=new_balance)


if __name__ == "__main__":
    init_db()
    app.run(host="127.0.0.1", port=5000, debug=False)
