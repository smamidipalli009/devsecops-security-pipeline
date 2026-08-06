"""
Vulnerable Flask application — intentional security flaws for SAST demo.
DO NOT deploy to production.

Vulnerabilities present (CodeQL will detect these):
  1. SQL Injection       — user input passed directly into SQL query
  2. Command Injection   — user input passed directly to os.system()
  3. Path Traversal      — user-controlled filename used in file open()
  4. Hardcoded Secret    — API key and DB password hardcoded in source
  5. Debug Mode Enabled  — Flask running with debug=True in production
"""

import os
import sqlite3

from flask import Flask, request

app = Flask(__name__)

# -----------------------------------------------------------------------
# VULNERABILITY 1: Hardcoded credentials
# CodeQL rule: py/hardcoded-credentials
# -----------------------------------------------------------------------
DB_PASSWORD = "supersecret123"       # hardcoded DB password
API_KEY     = "sk-prod-abc123xyz"    # hardcoded API key


def get_db():
    """Return a connection to the local SQLite database."""
    conn = sqlite3.connect("users.db")
    conn.execute(
        "CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT, email TEXT)"
    )
    return conn


# -----------------------------------------------------------------------
# VULNERABILITY 2: SQL Injection
# CodeQL rule: py/sql-injection
# Fix: use parameterised queries → cursor.execute("SELECT * FROM users WHERE username=?", (username,))
# -----------------------------------------------------------------------
@app.route("/user")
def get_user():
    username = request.args.get("username", "")
    conn = get_db()
    # BAD: f-string interpolation directly into SQL
    query = f"SELECT * FROM users WHERE username = '{username}'"
    cursor = conn.execute(query)
    rows = cursor.fetchall()
    return {"users": rows}


# -----------------------------------------------------------------------
# VULNERABILITY 3: Command Injection
# CodeQL rule: py/command-injection
# Fix: never pass user input to shell; use subprocess with a list of args
# -----------------------------------------------------------------------
@app.route("/ping")
def ping():
    host = request.args.get("host", "localhost")
    # BAD: user-controlled input passed directly to os.system()
    os.system(f"ping -c 1 {host}")
    return {"status": "pinged", "host": host}


# -----------------------------------------------------------------------
# VULNERABILITY 4: Path Traversal
# CodeQL rule: py/path-injection
# Fix: use os.path.basename() to strip directory components, then join
#      against a fixed safe directory
# -----------------------------------------------------------------------
@app.route("/file")
def read_file():
    filename = request.args.get("filename", "")
    # BAD: user can supply ../../etc/passwd
    with open(filename, "r") as f:
        content = f.read()
    return {"content": content}


# -----------------------------------------------------------------------
# VULNERABILITY 5: Debug mode enabled
# CodeQL rule: py/flask-debug
# Fix: set debug=False (or better, drive it from an env var)
# -----------------------------------------------------------------------
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)   # BAD: debug=True in prod
