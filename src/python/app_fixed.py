"""
Hardened Flask application — all SAST findings from app.py fixed.
This is the version that should actually be deployed.

Fixes applied:
  1. SQL Injection       → parameterised query with ?  placeholder
  2. Command Injection   → subprocess with list args, no shell=True
  3. Path Traversal      → os.path.basename() + safe directory join
  4. Hardcoded Secret    → credentials loaded from environment variables
  5. Debug Mode          → driven by DEBUG env var, defaults to False
"""

import os
import sqlite3
import subprocess

from flask import Flask, request, abort

app = Flask(__name__)

# -----------------------------------------------------------------------
# FIX 1: Credentials from environment variables, never hardcoded
# -----------------------------------------------------------------------
DB_PASSWORD = os.environ.get("DB_PASSWORD")
API_KEY     = os.environ.get("API_KEY")

SAFE_FILE_DIR = "/app/safe_files"   # files may only be served from here


def get_db():
    conn = sqlite3.connect("users.db")
    conn.execute(
        "CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT, email TEXT)"
    )
    return conn


# -----------------------------------------------------------------------
# FIX 2: Parameterised query — SQL injection not possible
# -----------------------------------------------------------------------
@app.route("/user")
def get_user():
    username = request.args.get("username", "")
    conn = get_db()
    cursor = conn.execute(
        "SELECT * FROM users WHERE username = ?", (username,)   # safe
    )
    rows = cursor.fetchall()
    return {"users": rows}


# -----------------------------------------------------------------------
# FIX 3: subprocess with list args — command injection not possible
# -----------------------------------------------------------------------
@app.route("/ping")
def ping():
    host = request.args.get("host", "localhost")
    result = subprocess.run(
        ["ping", "-c", "1", host],    # list form — no shell interpolation
        capture_output=True,
        text=True,
        timeout=5,
    )
    return {"status": "pinged", "host": host, "output": result.stdout}


# -----------------------------------------------------------------------
# FIX 4: Path traversal prevented — strip directory components, then
#         join against a fixed safe directory
# -----------------------------------------------------------------------
@app.route("/file")
def read_file():
    filename = request.args.get("filename", "")
    safe_name = os.path.basename(filename)                        # strip ../
    safe_path = os.path.join(SAFE_FILE_DIR, safe_name)
    if not safe_path.startswith(SAFE_FILE_DIR):                   # double-check
        abort(400)
    with open(safe_path, "r") as f:
        content = f.read()
    return {"content": content}


# -----------------------------------------------------------------------
# FIX 5: Debug driven by env var, defaults to False
# -----------------------------------------------------------------------
if __name__ == "__main__":
    debug = os.environ.get("FLASK_DEBUG", "false").lower() == "true"
    app.run(host="0.0.0.0", port=5000, debug=debug)
