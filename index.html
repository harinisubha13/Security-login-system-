"""
Simple Secure Login System — single-file Flask + HTML version
----------------------------------------------------------------
Run with:  python login_system_app.py
Then open: http://127.0.0.1:5000

Everything (Python backend, HTML, CSS) lives in this one file.

Security measures used:
- Passwords hashed with werkzeug's generate_password_hash (scrypt by
  default, salted automatically) — never stored or logged in plain text.
- Session cookies are HttpOnly and SameSite=Lax, so they can't be read
  by JavaScript and aren't sent on cross-site requests.
- Login attempts are rate-limited per username to slow brute force.
- Generic error messages (no "username exists but password wrong" hints).
"""

import json
import os
import secrets
import time
from functools import wraps

from flask import Flask, render_template_string, request, redirect, url_for, session, flash
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)

# In production, set this via an environment variable so it stays stable
# across restarts (a changing key logs everyone out each time the app starts).
app.secret_key = os.environ.get("SECRET_KEY", secrets.token_hex(32))

app.config.update(
    SESSION_COOKIE_HTTPONLY=True,   # JS can't read the session cookie
    SESSION_COOKIE_SAMESITE="Lax",  # mitigates CSRF on cookie use
    # SESSION_COOKIE_SECURE=True,   # enable once served over HTTPS
)

USER_DB_FILE = "users.json"
MAX_ATTEMPTS = 5          # failed logins allowed
LOCKOUT_SECONDS = 60      # lockout duration after hitting the limit

_failed_attempts = {}  # username -> {"count": int, "locked_until": timestamp}


# ----------------------------------------------------------------------------
# Templates (normally separate .html files — inlined here so it's one file)
# ----------------------------------------------------------------------------

BASE_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>{{ title }}</title>
  <style>
    :root {
      --ink: #0e1420; --panel: #161d2c; --line: #2a3346;
      --text: #e7ebf3; --text-dim: #8b94a8;
      --accent: #5fe3b3; --danger: #ff8b8b;
    }
    * { box-sizing: border-box; }
    body {
      margin: 0; min-height: 100vh; background: var(--ink); color: var(--text);
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
      display: flex; align-items: center; justify-content: center; padding: 24px;
    }
    .page { width: 100%; max-width: 380px; display: flex; flex-direction: column; align-items: center; gap: 16px; }
    .card { width: 100%; background: var(--panel); border: 1px solid var(--line); border-radius: 14px; padding: 32px 28px; }
    .card__mark { font-family: "SFMono-Regular", Consolas, Menlo, monospace; color: var(--accent); font-size: 20px; letter-spacing: 2px; margin-bottom: 18px; }
    .mark__dot { display: inline-block; width: 7px; height: 7px; border-radius: 50%; background: var(--accent); margin: 0 4px; vertical-align: middle; box-shadow: 0 0 8px var(--accent); }
    h1 { font-size: 22px; margin: 0 0 4px; }
    .card__sub { color: var(--text-dim); font-size: 14px; margin: 0 0 22px; }
    form { display: flex; flex-direction: column; gap: 6px; }
    label { font-size: 12px; text-transform: uppercase; letter-spacing: 0.06em; color: var(--text-dim); margin-top: 12px; }
    input { background: var(--ink); border: 1px solid var(--line); border-radius: 8px; padding: 11px 12px; color: var(--text); font-size: 15px; outline: none; transition: border-color 0.15s ease; }
    input:focus { border-color: var(--accent); }
    button, .button { margin-top: 22px; padding: 12px; border-radius: 8px; border: none; background: var(--accent); color: #07150f; font-size: 15px; font-weight: 600; cursor: pointer; text-align: center; text-decoration: none; display: inline-block; }
    button:hover, .button:hover { filter: brightness(1.08); }
    .button--secondary { background: transparent; border: 1px solid var(--line); color: var(--text); }
    .card__link { margin: 18px 0 0; font-size: 14px; color: var(--text-dim); text-align: center; }
    .card__link a { color: var(--accent); text-decoration: none; }
    .flash { list-style: none; padding: 0; margin: 0 0 18px; display: flex; flex-direction: column; gap: 6px; }
    .flash li { background: rgba(255, 139, 139, 0.1); border: 1px solid rgba(255, 139, 139, 0.3); color: var(--danger); font-size: 13px; padding: 9px 12px; border-radius: 8px; }
    .page__footnote { color: var(--text-dim); font-size: 12px; text-align: center; margin: 0; }
  </style>
</head>
<body>
  <div class="page">
    <div class="card">
      <div class="card__mark" aria-hidden="true">
        <span>[</span><span class="mark__dot"></span><span>]</span>
      </div>
      {% with messages = get_flashed_messages() %}
        {% if messages %}
          <ul class="flash">
            {% for message in messages %}<li>{{ message }}</li>{% endfor %}
          </ul>
        {% endif %}
      {% endwith %}
      {{ content|safe }}
    </div>
    <p class="page__footnote">Passwords are hashed and salted (scrypt) and never stored in plain text.</p>
  </div>
</body>
</html>
"""

LOGIN_CONTENT = """
<h1>Log in</h1>
<p class="card__sub">Access your account.</p>
<form method="POST" action="{{ url_for('login') }}" autocomplete="off">
  <label for="username">Username</label>
  <input type="text" id="username" name="username" required autofocus>
  <label for="password">Password</label>
  <input type="password" id="password" name="password" required>
  <button type="submit">Log in</button>
</form>
<p class="card__link">No account? <a href="{{ url_for('register') }}">Register</a></p>
"""

REGISTER_CONTENT = """
<h1>Create an account</h1>
<p class="card__sub">Use a password with at least 8 characters.</p>
<form method="POST" action="{{ url_for('register') }}" autocomplete="off">
  <label for="username">Username</label>
  <input type="text" id="username" name="username" required autofocus>
  <label for="password">Password</label>
  <input type="password" id="password" name="password" required>
  <label for="confirm">Confirm password</label>
  <input type="password" id="confirm" name="confirm" required>
  <button type="submit">Register</button>
</form>
<p class="card__link">Already have an account? <a href="{{ url_for('login') }}">Log in</a></p>
"""

DASHBOARD_CONTENT = """
<h1>Welcome, {{ username }}</h1>
<p class="card__sub">You're signed in. This page is only reachable with a valid session.</p>
<a class="button button--secondary" href="{{ url_for('logout') }}">Log out</a>
"""


def render(content_template, title, **context):
    content = render_template_string(content_template, **context)
    return render_template_string(BASE_HTML, title=title, content=content)


# ----------------------------------------------------------------------------
# Storage helpers
# ----------------------------------------------------------------------------

def _load_users():
    if not os.path.exists(USER_DB_FILE):
        return {}
    with open(USER_DB_FILE, "r") as f:
        return json.load(f)


def _save_users(users):
    with open(USER_DB_FILE, "w") as f:
        json.dump(users, f, indent=2)


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if "username" not in session:
            return redirect(url_for("login"))
        return view(*args, **kwargs)
    return wrapped


def _is_locked_out(username):
    record = _failed_attempts.get(username)
    if record and record["count"] >= MAX_ATTEMPTS:
        if time.time() < record["locked_until"]:
            return True
        _failed_attempts.pop(username, None)  # lockout expired, reset
    return False


def _record_failed_attempt(username):
    record = _failed_attempts.setdefault(username, {"count": 0, "locked_until": 0})
    record["count"] += 1
    if record["count"] >= MAX_ATTEMPTS:
        record["locked_until"] = time.time() + LOCKOUT_SECONDS


# ----------------------------------------------------------------------------
# Routes
# ----------------------------------------------------------------------------

@app.route("/")
def index():
    if "username" in session:
        return redirect(url_for("dashboard"))
    return redirect(url_for("login"))


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        confirm = request.form.get("confirm", "")

        if len(username) < 3:
            flash("Username must be at least 3 characters.")
        elif len(password) < 8:
            flash("Password must be at least 8 characters.")
        elif password != confirm:
            flash("Passwords do not match.")
        else:
            users = _load_users()
            if username in users:
                flash("That username is taken.")
            else:
                users[username] = {"hash": generate_password_hash(password)}
                _save_users(users)
                flash("Account created. You can log in now.")
                return redirect(url_for("login"))

    return render(REGISTER_CONTENT, "Register")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        if _is_locked_out(username):
            flash("Too many failed attempts. Try again in a minute.")
            return render(LOGIN_CONTENT, "Log in")

        users = _load_users()
        record = users.get(username)

        # Same generic message whether the username exists or not,
        # so an attacker can't use this to enumerate valid accounts.
        if record and check_password_hash(record["hash"], password):
            _failed_attempts.pop(username, None)
            session.clear()
            session["username"] = username
            return redirect(url_for("dashboard"))
        else:
            _record_failed_attempt(username)
            flash("Invalid username or password.")

    return render(LOGIN_CONTENT, "Log in")


@app.route("/dashboard")
@login_required
def dashboard():
    return render(DASHBOARD_CONTENT, "Dashboard", username=session["username"])


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


if __name__ == "__main__":
    # debug=True is for local development only — turn off in production
    app.run(debug=True)
          
