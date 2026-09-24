"""
TASK 3 - SECURE CODE ASSESSMENT
--------------------------------
Secure demonstration Flask application.

This application demonstrates common secure coding practices:
- Environment-based secret management
- Parameterized SQL queries
- Password hashing using PBKDF2
- Input validation
- Safe subprocess execution
- Path traversal protection
- CSRF protection
- Security headers
- Debug mode disabled

For educational/internship purposes.
"""

import hashlib
import ipaddress
import os
import re
import secrets
import sqlite3
import subprocess
from pathlib import Path

from flask import (
    Flask,
    abort,
    flash,
    redirect,
    render_template_string,
    request,
    session,
    url_for,
)
from werkzeug.security import check_password_hash, generate_password_hash


# ============================================================
# APPLICATION CONFIGURATION
# ============================================================

app = Flask(__name__)

SECRET_KEY = os.environ.get("APP_SECRET_KEY")

if not SECRET_KEY:
    raise RuntimeError(
        "APP_SECRET_KEY environment variable is not set."
    )

app.config["SECRET_KEY"] = SECRET_KEY
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_SECURE"] = (
    os.environ.get("APP_ENV") == "production"
    or os.environ.get("FLASK_ENV") == "production"
)


BASE_DIR = Path(__file__).resolve().parent
DATABASE = BASE_DIR / "secure_users.db"
SAFE_FILES_DIR = BASE_DIR / "secure_files"

SAFE_FILES_DIR.mkdir(exist_ok=True)


# ============================================================
# HTML TEMPLATE
# ============================================================

BASE_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport"
          content="width=device-width, initial-scale=1.0">

    <title>{{ title }} - Task 3</title>

    <style>
        * {
            box-sizing: border-box;
        }

        body {
            margin: 0;
            font-family:
                -apple-system,
                BlinkMacSystemFont,
                "Segoe UI",
                sans-serif;
            background: #0f172a;
            color: #e2e8f0;
        }

        nav {
            background: #111827;
            padding: 18px 7%;
            border-bottom: 1px solid #334155;
        }

        nav a {
            color: #cbd5e1;
            text-decoration: none;
            margin-right: 22px;
            font-weight: 600;
        }

        nav a:hover {
            color: #38bdf8;
        }

        .container {
            width: 90%;
            max-width: 1100px;
            margin: 40px auto;
        }

        .hero {
            background: linear-gradient(
                135deg,
                #172554,
                #0f172a
            );
            border: 1px solid #334155;
            border-radius: 18px;
            padding: 40px;
            margin-bottom: 28px;
        }

        h1 {
            margin-top: 0;
            font-size: 42px;
        }

        h2 {
            color: #7dd3fc;
        }

        .subtitle {
            color: #94a3b8;
            font-size: 18px;
        }

        .grid {
            display: grid;
            grid-template-columns:
                repeat(auto-fit, minmax(220px, 1fr));
            gap: 18px;
        }

        .card {
            background: #1e293b;
            border: 1px solid #334155;
            border-radius: 15px;
            padding: 24px;
            transition: 0.2s;
        }

        .card:hover {
            transform: translateY(-3px);
            border-color: #38bdf8;
        }

        .card a {
            color: #7dd3fc;
            text-decoration: none;
            font-weight: bold;
        }

        .status {
            display: inline-block;
            background: #064e3b;
            color: #6ee7b7;
            padding: 8px 13px;
            border-radius: 999px;
            font-size: 13px;
            font-weight: bold;
        }

        form {
            background: #1e293b;
            border: 1px solid #334155;
            border-radius: 15px;
            padding: 28px;
            max-width: 650px;
        }

        label {
            display: block;
            margin: 15px 0 7px;
            font-weight: 600;
        }

        input {
            width: 100%;
            padding: 13px;
            border-radius: 9px;
            border: 1px solid #475569;
            background: #0f172a;
            color: white;
            font-size: 16px;
        }

        button {
            margin-top: 20px;
            padding: 12px 22px;
            border: none;
            border-radius: 9px;
            background: #0284c7;
            color: white;
            font-weight: bold;
            cursor: pointer;
        }

        button:hover {
            background: #0369a1;
        }

        .result {
            margin-top: 25px;
            background: #020617;
            border: 1px solid #334155;
            border-radius: 12px;
            padding: 20px;
            word-break: break-word;
        }

        .flash {
            background: #7f1d1d;
            border: 1px solid #ef4444;
            padding: 12px;
            border-radius: 9px;
            margin-bottom: 20px;
        }

        .success {
            background: #064e3b;
            border-color: #10b981;
        }

        footer {
            text-align: center;
            color: #64748b;
            padding: 40px;
        }

        code {
            background: #020617;
            padding: 3px 7px;
            border-radius: 5px;
        }
    </style>
</head>

<body>

<nav>
    <a href="{{ url_for('home') }}">Security Dashboard</a>
    <a href="{{ url_for('login') }}">Login</a>
    <a href="{{ url_for('hash_password') }}">Password Hashing</a>
    <a href="{{ url_for('ping') }}">Network Ping</a>
    <a href="{{ url_for('read_file') }}">Secure File Access</a>
</nav>

<div class="container">

    {% with messages = get_flashed_messages() %}
        {% if messages %}
            {% for message in messages %}
                <div class="flash">
                    {{ message }}
                </div>
            {% endfor %}
        {% endif %}
    {% endwith %}

    {{ content|safe }}

</div>

<footer>
    Task 3 — Secure Code Assessment<br>
    Educational security demonstration
</footer>

</body>
</html>
"""


# ============================================================
# DATABASE
# ============================================================

def get_connection():
    connection = sqlite3.connect(DATABASE)
    connection.row_factory = sqlite3.Row
    return connection


def initialize_database():
    connection = get_connection()

    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL
        )
        """
    )

    existing_user = connection.execute(
        "SELECT id FROM users WHERE username = ?",
        ("admin",)
    ).fetchone()

    if existing_user is None:
        password_hash = generate_password_hash(
            "admin123",
            method="pbkdf2:sha256",
            salt_length=16
        )

        connection.execute(
            """
            INSERT INTO users (username, password_hash)
            VALUES (?, ?)
            """,
            ("admin", password_hash)
        )

    connection.commit()
    connection.close()


initialize_database()


# ============================================================
# CSRF PROTECTION
# ============================================================

def get_csrf_token():
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_urlsafe(32)

    return session["csrf_token"]


def validate_csrf():
    submitted_token = request.form.get("csrf_token", "")
    session_token = session.get("csrf_token", "")

    if not submitted_token or not secrets.compare_digest(
        submitted_token,
        session_token
    ):
        abort(400, description="Invalid CSRF token.")


# ============================================================
# SECURITY HEADERS
# ============================================================

@app.after_request
def add_security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers[
        "Content-Security-Policy"
    ] = (
        "default-src 'self'; "
        "style-src 'unsafe-inline'"
    )

    return response


# ============================================================
# HOME DASHBOARD
# ============================================================

@app.route("/")
def home():

    content = """
    <section class="hero">

        <span class="status">
            SECURE APPLICATION
        </span>

        <h1>Secure Code Assessment</h1>

        <p class="subtitle">
            Task 3 — Secure coding demonstration
            and vulnerability remediation.
        </p>

        <p>
            This application demonstrates how common
            vulnerabilities identified during a security
            review can be mitigated using secure coding
            practices.
        </p>

    </section>

    <h2>Security Testing Modules</h2>

    <div class="grid">

        <div class="card">
            <h3>🔐 Authentication</h3>
            <p>
                Parameterized SQL queries and secure
                password verification.
            </p>
            <a href="/login">Test Login →</a>
        </div>

        <div class="card">
            <h3>🔑 Password Hashing</h3>
            <p>
                Password-specific PBKDF2 hashing instead
                of plain SHA-256.
            </p>
            <a href="/hash">Test Hashing →</a>
        </div>

        <div class="card">
            <h3>🌐 Network Input</h3>
            <p>
                Host validation and subprocess execution
                without shell injection.
            </p>
            <a href="/ping">Test Ping →</a>
        </div>

        <div class="card">
            <h3>📁 File Security</h3>
            <p>
                File access restricted to an approved
                directory.
            </p>
            <a href="/read">Test File Access →</a>
        </div>

    </div>

    <h2>Security Controls</h2>

    <div class="card">

        <ul>
            <li>Environment-based application secret</li>
            <li>Parameterized SQL queries</li>
            <li>PBKDF2 password hashing</li>
            <li>Input validation</li>
            <li>Safe subprocess execution</li>
            <li>Path traversal protection</li>
            <li>CSRF protection</li>
            <li>Security response headers</li>
            <li>HTTP-only session cookies</li>
            <li>Debug mode disabled</li>
        </ul>

    </div>
    """

    return render_template_string(
        BASE_TEMPLATE,
        title="Dashboard",
        content=content
    )


# ============================================================
# LOGIN
# ============================================================

@app.route("/login", methods=["GET", "POST"])
def login():

    result_message = ""

    if request.method == "POST":

        validate_csrf()

        username = request.form.get(
            "username",
            ""
        ).strip()

        password = request.form.get(
            "password",
            ""
        )

        if not re.fullmatch(
            r"[A-Za-z0-9_.-]{3,32}",
            username
        ):
            flash(
                "Invalid username format."
            )

            return redirect(url_for("login"))

        connection = get_connection()

        user = connection.execute(
            """
            SELECT username, password_hash
            FROM users
            WHERE username = ?
            """,
            (username,)
        ).fetchone()

        connection.close()

        if user and check_password_hash(
            user["password_hash"],
            password
        ):
            session["authenticated_user"] = username

            result_message = (
                "<div class='result'>"
                "<strong>Login successful.</strong>"
                "<br><br>"
                "Credentials were verified using "
                "a parameterized SQL query and a "
                "secure password hash."
                "</div>"
            )
        else:
            result_message = (
                "<div class='result'>"
                "<strong>Invalid credentials.</strong>"
                "</div>"
            )

    content = f"""
    <h1>🔐 Secure Login</h1>

    <p class="subtitle">
        Authentication protected against SQL injection
        and plaintext password storage.
    </p>

    <form method="POST">

        <input
            type="hidden"
            name="csrf_token"
            value="{get_csrf_token()}"
        >

        <label>Username</label>

        <input
            type="text"
            name="username"
            placeholder="Enter username"
            maxlength="32"
            required
        >

        <label>Password</label>

        <input
            type="password"
            name="password"
            placeholder="Enter password"
            required
        >

        <button type="submit">
            Authenticate
        </button>

    </form>

    {result_message}

    <div class="card" style="margin-top:25px;">
        <strong>Demo account</strong><br><br>
        Username: <code>admin</code><br>
        Password: <code>admin123</code>
    </div>
    """

    return render_template_string(
        BASE_TEMPLATE,
        title="Login",
        content=content
    )


# ============================================================
# PASSWORD HASHING
# ============================================================

@app.route("/hash", methods=["GET", "POST"])
def hash_password():

    result = ""

    if request.method == "POST":

        validate_csrf()

        password = request.form.get(
            "password",
            ""
        )

        if len(password) < 8:
            flash(
                "Password must contain at least 8 characters."
            )

            return redirect(url_for("hash_password"))

        password_hash = generate_password_hash(
            password,
            method="pbkdf2:sha256",
            salt_length=16
        )

        result = f"""
        <div class="result">

            <strong>Generated secure password hash:</strong>

            <p>
                <code>{password_hash}</code>
            </p>

            <p>
                The password is not stored in plaintext.
                A unique salt is automatically used.
            </p>

        </div>
        """

    content = f"""
    <h1>🔑 Secure Password Hashing</h1>

    <p class="subtitle">
        Demonstrates password-specific hashing using PBKDF2.
    </p>

    <form method="POST">

        <input
            type="hidden"
            name="csrf_token"
            value="{get_csrf_token()}"
        >

        <label>Password</label>

        <input
            type="password"
            name="password"
            minlength="8"
            placeholder="Enter a test password"
            required
        >

        <button type="submit">
            Generate Secure Hash
        </button>

    </form>

    {result}
    """

    return render_template_string(
        BASE_TEMPLATE,
        title="Password Hashing",
        content=content
    )


# ============================================================
# SAFE PING
# ============================================================

def validate_host(host):

    host = host.strip()

    if not host or len(host) > 253:
        return False

    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        pass

    hostname_pattern = re.compile(
        r"^(?=.{1,253}$)"
        r"(?:[A-Za-z0-9]"
        r"(?:[A-Za-z0-9-]{0,61}"
        r"[A-Za-z0-9])?\.)*"
        r"[A-Za-z0-9]"
        r"(?:[A-Za-z0-9-]{0,61}"
        r"[A-Za-z0-9])?$"
    )

    return bool(hostname_pattern.fullmatch(host))


@app.route("/ping", methods=["GET", "POST"])
def ping():

    result = ""

    if request.method == "POST":

        validate_csrf()

        host = request.form.get(
            "host",
            ""
        ).strip()

        if not validate_host(host):
            flash(
                "Invalid host. Enter a valid IP address "
                "or hostname."
            )

            return redirect(url_for("ping"))

        try:
            completed = subprocess.run(
                [
                    "ping",
                    "-c",
                    "1",
                    "-W",
                    "2000",
                    host
                ],
                capture_output=True,
                text=True,
                timeout=5,
                check=False
            )

            output = (
                completed.stdout
                if completed.stdout
                else completed.stderr
            )

            result = f"""
            <div class="result">

                <strong>Ping result for {host}</strong>

                <pre>{output}</pre>

            </div>
            """

        except subprocess.TimeoutExpired:

            result = """
            <div class="result">
                Ping request timed out.
            </div>
            """

        except OSError:

            result = """
            <div class="result">
                Ping command could not be executed.
            </div>
            """

    content = f"""
    <h1>🌐 Secure Network Ping</h1>

    <p class="subtitle">
        Host input is validated and passed as an argument
        without shell command execution.
    </p>

    <form method="POST">

        <input
            type="hidden"
            name="csrf_token"
            value="{get_csrf_token()}"
        >

        <label>Host</label>

        <input
            type="text"
            name="host"
            placeholder="127.0.0.1"
            maxlength="253"
            required
        >

        <button type="submit">
            Ping Host
        </button>

    </form>

    {result}
    """

    return render_template_string(
        BASE_TEMPLATE,
        title="Network Ping",
        content=content
    )


# ============================================================
# SECURE FILE ACCESS
# ============================================================

@app.route("/read", methods=["GET", "POST"])
def read_file():

    result = ""

    if request.method == "POST":

        validate_csrf()

        filename = request.form.get(
            "file",
            ""
        ).strip()

        if not re.fullmatch(
            r"[A-Za-z0-9_.-]{1,100}",
            filename
        ):
            flash(
                "Invalid filename. Only simple filenames "
                "are permitted."
            )

            return redirect(url_for("read_file"))

        requested_file = (
            SAFE_FILES_DIR / filename
        ).resolve()

        safe_directory = SAFE_FILES_DIR.resolve()

        try:
            requested_file.relative_to(
                safe_directory
            )
        except ValueError:
            abort(
                403,
                description="File access outside the approved directory is prohibited."
            )

        if not requested_file.is_file():
            result = """
            <div class="result">
                File not found.
            </div>
            """
        else:
            try:
                file_contents = requested_file.read_text(
                    encoding="utf-8"
                )

                result = f"""
                <div class="result">

                    <strong>File contents:</strong>

                    <pre>{file_contents}</pre>

                </div>
                """

            except OSError:
                result = """
                <div class="result">
                    Unable to read the requested file.
                </div>
                """

    content = f"""
    <h1>📁 Secure File Access</h1>

    <p class="subtitle">
        File access is restricted to the application's
        approved secure_files directory.
    </p>

    <form method="POST">

        <input
            type="hidden"
            name="csrf_token"
            value="{get_csrf_token()}"
        >

        <label>Filename</label>

        <input
            type="text"
            name="file"
            placeholder="example.txt"
            maxlength="100"
            required
        >

        <button type="submit">
            Read File
        </button>

    </form>

    {result}
    """

    return render_template_string(
        BASE_TEMPLATE,
        title="Secure File Access",
        content=content
    )


# ============================================================
# ERROR HANDLERS
# ============================================================

@app.errorhandler(400)
def bad_request(error):

    content = f"""
    <h1>400 — Bad Request</h1>

    <div class="result">
        {error.description}
    </div>

    <br>

    <a href="/">
        Return to dashboard
    </a>
    """

    return render_template_string(
        BASE_TEMPLATE,
        title="Bad Request",
        content=content
    ), 400


@app.errorhandler(403)
def forbidden(error):

    content = f"""
    <h1>403 — Access Denied</h1>

    <div class="result">
        {error.description}
    </div>

    <br>

    <a href="/">
        Return to dashboard
    </a>
    """

    return render_template_string(
        BASE_TEMPLATE,
        title="Access Denied",
        content=content
    ), 403


@app.errorhandler(404)
def not_found(error):

    content = """
    <h1>404 — Page Not Found</h1>

    <div class="result">
        The requested resource does not exist.
    </div>

    <br>

    <a href="/">
        Return to dashboard
    </a>
    """

    return render_template_string(
        BASE_TEMPLATE,
        title="Not Found",
        content=content
    ), 404


# ============================================================
# APPLICATION START
# ============================================================

if __name__ == "__main__":
    app.run(
        host="127.0.0.1",
        port=5001,
        debug=False
    )