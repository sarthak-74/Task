"""
Vulnerable Demo Application
---------------------------

This application intentionally contains common security
weaknesses for educational security assessment purposes.

DO NOT deploy this application to a public or production
environment.
"""

import hashlib
import os
import sqlite3
import subprocess

from flask import Flask, request


app = Flask(__name__)

# VULNERABILITY:
# Hardcoded application secret.
SECRET_KEY = "internship-secret-123"


DATABASE = "users.db"


# ============================================================
# DATABASE
# ============================================================

def get_connection():
    return sqlite3.connect(DATABASE)


def initialize_database():

    connection = get_connection()

    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE,
            password TEXT
        )
        """
    )

    connection.commit()

    # VULNERABILITY:
    # Hardcoded credentials and plaintext password.
    connection.execute(
        """
        INSERT OR IGNORE INTO users
        (username, password)
        VALUES ('admin', 'admin123')
        """
    )

    connection.commit()
    connection.close()


initialize_database()


# ============================================================
# LOGIN
# ============================================================

@app.route("/login")
def login():

    username = request.args.get(
        "username",
        ""
    )

    password = request.args.get(
        "password",
        ""
    )

    connection = get_connection()

    # VULNERABILITY:
    # SQL Injection caused by string concatenation.
    query = (
        "SELECT * FROM users "
        "WHERE username = '"
        + username
        + "' AND password = '"
        + password
        + "'"
    )

    result = connection.execute(
        query
    ).fetchone()

    connection.close()

    if result:
        return "Login successful"

    return "Invalid credentials"


# ============================================================
# PASSWORD HASHING
# ============================================================

@app.route("/hash")
def hash_password():

    password = request.args.get(
        "password",
        ""
    )

    # VULNERABILITY:
    # SHA-256 is not suitable for password storage.
    # Password-specific hashing should be used.
    password_hash = hashlib.sha256(
        password.encode()
    ).hexdigest()

    return password_hash


# ============================================================
# COMMAND EXECUTION
# ============================================================

@app.route("/ping")
def ping():

    host = request.args.get(
        "host",
        "127.0.0.1"
    )

    # VULNERABILITY:
    # User-controlled input is passed into
    # a shell command.
    command = "ping -c 1 " + host

    result = subprocess.check_output(
        command,
        shell=True,
        text=True
    )

    return result


# ============================================================
# FILE ACCESS
# ============================================================

@app.route("/read")
def read_file():

    filename = request.args.get(
        "file",
        "example.txt"
    )

    # VULNERABILITY:
    # User-controlled file path is used directly.
    with open(
        filename,
        "r"
    ) as file:

        return file.read()


# ============================================================
# APPLICATION START
# ============================================================

if __name__ == "__main__":

    # VULNERABILITY:
    # Debug mode should not be enabled in production.
    app.run(
        debug=True
    )