"""Opens the database and makes the tables.

It uses the sqlite3 module that comes with Python, makes the tables on the first
run, and adds the four demo accounts.
"""

import sqlite3
from datetime import datetime, timezone

from app import config
from app import passwords

# demo accounts, public passwords, for local testing only
DEMO_USERS = [
    ("admin@example.com", "admin-demo-pass", "admin"),
    ("alice@example.com", "alice-demo-pass", "user"),
    ("bob@example.com", "bob-demo-pass", "user"),
    ("carol@example.com", "carol-demo-pass", "user"),
]

# times are UTC text like 2026-10-04T12:00:00, which sorts correctly
TIME_FORMAT = "%Y-%m-%dT%H:%M:%S"

# safe to run on every start, and later columns are made now
TABLES_SQL = """
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY,
    email TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'user',
    failed_attempts INTEGER NOT NULL DEFAULT 0,
    locked_until TEXT,
    totp_secret_encrypted TEXT,
    totp_last_step INTEGER
);

-- user_id is empty when the email did not match any user
CREATE TABLE IF NOT EXISTS login_history (
    id INTEGER PRIMARY KEY,
    user_id INTEGER REFERENCES users(id),
    time TEXT NOT NULL,
    ip TEXT,
    country TEXT,
    asn TEXT,
    browser TEXT,
    os TEXT,
    device TEXT,
    success INTEGER NOT NULL,
    risk_level TEXT,
    risk_reasons TEXT
);

-- Only the hash of a session token is stored, so a DB leak gives no live sessions
CREATE TABLE IF NOT EXISTS sessions (
    token_hash TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id),
    context_hash TEXT,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS passkeys (
    credential_id BLOB PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id),
    public_key BLOB NOT NULL,
    sign_count INTEGER NOT NULL DEFAULT 0
);

-- Each row stores the hash of the row before it, so editing old rows breaks the chain
CREATE TABLE IF NOT EXISTS audit_log (
    id INTEGER PRIMARY KEY,
    time TEXT NOT NULL,
    event TEXT NOT NULL,
    details TEXT,
    prev_hash TEXT NOT NULL,
    hash TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS blocked_ips (
    ip TEXT PRIMARY KEY,
    reason TEXT,
    time TEXT NOT NULL
);
"""


def get_connection() -> sqlite3.Connection:
    """Open the database so rows can be read by column name, like row["email"]."""
    # read every time, so tests can point it at their own file
    connection = sqlite3.connect(config.DB_PATH)
    connection.row_factory = sqlite3.Row
    # SQLite only checks the links between tables if this is on
    connection.execute("PRAGMA foreign_keys = ON")
    return connection


def utc_now() -> str:
    """Return the current UTC time as text like 2026-10-04T12:00:00."""
    return datetime.now(timezone.utc).strftime(TIME_FORMAT)


def create_tables() -> None:
    """Make every table the app needs. Safe to call more than once."""
    connection = get_connection()
    connection.executescript(TABLES_SQL)
    connection.commit()
    connection.close()


def seed_demo_users(pepper: str) -> None:
    """Add the demo accounts, but only if the users table is empty."""
    connection = get_connection()
    user_count = connection.execute("SELECT COUNT(*) FROM users").fetchone()[0]
    if user_count > 0:
        connection.close()
        return

    for email, password, role in DEMO_USERS:
        password_hash = passwords.hash_password(password, pepper)
        connection.execute(
            "INSERT INTO users (email, password_hash, role) VALUES (?, ?, ?)",
            (email, password_hash, role),
        )
    connection.commit()
    connection.close()


def get_user_by_email(email: str) -> sqlite3.Row | None:
    """Return the user with this email, or None if there is no such user."""
    connection = get_connection()
    user_row = connection.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()
    connection.close()
    return user_row


def get_user_by_id(user_id: int) -> sqlite3.Row | None:
    """Return the user with this id, or None if there is no such user."""
    connection = get_connection()
    user_row = connection.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    connection.close()
    return user_row


def has_passkey(user_id: int) -> bool:
    """Return True if the user has registered at least one passkey."""
    connection = get_connection()
    passkey_count = connection.execute(
        "SELECT COUNT(*) FROM passkeys WHERE user_id = ?", (user_id,)
    ).fetchone()[0]
    connection.close()
    return passkey_count > 0


def record_login_attempt(
    user_id: int | None,
    context: dict,
    success: bool,
    risk_level: str | None = None,
    risk_reasons: list | None = None,
) -> None:
    """Save one login attempt, good or bad, with where it came from and its risk."""
    reasons_text = None
    if risk_reasons is not None:
        reasons_text = "; ".join(risk_reasons)

    connection = get_connection()
    connection.execute(
        "INSERT INTO login_history "
        "(user_id, time, ip, country, asn, browser, os, device, success, risk_level, risk_reasons) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (
            user_id,
            utc_now(),
            context["ip"],
            context["country"],
            context["asn"],
            context["browser"],
            context["os"],
            context["device"],
            success,
            risk_level,
            reasons_text,
        ),
    )
    connection.commit()
    connection.close()
