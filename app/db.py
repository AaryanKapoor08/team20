"""Database connection and table setup, using Python's built-in sqlite3."""

import sqlite3
from datetime import datetime, timezone
from pathlib import Path

from app import config
from app import passwords

# Demo accounts for trying the app. These passwords are public (listed in the README),
# so they are only for local testing.
DEMO_USERS = [
    ("admin@example.com", "admin-demo-pass", "admin"),
    ("alice@example.com", "alice-demo-pass", "user"),
    ("bob@example.com", "bob-demo-pass", "user"),
    ("carol@example.com", "carol-demo-pass", "user"),
]

# Every time is stored as UTC text like 2026-10-04T12:00:00.
# Text in this format sorts and compares in the right order.
TIME_FORMAT = "%Y-%m-%dT%H:%M:%S"

# IF NOT EXISTS makes this safe to run on every start.
# Columns used by later phases are made now, so nobody has to rebuild the database.
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


def get_connection(db_path: Path = config.DB_PATH) -> sqlite3.Connection:
    """Open the database so rows can be read by column name, like row["email"]."""
    connection = sqlite3.connect(db_path)
    connection.row_factory = sqlite3.Row
    # SQLite skips REFERENCES checks unless this is turned on for each connection
    connection.execute("PRAGMA foreign_keys = ON")
    return connection


def utc_now() -> str:
    """Return the current UTC time as text like 2026-10-04T12:00:00."""
    return datetime.now(timezone.utc).strftime(TIME_FORMAT)


def create_tables(db_path: Path = config.DB_PATH) -> None:
    """Make every table the app needs. Safe to call more than once."""
    connection = get_connection(db_path)
    connection.executescript(TABLES_SQL)
    connection.commit()
    connection.close()


def seed_demo_users(pepper: str, db_path: Path = config.DB_PATH) -> None:
    """Add the demo accounts, but only if the users table is empty."""
    connection = get_connection(db_path)
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
