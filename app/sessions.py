"""Login sessions: a random token in the browser, only its hash in the database."""

import hashlib
import secrets
import sqlite3
from datetime import datetime, timedelta, timezone

from app import db

SESSION_LIFETIME = timedelta(hours=8)


def hash_token(token: str) -> str:
    """Return the SHA-256 hash of a session token."""
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def create_session(user_id: int) -> str:
    """Make a new session for the user and return its token for the cookie."""
    # secrets gives a token nobody can guess; 32 bytes is far too many to brute force
    token = secrets.token_urlsafe(32)
    now = datetime.now(timezone.utc)
    created_at = now.strftime(db.TIME_FORMAT)
    expires_at = (now + SESSION_LIFETIME).strftime(db.TIME_FORMAT)

    # Only the hash is saved, so a leaked database gives no working session cookies
    connection = db.get_connection()
    connection.execute(
        "INSERT INTO sessions (token_hash, user_id, created_at, expires_at) VALUES (?, ?, ?, ?)",
        (hash_token(token), user_id, created_at, expires_at),
    )
    connection.commit()
    connection.close()
    return token


def get_user_for_token(token: str) -> sqlite3.Row | None:
    """Return the logged in user for this token, or None if it is unknown or expired."""
    if token == "":
        return None
    connection = db.get_connection()
    user_row = connection.execute(
        "SELECT users.* FROM sessions JOIN users ON users.id = sessions.user_id "
        "WHERE sessions.token_hash = ? AND sessions.expires_at > ?",
        (hash_token(token), db.utc_now()),
    ).fetchone()
    connection.close()
    return user_row


def delete_session(token: str) -> None:
    """Remove the session, so its token stops working."""
    connection = db.get_connection()
    connection.execute("DELETE FROM sessions WHERE token_hash = ?", (hash_token(token),))
    connection.commit()
    connection.close()
