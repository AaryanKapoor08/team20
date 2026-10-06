"""Login sessions: a random token in the browser, only its hash in the database."""

import hashlib
import secrets
import sqlite3
from datetime import datetime, timedelta, timezone

import flask

from app import config
from app import db

SESSION_LIFETIME = timedelta(hours=8)
SESSION_COOKIE = "session_token"


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


def current_user() -> sqlite3.Row | None:
    """Return the logged in user for this request, or None."""
    token = flask.request.cookies.get(SESSION_COOKIE, "")
    return get_user_for_token(token)


def log_in(user_id: int) -> flask.Response:
    """Make a session for the user, set its cookie and go to the home page."""
    clear_pending()
    token = create_session(user_id)
    response = flask.redirect(flask.url_for("home"))
    # HttpOnly: page scripts cannot read the cookie. Lax: other sites' forms do not send it.
    # secure=False because the app runs on plain http://localhost
    max_age = int(SESSION_LIFETIME.total_seconds())
    response.set_cookie(SESSION_COOKIE, token, max_age=max_age, httponly=True, samesite="Lax")
    return response


def delete_session(token: str) -> None:
    """Remove the session, so its token stops working."""
    connection = db.get_connection()
    connection.execute("DELETE FROM sessions WHERE token_hash = ?", (hash_token(token),))
    connection.commit()
    connection.close()


def start_pending(user_id: int, step: str) -> None:
    """Remember a login that passed the password but still needs an extra check."""
    # Kept in Flask's signed cookie, so the browser cannot change the user id or the step.
    # This is not a session: protected pages only look at the session_token cookie.
    expires = datetime.now(timezone.utc) + timedelta(minutes=config.PENDING_MINUTES)
    flask.session["pending_user_id"] = user_id
    flask.session["pending_step"] = step
    flask.session["pending_expires"] = expires.strftime(db.TIME_FORMAT)


def get_pending_user_id(step: str) -> int | None:
    """Return the half logged in user's id, if the marker is for this step and not expired."""
    # The step must match, so a login sent to the passkey check cannot pick the easier code check
    if flask.session.get("pending_step") != step:
        return None
    if flask.session.get("pending_expires", "") < db.utc_now():
        clear_pending()
        return None
    return flask.session.get("pending_user_id")


def clear_pending() -> None:
    """Forget the half logged in marker."""
    flask.session.pop("pending_user_id", None)
    flask.session.pop("pending_step", None)
    flask.session.pop("pending_expires", None)
