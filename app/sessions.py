"""Keeps people logged in.

The browser gets a random token in a cookie and the database keeps only its hash,
so a leaked database hands nobody a working login.
"""

import hashlib
import hmac
import logging
import secrets
import sqlite3
from datetime import datetime, timedelta, timezone

import flask

from app import audit_log
from app import client_context
from app import config
from app import db

SESSION_LIFETIME = timedelta(hours=8)
SESSION_COOKIE = "session_token"

logger = logging.getLogger(__name__)


def hash_token(token: str) -> str:
    """Return the SHA-256 hash of a session token."""
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def ip_prefix(ip: str) -> str:
    """Return the network part of an IP: the first three numbers of an IPv4 address."""
    parts = ip.split(".")
    if len(parts) != 4:
        # not IPv4, so keep the whole address
        return ip
    return ".".join(parts[:3])


def context_hash(context: dict) -> str:
    """Return a SHA-256 fingerprint of the browser, OS and network of a request."""
    # only the first part of the IP, so a new address at home still matches
    text = f"{context['browser']}|{context['os']}|{ip_prefix(context['ip'])}"
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def create_session(user_id: int, context: dict) -> str:
    """Make a new session for the user and return its token for the cookie."""
    # secrets, not random: nobody can guess this token
    token = secrets.token_urlsafe(32)
    now = datetime.now(timezone.utc)
    created_at = now.strftime(db.TIME_FORMAT)
    expires_at = (now + SESSION_LIFETIME).strftime(db.TIME_FORMAT)

    # only the hash is saved, so a leaked database gives no working cookies
    connection = db.get_connection()
    connection.execute(
        "INSERT INTO sessions (token_hash, user_id, context_hash, created_at, expires_at) "
        "VALUES (?, ?, ?, ?, ?)",
        (hash_token(token), user_id, context_hash(context), created_at, expires_at),
    )
    connection.commit()
    connection.close()
    return token


def get_user_for_token(token: str, context: dict) -> sqlite3.Row | None:
    """Return the logged in user for this token, or None if it is unknown, expired or moved."""
    if token == "":
        return None
    connection = db.get_connection()
    session_row = connection.execute(
        "SELECT * FROM sessions WHERE token_hash = ? AND expires_at > ?",
        (hash_token(token), db.utc_now()),
    ).fetchone()
    connection.close()
    if session_row is None:
        return None

    # a cookie used from another machine is thrown away at once
    if config.SESSION_BINDING and not same_device(session_row, context):
        delete_session(token)
        logger.warning("Session ended: used from another device for user %s", session_row["user_id"])
        details = {
            "user_id": session_row["user_id"],
            "ip": context["ip"],
            "reason": "used from another device",
        }
        audit_log.add_event("session_ended", details)
        return None
    return db.get_user_by_id(session_row["user_id"])


def same_device(session_row: sqlite3.Row, context: dict) -> bool:
    """Return True if this request comes from the context the session was made on."""
    saved_hash = session_row["context_hash"] or ""
    # compare_digest: same speed for any wrong value, so timing gives nothing away
    return hmac.compare_digest(saved_hash, context_hash(context))


def current_user() -> sqlite3.Row | None:
    """Return the logged in user for this request, or None."""
    token = flask.request.cookies.get(SESSION_COOKIE, "")
    context = client_context.get_context(flask.request)
    return get_user_for_token(token, context)


def log_in(user_id: int) -> flask.Response:
    """Make a session for the user, set its cookie and go to the home page."""
    clear_pending()
    context = client_context.get_context(flask.request)
    token = create_session(user_id, context)
    audit_log.add_event("login_success", {"user_id": user_id, "ip": context["ip"]})
    response = flask.redirect(flask.url_for("home"))
    # HttpOnly: scripts cannot read it. Lax: other sites cannot send it.
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
    # kept in Flask's signed cookie, so the browser cannot change it
    expires = datetime.now(timezone.utc) + timedelta(minutes=config.PENDING_MINUTES)
    flask.session["pending_user_id"] = user_id
    flask.session["pending_step"] = step
    flask.session["pending_expires"] = expires.strftime(db.TIME_FORMAT)


def get_pending_user_id(step: str) -> int | None:
    """Return the half logged in user's id, if the marker is for this step and not expired."""
    # the step must match, so nobody can swap a passkey check for a code
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
