"""CSRF token: a hidden random value that proves a form came from our own site."""

import hmac
import secrets

from flask import session


def make_token() -> str:
    """Return this browser's CSRF token, making a new one the first time."""
    # Saved in Flask's signed cookie, so another site cannot read or fake it
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_urlsafe(32)
    return session["csrf_token"]


def check_token(form_token: str) -> bool:
    """Return True if the token sent with the form matches this browser's token."""
    saved_token = session.get("csrf_token", "")
    if saved_token == "" or form_token == "":
        return False
    # compare_digest takes the same time for any mismatch, so timing reveals nothing
    return hmac.compare_digest(saved_token, form_token)
