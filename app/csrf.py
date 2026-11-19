"""Checks that a form really came from our own site.

Every form carries a hidden random value, and a form sent without the right one
is thrown away.
"""

import hmac
import secrets

from flask import session


def make_token() -> str:
    """Return this browser's CSRF token, making a new one the first time."""
    # kept in Flask's signed cookie, so another site cannot fake it
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_urlsafe(32)
    return session["csrf_token"]


def check_token(form_token: str) -> bool:
    """Return True if the token sent with the form matches this browser's token."""
    saved_token = session.get("csrf_token", "")
    if saved_token == "" or form_token == "":
        return False
    # same speed for any wrong value, so timing gives nothing away
    return hmac.compare_digest(saved_token, form_token)
