"""Pages for setting up and passing the extra login checks: TOTP codes and passkeys."""

from flask import Blueprint, redirect, render_template, request, url_for
from flask import session as flask_session

from app import audit_log
from app import client_context
from app import config
from app import db
from app import limits
from app import passkeys
from app import sessions
from app import totp

TOO_MANY_ATTEMPTS = "Too many attempts. Try again later."
WRONG_CODE = "That code is wrong or was already used."
PASSKEY_FAILED = "The passkey check failed. Try again."

# A blueprint is a group of routes that routes.py adds to the app
step_up = Blueprint("step_up", __name__)
keys = config.load_keys()


def finish_step_up(user_id: int, check_name: str):
    """Log in a user who passed the extra check, and remember where they logged in from."""
    user = db.get_user_by_id(user_id)
    limits.record_success(user)
    # Saved as a success, so the risk check learns this new place and does not ask every time
    context = client_context.get_context(request)
    db.record_login_attempt(user_id, context, True, None, [f"passed {check_name} check"])
    audit_log.add_event("step_up_passed", {"user_id": user_id, "ip": context["ip"], "check": check_name})
    return sessions.log_in(user_id)


def log_step_up_failure(user_id: int, check_name: str, reason: str) -> None:
    """Save a failed TOTP or passkey check in the audit log (never the code itself)."""
    context = client_context.get_context(request)
    details = {"user_id": user_id, "ip": context["ip"], "check": check_name, "reason": reason}
    audit_log.add_event("step_up_failed", details)


@step_up.route("/setup/totp", methods=["GET", "POST"])
def setup_totp():
    """Let a logged in user add an authenticator app by scanning a QR code."""
    user = sessions.current_user()
    if user is None:
        return redirect(url_for("login"))
    if user["totp_secret_encrypted"] is not None:
        return redirect(url_for("home"))
    if request.method == "GET":
        # Held in Flask's signed cookie until the user proves their phone has it
        flask_session["totp_setup_secret"] = totp.new_secret()
        return show_totp_setup(user, None)

    secret = flask_session.get("totp_setup_secret")
    if secret is None:
        return redirect(url_for("step_up.setup_totp"))
    code = request.form.get("code", "").strip()
    step = totp.matching_step(secret, code)
    if step is None:
        return show_totp_setup(user, WRONG_CODE), 400
    totp.save_secret(user["id"], secret, keys["aes_key"], step)
    flask_session.pop("totp_setup_secret")
    return redirect(url_for("home"))


def show_totp_setup(user, error: str | None):
    """Show the QR code page for the secret being set up."""
    secret = flask_session["totp_setup_secret"]
    qr_svg = totp.qr_code_svg(secret, user["email"])
    return render_template("totp_setup.html", qr_svg=qr_svg, secret=secret, error=error)


@step_up.route("/verify/totp", methods=["GET", "POST"])
def verify_totp():
    """Ask a half logged in user for the code from their authenticator app."""
    user_id = sessions.get_pending_user_id("totp")
    if user_id is None:
        return redirect(url_for("login"))
    if request.method == "GET":
        return render_template("verify_totp.html")

    user = db.get_user_by_id(user_id)
    # Wrong codes count toward the same lockout as wrong passwords,
    # so nobody can try all one million codes
    if limits.is_account_locked(user):
        log_step_up_failure(user_id, "TOTP", "account locked")
        sessions.clear_pending()
        return render_template("login.html", error=TOO_MANY_ATTEMPTS), 429
    code = request.form.get("code", "").strip()
    if not totp.verify_code(user, code, keys["aes_key"]):
        log_step_up_failure(user_id, "TOTP", "wrong or reused code")
        limits.record_failure(user)
        return render_template("verify_totp.html", error=WRONG_CODE), 401
    return finish_step_up(user_id, "TOTP")


@step_up.route("/setup/passkey", methods=["GET", "POST"])
def setup_passkey():
    """Let a logged in user add a passkey (Windows Hello, Touch ID, a phone, a security key)."""
    user = sessions.current_user()
    if user is None:
        return redirect(url_for("login"))
    if request.method == "GET":
        return show_passkey_setup(user, None)

    # The challenge is taken out of the session, so each one can be used only once
    challenge = flask_session.pop("passkey_challenge", None)
    credential_json = request.form.get("credential", "")
    if challenge is None or not passkeys.save_passkey(user["id"], credential_json, challenge):
        return show_passkey_setup(user, PASSKEY_FAILED), 400
    return redirect(url_for("home"))


def show_passkey_setup(user, error: str | None):
    """Show the add-a-passkey page with a fresh challenge."""
    options_json, challenge = passkeys.registration_options(user)
    flask_session["passkey_challenge"] = challenge
    return render_template("passkey_setup.html", options_json=options_json, error=error)


@step_up.route("/verify/passkey", methods=["GET", "POST"])
def verify_passkey():
    """Ask a half logged in user to sign in with their passkey."""
    user_id = sessions.get_pending_user_id("passkey")
    if user_id is None:
        return redirect(url_for("login"))
    if request.method == "GET":
        return show_passkey_check(user_id, None)

    challenge = flask_session.pop("passkey_challenge", None)
    credential_json = request.form.get("credential", "")
    if challenge is None or not passkeys.check_login(user_id, credential_json, challenge):
        log_step_up_failure(user_id, "passkey", "passkey check failed")
        return show_passkey_check(user_id, PASSKEY_FAILED), 401
    return finish_step_up(user_id, "passkey")


def show_passkey_check(user_id: int, error: str | None):
    """Show the passkey login page with a fresh challenge."""
    options_json, challenge = passkeys.authentication_options(user_id)
    flask_session["passkey_challenge"] = challenge
    return render_template("verify_passkey.html", options_json=options_json, error=error)
