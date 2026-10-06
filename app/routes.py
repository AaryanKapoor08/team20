"""Creates the Flask app and holds all the page routes."""

from flask import Flask, abort, redirect, render_template, request, url_for
from flask import session as flask_session

from app import client_context
from app import config
from app import csrf
from app import db
from app import limits
from app import passwords
from app import risk
from app import sessions
from app import totp

SESSION_COOKIE = "session_token"
# Same message for a wrong email and a wrong password, so attackers cannot tell
# which emails have an account
LOGIN_ERROR = "Wrong email or password."
TOO_MANY_ATTEMPTS = "Too many attempts. Try again later."
UNUSUAL_LOGIN = "This login looks unusual and was blocked. Try again from your usual device."
WRONG_CODE = "That code is wrong or was already used."

app = Flask(__name__)

# Flask signs its own cookie with this key, so nobody can fake one.
# It comes from keys.json, never from the code.
keys = config.load_keys()
app.secret_key = keys["flask_secret_key"]
# HttpOnly: page scripts cannot read the cookie. Lax: other sites' forms do not send it.
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
# Lets every template write {{ csrf_token() }} inside its forms
app.jinja_env.globals["csrf_token"] = csrf.make_token

db.create_tables()
db.seed_demo_users(keys["pepper"])


def current_user():
    """Return the logged in user for this request, or None."""
    token = request.cookies.get(SESSION_COOKIE, "")
    return sessions.get_user_for_token(token)


@app.before_request
def check_csrf_token():
    """Reject any POST that does not carry this browser's CSRF token."""
    if request.method != "POST":
        return None
    form_token = request.form.get("csrf_token", "")
    if not csrf.check_token(form_token):
        abort(400)
    return None


@app.route("/")
def home():
    """Show who is logged in, or send the visitor to the login page."""
    user = current_user()
    if user is None:
        return redirect(url_for("login"))
    return render_template("home.html", user=user)


@app.route("/login", methods=["GET", "POST"])
def login():
    """Show the login form, or check the email and password that were sent."""
    if request.method == "GET":
        return render_template("login.html")

    email = request.form.get("email", "").strip().lower()
    password = request.form.get("password", "")
    context = client_context.get_context(request)

    # The IP check comes first, so a blocked IP learns nothing about any account
    if limits.is_ip_blocked(context["ip"]):
        return refuse_login(context, None, TOO_MANY_ATTEMPTS, 429)

    user = db.get_user_by_email(email)
    if user is None:
        # Do a full password check anyway, so a wrong email is not faster than a wrong password
        passwords.check_password(passwords.DUMMY_HASH, password, keys["pepper"])
        return refuse_login(context, None, LOGIN_ERROR, 401)

    if limits.is_account_locked(user):
        return refuse_login(context, user["id"], TOO_MANY_ATTEMPTS, 429)

    if not passwords.check_password(user["password_hash"], password, keys["pepper"]):
        limits.record_failure(user)
        return refuse_login(context, user["id"], LOGIN_ERROR, 401)

    # BASELINE is the "most sites" setup: a right password is enough
    if config.SECURITY_PROFILE != "ADAPTIVE":
        limits.record_success(user)
        db.record_login_attempt(user["id"], context, True)
        return start_session(user["id"])
    return adaptive_login(user, context)


def adaptive_login(user, context: dict):
    """Score a login with a right password, then let it in, ask for more, or block it."""
    result = risk.score_login(user["id"], context)
    has_totp = user["totp_secret_encrypted"] is not None
    has_passkey = db.has_passkey(user["id"])
    step = risk.choose_step(result["level"], has_totp, has_passkey)

    # Only a finished login is saved as a success. Otherwise an attacker with a stolen
    # password, stuck at the extra check, would teach the risk engine their country is normal.
    finished = step == "login"
    db.record_login_attempt(user["id"], context, finished, result["level"], result["reasons"])

    if step == "login":
        limits.record_success(user)
        return start_session(user["id"])
    # The failure count is not cleared yet. Otherwise an attacker with the password could
    # guess codes, log in again to reset the count, and keep guessing forever.
    if step == "block":
        return render_template("login.html", error=UNUSUAL_LOGIN), 403
    sessions.start_pending(user["id"], step)
    if step == "totp":
        return redirect(url_for("verify_totp"))
    return redirect(url_for("verify_passkey"))


def refuse_login(context: dict, user_id, message: str, status_code: int):
    """Save the failed attempt and show the login page again with a message."""
    db.record_login_attempt(user_id, context, False)
    return render_template("login.html", error=message), status_code


def start_session(user_id: int):
    """Make a session for the user, set its cookie and go to the home page."""
    sessions.clear_pending()
    token = sessions.create_session(user_id)
    response = redirect(url_for("home"))
    # secure=False because the app runs on plain http://localhost
    max_age = int(sessions.SESSION_LIFETIME.total_seconds())
    response.set_cookie(SESSION_COOKIE, token, max_age=max_age, httponly=True, samesite="Lax")
    return response


@app.route("/logout", methods=["POST"])
def logout():
    """End the session in the database and remove the cookie."""
    token = request.cookies.get(SESSION_COOKIE, "")
    sessions.delete_session(token)
    response = redirect(url_for("login"))
    response.delete_cookie(SESSION_COOKIE)
    return response


@app.route("/admin")
def admin():
    """Show the admin page, only to users with the admin role."""
    user = current_user()
    if user is None:
        return redirect(url_for("login"))
    if user["role"] != "admin":
        abort(403)
    return render_template("admin.html", user=user)


@app.route("/setup/totp", methods=["GET", "POST"])
def setup_totp():
    """Let a logged in user add an authenticator app by scanning a QR code."""
    user = current_user()
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
        return redirect(url_for("setup_totp"))
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


@app.route("/verify/totp", methods=["GET", "POST"])
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
        sessions.clear_pending()
        return render_template("login.html", error=TOO_MANY_ATTEMPTS), 429
    code = request.form.get("code", "").strip()
    if not totp.verify_code(user, code, keys["aes_key"]):
        limits.record_failure(user)
        return render_template("verify_totp.html", error=WRONG_CODE), 401
    limits.record_success(user)
    return start_session(user_id)


@app.route("/verify/passkey")
def verify_passkey():
    """Ask a half logged in user for their passkey (placeholder for now)."""
    if sessions.get_pending_user_id("passkey") is None:
        return redirect(url_for("login"))
    return render_template("verify.html", check_name="passkey")
