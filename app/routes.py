"""Creates the Flask app and holds the login, logout, home and admin pages."""

from flask import Flask, abort, redirect, render_template, request, url_for

from app import client_context
from app import config
from app import csrf
from app import db
from app import limits
from app import passwords
from app import risk
from app import sessions
from app import step_up_routes

# Same message for a wrong email and a wrong password, so attackers cannot tell
# which emails have an account
LOGIN_ERROR = "Wrong email or password."
TOO_MANY_ATTEMPTS = step_up_routes.TOO_MANY_ATTEMPTS
UNUSUAL_LOGIN = "This login looks unusual and was blocked. Try again from your usual device."

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
# The TOTP and passkey pages live in their own file
app.register_blueprint(step_up_routes.step_up)

db.create_tables()
db.seed_demo_users(keys["pepper"])


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
    user = sessions.current_user()
    if user is None:
        return redirect(url_for("login"))
    has_passkey = db.has_passkey(user["id"])
    return render_template("home.html", user=user, has_passkey=has_passkey)


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
        return sessions.log_in(user["id"])
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
        return sessions.log_in(user["id"])
    # The failure count is not cleared yet. Otherwise an attacker with the password could
    # guess codes, log in again to reset the count, and keep guessing forever.
    if step == "block":
        return render_template("login.html", error=UNUSUAL_LOGIN), 403
    sessions.start_pending(user["id"], step)
    if step == "totp":
        return redirect(url_for("step_up.verify_totp"))
    return redirect(url_for("step_up.verify_passkey"))


def refuse_login(context: dict, user_id, message: str, status_code: int):
    """Save the failed attempt and show the login page again with a message."""
    db.record_login_attempt(user_id, context, False)
    return render_template("login.html", error=message), status_code


@app.route("/logout", methods=["POST"])
def logout():
    """End the session in the database and remove the cookie."""
    token = request.cookies.get(sessions.SESSION_COOKIE, "")
    sessions.delete_session(token)
    response = redirect(url_for("login"))
    response.delete_cookie(sessions.SESSION_COOKIE)
    return response


@app.route("/admin")
def admin():
    """Show the admin page, only to users with the admin role."""
    user = sessions.current_user()
    if user is None:
        return redirect(url_for("login"))
    if user["role"] != "admin":
        abort(403)
    return render_template("admin.html", user=user)
