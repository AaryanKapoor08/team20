"""Creates the Flask app and holds all the page routes."""

from flask import Flask, abort, redirect, render_template, request, url_for

from app import config
from app import csrf
from app import db
from app import limits
from app import passwords
from app import sessions

SESSION_COOKIE = "session_token"
# Same message for a wrong email and a wrong password, so attackers cannot tell
# which emails have an account
LOGIN_ERROR = "Wrong email or password."
TOO_MANY_ATTEMPTS = "Too many attempts. Try again later."

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

    # The IP check comes first, so a blocked IP learns nothing about any account
    if limits.is_ip_blocked(request.remote_addr):
        return refuse_login(None, TOO_MANY_ATTEMPTS, 429)

    user = db.get_user_by_email(email)
    if user is None:
        # Do a full password check anyway, so a wrong email is not faster than a wrong password
        passwords.check_password(passwords.DUMMY_HASH, password, keys["pepper"])
        return refuse_login(None, LOGIN_ERROR, 401)

    if limits.is_account_locked(user):
        return refuse_login(user["id"], TOO_MANY_ATTEMPTS, 429)

    if not passwords.check_password(user["password_hash"], password, keys["pepper"]):
        limits.record_failure(user)
        return refuse_login(user["id"], LOGIN_ERROR, 401)

    limits.record_success(user)
    db.record_login_attempt(user["id"], request.remote_addr, True)
    return start_session(user["id"])


def refuse_login(user_id, message: str, status_code: int):
    """Save the failed attempt and show the login page again with a message."""
    db.record_login_attempt(user_id, request.remote_addr, False)
    return render_template("login.html", error=message), status_code


def start_session(user_id: int):
    """Make a session for the user, set its cookie and go to the home page."""
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
