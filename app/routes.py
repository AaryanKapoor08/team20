"""Makes the Flask app and holds the login, logout and home pages.

Each route reads the form, calls the other files to do the work, and shows a page.
"""

from flask import Flask, abort, redirect, render_template, request, url_for
from werkzeug.middleware.proxy_fix import ProxyFix

from app import admin_routes
from app import audit_log
from app import client_context
from app import config
from app import csrf
from app import db
from app import firewall
from app import limits
from app import passwords
from app import risk
from app import sessions
from app import step_up_routes

# same message either way, so nobody can find out which emails exist
LOGIN_ERROR = "Wrong email or password."
TOO_MANY_ATTEMPTS = step_up_routes.TOO_MANY_ATTEMPTS
UNUSUAL_LOGIN = "This login looks unusual and was blocked. Try again from your usual device."

app = Flask(__name__)

# in Docker, take the visitor's IP from Nginx, trusting one proxy only
if config.BEHIND_PROXY:
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1)

# Flask signs its cookie with this key, so nobody can fake one
keys = config.load_keys()
app.secret_key = keys["flask_secret_key"]
# HttpOnly: scripts cannot read it. Lax: other sites cannot send it.
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
# lets every form write {{ csrf_token() }}
app.jinja_env.globals["csrf_token"] = csrf.make_token
# the TOTP, passkey and admin pages live in their own files
app.register_blueprint(step_up_routes.step_up)
app.register_blueprint(admin_routes.admin)

db.create_tables()
db.seed_demo_users(keys["pepper"])


# written first, so the firewall runs before any page code
@app.before_request
def check_firewall():
    """Refuse every request from a blocked IP, before any page code runs."""
    ip = client_context.get_context(request)["ip"]
    if firewall.is_blocked(ip):
        abort(403)
    return None


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

    # IP check first, so a blocked IP learns nothing about any account
    if limits.is_ip_blocked(context["ip"]):
        return refuse_login(context, None, "too many failures from this IP", TOO_MANY_ATTEMPTS, 429)

    user = db.get_user_by_email(email)
    if user is None:
        # check a fake hash anyway, so a wrong email is not faster
        passwords.check_password(passwords.DUMMY_HASH, password, keys["pepper"])
        return refuse_login(context, None, "unknown email", LOGIN_ERROR, 401)

    if limits.is_account_locked(user):
        return refuse_login(context, user["id"], "account locked", TOO_MANY_ATTEMPTS, 429)

    if not passwords.check_password(user["password_hash"], password, keys["pepper"]):
        limits.record_failure(user)
        return refuse_login(context, user["id"], "wrong password", LOGIN_ERROR, 401)

    # BASELINE is what most sites do: a right password is enough
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
    # a very high score blocks the IP on every page, not just this login
    if result["score"] >= config.RISK_BLOCK:
        firewall.block_ip(context["ip"], f"login risk score {result['score']}")
        step = "block"

    # only a finished login counts, so a stuck attacker teaches it nothing
    finished = step == "login"
    db.record_login_attempt(user["id"], context, finished, result["level"], result["reasons"])

    if step == "login":
        limits.record_success(user)
        return sessions.log_in(user["id"])
    details = {
        "user_id": user["id"],
        "ip": context["ip"],
        "risk_level": result["level"],
        "reasons": result["reasons"],
    }
    # the failure count stays, so codes cannot be guessed forever
    if step == "block":
        audit_log.add_event("login_blocked", details)
        return render_template("login.html", error=UNUSUAL_LOGIN), 403
    details["step"] = step
    audit_log.add_event("step_up_asked", details)
    sessions.start_pending(user["id"], step)
    if step == "totp":
        return redirect(url_for("step_up.verify_totp"))
    return redirect(url_for("step_up.verify_passkey"))


def refuse_login(context: dict, user_id, reason: str, message: str, status_code: int):
    """Save the failed attempt and show the login page again with a message."""
    db.record_login_attempt(user_id, context, False)
    # the real reason goes to the log only
    audit_log.add_event("login_failed", {"user_id": user_id, "ip": context["ip"], "reason": reason})
    return render_template("login.html", error=message), status_code


# vague on purpose: an attacker should not learn why they were refused
ERROR_MESSAGES = {
    400: "That form could not be checked. Go back and try again.",
    403: "You do not have access to this page.",
    404: "That page does not exist.",
    429: "Too many attempts. Try again later.",
}


def show_error_page(error):
    """Show one simple page, in the site's own style, for any error we expect."""
    message = ERROR_MESSAGES.get(error.code, "Something went wrong.")
    return render_template("error.html", code=error.code, message=message), error.code


# one handler per code, so a loop saves repeating the line
for error_code in ERROR_MESSAGES:
    app.register_error_handler(error_code, show_error_page)


@app.route("/logout", methods=["POST"])
def logout():
    """End the session in the database and remove the cookie."""
    token = request.cookies.get(sessions.SESSION_COOKIE, "")
    sessions.delete_session(token)
    response = redirect(url_for("login"))
    response.delete_cookie(sessions.SESSION_COOKIE)
    return response

