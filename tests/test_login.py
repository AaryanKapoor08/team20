"""Tests for login, logout, the admin page and CSRF tokens."""

from app import db
from app import sessions

ALICE = {"email": "alice@example.com", "password": "alice-demo-pass"}
ADMIN = {"email": "admin@example.com", "password": "admin-demo-pass"}


def get_csrf_token(client) -> str:
    """Open the login page and return the CSRF token saved for this test browser."""
    client.get("/login")
    with client.session_transaction() as flask_session:
        return flask_session["csrf_token"]


def log_in(client, email, password):
    """Send the login form with a valid CSRF token and return the response."""
    form = {"email": email, "password": password, "csrf_token": get_csrf_token(client)}
    return client.post("/login", data=form)


def count_sessions() -> int:
    """Return how many sessions are saved in the database."""
    connection = db.get_connection()
    session_count = connection.execute("SELECT COUNT(*) FROM sessions").fetchone()[0]
    connection.close()
    return session_count


def count_login_attempts() -> int:
    """Return how many login attempts are saved in login_history."""
    connection = db.get_connection()
    attempt_count = connection.execute("SELECT COUNT(*) FROM login_history").fetchone()[0]
    connection.close()
    return attempt_count


def test_good_login_shows_home_page(client):
    """The right password logs in and the home page shows the user's email."""
    response = log_in(client, ALICE["email"], ALICE["password"])
    home_page = client.get("/")

    assert response.status_code == 302
    assert b"alice@example.com" in home_page.data


def test_bad_email_and_bad_password_show_same_page(client):
    """A wrong email and a wrong password give the exact same response."""
    wrong_email = log_in(client, "nobody@example.com", ALICE["password"])
    wrong_password = log_in(client, ALICE["email"], "not-the-password")

    assert wrong_email.status_code == 401
    assert b"Wrong email or password." in wrong_email.data
    assert wrong_email.data == wrong_password.data


def test_missing_csrf_token_is_rejected(client):
    """A login form sent without the CSRF token is refused."""
    response = client.post("/login", data=ALICE)

    assert response.status_code == 400


def test_wrong_csrf_token_is_rejected(client):
    """A login form with a made up CSRF token is refused."""
    get_csrf_token(client)
    form = {"email": ALICE["email"], "password": ALICE["password"], "csrf_token": "fake"}
    response = client.post("/login", data=form)

    assert response.status_code == 400


def test_home_page_needs_login(client):
    """A visitor who is not logged in is sent to the login page."""
    response = client.get("/")

    assert response.status_code == 302
    assert response.headers["Location"].endswith("/login")


def test_session_cookie_is_httponly_and_lax(client):
    """The session cookie cannot be read by scripts and is not sent by other sites' forms."""
    response = log_in(client, ALICE["email"], ALICE["password"])
    cookie_header = response.headers["Set-Cookie"]

    assert "session_token=" in cookie_header
    assert "HttpOnly" in cookie_header
    assert "SameSite=Lax" in cookie_header


def test_only_token_hash_is_stored(client):
    """The database holds the SHA-256 of the session token, never the token itself."""
    log_in(client, ALICE["email"], ALICE["password"])
    token = client.get_cookie("session_token").value
    connection = db.get_connection()
    stored_hash = connection.execute("SELECT token_hash FROM sessions").fetchone()["token_hash"]
    connection.close()

    assert stored_hash != token
    assert stored_hash == sessions.hash_token(token)


def test_logout_ends_the_session(client):
    """After logout the session row is gone and the home page needs login again."""
    log_in(client, ALICE["email"], ALICE["password"])
    client.post("/logout", data={"csrf_token": get_csrf_token(client)})
    home_page = client.get("/")

    assert count_sessions() == 0
    assert home_page.status_code == 302


def test_every_login_attempt_is_recorded(client):
    """Good and bad logins each add one row to login_history."""
    log_in(client, ALICE["email"], "not-the-password")
    log_in(client, "nobody@example.com", "whatever")
    log_in(client, ALICE["email"], ALICE["password"])

    assert count_login_attempts() == 3


def test_normal_user_gets_403_on_admin(client):
    """A logged in user without the admin role cannot open the admin page."""
    log_in(client, ALICE["email"], ALICE["password"])
    response = client.get("/admin")

    assert response.status_code == 403


def test_admin_can_open_admin_page(client):
    """The admin user can open the admin page."""
    log_in(client, ADMIN["email"], ADMIN["password"])
    response = client.get("/admin")

    assert response.status_code == 200
    assert b"Admin" in response.data
