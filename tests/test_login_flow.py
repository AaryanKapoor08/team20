"""Tests for the ADAPTIVE login flow: each risk level goes to the right place."""

import json

import pyotp
import pytest

from app import client_context
from app import config
from app import db
from app import routes
from app import totp

ALICE_EMAIL = "alice@example.com"
ALICE_PASSWORD = "alice-demo-pass"

CHROME_WINDOWS = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/129.0 Safari/537.36"
)
FIREFOX_ANDROID = "Mozilla/5.0 (Android 14; Mobile; rv:130.0) Gecko/130.0 Firefox/130.0"

# Lab headers for Alice's usual login, a new country (medium) and everything new (high)
HOME = {"ip": "24.1.1.1", "country": "CA", "asn": "AS812", "user_agent": CHROME_WINDOWS}
ABROAD = {"ip": "177.2.2.2", "country": "BR", "asn": "AS28573", "user_agent": CHROME_WINDOWS}
STRANGER = {"ip": "45.9.9.9", "country": "RU", "asn": "AS9009", "user_agent": FIREFOX_ANDROID}


@pytest.fixture
def adaptive(client, monkeypatch):
    """Turn on ADAPTIVE and lab mode, and give Alice 10 usual logins as history."""
    monkeypatch.setattr(config, "SECURITY_PROFILE", "ADAPTIVE")
    monkeypatch.setattr(config, "LAB_MODE", True)
    home_context = {"ip": HOME["ip"], "country": HOME["country"], "asn": HOME["asn"]}
    home_context.update(client_context.parse_user_agent(CHROME_WINDOWS))
    alice_id = alice_user_id()
    for attempt in range(10):
        db.record_login_attempt(alice_id, home_context, True)
    return client


def alice_user_id() -> int:
    """Return Alice's user id."""
    return db.get_user_by_email(ALICE_EMAIL)["id"]


def log_in_from(client, lab_client: dict):
    """Log in as Alice, faking where the login comes from with the lab header."""
    client.get("/login")
    with client.session_transaction() as flask_session:
        csrf_token = flask_session["csrf_token"]
    form = {"email": ALICE_EMAIL, "password": ALICE_PASSWORD, "csrf_token": csrf_token}
    headers = {"X-Lab-Client": json.dumps(lab_client)}
    return client.post("/login", data=form, headers=headers)


def give_alice_totp() -> None:
    """Mark Alice as having an authenticator app set up."""
    connection = db.get_connection()
    connection.execute(
        "UPDATE users SET totp_secret_encrypted = ? WHERE id = ?",
        ("not-a-real-secret", alice_user_id()),
    )
    connection.commit()
    connection.close()


def give_alice_passkey() -> None:
    """Give Alice a (fake) registered passkey."""
    connection = db.get_connection()
    connection.execute(
        "INSERT INTO passkeys (credential_id, user_id, public_key) VALUES (?, ?, ?)",
        (b"fake-id", alice_user_id(), b"fake-key"),
    )
    connection.commit()
    connection.close()


def last_login_row():
    """Return the newest row in login_history."""
    connection = db.get_connection()
    row = connection.execute("SELECT * FROM login_history ORDER BY id DESC LIMIT 1").fetchone()
    connection.close()
    return row


def test_baseline_skips_the_risk_check(client, monkeypatch):
    """In BASELINE a right password logs in, even from a new country."""
    monkeypatch.setattr(config, "LAB_MODE", True)
    response = log_in_from(client, ABROAD)

    assert response.headers["Location"] == "/"
    assert last_login_row()["risk_level"] is None


def test_low_risk_goes_straight_in(adaptive):
    """A usual login in ADAPTIVE goes to the home page."""
    response = log_in_from(adaptive, HOME)
    home_page = adaptive.get("/")

    assert response.headers["Location"] == "/"
    assert b"alice@example.com" in home_page.data


def test_medium_risk_goes_to_totp(adaptive):
    """A new country goes to the code check when the user has an authenticator app."""
    give_alice_totp()
    response = log_in_from(adaptive, ABROAD)

    assert response.headers["Location"] == "/verify/totp"
    assert adaptive.get("/verify/totp").status_code == 200


def test_medium_risk_without_totp_goes_to_passkey(adaptive):
    """Medium with no authenticator app is treated as high."""
    give_alice_passkey()
    response = log_in_from(adaptive, ABROAD)

    assert response.headers["Location"] == "/verify/passkey"


def test_high_risk_goes_to_passkey(adaptive):
    """A login where everything is new goes to the passkey check."""
    give_alice_totp()
    give_alice_passkey()
    response = log_in_from(adaptive, STRANGER)

    assert response.headers["Location"] == "/verify/passkey"
    assert adaptive.get("/verify/passkey").status_code == 200


def test_high_risk_without_passkey_is_blocked(adaptive):
    """With no passkey there is no strong check to ask for, so the login is blocked."""
    give_alice_totp()
    response = log_in_from(adaptive, STRANGER)

    assert response.status_code == 403
    assert b"looks unusual" in response.data


def test_risk_level_and_reasons_are_saved(adaptive):
    """The level and reasons go into login_history, and step-up is not saved as a success."""
    give_alice_totp()
    log_in_from(adaptive, ABROAD)
    row = last_login_row()

    assert row["risk_level"] == "medium"
    assert "new country for this user" in row["risk_reasons"]
    assert row["success"] == 0


def test_half_logged_in_user_cannot_open_protected_pages(adaptive):
    """The step-up marker is not a session: home and admin still send you to log in."""
    give_alice_totp()
    log_in_from(adaptive, ABROAD)

    assert adaptive.get("/").headers["Location"] == "/login"
    assert adaptive.get("/admin").headers["Location"] == "/login"


def test_passkey_login_cannot_switch_to_the_code_check(adaptive):
    """A login sent to the passkey check cannot open the easier code check instead."""
    give_alice_passkey()
    log_in_from(adaptive, STRANGER)
    response = adaptive.get("/verify/totp")

    assert response.headers["Location"] == "/login"


def test_expired_marker_is_refused(adaptive):
    """After the time limit the step-up page sends you back to log in."""
    give_alice_totp()
    log_in_from(adaptive, ABROAD)
    with adaptive.session_transaction() as flask_session:
        flask_session["pending_expires"] = "2000-01-01T00:00:00"
    response = adaptive.get("/verify/totp")

    assert response.headers["Location"] == "/login"


def test_verify_page_without_marker_goes_to_login(client):
    """Opening a step-up page without logging in first goes to the login page."""
    response = client.get("/verify/totp")

    assert response.headers["Location"] == "/login"


def test_marker_is_cleared_when_a_session_starts(adaptive):
    """A full login removes any old step-up marker."""
    give_alice_totp()
    log_in_from(adaptive, ABROAD)
    log_in_from(adaptive, HOME)

    with adaptive.session_transaction() as flask_session:
        assert "pending_user_id" not in flask_session


def give_alice_real_totp() -> str:
    """Set up a real authenticator secret for Alice and return it."""
    secret = totp.new_secret()
    totp.save_secret(alice_user_id(), secret, routes.keys["aes_key"], 0)
    return secret


def current_code(secret: str) -> str:
    """Return the code the phone shows right now."""
    return pyotp.TOTP(secret).now()


def send_code(client, page: str, code: str, lab_client: dict | None = None):
    """Post a code to a page with the CSRF token, optionally faking where it comes from."""
    with client.session_transaction() as flask_session:
        csrf_token = flask_session["csrf_token"]
    headers = {}
    if lab_client is not None:
        headers["X-Lab-Client"] = json.dumps(lab_client)
    return client.post(page, data={"code": code, "csrf_token": csrf_token}, headers=headers)


def test_right_code_finishes_a_medium_risk_login(adaptive):
    """After a new-country login, the right code gives a real session."""
    secret = give_alice_real_totp()
    log_in_from(adaptive, ABROAD)
    response = send_code(adaptive, "/verify/totp", current_code(secret))

    assert response.headers["Location"] == "/"
    assert b"alice@example.com" in adaptive.get("/").data


def test_passed_code_check_is_saved_as_a_success(adaptive):
    """A login that passed the code check is saved as a success, so the new place is learned."""
    secret = give_alice_real_totp()
    log_in_from(adaptive, ABROAD)
    send_code(adaptive, "/verify/totp", current_code(secret), ABROAD)
    row = last_login_row()

    assert row["success"] == 1
    assert row["country"] == "BR"
    assert row["risk_reasons"] == "passed TOTP check"


def test_wrong_code_gives_no_session(adaptive):
    """A wrong code shows an error and does not log in."""
    give_alice_real_totp()
    log_in_from(adaptive, ABROAD)
    response = send_code(adaptive, "/verify/totp", "12345x")

    assert response.status_code == 401
    assert b"wrong or was already used" in response.data
    assert adaptive.get("/").headers["Location"] == "/login"


def test_wrong_codes_lock_the_account(adaptive, monkeypatch):
    """Wrong codes count toward lockout, and a right password does not reset the count."""
    monkeypatch.setattr(config, "LOCKOUT_FAILURES", 3)
    # A high limit so this test is about the account lock, not the IP limit
    monkeypatch.setattr(config, "IP_FAIL_LIMIT", 100)
    secret = give_alice_real_totp()
    log_in_from(adaptive, ABROAD)
    send_code(adaptive, "/verify/totp", "12345x")
    send_code(adaptive, "/verify/totp", "12345x")
    log_in_from(adaptive, ABROAD)
    send_code(adaptive, "/verify/totp", "12345x")
    response = send_code(adaptive, "/verify/totp", current_code(secret))

    assert response.status_code == 429
    assert adaptive.get("/").headers["Location"] == "/login"


def test_setup_saves_the_secret_after_one_right_code(client):
    """Scanning the QR code and typing one code turns the authenticator app on."""
    log_in_from(client, HOME)
    page = client.get("/setup/totp")
    with client.session_transaction() as flask_session:
        secret = flask_session["totp_setup_secret"]
    response = send_code(client, "/setup/totp", current_code(secret))

    assert b"<svg" in page.data
    assert response.headers["Location"] == "/"
    assert db.get_user_by_email(ALICE_EMAIL)["totp_secret_encrypted"] is not None
    assert b"Authenticator app: on" in client.get("/").data


def test_setup_with_wrong_code_saves_nothing(client):
    """A wrong code during setup does not turn the app on."""
    log_in_from(client, HOME)
    client.get("/setup/totp")
    response = send_code(client, "/setup/totp", "12345x")

    assert response.status_code == 400
    assert db.get_user_by_email(ALICE_EMAIL)["totp_secret_encrypted"] is None


def test_setup_code_cannot_be_used_again_to_log_in(adaptive):
    """The code typed during setup is already spent for the login check."""
    log_in_from(adaptive, HOME)
    adaptive.get("/setup/totp")
    with adaptive.session_transaction() as flask_session:
        secret = flask_session["totp_setup_secret"]
    code = current_code(secret)
    send_code(adaptive, "/setup/totp", code)
    log_in_from(adaptive, ABROAD)
    response = send_code(adaptive, "/verify/totp", code)

    assert response.status_code == 401


def test_setup_page_needs_a_login(client):
    """Without a session the setup page sends you to log in."""
    assert client.get("/setup/totp").headers["Location"] == "/login"
