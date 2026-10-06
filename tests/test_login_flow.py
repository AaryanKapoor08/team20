"""Tests for the ADAPTIVE login flow: each risk level goes to the right place."""

import json

import pytest

from app import client_context
from app import config
from app import db

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
