"""Tests for the hash chained audit log: events are saved, and any edit is found."""

import json

import pytest

from app import audit_log
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
HOME = {"ip": "24.1.1.1", "country": "CA", "asn": "AS812", "user_agent": CHROME_WINDOWS}
ABROAD = {"ip": "177.2.2.2", "country": "BR", "asn": "AS28573", "user_agent": CHROME_WINDOWS}
THIEF = {"ip": "91.200.5.5", "country": "NL", "asn": "AS9009", "user_agent": CHROME_WINDOWS}


@pytest.fixture
def lab_client(client, monkeypatch):
    """Turn on lab mode so tests can fake where each request comes from."""
    monkeypatch.setattr(config, "LAB_MODE", True)
    return client


@pytest.fixture
def adaptive(lab_client, monkeypatch):
    """Turn on ADAPTIVE and give Alice 10 usual logins from home as history."""
    monkeypatch.setattr(config, "SECURITY_PROFILE", "ADAPTIVE")
    home_context = {"ip": HOME["ip"], "country": HOME["country"], "asn": HOME["asn"]}
    home_context.update(client_context.parse_user_agent(CHROME_WINDOWS))
    alice_id = db.get_user_by_email(ALICE_EMAIL)["id"]
    for attempt in range(10):
        db.record_login_attempt(alice_id, home_context, True)
    return lab_client


def lab_headers(lab_client_info: dict) -> dict:
    """Return the header that fakes where a request comes from."""
    return {"X-Lab-Client": json.dumps(lab_client_info)}


def csrf_token_of(client) -> str:
    """Return the CSRF token saved for this test browser."""
    client.get("/login")
    with client.session_transaction() as flask_session:
        return flask_session["csrf_token"]


def log_in(client, password: str, lab_client_info: dict = HOME):
    """Send the login form for Alice from the given place."""
    form = {"email": ALICE_EMAIL, "password": password, "csrf_token": csrf_token_of(client)}
    return client.post("/login", data=form, headers=lab_headers(lab_client_info))


def saved_events() -> list:
    """Return every row of the audit log, oldest first."""
    connection = db.get_connection()
    rows = connection.execute("SELECT * FROM audit_log ORDER BY id").fetchall()
    connection.close()
    return rows


def event_names() -> list:
    """Return the event name of every audit log row, oldest first."""
    names = []
    for row in saved_events():
        names.append(row["event"])
    return names


def add_four_events() -> None:
    """Fill the log with four simple events."""
    for number in range(4):
        audit_log.add_event("test_event", {"number": number})


def test_empty_log_verifies(temp_db):
    """A log with no rows has nothing broken."""
    assert audit_log.verify_chain() is None


def test_first_row_links_to_64_zeros(temp_db):
    """The first row has no row before it, so its previous hash is all zeros."""
    audit_log.add_event("test_event", {"number": 0})

    assert saved_events()[0]["prev_hash"] == "0" * 64


def test_each_row_links_to_the_row_before(temp_db):
    """Every row saves the hash of the row before it."""
    add_four_events()
    rows = saved_events()

    for index in range(1, len(rows)):
        assert rows[index]["prev_hash"] == rows[index - 1]["hash"]


def test_clean_chain_verifies(temp_db):
    """A log nobody touched checks out."""
    add_four_events()

    assert audit_log.verify_chain() is None


def test_edited_row_is_caught_at_that_row(temp_db):
    """Changing one row with plain SQL is found, and the id of that exact row is returned."""
    add_four_events()
    connection = db.get_connection()
    connection.execute("UPDATE audit_log SET details = ? WHERE id = 3", ('{"number": 99}',))
    connection.commit()
    connection.close()

    assert audit_log.verify_chain() == 3


def test_deleted_row_is_caught_at_the_next_row(temp_db):
    """Removing a row in the middle breaks the link of the row after it."""
    add_four_events()
    connection = db.get_connection()
    connection.execute("DELETE FROM audit_log WHERE id = 2")
    connection.commit()
    connection.close()

    assert audit_log.verify_chain() == 3


def test_good_logins_are_saved_and_chain_verifies(lab_client):
    """A few logins add login_success events, and the chain still checks out."""
    for attempt in range(3):
        log_in(lab_client, ALICE_PASSWORD)

    assert event_names() == ["login_success", "login_success", "login_success"]
    assert audit_log.verify_chain() is None


def test_wrong_password_is_saved_without_the_password(lab_client):
    """A failed login is saved with its reason, but the password typed is never saved."""
    log_in(lab_client, "my-secret-guess")
    row = saved_events()[0]

    assert row["event"] == "login_failed"
    assert json.loads(row["details"])["reason"] == "wrong password"
    assert "my-secret-guess" not in row["details"]
    assert ALICE_EMAIL not in row["details"]


def test_lockout_is_saved(lab_client, monkeypatch):
    """The wrong password that locks the account adds an account_locked event."""
    monkeypatch.setattr(config, "LOCKOUT_FAILURES", 3)
    monkeypatch.setattr(config, "IP_FAIL_LIMIT", 100)
    for attempt in range(3):
        log_in(lab_client, "wrong-pass")

    assert "account_locked" in event_names()


def test_stolen_session_is_saved(lab_client):
    """A session used from another device adds a session_ended event."""
    log_in(lab_client, ALICE_PASSWORD, HOME)
    lab_client.get("/", headers=lab_headers(THIEF))

    assert event_names() == ["login_success", "session_ended"]


def test_step_up_events_are_saved_without_the_code(adaptive):
    """A login from abroad asks for a code, and a wrong code is saved but the code is not."""
    secret = totp.new_secret()
    alice_id = db.get_user_by_email(ALICE_EMAIL)["id"]
    totp.save_secret(alice_id, secret, routes.keys["aes_key"], 0)
    log_in(adaptive, ALICE_PASSWORD, ABROAD)
    wrong_code = "000000"
    form = {"code": wrong_code, "csrf_token": csrf_token_of(adaptive)}
    adaptive.post("/verify/totp", data=form, headers=lab_headers(ABROAD))
    rows = saved_events()

    assert event_names() == ["step_up_asked", "step_up_failed"]
    assert json.loads(rows[0]["details"])["risk_level"] == "medium"
    assert wrong_code not in rows[1]["details"]
