"""Tests for passkeys: adding one, and using it to pass a high-risk login."""

import html
import json
import re

import pytest

from app import client_context
from app import config
from app import db
from tests import fake_passkey

ALICE_EMAIL = "alice@example.com"
ALICE_PASSWORD = "alice-demo-pass"
CHROME_WINDOWS = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/129.0 Safari/537.36"
)
FIREFOX_ANDROID = "Mozilla/5.0 (Android 14; Mobile; rv:130.0) Gecko/130.0 Firefox/130.0"
HOME = {"ip": "24.1.1.1", "country": "CA", "asn": "AS812", "user_agent": CHROME_WINDOWS}
STRANGER = {"ip": "45.9.9.9", "country": "RU", "asn": "AS9009", "user_agent": FIREFOX_ANDROID}


@pytest.fixture
def adaptive(client, monkeypatch):
    """Turn on ADAPTIVE and lab mode, and give Alice 10 usual logins as history."""
    monkeypatch.setattr(config, "SECURITY_PROFILE", "ADAPTIVE")
    monkeypatch.setattr(config, "LAB_MODE", True)
    home_context = {"ip": HOME["ip"], "country": HOME["country"], "asn": HOME["asn"]}
    home_context.update(client_context.parse_user_agent(CHROME_WINDOWS))
    alice_id = db.get_user_by_email(ALICE_EMAIL)["id"]
    for attempt in range(10):
        db.record_login_attempt(alice_id, home_context, True)
    return client


def lab_headers(lab_client: dict) -> dict:
    """Return the header that fakes where a request comes from."""
    return {"X-Lab-Client": json.dumps(lab_client)}


def csrf_token(client) -> str:
    """Return the CSRF token saved in the test browser."""
    with client.session_transaction() as flask_session:
        return flask_session["csrf_token"]


def log_in_from(client, lab_client: dict):
    """Log in as Alice with her password, from the given place."""
    client.get("/login", headers=lab_headers(lab_client))
    form = {"email": ALICE_EMAIL, "password": ALICE_PASSWORD, "csrf_token": csrf_token(client)}
    return client.post("/login", data=form, headers=lab_headers(lab_client))


def page_options(client, page: str, lab_client: dict) -> str:
    """Open a passkey page and return the options the server put in its button."""
    response = client.get(page, headers=lab_headers(lab_client))
    match = re.search(r'data-options="([^"]*)"', response.get_data(as_text=True))
    return html.unescape(match.group(1))


def send_credential(client, page: str, credential_json: str, lab_client: dict):
    """Post the device's answer to a passkey page, like passkey.js does."""
    form = {"credential": credential_json, "csrf_token": csrf_token(client)}
    return client.post(page, data=form, headers=lab_headers(lab_client))


def add_passkey(client, device: dict):
    """Log in from home, add the fake device as Alice's passkey, then log out."""
    log_in_from(client, HOME)
    options_json = page_options(client, "/setup/passkey", HOME)
    answer = fake_passkey.register(device, options_json)
    response = send_credential(client, "/setup/passkey", answer, HOME)
    client.post("/logout", data={"csrf_token": csrf_token(client)}, headers=lab_headers(HOME))
    return response


def test_adding_a_passkey_saves_its_public_key(adaptive):
    """A good registration saves the passkey, and the home page says it is on."""
    response = add_passkey(adaptive, fake_passkey.new_device())
    log_in_from(adaptive, HOME)

    assert response.headers["Location"] == "/"
    assert db.has_passkey(db.get_user_by_email(ALICE_EMAIL)["id"])
    assert b"Passkey: on" in adaptive.get("/", headers=lab_headers(HOME)).data


def test_bad_registration_saves_nothing(adaptive):
    """An answer that is not a passkey response is refused."""
    log_in_from(adaptive, HOME)
    page_options(adaptive, "/setup/passkey", HOME)
    response = send_credential(adaptive, "/setup/passkey", "not json", HOME)

    assert response.status_code == 400
    assert not db.has_passkey(db.get_user_by_email(ALICE_EMAIL)["id"])


def test_passkey_finishes_a_high_risk_login(adaptive):
    """After a login where everything is new, the passkey gives a real session."""
    device = fake_passkey.new_device()
    add_passkey(adaptive, device)
    login_response = log_in_from(adaptive, STRANGER)
    options_json = page_options(adaptive, "/verify/passkey", STRANGER)
    answer = fake_passkey.sign_in(device, options_json)
    response = send_credential(adaptive, "/verify/passkey", answer, STRANGER)

    assert login_response.headers["Location"] == "/verify/passkey"
    assert response.headers["Location"] == "/"
    assert b"alice@example.com" in adaptive.get("/", headers=lab_headers(STRANGER)).data


def test_passkey_from_a_phishing_site_is_rejected(adaptive):
    """A passkey answer made for another web address is refused."""
    device = fake_passkey.new_device()
    add_passkey(adaptive, device)
    log_in_from(adaptive, STRANGER)
    options_json = page_options(adaptive, "/verify/passkey", STRANGER)
    answer = fake_passkey.sign_in(device, options_json, origin="http://localhost-login.example")
    response = send_credential(adaptive, "/verify/passkey", answer, STRANGER)

    assert response.status_code == 401
    assert adaptive.get("/", headers=lab_headers(STRANGER)).headers["Location"] == "/login"


def test_unknown_passkey_is_rejected(adaptive):
    """A device that was never registered cannot pass the check."""
    add_passkey(adaptive, fake_passkey.new_device())
    log_in_from(adaptive, STRANGER)
    options_json = page_options(adaptive, "/verify/passkey", STRANGER)
    answer = fake_passkey.sign_in(fake_passkey.new_device(), options_json)
    response = send_credential(adaptive, "/verify/passkey", answer, STRANGER)

    assert response.status_code == 401


def test_old_passkey_answer_cannot_be_replayed(adaptive):
    """An answer to an old challenge does not work on a new login."""
    device = fake_passkey.new_device()
    add_passkey(adaptive, device)
    log_in_from(adaptive, STRANGER)
    old_answer = fake_passkey.sign_in(device, page_options(adaptive, "/verify/passkey", STRANGER))
    send_credential(adaptive, "/verify/passkey", old_answer, STRANGER)
    log_in_from(adaptive, STRANGER)
    page_options(adaptive, "/verify/passkey", STRANGER)
    response = send_credential(adaptive, "/verify/passkey", old_answer, STRANGER)

    assert response.status_code == 401


def test_setup_passkey_page_needs_a_login(client):
    """Without a session the add-a-passkey page sends you to log in."""
    assert client.get("/setup/passkey").headers["Location"] == "/login"
