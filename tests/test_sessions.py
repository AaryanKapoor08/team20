"""Tests for device-bound sessions: a cookie only works from the device it was made on."""

import json

import pytest

from app import config
from app import db
from app import sessions

CHROME_WINDOWS = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/129.0 Safari/537.36"
)
FIREFOX_LINUX = "Mozilla/5.0 (X11; Linux x86_64; rv:130.0) Gecko/20100101 Firefox/130.0"
VICTIM = {"ip": "24.1.1.10", "country": "CA", "asn": "AS812", "user_agent": CHROME_WINDOWS}
# Same home network, the router just gave out a new address
VICTIM_NEW_ADDRESS = {"ip": "24.1.1.77", "country": "CA", "asn": "AS812", "user_agent": CHROME_WINDOWS}
# The infostealer's machine: same browser, but a different network
THIEF = {"ip": "91.200.5.5", "country": "NL", "asn": "AS9009", "user_agent": CHROME_WINDOWS}
# Same network, but a different browser and OS
OTHER_BROWSER = {"ip": "24.1.1.10", "country": "CA", "asn": "AS812", "user_agent": FIREFOX_LINUX}


@pytest.fixture
def lab_client(client, monkeypatch):
    """Turn on lab mode so tests can fake where each request comes from."""
    monkeypatch.setattr(config, "LAB_MODE", True)
    return client


def lab_headers(lab_client_info: dict) -> dict:
    """Return the header that fakes where a request comes from."""
    return {"X-Lab-Client": json.dumps(lab_client_info)}


def log_in_from(client, lab_client_info: dict):
    """Log in as Alice from the given place."""
    client.get("/login", headers=lab_headers(lab_client_info))
    with client.session_transaction() as flask_session:
        csrf_token = flask_session["csrf_token"]
    form = {"email": "alice@example.com", "password": "alice-demo-pass", "csrf_token": csrf_token}
    return client.post("/login", data=form, headers=lab_headers(lab_client_info))


def open_home(client, lab_client_info: dict):
    """Open the home page from the given place."""
    return client.get("/", headers=lab_headers(lab_client_info))


def session_count() -> int:
    """Return how many sessions are saved."""
    connection = db.get_connection()
    count = connection.execute("SELECT COUNT(*) FROM sessions").fetchone()[0]
    connection.close()
    return count


def test_ip_prefix_keeps_the_first_three_numbers():
    """Only the network part of an IPv4 address is used."""
    assert sessions.ip_prefix("24.1.1.10") == "24.1.1"
    assert sessions.ip_prefix("::1") == "::1"


def test_session_saves_a_context_hash_not_the_context(lab_client):
    """The sessions table holds a 64 character hash, not the IP or browser."""
    log_in_from(lab_client, VICTIM)
    connection = db.get_connection()
    saved_hash = connection.execute("SELECT context_hash FROM sessions").fetchone()[0]
    connection.close()

    assert len(saved_hash) == 64
    assert "24.1.1" not in saved_hash


def test_same_device_keeps_working(lab_client):
    """The cookie works from the device it was made on."""
    log_in_from(lab_client, VICTIM)

    assert b"alice@example.com" in open_home(lab_client, VICTIM).data


def test_new_address_on_same_network_keeps_working(lab_client):
    """A small IP change on the same network does not log the user out."""
    log_in_from(lab_client, VICTIM)

    assert b"alice@example.com" in open_home(lab_client, VICTIM_NEW_ADDRESS).data


def test_cookie_from_another_network_ends_the_session(lab_client):
    """A copied cookie used from the thief's network is refused and the session is deleted."""
    log_in_from(lab_client, VICTIM)
    response = open_home(lab_client, THIEF)

    assert response.headers["Location"] == "/login"
    assert session_count() == 0
    # The session is gone, so it does not work from the victim's device anymore either
    assert open_home(lab_client, VICTIM).headers["Location"] == "/login"


def test_cookie_from_another_browser_ends_the_session(lab_client):
    """The same cookie from a different browser and OS is refused."""
    log_in_from(lab_client, VICTIM)

    assert open_home(lab_client, OTHER_BROWSER).headers["Location"] == "/login"


def test_binding_off_lets_a_stolen_cookie_work(lab_client, monkeypatch):
    """With SESSION_BINDING off the cookie works from anywhere (what E4 measures)."""
    monkeypatch.setattr(config, "SESSION_BINDING", False)
    log_in_from(lab_client, VICTIM)

    assert b"alice@example.com" in open_home(lab_client, THIEF).data
