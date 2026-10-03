"""Tests for reading the client context and the lab mode header."""

import json

import pytest
from flask import request
from werkzeug.exceptions import BadRequest

from app import client_context
from app import config
from app import db
from app import routes

CHROME_WINDOWS = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36"
)
EDGE_WINDOWS = CHROME_WINDOWS + " Edg/129.0.0.0"
FIREFOX_MAC = "Mozilla/5.0 (Macintosh; Intel Mac OS X 14.6; rv:131.0) Gecko/20100101 Firefox/131.0"
SAFARI_IPHONE = (
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_6 like Mac OS X) AppleWebKit/605.1.15 "
    "(KHTML, like Gecko) Version/17.6 Mobile/15E148 Safari/604.1"
)
CHROME_ANDROID = (
    "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/129.0.0.0 Mobile Safari/537.36"
)

LAB_CLIENT = {
    "ip": "203.0.113.7",
    "country": "BR",
    "asn": "AS28573",
    "user_agent": FIREFOX_MAC,
}


def context_for(headers: dict) -> dict:
    """Build a fake request from 10.0.0.9 with these headers and return its context."""
    with routes.app.test_request_context(headers=headers, environ_base={"REMOTE_ADDR": "10.0.0.9"}):
        return client_context.get_context(request)


def test_user_agents_are_read_correctly():
    """Common browsers give the right browser, os and device."""
    expected_results = [
        (CHROME_WINDOWS, "Chrome", "Windows", "Desktop"),
        (EDGE_WINDOWS, "Edge", "Windows", "Desktop"),
        (FIREFOX_MAC, "Firefox", "macOS", "Desktop"),
        (SAFARI_IPHONE, "Safari", "iOS", "Mobile"),
        (CHROME_ANDROID, "Chrome", "Android", "Mobile"),
        ("Python-urllib/3.11", "Python script", "Other", "Desktop"),
    ]
    for user_agent, browser, os_name, device in expected_results:
        parsed = client_context.parse_user_agent(user_agent)
        assert parsed == {"browser": browser, "os": os_name, "device": device}


def test_empty_user_agent_gives_other():
    """A request with no User-Agent still gets a context."""
    parsed = client_context.parse_user_agent("")

    assert parsed == {"browser": "Other", "os": "Other", "device": "Desktop"}


def test_normal_request_is_local():
    """Without lab mode, the IP is the real one and country and asn are "local"."""
    context = context_for({"User-Agent": CHROME_WINDOWS})

    assert context["ip"] == "10.0.0.9"
    assert context["country"] == "local"
    assert context["asn"] == "local"
    assert context["browser"] == "Chrome"


def test_lab_header_is_used_when_lab_mode_is_on(monkeypatch):
    """With LAB_MODE on, the X-Lab-Client header replaces the real details."""
    monkeypatch.setattr(config, "LAB_MODE", True)
    headers = {"User-Agent": CHROME_WINDOWS, "X-Lab-Client": json.dumps(LAB_CLIENT)}

    context = context_for(headers)

    assert context["ip"] == "203.0.113.7"
    assert context["country"] == "BR"
    assert context["asn"] == "AS28573"
    assert context["browser"] == "Firefox"


def test_lab_header_is_ignored_when_lab_mode_is_off(monkeypatch):
    """With LAB_MODE off, nobody can fake where they are with the lab header."""
    monkeypatch.setattr(config, "LAB_MODE", False)
    headers = {"User-Agent": CHROME_WINDOWS, "X-Lab-Client": json.dumps(LAB_CLIENT)}

    context = context_for(headers)

    assert context["ip"] == "10.0.0.9"
    assert context["country"] == "local"
    assert context["asn"] == "local"
    assert context["browser"] == "Chrome"


def test_broken_lab_header_is_rejected(monkeypatch):
    """With LAB_MODE on, a lab header that is not JSON gives a 400 error."""
    monkeypatch.setattr(config, "LAB_MODE", True)

    with pytest.raises(BadRequest):
        context_for({"X-Lab-Client": "not json"})


def test_login_saves_context_to_history(client):
    """A login attempt saves the browser and country in login_history."""
    client.get("/login")
    with client.session_transaction() as flask_session:
        csrf_token = flask_session["csrf_token"]
    form = {"email": "alice@example.com", "password": "alice-demo-pass", "csrf_token": csrf_token}
    client.post("/login", data=form, headers={"User-Agent": FIREFOX_MAC})

    connection = db.get_connection()
    row = connection.execute("SELECT * FROM login_history").fetchone()
    connection.close()

    assert row["browser"] == "Firefox"
    assert row["os"] == "macOS"
    assert row["country"] == "local"
    assert row["success"] == 1
