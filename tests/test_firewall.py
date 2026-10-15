"""Tests for the IP blocklist, the admin IP allowlist and the admin dashboard."""

import json

from app import audit_log
from app import client_context
from app import config
from app import db
from app import firewall

ALICE = {"email": "alice@example.com", "password": "alice-demo-pass"}
ADMIN = {"email": "admin@example.com", "password": "admin-demo-pass"}
BAD_IP = "203.0.113.5"
OTHER_IP = "198.51.100.7"
CHROME_WINDOWS = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/129.0 Safari/537.36"
)
FIREFOX_ANDROID = "Mozilla/5.0 (Android 14; Mobile; rv:130.0) Gecko/130.0 Firefox/130.0"
STRANGER = {"ip": "45.9.9.9", "country": "RU", "asn": "AS9009", "user_agent": FIREFOX_ANDROID}


def log_in(client, email: str, password: str, headers: dict | None = None):
    """Send the login form with a valid CSRF token and return the response."""
    client.get("/login", headers=headers)
    with client.session_transaction() as flask_session:
        csrf_token = flask_session["csrf_token"]
    form = {"email": email, "password": password, "csrf_token": csrf_token}
    return client.post("/login", data=form, headers=headers)


def give_alice_usual_history() -> None:
    """Save 10 normal logins for Alice from Canada on Chrome."""
    context = {"ip": "24.1.1.1", "country": "CA", "asn": "AS812"}
    context.update(client_context.parse_user_agent(CHROME_WINDOWS))
    alice_id = db.get_user_by_email(ALICE["email"])["id"]
    for attempt in range(10):
        db.record_login_attempt(alice_id, context, True)


def test_blocked_ip_gets_403(client):
    """Every page refuses a blocked IP, even the login page."""
    firewall.block_ip(BAD_IP, "test")
    response = client.get("/login", environ_base={"REMOTE_ADDR": BAD_IP})

    assert response.status_code == 403


def test_other_ips_still_get_in(client):
    """Blocking one IP does not affect other visitors."""
    firewall.block_ip(BAD_IP, "test")
    response = client.get("/login", environ_base={"REMOTE_ADDR": OTHER_IP})

    assert response.status_code == 200


def test_blocking_an_ip_is_saved_in_the_audit_log(temp_db):
    """block_ip writes an ip_blocked event and the chain still checks out."""
    firewall.block_ip(BAD_IP, "test")
    connection = db.get_connection()
    row = connection.execute("SELECT event, details FROM audit_log").fetchone()
    connection.close()

    assert row["event"] == "ip_blocked"
    assert json.loads(row["details"])["ip"] == BAD_IP
    assert audit_log.verify_chain() is None


def test_admin_ip_is_never_blocked(temp_db):
    """An IP on the admin allowlist cannot be put on the blocklist."""
    assert firewall.block_ip("127.0.0.1", "test") is False
    assert firewall.is_blocked("127.0.0.1") is False


def test_critical_risk_login_blocks_the_ip(client, monkeypatch):
    """A right password with a score at the block level blocks that IP for every page."""
    monkeypatch.setattr(config, "SECURITY_PROFILE", "ADAPTIVE")
    monkeypatch.setattr(config, "LAB_MODE", True)
    give_alice_usual_history()
    headers = {"X-Lab-Client": json.dumps(STRANGER)}
    # Everything new (10 points) plus 3 recent failures on the account (3 points) = 13
    for attempt in range(3):
        log_in(client, ALICE["email"], "wrong-password", headers)
    response = log_in(client, ALICE["email"], ALICE["password"], headers)

    assert response.status_code == 403
    assert firewall.is_blocked(STRANGER["ip"])
    assert client.get("/login", headers=headers).status_code == 403


def test_non_admin_gets_403(client):
    """A normal user cannot open the admin page, even from an allowed IP."""
    log_in(client, ALICE["email"], ALICE["password"])

    assert client.get("/admin").status_code == 403


def test_admin_from_allowed_ip_sees_the_dashboard(client):
    """The admin on localhost sees logins, blocked IPs and a good chain."""
    firewall.block_ip(BAD_IP, "test")
    log_in(client, ADMIN["email"], ADMIN["password"])
    response = client.get("/admin")

    assert response.status_code == 200
    assert b"admin@example.com" in response.data
    assert BAD_IP.encode() in response.data
    assert b"Audit log OK" in response.data


def test_admin_from_other_ip_gets_403(client):
    """The right admin password is not enough from an IP that is not on the allowlist."""
    client.environ_base["REMOTE_ADDR"] = OTHER_IP
    log_in(client, ADMIN["email"], ADMIN["password"])

    assert client.get("/admin").status_code == 403


def test_lab_header_cannot_fake_an_admin_ip(client, monkeypatch):
    """The allowlist reads the real network address, never the lab header."""
    monkeypatch.setattr(config, "LAB_MODE", True)
    client.environ_base["REMOTE_ADDR"] = OTHER_IP
    headers = {"X-Lab-Client": json.dumps({"ip": "127.0.0.1"})}
    log_in(client, ADMIN["email"], ADMIN["password"], headers)

    assert client.get("/admin", headers=headers).status_code == 403


def test_admin_can_unblock_an_ip(client):
    """The Unblock button takes the IP off the blocklist."""
    firewall.block_ip(BAD_IP, "test")
    log_in(client, ADMIN["email"], ADMIN["password"])
    with client.session_transaction() as flask_session:
        csrf_token = flask_session["csrf_token"]
    client.post("/admin/unblock", data={"ip": BAD_IP, "csrf_token": csrf_token})

    assert firewall.is_blocked(BAD_IP) is False


def test_non_admin_cannot_unblock(client):
    """A normal user's unblock request is refused and the IP stays blocked."""
    firewall.block_ip(BAD_IP, "test")
    log_in(client, ALICE["email"], ALICE["password"])
    with client.session_transaction() as flask_session:
        csrf_token = flask_session["csrf_token"]
    response = client.post("/admin/unblock", data={"ip": BAD_IP, "csrf_token": csrf_token})

    assert response.status_code == 403
    assert firewall.is_blocked(BAD_IP)


def test_dashboard_says_no_results_yet(client, monkeypatch, tmp_path):
    """Before any experiment has run, the charts area says so."""
    monkeypatch.setattr(config, "RESULTS_DIR", tmp_path / "results")
    log_in(client, ADMIN["email"], ADMIN["password"])

    assert b"No results yet" in client.get("/admin").data


def test_dashboard_shows_experiment_charts(client, monkeypatch, tmp_path):
    """A PNG in results/ is listed on the dashboard and can be opened by the admin."""
    monkeypatch.setattr(config, "RESULTS_DIR", tmp_path)
    (tmp_path / "e1_hashes.png").write_bytes(b"fake png")
    log_in(client, ADMIN["email"], ADMIN["password"])

    assert b"/admin/charts/e1_hashes.png" in client.get("/admin").data
    assert client.get("/admin/charts/e1_hashes.png").data == b"fake png"
