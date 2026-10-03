"""Tests for the BASELINE defense: per-IP rate limit and account lockout."""

from app import config
from app import db
from app import limits

ALICE_EMAIL = "alice@example.com"
ALICE_PASSWORD = "alice-demo-pass"


def log_in_from_ip(client, email, password, ip):
    """Send the login form from the given IP address and return the response."""
    client.get("/login")
    with client.session_transaction() as flask_session:
        csrf_token = flask_session["csrf_token"]
    form = {"email": email, "password": password, "csrf_token": csrf_token}
    return client.post("/login", data=form, environ_base={"REMOTE_ADDR": ip})


def set_locked_until(email, locked_until):
    """Set a user's lock end time directly, so tests do not have to wait."""
    connection = db.get_connection()
    connection.execute("UPDATE users SET locked_until = ? WHERE email = ?", (locked_until, email))
    connection.commit()
    connection.close()


def test_sixth_wrong_login_from_one_ip_is_blocked(client):
    """After 5 failures from one IP, the 6th try is blocked even for a new email."""
    for attempt in range(config.IP_FAIL_LIMIT):
        response = log_in_from_ip(client, f"nobody{attempt}@example.com", "wrong", "10.0.0.1")
        assert response.status_code == 401

    response = log_in_from_ip(client, "someone-else@example.com", "wrong", "10.0.0.1")

    assert response.status_code == 429
    assert b"Too many attempts. Try again later." in response.data


def test_blocked_ip_cannot_log_in_with_right_password(client):
    """A blocked IP is refused before the password is even checked."""
    for attempt in range(config.IP_FAIL_LIMIT):
        log_in_from_ip(client, f"nobody{attempt}@example.com", "wrong", "10.0.0.1")

    response = log_in_from_ip(client, ALICE_EMAIL, ALICE_PASSWORD, "10.0.0.1")

    assert response.status_code == 429


def test_other_ip_is_not_blocked(client):
    """Failures from one IP do not block a different IP."""
    for attempt in range(config.IP_FAIL_LIMIT):
        log_in_from_ip(client, f"nobody{attempt}@example.com", "wrong", "10.0.0.1")

    response = log_in_from_ip(client, ALICE_EMAIL, ALICE_PASSWORD, "10.0.0.2")

    assert response.status_code == 302


def test_old_failures_do_not_count(temp_db):
    """Failures from before the time window do not block the IP."""
    old_time = limits.time_in_minutes(-(config.IP_WINDOW_MINUTES + 1))
    connection = db.get_connection()
    for attempt in range(config.IP_FAIL_LIMIT):
        connection.execute(
            "INSERT INTO login_history (time, ip, success) VALUES (?, ?, ?)",
            (old_time, "10.0.0.1", False),
        )
    connection.commit()
    connection.close()

    assert limits.is_ip_blocked("10.0.0.1") is False


def test_account_locks_after_lockout_failures(client):
    """LOCKOUT_FAILURES wrong passwords lock the account, even from different IPs."""
    for attempt in range(config.LOCKOUT_FAILURES):
        log_in_from_ip(client, ALICE_EMAIL, "wrong", f"10.0.1.{attempt}")

    user = db.get_user_by_email(ALICE_EMAIL)

    assert limits.is_account_locked(user) is True


def test_locked_account_refuses_right_password(client):
    """While locked, even the right password gets the too-many-attempts message."""
    set_locked_until(ALICE_EMAIL, limits.time_in_minutes(5))

    response = log_in_from_ip(client, ALICE_EMAIL, ALICE_PASSWORD, "10.0.0.1")

    assert response.status_code == 429
    assert b"Too many attempts. Try again later." in response.data


def test_account_unlocks_when_lock_time_is_past(client):
    """Once locked_until is in the past, the right password works again."""
    set_locked_until(ALICE_EMAIL, limits.time_in_minutes(-1))

    response = log_in_from_ip(client, ALICE_EMAIL, ALICE_PASSWORD, "10.0.0.1")

    assert response.status_code == 302


def test_right_password_resets_failed_attempts(client):
    """A good login sets the failure count back to 0."""
    log_in_from_ip(client, ALICE_EMAIL, "wrong", "10.0.0.1")
    log_in_from_ip(client, ALICE_EMAIL, ALICE_PASSWORD, "10.0.0.1")

    user = db.get_user_by_email(ALICE_EMAIL)

    assert user["failed_attempts"] == 0
