"""Per-IP rate limit and account lockout: the BASELINE defense against guessing."""

import sqlite3
from datetime import datetime, timedelta, timezone

from app import audit_log
from app import config
from app import db


def time_in_minutes(minutes: int) -> str:
    """Return the UTC time this many minutes from now (negative means in the past)."""
    moment = datetime.now(timezone.utc) + timedelta(minutes=minutes)
    return moment.strftime(db.TIME_FORMAT)


def is_ip_blocked(ip: str) -> bool:
    """Return True if this IP has too many failed logins in the recent time window."""
    window_start = time_in_minutes(-config.IP_WINDOW_MINUTES)
    connection = db.get_connection()
    failed_count = connection.execute(
        "SELECT COUNT(*) FROM login_history WHERE ip = ? AND success = 0 AND time >= ?",
        (ip, window_start),
    ).fetchone()[0]
    connection.close()
    return failed_count >= config.IP_FAIL_LIMIT


def is_account_locked(user: sqlite3.Row) -> bool:
    """Return True if the account's lock time is still in the future."""
    if user["locked_until"] is None:
        return False
    return user["locked_until"] > db.utc_now()


def record_failure(user: sqlite3.Row) -> None:
    """Count one more wrong password, and lock the account when there are too many."""
    connection = db.get_connection()
    # Adding 1 inside SQL (not in Python) keeps the count right when logins arrive at once
    connection.execute(
        "UPDATE users SET failed_attempts = failed_attempts + 1 WHERE id = ?", (user["id"],)
    )
    failed_attempts = connection.execute(
        "SELECT failed_attempts FROM users WHERE id = ?", (user["id"],)
    ).fetchone()[0]

    # Start counting from 0 again after a lock, so one typo after it ends does not re-lock
    should_lock = failed_attempts >= config.LOCKOUT_FAILURES
    if should_lock:
        connection.execute(
            "UPDATE users SET failed_attempts = 0, locked_until = ? WHERE id = ?",
            (time_in_minutes(config.LOCKOUT_MINUTES), user["id"]),
        )
    connection.commit()
    connection.close()
    # Written after commit: the audit log opens its own connection and needs the write lock
    if should_lock:
        audit_log.add_event("account_locked", {"user_id": user["id"], "minutes": config.LOCKOUT_MINUTES})


def record_success(user: sqlite3.Row) -> None:
    """Clear the failure count and any old lock after a correct password."""
    connection = db.get_connection()
    connection.execute(
        "UPDATE users SET failed_attempts = 0, locked_until = NULL WHERE id = ?", (user["id"],)
    )
    connection.commit()
    connection.close()
