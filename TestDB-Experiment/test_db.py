"""Tests for the database tables and the demo accounts."""

from datetime import datetime

from app import db
from app import passwords

ALL_TABLES = ["audit_log", "blocked_ips", "login_history", "passkeys", "sessions", "users"]


def table_names():
    """Return the names of all tables, sorted."""
    connection = db.get_connection()
    rows = connection.execute("SELECT name FROM sqlite_master WHERE type = 'table'").fetchall()
    connection.close()
    names = []
    for row in rows:
        names.append(row["name"])
    return sorted(names)


def count_users():
    """Return how many users are in the database."""
    connection = db.get_connection()
    user_count = connection.execute("SELECT COUNT(*) FROM users").fetchone()[0]
    connection.close()
    return user_count


def test_every_table_exists(temp_db):
    """Check generated tables"""
    assert table_names() == ALL_TABLES


def test_making_tables_twice_is_fine(temp_db):
    db.create_tables()
    assert table_names() == ALL_TABLES


def test_rows_can_be_read_by_name(temp_db):
    connection = db.get_connection()
    connection.execute("INSERT INTO users (email, password_hash) VALUES (?, ?)", ("alice@example.com", "x"))
    row = connection.execute("SELECT * FROM users").fetchone()
    connection.close()
    assert row["email"] == "alice@example.com"
    assert row["role"] == "user"


def test_time_text_looks_right():
    now_text = db.utc_now()
    assert len(now_text) == 19
    assert datetime.strptime(now_text, db.TIME_FORMAT).strftime(db.TIME_FORMAT) == now_text


def test_seed_adds_four_users(temp_db):
    db.seed_demo_users("test-pepper")
    assert count_users() == 4


def test_seed_twice_adds_nothing_more(temp_db):
    db.seed_demo_users("test-pepper")
    db.seed_demo_users("test-pepper")
    assert count_users() == 4


def test_demo_password_works(temp_db):
    """Check given password is matched"""
    db.seed_demo_users("test-pepper")
    user = db.get_user_by_email("alice@example.com")
    assert passwords.check_password(user["password_hash"], "alice-demo-pass", "test-pepper")


def test_unknown_email_gives_none(temp_db):
    """Check non-existing user email"""
    assert db.get_user_by_email("nobody@example.com") is None
