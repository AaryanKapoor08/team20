"""Tests for the database connection, table setup and demo users."""

from datetime import datetime

from app import db
from app import passwords

EXPECTED_TABLES = ["audit_log", "blocked_ips", "login_history", "passkeys", "sessions", "users"]


def get_table_names() -> list:
    """Return the sorted names of all tables in the database file."""
    connection = db.get_connection()
    rows = connection.execute("SELECT name FROM sqlite_master WHERE type = 'table'").fetchall()
    connection.close()

    table_names = []
    for row in rows:
        table_names.append(row["name"])
    return sorted(table_names)


def test_every_table_exists_after_setup(temp_db):
    """create_tables makes all six tables."""
    assert get_table_names() == EXPECTED_TABLES


def test_create_tables_twice_gives_no_error(temp_db):
    """Running create_tables a second time is safe and keeps the same tables."""
    db.create_tables()

    assert get_table_names() == EXPECTED_TABLES


def test_rows_can_be_read_by_column_name(temp_db):
    """row_factory lets code write row["email"] instead of row[1]."""
    connection = db.get_connection()
    connection.execute(
        "INSERT INTO users (email, password_hash) VALUES (?, ?)",
        ("alice@example.com", "fake-hash"),
    )
    row = connection.execute("SELECT * FROM users").fetchone()
    connection.close()

    assert row["email"] == "alice@example.com"
    assert row["role"] == "user"


def test_utc_now_uses_sortable_text_format():
    """utc_now gives text like 2026-10-04T12:00:00 with no time zone suffix."""
    now_text = db.utc_now()
    parsed = datetime.strptime(now_text, db.TIME_FORMAT)

    assert len(now_text) == 19
    assert parsed.strftime(db.TIME_FORMAT) == now_text


def test_seed_adds_one_admin_and_three_users(temp_db):
    """seed_demo_users fills an empty users table with the 4 demo accounts."""
    db.seed_demo_users("test-pepper")
    connection = db.get_connection()
    rows = connection.execute("SELECT role FROM users").fetchall()
    connection.close()

    roles = []
    for row in rows:
        roles.append(row["role"])
    assert sorted(roles) == ["admin", "user", "user", "user"]


def test_seed_twice_does_not_add_more_users(temp_db):
    """A second seed sees the users already there and adds nothing."""
    db.seed_demo_users("test-pepper")
    db.seed_demo_users("test-pepper")
    connection = db.get_connection()
    user_count = connection.execute("SELECT COUNT(*) FROM users").fetchone()[0]
    connection.close()

    assert user_count == 4


def test_seeded_password_can_be_checked(temp_db):
    """A demo user's stored hash matches their demo password."""
    db.seed_demo_users("test-pepper")
    user = db.get_user_by_email("alice@example.com")

    assert passwords.check_password(user["password_hash"], "alice-demo-pass", "test-pepper")


def test_unknown_email_gives_no_user(temp_db):
    """get_user_by_email returns None when nobody has that email."""
    assert db.get_user_by_email("nobody@example.com") is None
