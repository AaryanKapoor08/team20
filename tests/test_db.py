"""Tests for the database connection, table setup and demo users."""

from datetime import datetime

from app import db
from app import passwords

EXPECTED_TABLES = ["audit_log", "blocked_ips", "login_history", "passkeys", "sessions", "users"]


def get_table_names(db_path) -> list:
    """Return the sorted names of all tables in the database file."""
    connection = db.get_connection(db_path)
    rows = connection.execute("SELECT name FROM sqlite_master WHERE type = 'table'").fetchall()
    connection.close()

    table_names = []
    for row in rows:
        table_names.append(row["name"])
    return sorted(table_names)


def test_every_table_exists_after_setup(tmp_path):
    """create_tables makes all six tables."""
    db_path = tmp_path / "test.db"
    db.create_tables(db_path)

    assert get_table_names(db_path) == EXPECTED_TABLES


def test_create_tables_twice_gives_no_error(tmp_path):
    """Running create_tables a second time is safe and keeps the same tables."""
    db_path = tmp_path / "test.db"
    db.create_tables(db_path)
    db.create_tables(db_path)

    assert get_table_names(db_path) == EXPECTED_TABLES


def test_rows_can_be_read_by_column_name(tmp_path):
    """row_factory lets code write row["email"] instead of row[1]."""
    db_path = tmp_path / "test.db"
    db.create_tables(db_path)
    connection = db.get_connection(db_path)
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


def test_seed_adds_one_admin_and_three_users(tmp_path):
    """seed_demo_users fills an empty users table with the 4 demo accounts."""
    db_path = tmp_path / "test.db"
    db.create_tables(db_path)
    db.seed_demo_users("test-pepper", db_path)
    connection = db.get_connection(db_path)
    rows = connection.execute("SELECT role FROM users").fetchall()
    connection.close()

    roles = []
    for row in rows:
        roles.append(row["role"])
    assert sorted(roles) == ["admin", "user", "user", "user"]


def test_seed_twice_does_not_add_more_users(tmp_path):
    """A second seed sees the users already there and adds nothing."""
    db_path = tmp_path / "test.db"
    db.create_tables(db_path)
    db.seed_demo_users("test-pepper", db_path)
    db.seed_demo_users("test-pepper", db_path)
    connection = db.get_connection(db_path)
    user_count = connection.execute("SELECT COUNT(*) FROM users").fetchone()[0]
    connection.close()

    assert user_count == 4


def test_seeded_password_can_be_checked(tmp_path):
    """A demo user's stored hash matches their demo password."""
    db_path = tmp_path / "test.db"
    db.create_tables(db_path)
    db.seed_demo_users("test-pepper", db_path)
    connection = db.get_connection(db_path)
    row = connection.execute(
        "SELECT password_hash FROM users WHERE email = ?", ("alice@example.com",)
    ).fetchone()
    connection.close()

    assert passwords.check_password(row["password_hash"], "alice-demo-pass", "test-pepper")
