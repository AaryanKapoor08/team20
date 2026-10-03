"""Shared test setup: every test gets its own empty database in a temp folder."""

import pytest

from app import config
from app import db
from app import routes


@pytest.fixture
def temp_db(monkeypatch, tmp_path):
    """Point the app at a new database file with all tables made."""
    monkeypatch.setattr(config, "DB_PATH", tmp_path / "test.db")
    db.create_tables()


@pytest.fixture
def client(temp_db):
    """Return a test browser for the app, with the demo users added."""
    db.seed_demo_users(routes.keys["pepper"])
    return routes.app.test_client()
