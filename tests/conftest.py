"""Shared test setup: every test gets its own empty database in a temp folder."""

import pytest

from app import config
from app import db
from app import routes


@pytest.fixture
def temp_db(monkeypatch, tmp_path):
    """Point the app at a new database file with all tables made."""
    monkeypatch.setattr(config, "DB_PATH", tmp_path / "test.db")
    # Every test starts from the same settings, whatever the defaults or the shell say.
    # Tests that need ADAPTIVE or lab mode switch them on themselves.
    monkeypatch.setattr(config, "SECURITY_PROFILE", "BASELINE")
    monkeypatch.setattr(config, "LAB_MODE", False)
    db.create_tables()


@pytest.fixture
def demo_users(temp_db):
    """Add the 4 demo users to the temp database."""
    db.seed_demo_users(routes.keys["pepper"])


@pytest.fixture
def client(demo_users):
    """Return a test browser for the app, with the demo users added."""
    return routes.app.test_client()
