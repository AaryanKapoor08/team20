"""Test setup: every test gets its own empty database."""

import pytest

from app import config
from app import db
from app import routes


@pytest.fixture
def temp_db(monkeypatch, tmp_path):
    """Use a new database file in a temp folder, with the default settings."""
    monkeypatch.setattr(config, "DB_PATH", tmp_path / "test.db")
    monkeypatch.setattr(config, "SECURITY_PROFILE", "BASELINE")
    monkeypatch.setattr(config, "LAB_MODE", False)
    db.create_tables()


@pytest.fixture
def demo_users(temp_db):
    """Add the 4 demo accounts."""
    db.seed_demo_users(routes.keys["pepper"])


@pytest.fixture
def client(demo_users):
    """Return a test browser for the app."""
    return routes.app.test_client()
