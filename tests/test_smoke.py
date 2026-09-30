"""Smoke test: checks that the main packages are installed."""


def test_main_packages_import():
    """Flask and argon2 import without errors."""
    import flask
    import argon2

    assert flask is not None
    assert argon2 is not None
