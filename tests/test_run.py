"""Tests for the command line flags of run.py."""

import os

import pytest

import run


@pytest.fixture
def clean_env(monkeypatch):
    """Start each test with neither setting in the environment."""
    monkeypatch.delenv("SECURITY_PROFILE", raising=False)
    monkeypatch.delenv("LAB_MODE", raising=False)


def test_no_flags_change_nothing(clean_env):
    """Plain `python run.py` leaves the defaults alone (ADAPTIVE, lab mode off)."""
    run.read_flags([])

    assert "SECURITY_PROFILE" not in os.environ
    assert "LAB_MODE" not in os.environ


def test_baseline_flag_picks_baseline(clean_env):
    """--baseline tells the app to use the BASELINE profile."""
    run.read_flags(["--baseline"])

    assert os.environ["SECURITY_PROFILE"] == "BASELINE"


def test_lab_flag_turns_on_lab_mode(clean_env):
    """--lab tells the app to read the X-Lab-Client header."""
    run.read_flags(["--lab"])

    assert os.environ["LAB_MODE"] == "1"


def test_unknown_flag_stops_with_usage(clean_env):
    """A typo like --labb stops the script instead of being ignored."""
    with pytest.raises(SystemExit):
        run.read_flags(["--labb"])
