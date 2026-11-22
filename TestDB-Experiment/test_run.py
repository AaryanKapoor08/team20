"""Tests for the --baseline and --lab flags of run.py."""

import os
import pytest
import run


@pytest.fixture
def clean_env(monkeypatch):
    """Start with neither setting in the environment."""
    monkeypatch.delenv("SECURITY_PROFILE", raising=False)
    monkeypatch.delenv("LAB_MODE", raising=False)


def test_no_flags_change_nothing(clean_env):
     """Check flags if on the list"""
    run.read_flags([])
    assert "SECURITY_PROFILE" not in os.environ
    assert "LAB_MODE" not in os.environ


def test_baseline_flag(clean_env):
    """Check baseline flag"""
    run.read_flags(["--baseline"])
    assert os.environ["SECURITY_PROFILE"] == "BASELINE"


def test_lab_flag(clean_env):
    """Check lab environment"""
    run.read_flags(["--lab"])
    assert os.environ["LAB_MODE"] == "1"


def test_unknown_flag_stops(clean_env):
    """Check non-existing environment"""

    with pytest.raises(SystemExit):
        run.read_flags(["--labs"])
