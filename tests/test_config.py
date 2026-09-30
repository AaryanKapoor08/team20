"""Tests for loading the secret keys from keys.json."""

from app import config


def test_keys_file_is_made_on_first_run(tmp_path):
    """The first load creates keys.json with all three keys."""
    keys_path = tmp_path / "keys.json"
    keys = config.load_keys(keys_path)

    assert keys_path.exists()
    assert sorted(keys) == sorted(config.KEY_NAMES)


def test_keys_do_not_change_on_second_load(tmp_path):
    """Loading twice gives the same keys, so keys.json is never overwritten."""
    keys_path = tmp_path / "keys.json"
    first_keys = config.load_keys(keys_path)
    second_keys = config.load_keys(keys_path)

    assert first_keys == second_keys
