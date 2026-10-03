"""Tests for hashing and checking passwords."""

from app import passwords

PEPPER = "test-pepper"


def test_right_password_is_accepted():
    """The same password and pepper pass the check."""
    stored_hash = passwords.hash_password("correct horse", PEPPER)

    assert passwords.check_password(stored_hash, "correct horse", PEPPER) is True


def test_wrong_password_is_rejected():
    """A different password fails the check."""
    stored_hash = passwords.hash_password("correct horse", PEPPER)

    assert passwords.check_password(stored_hash, "wrong horse", PEPPER) is False


def test_hash_uses_argon2id():
    """The stored hash says it was made with Argon2id."""
    stored_hash = passwords.hash_password("correct horse", PEPPER)

    assert stored_hash.startswith("$argon2id$")


def test_same_password_gives_different_hashes():
    """The random salt makes two hashes of one password look different."""
    first_hash = passwords.hash_password("correct horse", PEPPER)
    second_hash = passwords.hash_password("correct horse", PEPPER)

    assert first_hash != second_hash


def test_wrong_pepper_is_rejected():
    """The right password with a different pepper fails, so a DB leak alone is not enough."""
    stored_hash = passwords.hash_password("correct horse", PEPPER)

    assert passwords.check_password(stored_hash, "correct horse", "other-pepper") is False
