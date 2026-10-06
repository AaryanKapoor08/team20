"""Tests for authenticator codes and the encryption of their secrets."""

import time

import pyotp

from app import db
from app import routes
from app import totp

AES_KEY = routes.keys["aes_key"]


def code_for_step(secret: str, steps_from_now: int) -> str:
    """Return the code the phone would show this many 30-second steps from now."""
    current_step = int(time.time()) // 30
    return pyotp.TOTP(secret).generate_otp(current_step + steps_from_now)


def alice_with_secret(secret: str):
    """Save a secret for Alice and return her user row."""
    alice = db.get_user_by_email("alice@example.com")
    totp.save_secret(alice["id"], secret, AES_KEY, 0)
    return db.get_user_by_id(alice["id"])


def test_encrypted_secret_decrypts_back():
    """Decrypting gives back the secret that went in."""
    secret = totp.new_secret()
    stored = totp.encrypt_secret(secret, AES_KEY)

    assert totp.decrypt_secret(stored, AES_KEY) == secret


def test_same_secret_encrypts_differently_each_time():
    """A new nonce each time means two encryptions never look the same."""
    secret = totp.new_secret()

    assert totp.encrypt_secret(secret, AES_KEY) != totp.encrypt_secret(secret, AES_KEY)


def test_database_value_is_not_the_plain_secret(demo_users):
    """The users table holds the encrypted secret, never the plain one."""
    secret = totp.new_secret()
    alice = alice_with_secret(secret)

    assert secret not in alice["totp_secret_encrypted"]


def test_right_code_is_accepted(demo_users):
    """The code the phone shows right now is accepted."""
    secret = totp.new_secret()
    alice = alice_with_secret(secret)

    assert totp.verify_code(alice, code_for_step(secret, 0), AES_KEY)


def test_wrong_code_is_rejected(demo_users):
    """A made-up code is rejected."""
    secret = totp.new_secret()
    alice = alice_with_secret(secret)
    right_code = code_for_step(secret, 0)
    wrong_code = "000000" if right_code != "000000" else "111111"

    assert not totp.verify_code(alice, wrong_code, AES_KEY)


def test_reused_code_is_rejected(demo_users):
    """The same code works once only."""
    secret = totp.new_secret()
    alice = alice_with_secret(secret)
    code = code_for_step(secret, 0)
    totp.verify_code(alice, code, AES_KEY)

    assert not totp.verify_code(alice, code, AES_KEY)


def test_code_from_one_step_ago_is_accepted(demo_users):
    """A phone clock that is 30 seconds slow still works."""
    secret = totp.new_secret()
    alice = alice_with_secret(secret)

    assert totp.verify_code(alice, code_for_step(secret, -1), AES_KEY)


def test_code_from_two_steps_ago_is_rejected():
    """A code older than one step is too old."""
    secret = totp.new_secret()

    assert totp.matching_step(secret, code_for_step(secret, -2)) is None


def test_non_ascii_code_is_rejected():
    """Odd characters are rejected instead of crashing compare_digest."""
    assert totp.matching_step(totp.new_secret(), "١٢٣٤٥٦") is None
