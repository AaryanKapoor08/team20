"""Turns passwords into hashes and checks them again at login.

It uses Argon2id with a salt for every password and a secret pepper kept outside
the database.
"""

import hashlib
import hmac

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError

# slow and memory hungry on purpose, so guessing takes forever
PASSWORD_HASHER = PasswordHasher()

# used when the email does not exist, so both answers take the same time
DUMMY_HASH = PASSWORD_HASHER.hash("not-a-real-password")


def add_pepper(password: str, pepper: str) -> str:
    """Mix the secret pepper into the password with HMAC-SHA256."""
    # the pepper lives in keys.json, so a leaked database is not enough
    peppered = hmac.new(pepper.encode("utf-8"), password.encode("utf-8"), hashlib.sha256)
    return peppered.hexdigest()


def hash_password(password: str, pepper: str) -> str:
    """Return the Argon2id hash of the peppered password, ready to store."""
    return PASSWORD_HASHER.hash(add_pepper(password, pepper))


def check_password(stored_hash: str, password: str, pepper: str) -> bool:
    """Return True if the password matches the stored hash."""
    try:
        return PASSWORD_HASHER.verify(stored_hash, add_pepper(password, pepper))
    except VerifyMismatchError:
        return False
