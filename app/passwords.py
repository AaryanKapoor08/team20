"""Hashing and checking passwords with Argon2id, a salt and a pepper."""

import hashlib
import hmac

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError

# Argon2id is slow on purpose and uses a lot of memory, so guessing passwords
# from a stolen database takes a very long time. It adds a random salt per hash.
PASSWORD_HASHER = PasswordHasher()

# Checked against when the email does not exist, so a wrong email takes as long
# as a wrong password and the response time does not reveal which emails exist.
DUMMY_HASH = PASSWORD_HASHER.hash("not-a-real-password")


def add_pepper(password: str, pepper: str) -> str:
    """Mix the secret pepper into the password with HMAC-SHA256."""
    # The pepper lives in keys.json, not the database, so a DB leak alone is not enough
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
