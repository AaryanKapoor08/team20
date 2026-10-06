"""Authenticator app codes (TOTP) and AES encryption of their secrets."""

import hmac
import secrets
import sqlite3
import time

import pyotp
import qrcode
import qrcode.image.svg
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from app import db

ISSUER_NAME = "Team 20"
# AES-GCM needs a new 12-byte nonce (a one-time number) every time it encrypts
NONCE_BYTES = 12


def encrypt_secret(secret: str, aes_key: str) -> str:
    """Encrypt a TOTP secret and return it as text for the database."""
    # The AES key lives in keys.json, not in the database. A stolen database alone
    # only holds scrambled secrets, so the thief still cannot make valid codes.
    nonce = secrets.token_bytes(NONCE_BYTES)
    cipher = AESGCM(bytes.fromhex(aes_key))
    ciphertext = cipher.encrypt(nonce, secret.encode("utf-8"), None)
    # The nonce is not secret. It is stored next to the ciphertext so decrypt can use it.
    return nonce.hex() + ":" + ciphertext.hex()


def decrypt_secret(stored: str, aes_key: str) -> str:
    """Turn the text from encrypt_secret back into the TOTP secret."""
    nonce_hex, ciphertext_hex = stored.split(":")
    cipher = AESGCM(bytes.fromhex(aes_key))
    # GCM also checks the data was not changed; if it was, this raises InvalidTag
    secret_bytes = cipher.decrypt(bytes.fromhex(nonce_hex), bytes.fromhex(ciphertext_hex), None)
    return secret_bytes.decode("utf-8")


def new_secret() -> str:
    """Make a new random TOTP secret."""
    return pyotp.random_base32()


def qr_code_svg(secret: str, email: str) -> str:
    """Return a QR code, as SVG text, that an authenticator app can scan."""
    totp = pyotp.TOTP(secret)
    setup_link = totp.provisioning_uri(name=email, issuer_name=ISSUER_NAME)
    # The SVG output needs no image library (no Pillow)
    image = qrcode.make(setup_link, image_factory=qrcode.image.svg.SvgPathImage)
    return image.to_string(encoding="unicode")


def matching_step(secret: str, code: str) -> int | None:
    """Return the 30-second step this code belongs to, or None if the code is wrong."""
    # compare_digest only accepts plain ASCII text
    if not code.isascii():
        return None
    totp = pyotp.TOTP(secret)
    current_step = int(time.time()) // totp.interval
    # Also accept the step before and after, in case the phone's clock is a little off
    for step in [current_step - 1, current_step, current_step + 1]:
        expected_code = totp.generate_otp(step)
        # Takes the same time no matter which digit is wrong, so timing gives nothing away
        if hmac.compare_digest(expected_code, code):
            return step
    return None


def save_secret(user_id: int, secret: str, aes_key: str, used_step: int) -> None:
    """Save the user's secret encrypted, and mark the code used to confirm it as spent."""
    connection = db.get_connection()
    connection.execute(
        "UPDATE users SET totp_secret_encrypted = ?, totp_last_step = ? WHERE id = ?",
        (encrypt_secret(secret, aes_key), used_step, user_id),
    )
    connection.commit()
    connection.close()


def verify_code(user: sqlite3.Row, code: str, aes_key: str) -> bool:
    """Return True if the code is right and newer than the last code this user used."""
    secret = decrypt_secret(user["totp_secret_encrypted"], aes_key)
    step = matching_step(secret, code)
    if step is None:
        return False

    # The step is only saved if it is newer than the last one, so a code cannot be
    # used twice, even by two requests that arrive at the same moment
    connection = db.get_connection()
    cursor = connection.execute(
        "UPDATE users SET totp_last_step = ? "
        "WHERE id = ? AND (totp_last_step IS NULL OR totp_last_step < ?)",
        (step, user["id"], step),
    )
    rows_changed = cursor.rowcount
    connection.commit()
    connection.close()
    return rows_changed == 1
