"""Six-digit codes from an authenticator app.

It makes the secret, draws the QR code, checks a code, and keeps the secret
encrypted so the database alone is not enough to make codes.
"""

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
# AES needs a new 12-byte one-time number for every secret
NONCE_BYTES = 12


def encrypt_secret(secret: str, aes_key: str) -> str:
    """Encrypt a TOTP secret and return it as text for the database."""
    # the key lives in keys.json, so a stolen database holds scrambled secrets only
    nonce = secrets.token_bytes(NONCE_BYTES)
    cipher = AESGCM(bytes.fromhex(aes_key))
    ciphertext = cipher.encrypt(nonce, secret.encode("utf-8"), None)
    # the one-time number is not secret, decrypting needs it
    return nonce.hex() + ":" + ciphertext.hex()


def decrypt_secret(stored: str, aes_key: str) -> str:
    """Turn the text from encrypt_secret back into the TOTP secret."""
    nonce_hex, ciphertext_hex = stored.split(":")
    cipher = AESGCM(bytes.fromhex(aes_key))
    # this also fails if someone changed the stored text
    secret_bytes = cipher.decrypt(bytes.fromhex(nonce_hex), bytes.fromhex(ciphertext_hex), None)
    return secret_bytes.decode("utf-8")


def new_secret() -> str:
    """Make a new random TOTP secret."""
    return pyotp.random_base32()


def qr_code_svg(secret: str, email: str) -> str:
    """Return a QR code, as SVG text, that an authenticator app can scan."""
    totp = pyotp.TOTP(secret)
    setup_link = totp.provisioning_uri(name=email, issuer_name=ISSUER_NAME)
    # SVG, so no image library is needed
    image = qrcode.make(setup_link, image_factory=qrcode.image.svg.SvgPathImage)
    return image.to_string(encoding="unicode")


def matching_step(secret: str, code: str) -> int | None:
    """Return the 30-second step this code belongs to, or None if the code is wrong."""
    # compare_digest only takes plain ASCII
    if not code.isascii():
        return None
    totp = pyotp.TOTP(secret)
    current_step = int(time.time()) // totp.interval
    # also take the step before and after, in case the phone clock is off
    for step in [current_step - 1, current_step, current_step + 1]:
        expected_code = totp.generate_otp(step)
        # same speed for any wrong digit, so timing gives nothing away
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

    # saved only if newer, so the same code cannot be used twice
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
