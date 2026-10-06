"""Passkeys (WebAuthn): save a device's public key, then check its signed logins."""

import sqlite3

import webauthn
from webauthn.helpers import bytes_to_base64url, parse_authentication_credential_json
from webauthn.helpers.exceptions import WebAuthnException
from webauthn.helpers.structs import PublicKeyCredentialDescriptor

from app import config
from app import db


def get_passkeys(user_id: int) -> list:
    """Return all passkey rows saved for this user."""
    connection = db.get_connection()
    passkey_rows = connection.execute(
        "SELECT * FROM passkeys WHERE user_id = ?", (user_id,)
    ).fetchall()
    connection.close()
    return passkey_rows


def credential_list(user_id: int) -> list:
    """Return the user's passkey ids in the form py_webauthn wants."""
    descriptors = []
    for passkey_row in get_passkeys(user_id):
        descriptors.append(PublicKeyCredentialDescriptor(id=passkey_row["credential_id"]))
    return descriptors


def registration_options(user: sqlite3.Row) -> tuple[str, str]:
    """Return the options for adding a passkey (as JSON) and their challenge (as text)."""
    # exclude_credentials stops the same device being added twice
    options = webauthn.generate_registration_options(
        rp_id=config.PASSKEY_RP_ID,
        rp_name=config.PASSKEY_RP_NAME,
        user_name=user["email"],
        exclude_credentials=credential_list(user["id"]),
    )
    return webauthn.options_to_json(options), bytes_to_base64url(options.challenge)


def save_passkey(user_id: int, credential_json: str, challenge: str) -> bool:
    """Check the device's answer and save its public key. Returns False if it is not valid."""
    try:
        verified = webauthn.verify_registration_response(
            credential=credential_json,
            expected_challenge=webauthn.base64url_to_bytes(challenge),
            expected_rp_id=config.PASSKEY_RP_ID,
            expected_origin=config.PASSKEY_ORIGIN,
        )
    except WebAuthnException:
        return False

    # Only the public key is saved. The private key never leaves the user's device,
    # so a stolen database cannot be used to log in.
    connection = db.get_connection()
    try:
        connection.execute(
            "INSERT INTO passkeys (credential_id, user_id, public_key, sign_count) "
            "VALUES (?, ?, ?, ?)",
            (verified.credential_id, user_id, verified.credential_public_key, verified.sign_count),
        )
        connection.commit()
    except sqlite3.IntegrityError:
        # This passkey is already saved
        return False
    finally:
        connection.close()
    return True


def authentication_options(user_id: int) -> tuple[str, str]:
    """Return the options for a passkey login (as JSON) and their challenge (as text)."""
    options = webauthn.generate_authentication_options(
        rp_id=config.PASSKEY_RP_ID,
        allow_credentials=credential_list(user_id),
    )
    return webauthn.options_to_json(options), bytes_to_base64url(options.challenge)


def check_login(user_id: int, credential_json: str, challenge: str) -> bool:
    """Return True if the device signed this login's challenge with one of the user's passkeys."""
    try:
        credential = parse_authentication_credential_json(credential_json)
    except WebAuthnException:
        return False
    passkey_row = find_passkey(user_id, credential.raw_id)
    if passkey_row is None:
        return False

    try:
        verified = webauthn.verify_authentication_response(
            credential=credential,
            expected_challenge=webauthn.base64url_to_bytes(challenge),
            expected_rp_id=config.PASSKEY_RP_ID,
            expected_origin=config.PASSKEY_ORIGIN,
            credential_public_key=passkey_row["public_key"],
            credential_current_sign_count=passkey_row["sign_count"],
        )
    except WebAuthnException:
        return False

    # The device counts its logins. py_webauthn rejects a count that went backwards,
    # which is a sign the passkey was copied.
    connection = db.get_connection()
    connection.execute(
        "UPDATE passkeys SET sign_count = ? WHERE credential_id = ?",
        (verified.new_sign_count, passkey_row["credential_id"]),
    )
    connection.commit()
    connection.close()
    return True


def find_passkey(user_id: int, credential_id: bytes) -> sqlite3.Row | None:
    """Return this user's passkey row with this id, or None."""
    connection = db.get_connection()
    passkey_row = connection.execute(
        "SELECT * FROM passkeys WHERE credential_id = ? AND user_id = ?",
        (credential_id, user_id),
    ).fetchone()
    connection.close()
    return passkey_row
