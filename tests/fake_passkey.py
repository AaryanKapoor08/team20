"""A fake passkey device for tests: it makes a key pair and signs challenges like a real one."""

import hashlib
import json
import secrets

import cbor2
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from webauthn.helpers import bytes_to_base64url

ORIGIN = "http://localhost:8000"
RP_ID = "localhost"
# Flag bits in the authenticator data
USER_PRESENT = 0x01
USER_VERIFIED = 0x04
HAS_CREDENTIAL_DATA = 0x40


def new_device() -> dict:
    """Return a new fake device with its own private key and credential id."""
    return {
        "private_key": ec.generate_private_key(ec.SECP256R1()),
        "credential_id": secrets.token_bytes(16),
        "sign_count": 0,
    }


def make_client_data(kind: str, challenge: str, origin: str) -> bytes:
    """Return the clientDataJSON a browser makes: what is signed, for which site."""
    client_data = {"type": kind, "challenge": challenge, "origin": origin, "crossOrigin": False}
    return json.dumps(client_data).encode("utf-8")


def make_authenticator_data(device: dict, flags: int, credential_data: bytes = b"") -> bytes:
    """Return the authenticator data: site hash, flags, sign count, then any credential data."""
    rp_id_hash = hashlib.sha256(RP_ID.encode("utf-8")).digest()
    sign_count = device["sign_count"].to_bytes(4, "big")
    return rp_id_hash + bytes([flags]) + sign_count + credential_data


def cose_public_key(device: dict) -> bytes:
    """Return the public key in COSE form, the CBOR key format WebAuthn uses."""
    numbers = device["private_key"].public_key().public_numbers()
    # kty 2 = EC2, alg -7 = ES256, crv 1 = P-256, then the x and y of the point
    cose_key = {
        1: 2,
        3: -7,
        -1: 1,
        -2: numbers.x.to_bytes(32, "big"),
        -3: numbers.y.to_bytes(32, "big"),
    }
    return cbor2.dumps(cose_key)


def register(device: dict, options_json: str, origin: str = ORIGIN) -> str:
    """Answer the server's registration options and return the JSON to send back."""
    options = json.loads(options_json)
    client_data = make_client_data("webauthn.create", options["challenge"], origin)

    credential_id = device["credential_id"]
    # 16 zero bytes say "unknown device model", then the id's length, the id and the public key
    id_length = len(credential_id).to_bytes(2, "big")
    credential_data = bytes(16) + id_length + credential_id + cose_public_key(device)
    flags = USER_PRESENT | USER_VERIFIED | HAS_CREDENTIAL_DATA
    auth_data = make_authenticator_data(device, flags, credential_data)
    # "none" attestation: the device does not prove which model it is
    attestation = cbor2.dumps({"fmt": "none", "attStmt": {}, "authData": auth_data})

    answer = {
        "id": bytes_to_base64url(credential_id),
        "rawId": bytes_to_base64url(credential_id),
        "type": "public-key",
        "response": {
            "clientDataJSON": bytes_to_base64url(client_data),
            "attestationObject": bytes_to_base64url(attestation),
        },
        "clientExtensionResults": {},
    }
    return json.dumps(answer)


def sign_in(device: dict, options_json: str, origin: str = ORIGIN) -> str:
    """Sign the server's login challenge and return the JSON to send back."""
    options = json.loads(options_json)
    client_data = make_client_data("webauthn.get", options["challenge"], origin)
    device["sign_count"] = device["sign_count"] + 1
    auth_data = make_authenticator_data(device, USER_PRESENT | USER_VERIFIED)

    # The device signs its own data plus a hash of the browser's data (which holds the origin)
    signed_bytes = auth_data + hashlib.sha256(client_data).digest()
    signature = device["private_key"].sign(signed_bytes, ec.ECDSA(hashes.SHA256()))

    answer = {
        "id": bytes_to_base64url(device["credential_id"]),
        "rawId": bytes_to_base64url(device["credential_id"]),
        "type": "public-key",
        "response": {
            "clientDataJSON": bytes_to_base64url(client_data),
            "authenticatorData": bytes_to_base64url(auth_data),
            "signature": bytes_to_base64url(signature),
        },
        "clientExtensionResults": {},
    }
    return json.dumps(answer)
