"""Attacker 3: copies the victim's whole setup.

This one knows the password and fakes the same country, network, browser and device,
so the login looks like the victim's own. If a code is asked for, it uses a phished
one. Start the app with `python run.py --lab` first.
"""

import sys
from pathlib import Path

# add the project root, so the app's own files can be imported
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

import pyotp

import common
from app import config
from app import db
from app import totp

# the victim and their stolen password
VICTIM_EMAIL = "bob@example.com"
VICTIM_PASSWORD = "bob-demo-pass"

# the victim's usual device, copied except for the IP
VICTIM_CONTEXT = {
    "ip": "24.70.15.5",
    "country": "CA",
    "asn": "AS852-Telus",
    "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/124.0 Safari/537.36",
}

# same as the victim everywhere except the IP
ATTACKER_CONTEXT = {
    "ip": "24.70.99.200",
    "country": "CA",
    "asn": "AS852-Telus",
    "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/124.0 Safari/537.36",
}


def phished_code(email: str) -> str:
    """Return a current TOTP code for the victim, or "" if they have no authenticator.

    In the lab this stands in for a code the attacker phished from the victim. It reads
    the victim's secret straight from our own database, decrypting it with the AES key.
    """
    user = db.get_user_by_email(email)
    if user is None or user["totp_secret_encrypted"] is None:
        return ""
    keys = config.load_keys()
    secret = totp.decrypt_secret(user["totp_secret_encrypted"], keys["aes_key"])
    return pyotp.TOTP(secret).now()


def submit_totp_code(opener, code: str) -> dict:
    """Send a TOTP code to the step-up page and return the response."""
    token = common.get_csrf_token(opener)
    form = {"code": code, "csrf_token": token}
    return common.send(opener, "/verify/totp", form)


def run() -> None:
    """Attack with a copied context, phishing a code if the app asks for one."""
    common.warn_lab_mode()

    # let the app learn the victim's usual device first
    common.establish_victim_history(VICTIM_EMAIL, VICTIM_PASSWORD, VICTIM_CONTEXT)

    opener = common.make_opener(ATTACKER_CONTEXT)
    response = common.attempt_login(opener, VICTIM_EMAIL, VICTIM_PASSWORD)
    outcome = common.describe_outcome(response)

    if outcome == "logged in":
        print("targeted_attacker: GOT IN with the password alone (copied context looked normal)")
        return

    if outcome == "risk step-up: TOTP code asked":
        code = phished_code(VICTIM_EMAIL)
        if code == "":
            print("targeted_attacker: asked for a TOTP code, but the victim has none set up")
            return
        after_code = submit_totp_code(opener, code)
        if common.logged_in(opener):
            print("targeted_attacker: GOT IN with a phished TOTP code")
        else:
            print(f"targeted_attacker: stopped at the code step ({common.describe_outcome(after_code)})")
        return

    if outcome == "risk step-up: passkey asked":
        print("targeted_attacker: stopped by passkey step-up (a passkey cannot be phished)")
        return

    print(f"targeted_attacker: stopped by {outcome}")


if __name__ == "__main__":
    common.require_localhost()
    run()
