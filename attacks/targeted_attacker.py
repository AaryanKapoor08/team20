"""Attacker 3: a targeted attacker who copies the victim's whole context.

This attacker did their homework. They know the victim's password and they fake the
same country, network (ASN), browser, OS and device, so the login looks like the
victim's own. If the risk check still asks for a TOTP code, they enter a phished code:
in the lab we read the victim's own secret to stand in for a code the attacker tricked
the victim into typing on a fake page.

This is the attack that shows a copied context and a phishable code are not enough to
stop: only a passkey, tied to the real site, resists it.

Run our own app first with: python run.py --lab
"""

import sys
from pathlib import Path

# Running `python attacks/targeted_attacker.py` puts attacks/ on the path, not the
# project root, so add the root to import the app's own TOTP and database helpers.
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

import pyotp

import common
from app import config
from app import db
from app import totp

# The victim and their correct (stolen) password
VICTIM_EMAIL = "bob@example.com"
VICTIM_PASSWORD = "bob-demo-pass"

# The victim's usual device, which this attacker copies exactly except for the IP
VICTIM_CONTEXT = {
    "ip": "24.70.15.5",
    "country": "CA",
    "asn": "AS852-Telus",
    "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/124.0 Safari/537.36",
}

# Same country, ASN, browser, OS and device as the victim; only the IP differs
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

    # Teach the app the victim's usual device first
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
