"""Attacker 4: infostealer malware that copies a logged-in session cookie.

The victim already logged in on their own machine. Malware on that machine copies both
the password and the live session cookie. The attacker then replays the stolen cookie
from their own machine, a different network and browser. Session binding should notice
the cookie is being used from a context it was never issued to, and drop it.

Run our own app first with: python run.py --lab
"""

import common

# The victim and their correct (stolen) password
VICTIM_EMAIL = "carol@example.com"
VICTIM_PASSWORD = "carol-demo-pass"

# The victim's machine, where the cookie is born
VICTIM_CONTEXT = {
    "ip": "24.70.15.5",
    "country": "CA",
    "asn": "AS852-Telus",
    "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/124.0 Safari/537.36",
}

# The attacker's machine, replaying the stolen cookie from somewhere else entirely
ATTACKER_CONTEXT = {
    "ip": "185.199.84.7",
    "country": "DE",
    "asn": "AS14061-DigitalOcean",
    "user_agent": "Mozilla/5.0 (X11; Linux x86_64) Firefox/125.0",
}


def run() -> None:
    """Log in as the victim, steal the cookie, then replay it from elsewhere."""
    common.warn_lab_mode()

    # Step 1: the victim logs in normally and gets a real session cookie
    victim = common.make_opener(VICTIM_CONTEXT)
    common.attempt_login(victim, VICTIM_EMAIL, VICTIM_PASSWORD)
    stolen_cookie = common.session_cookie(victim)
    if stolen_cookie == "":
        print("infostealer: could not get a session cookie (did the victim login succeed?)")
        return

    # Step 2: the attacker replays that exact cookie from a different machine
    attacker = common.make_opener(ATTACKER_CONTEXT)
    if common.logged_in(attacker, cookie=stolen_cookie):
        print("infostealer: GOT IN by replaying the stolen cookie (session binding was off)")
    else:
        print("infostealer: stopped by session binding (cookie rejected from a new context)")


if __name__ == "__main__":
    common.require_localhost()
    run()
