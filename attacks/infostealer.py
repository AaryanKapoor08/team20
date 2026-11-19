"""Attacker 4: malware that copies a logged-in session cookie.

The victim logs in on their own machine and malware copies the cookie. The attacker
then replays that cookie from their own machine, which session binding should spot.
Start the app with `python run.py --lab` first.
"""

import common

# the victim and their stolen password
VICTIM_EMAIL = "carol@example.com"
VICTIM_PASSWORD = "carol-demo-pass"

# the victim's machine, where the cookie is made
VICTIM_CONTEXT = {
    "ip": "24.70.15.5",
    "country": "CA",
    "asn": "AS852-Telus",
    "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/124.0 Safari/537.36",
}

# the attacker's machine, somewhere else entirely
ATTACKER_CONTEXT = {
    "ip": "185.199.84.7",
    "country": "DE",
    "asn": "AS14061-DigitalOcean",
    "user_agent": "Mozilla/5.0 (X11; Linux x86_64) Firefox/125.0",
}


def run() -> None:
    """Log in as the victim, steal the cookie, then replay it from elsewhere."""
    common.warn_lab_mode()

    # step 1: the victim logs in and gets a real cookie
    victim = common.make_opener(VICTIM_CONTEXT)
    common.attempt_login(victim, VICTIM_EMAIL, VICTIM_PASSWORD)
    stolen_cookie = common.session_cookie(victim)
    if stolen_cookie == "":
        print("infostealer: could not get a session cookie (did the victim login succeed?)")
        return

    # step 2: the attacker reuses that cookie from another machine
    attacker = common.make_opener(ATTACKER_CONTEXT)
    if common.logged_in(attacker, cookie=stolen_cookie):
        print("infostealer: GOT IN by replaying the stolen cookie (session binding was off)")
    else:
        print("infostealer: stopped by session binding (cookie rejected from a new context)")


if __name__ == "__main__":
    common.require_localhost()
    run()
