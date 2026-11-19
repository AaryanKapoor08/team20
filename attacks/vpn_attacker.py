"""Attacker 2: has the password but logs in through a VPN.

The password is correct and the VPN puts them in the victim's country, but the
network and browser are wrong, so the risk check should ask for a second factor.
Start the app with `python run.py --lab` first.
"""

import common

# the victim and their stolen password
VICTIM_EMAIL = "alice@example.com"
VICTIM_PASSWORD = "alice-demo-pass"

# where the victim normally logs in from
VICTIM_CONTEXT = {
    "ip": "24.70.15.5",
    "country": "CA",
    "asn": "AS852-Telus",
    "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/124.0 Safari/537.36",
}

# the attacker: same country, but a datacentre network and another browser
ATTACKER_CONTEXT = {
    "ip": "185.199.84.7",
    "country": "CA",
    "asn": "AS14061-DigitalOcean",
    "user_agent": "Mozilla/5.0 (X11; Linux x86_64) Firefox/125.0",
}


def run() -> None:
    """Build the victim's history, then attack from the VPN and report the result."""
    common.warn_lab_mode()

    # let the app learn the victim's usual device first
    common.establish_victim_history(VICTIM_EMAIL, VICTIM_PASSWORD, VICTIM_CONTEXT)

    opener = common.make_opener(ATTACKER_CONTEXT)
    response = common.attempt_login(opener, VICTIM_EMAIL, VICTIM_PASSWORD)
    outcome = common.describe_outcome(response)

    if outcome == "logged in":
        print("vpn_attacker: GOT IN with the stolen password (risk check did not fire)")
    else:
        print(f"vpn_attacker: stopped by {outcome}")


if __name__ == "__main__":
    common.require_localhost()
    run()
