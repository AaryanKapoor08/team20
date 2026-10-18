"""Attacker 2: has the victim's real password but logs in through a VPN.

This attacker phished or bought the correct password. They even route through a VPN
exit node in the victim's own country to look normal. But the network (ASN) and the
browser are not the victim's, so the risk check should notice and ask for a second
factor the attacker does not have.

Run our own app first with: python run.py --lab
"""

import common

# The victim and their correct (stolen) password
VICTIM_EMAIL = "alice@example.com"
VICTIM_PASSWORD = "alice-demo-pass"

# Where the victim normally logs in from: home ISP in Canada, on Chrome for Windows
VICTIM_CONTEXT = {
    "ip": "24.70.15.5",
    "country": "CA",
    "asn": "AS852-Telus",
    "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/124.0 Safari/537.36",
}

# The attacker: same country (VPN exit in Canada) but a datacentre ASN and Firefox on Linux
ATTACKER_CONTEXT = {
    "ip": "185.199.84.7",
    "country": "CA",
    "asn": "AS14061-DigitalOcean",
    "user_agent": "Mozilla/5.0 (X11; Linux x86_64) Firefox/125.0",
}


def run() -> None:
    """Build the victim's history, then attack from the VPN and report the result."""
    common.warn_lab_mode()

    # Teach the app the victim's usual device first, so there is something to compare against
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
