"""Attacker 5: locks a real user out on purpose.

This attacker does not want to get in. They send wrong passwords for a real account
until the lockout rule shuts the real owner out, which shows the cost of a plain
lockout. Start the app with `python run.py --lab` first.
"""

import common

# a real account, and some clearly wrong passwords to spend on it
VICTIM_EMAIL = "alice@example.com"
WRONG_PASSWORDS = ["wrong1", "wrong2", "wrong3", "wrong4", "wrong5"]

# one IP on purpose: the goal is the account's lockout counter
ATTACKER_CONTEXT = {
    "ip": "198.51.100.200",
    "country": "US",
    "asn": "AS1200",
    "user_agent": "Mozilla/5.0 (python lockout abuser)",
}

# stop after this many tries, so the script always ends
MAX_TRIES = 20


def run() -> None:
    """Send wrong passwords until the account locks, then report."""
    common.warn_lab_mode()

    wrong_count = 0
    for attempt_number in range(MAX_TRIES):
        # any wrong password counts toward the lockout
        password = WRONG_PASSWORDS[attempt_number % len(WRONG_PASSWORDS)]
        opener = common.make_opener(ATTACKER_CONTEXT)
        response = common.attempt_login(opener, VICTIM_EMAIL, password)
        outcome = common.describe_outcome(response)

        if outcome == "rate limit or account lockout":
            print(f"lockout_abuser: account locked after {wrong_count} wrong passwords")
            print("lockout_abuser: the real owner is now locked out too (plain lockout's weakness)")
            return
        wrong_count += 1

    print(f"lockout_abuser: sent {wrong_count} wrong passwords, account never locked")


if __name__ == "__main__":
    common.require_localhost()
    run()
