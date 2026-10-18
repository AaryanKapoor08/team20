"""Attacker 5: abuses the lockout rule to lock a real user out (a denial of service).

This attacker does not want to get in. They send wrong passwords for a real account on
purpose, so the account's lockout rule locks the real owner out. It shows the cost of a
plain lockout: the same rule that stops guessing can be turned against honest users.
Experiment E5 compares this with the risk-based handling, which does not punish the owner.

Run our own app first with: python run.py --lab
"""

import common

# A real account to lock out, and a few obviously wrong passwords to spend on it
VICTIM_EMAIL = "alice@example.com"
WRONG_PASSWORDS = ["wrong1", "wrong2", "wrong3", "wrong4", "wrong5"]

# The attacker stays on one IP: the goal is to burn the account's lockout counter
ATTACKER_CONTEXT = {
    "ip": "198.51.100.200",
    "country": "US",
    "asn": "AS1200",
    "user_agent": "Mozilla/5.0 (python lockout abuser)",
}

# Stop after this many tries even if the account never locks, so the script always ends
MAX_TRIES = 20


def run() -> None:
    """Send wrong passwords until the account locks, then report."""
    common.warn_lab_mode()

    wrong_count = 0
    for attempt_number in range(MAX_TRIES):
        # Cycle through the wrong passwords; any wrong one counts toward the lockout
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
