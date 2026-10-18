"""Attacker 1: a naive botnet that sprays leaked passwords from many fake IPs.

It knows nothing about the victims. It just tries a short list of common leaked
passwords against the demo accounts, each guess from a different fake IP and country
so no single IP trips the per-IP rate limit. This is the attack the app should shrug
off with password strength alone, because none of these passwords are real.

Run our own app first with: python run.py --lab
"""

import common

# The demo accounts the botnet knows exist (emails are easy to guess or leak)
TARGET_EMAILS = [
    "alice@example.com",
    "bob@example.com",
    "carol@example.com",
    "admin@example.com",
]

# A short list of the kind of passwords that top every leaked-password dump
LEAKED_PASSWORDS = [
    "123456",
    "password",
    "qwerty",
    "letmein",
    "welcome",
]

# A few fake IPs and countries to spread the guesses across, like a real botnet
FAKE_SOURCES = [
    {"ip": "203.0.113.10", "country": "BR", "asn": "AS1001"},
    {"ip": "198.51.100.22", "country": "RU", "asn": "AS1002"},
    {"ip": "192.0.2.33", "country": "CN", "asn": "AS1003"},
    {"ip": "203.0.113.44", "country": "IN", "asn": "AS1004"},
    {"ip": "198.51.100.55", "country": "NG", "asn": "AS1005"},
    {"ip": "192.0.2.66", "country": "VN", "asn": "AS1006"},
]

BOT_USER_AGENT = "Mozilla/5.0 (python botnet)"


def run() -> None:
    """Spray the leaked passwords and report how the app held up."""
    common.warn_lab_mode()

    got_in = 0
    rejected = 0
    rate_limited = 0
    source_number = 0

    for email in TARGET_EMAILS:
        for password in LEAKED_PASSWORDS:
            # Use the next fake source, so guesses are spread thin across many IPs
            source = FAKE_SOURCES[source_number % len(FAKE_SOURCES)]
            source_number += 1
            lab_client = {
                "ip": source["ip"],
                "country": source["country"],
                "asn": source["asn"],
                "user_agent": BOT_USER_AGENT,
            }
            opener = common.make_opener(lab_client)
            response = common.attempt_login(opener, email, password)
            outcome = common.describe_outcome(response)

            if outcome == "logged in":
                got_in += 1
            elif "rate limit" in outcome or "block" in outcome or "firewall" in outcome:
                rate_limited += 1
            else:
                rejected += 1

    total = got_in + rejected + rate_limited
    print(f"naive_botnet: tried {total} guesses from {len(FAKE_SOURCES)} fake IPs")
    print(f"  got in: {got_in}")
    print(f"  wrong password, rejected: {rejected}")
    print(f"  stopped by rate limit or block: {rate_limited}")
    if got_in == 0:
        print("naive_botnet: stopped (none of the leaked passwords were real)")
    else:
        print("naive_botnet: WARNING, a leaked password worked")


if __name__ == "__main__":
    common.require_localhost()
    run()
