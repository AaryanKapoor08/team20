"""Attacker 1: a botnet spraying common leaked passwords.

It knows nothing about the victims and tries a short list of common passwords from
many fake IPs, so no single IP trips the rate limit. Start the app with
`python run.py --lab` first.
"""

import common

# the demo accounts, since emails are easy to guess
TARGET_EMAILS = [
    "alice@example.com",
    "bob@example.com",
    "carol@example.com",
    "admin@example.com",
]

# the kind of passwords that top every leaked list
LEAKED_PASSWORDS = [
    "123456",
    "password",
    "qwerty",
    "letmein",
    "welcome",
]

# fake IPs to spread the guesses across, like a real botnet
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
            # next fake IP, so no single one is used much
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
