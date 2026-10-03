"""App settings and loading of the secret keys from keys.json."""

import json
import secrets
from pathlib import Path

PROJECT_DIR = Path(__file__).resolve().parent.parent
KEYS_PATH = PROJECT_DIR / "keys.json"
KEY_NAMES = ["pepper", "aes_key", "flask_secret_key"]
# The SQLite file; *.db is in .gitignore so it is never committed
DB_PATH = PROJECT_DIR / "team20.db"

# "BASELINE" is what most sites do: rate limit + lockout only.
# "ADAPTIVE" also turns on the risk check and extra login steps from Part 2.
SECURITY_PROFILE = "BASELINE"

# Lab mode lets attack scripts fake their IP, country, ASN and browser with the
# X-Lab-Client header. Off by default: tests and attack runs turn it on.
LAB_MODE = False

# BASELINE numbers. Experiments change these to compare settings.
IP_FAIL_LIMIT = 5
IP_WINDOW_MINUTES = 10
LOCKOUT_FAILURES = 10
LOCKOUT_MINUTES = 15

# Risk engine (ADAPTIVE). Experiments change these to trade safety against
# how often real users get asked for an extra check.
RISK_MEDIUM = 3
RISK_HIGH = 7
# So risky that the IP gets blocked (used by the firewall later)
RISK_BLOCK = 12
# Points when a value is new or rare for this user (half if it is common for everyone)
FEATURE_POINTS = {"ip": 1, "asn": 2, "country": 3, "browser": 2, "os": 1, "device": 1}
# A value seen in at least this share of logins counts as usual
USUAL_SHARE = 0.1
# Velocity: how many things happened in the last RISK_WINDOW_MINUTES
RISK_WINDOW_MINUTES = 10
SITE_FAIL_LIMIT = 20
ACCOUNT_FAIL_LIMIT = 3
IP_ACCOUNTS_LIMIT = 3
VELOCITY_POINTS = 3


def load_keys(keys_path: Path = KEYS_PATH) -> dict:
    """Read the secret keys, or make and save new ones on the first run."""
    # Never overwrite an existing keys.json: a new pepper breaks every saved password
    if keys_path.exists():
        return json.loads(keys_path.read_text(encoding="utf-8"))

    # secrets (not random) gives values an attacker cannot predict
    keys = {}
    for name in KEY_NAMES:
        keys[name] = secrets.token_hex(32)

    keys_path.write_text(json.dumps(keys, indent=2), encoding="utf-8")
    return keys
