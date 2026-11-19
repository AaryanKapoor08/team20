"""All the settings for the app in one place.

It also loads the three secret keys from keys.json, or makes them on the first run.
"""

import json
import os
import secrets
from pathlib import Path

PROJECT_DIR = Path(__file__).resolve().parent.parent
KEYS_PATH = PROJECT_DIR / "keys.json"
KEY_NAMES = ["pepper", "aes_key", "flask_secret_key"]
# the database file, never committed
DB_PATH = PROJECT_DIR / "team20.db"

# ADAPTIVE adds the risk check, BASELINE is rate limit and lockout only
SECURITY_PROFILE = os.environ.get("SECURITY_PROFILE", "ADAPTIVE")

# lets the attack scripts fake their IP and browser, off unless --lab
LAB_MODE = os.environ.get("LAB_MODE") == "1"

# BASELINE limits. The IP one is higher because people share an IP.
IP_FAIL_LIMIT = 20
IP_WINDOW_MINUTES = 10
LOCKOUT_FAILURES = 10
LOCKOUT_MINUTES = 15

# Risk engine, used in ADAPTIVE only.
RISK_MEDIUM = 3
RISK_HIGH = 7
# this risky and the IP is blocked on every page
RISK_BLOCK = 12
# points for a value that is new for this user
FEATURE_POINTS = {"ip": 1, "asn": 2, "country": 3, "browser": 2, "os": 1, "device": 1}
# a value seen this often counts as normal
USUAL_SHARE = 0.1
# how much happened in the last few minutes
RISK_WINDOW_MINUTES = 10
SITE_FAIL_LIMIT = 20
ACCOUNT_FAIL_LIMIT = 3
# 5, so a few people sharing one IP are not flagged
IP_ACCOUNTS_LIMIT = 5
VELOCITY_POINTS = 3
# how long you get to finish the extra check
PENDING_MINUTES = 5

# a cookie only works from the device it was made on, so a stolen one is useless
SESSION_BINDING = True

# the admin page opens from these IPs only
ADMIN_ALLOWED_IPS = ["127.0.0.1", "::1"]

# set by Docker only: trust the visitor IP that Nginx sends
BEHIND_PROXY = os.environ.get("BEHIND_PROXY") == "1"
# in Docker your own laptop shows up as the gateway address
docker_admin_ip = os.environ.get("DOCKER_ADMIN_IP")
if docker_admin_ip:
    ADMIN_ALLOWED_IPS.append(docker_admin_ip)

# where the experiment charts are saved
RESULTS_DIR = PROJECT_DIR / "results"

# passkeys are tied to this exact address, so a fake site cannot use them
PASSKEY_RP_ID = "localhost"
PASSKEY_RP_NAME = "Team 20"
PASSKEY_ORIGIN = "http://localhost:8000"


def load_keys(keys_path: Path = KEYS_PATH) -> dict:
    """Read the secret keys, or make and save new ones on the first run."""
    # never overwrite keys.json: a new pepper breaks every saved password
    if keys_path.exists():
        return json.loads(keys_path.read_text(encoding="utf-8"))

    # secrets, not random: an attacker cannot guess these
    keys = {}
    for name in KEY_NAMES:
        keys[name] = secrets.token_hex(32)

    keys_path.write_text(json.dumps(keys, indent=2), encoding="utf-8")
    return keys
