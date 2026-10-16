"""App settings and loading of the secret keys from keys.json."""

import json
import os
import secrets
from pathlib import Path

PROJECT_DIR = Path(__file__).resolve().parent.parent
KEYS_PATH = PROJECT_DIR / "keys.json"
KEY_NAMES = ["pepper", "aes_key", "flask_secret_key"]
# The SQLite file; *.db is in .gitignore so it is never committed
DB_PATH = PROJECT_DIR / "team20.db"

# "ADAPTIVE" (the default) turns on the risk check and extra login steps from Part 2.
# "BASELINE" is what most sites do: rate limit + lockout only. `python run.py --baseline`
# picks it; run.py passes the choice on in the SECURITY_PROFILE environment variable.
SECURITY_PROFILE = os.environ.get("SECURITY_PROFILE", "ADAPTIVE")

# Lab mode lets attack scripts fake their IP, country, ASN and browser with the
# X-Lab-Client header. Off unless started with `python run.py --lab`.
LAB_MODE = os.environ.get("LAB_MODE") == "1"

# BASELINE numbers. Experiments change these to compare settings.
# Higher than LOCKOUT_FAILURES on purpose: many people can share one IP (campus Wi-Fi,
# a home router), so a few typos there must not lock everyone on it out
IP_FAIL_LIMIT = 20
IP_WINDOW_MINUTES = 10
LOCKOUT_FAILURES = 10
LOCKOUT_MINUTES = 15

# Risk engine (ADAPTIVE). Experiments change these to trade safety against
# how often real users get asked for an extra check.
RISK_MEDIUM = 3
RISK_HIGH = 7
# So risky that the firewall blocks the IP for every page, not just this login
RISK_BLOCK = 12
# Points when a value is new or rare for this user (half if it is common for everyone)
FEATURE_POINTS = {"ip": 1, "asn": 2, "country": 3, "browser": 2, "os": 1, "device": 1}
# A value seen in at least this share of logins counts as usual
USUAL_SHARE = 0.1
# Velocity: how many things happened in the last RISK_WINDOW_MINUTES
RISK_WINDOW_MINUTES = 10
SITE_FAIL_LIMIT = 20
ACCOUNT_FAIL_LIMIT = 3
# 5, not 3: a few people sharing one IP who each mistype once is not credential
# stuffing. Real stuffing tries hundreds of accounts per IP, so 5 still catches it.
IP_ACCOUNTS_LIMIT = 5
VELOCITY_POINTS = 3
# How long a half logged in user has to pass the extra check
PENDING_MINUTES = 5

# A session cookie only works from the browser, OS and network it was made on.
# On by default; experiment E4 turns it off to show what a stolen cookie can do.
SESSION_BINDING = True

# The admin page only opens from these IPs, even for an admin account.
# A stolen admin password alone is then not enough: the attacker must also be on this machine.
ADMIN_ALLOWED_IPS = ["127.0.0.1", "::1"]

# Only docker-compose.yml sets these. Behind Nginx, Flask learns the visitor's IP
# from Nginx's X-Forwarded-For header. Trusted only when BEHIND_PROXY is on:
# without Nginx in front, anyone could send that header and pick any IP they like.
BEHIND_PROXY = os.environ.get("BEHIND_PROXY") == "1"
# Inside Docker your own laptop shows up as the Docker network's gateway address
docker_admin_ip = os.environ.get("DOCKER_ADMIN_IP")
if docker_admin_ip:
    ADMIN_ALLOWED_IPS.append(docker_admin_ip)

# Experiment charts (PNG files) are saved here and shown on the admin page
RESULTS_DIR = PROJECT_DIR / "results"

# Passkeys are tied to the site's address. A browser only signs for this exact
# origin, so a look-alike phishing site cannot use a passkey made here.
# Passkeys refuse IP addresses, which is why the app always runs on "localhost".
PASSKEY_RP_ID = "localhost"
PASSKEY_RP_NAME = "Team 20"
PASSKEY_ORIGIN = "http://localhost:8000"


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
