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

# BASELINE numbers. Experiments change these to compare settings.
IP_FAIL_LIMIT = 5
IP_WINDOW_MINUTES = 10
LOCKOUT_FAILURES = 10
LOCKOUT_MINUTES = 15


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
