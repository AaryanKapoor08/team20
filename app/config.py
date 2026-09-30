"""App settings and loading of the secret keys from keys.json."""

import json
import secrets
from pathlib import Path

PROJECT_DIR = Path(__file__).resolve().parent.parent
KEYS_PATH = PROJECT_DIR / "keys.json"
KEY_NAMES = ["pepper", "aes_key", "flask_secret_key"]


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
