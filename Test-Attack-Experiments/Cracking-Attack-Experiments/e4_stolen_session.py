"""E4: does a stolen session cookie still work from another device?

The victim logs in, then the same cookie is used from the attacker's machine.
Done twice: with session binding on, then off.
Run from the project root:  python experiments/e4_stolen_session.py
"""

import csv
import json
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

from app import config

# settings must be made before the app is imported
config.DB_PATH = Path(tempfile.mkdtemp()) / "startup.db"
config.SECURITY_PROFILE = "ADAPTIVE"
config.LAB_MODE = True

from app import db
from app import routes

CSV_PATH = ROOT / "results" / "e4_stolen_session.csv"
CHART_PATH = ROOT / "results" / "e4_stolen_session.png"

VICTIM = {
    "ip": "24.70.15.5",
    "country": "CA",
    "asn": "AS852-Telus",
    "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/124.0 Safari/537.36",
}
ATTACKER = {
    "ip": "185.199.84.7",
    "country": "DE",
    "asn": "AS14061-DigitalOcean",
    "user_agent": "Mozilla/5.0 (X11; Linux x86_64) Firefox/125.0",
}


def from_place(place):
    """Return the lab header that says where a request comes from."""
    return {"X-Lab-Client": json.dumps(place)}


def try_stolen_cookie(binding_on):
    """Log the victim in, then use their cookie from the attacker's place."""
    config.DB_PATH = Path(tempfile.mkdtemp()) / "experiment.db"
    db.create_tables()
    db.seed_demo_users(routes.keys["pepper"])
    config.SESSION_BINDING = binding_on

    browser = routes.app.test_client()
    browser.get("/login", headers=from_place(VICTIM))
    with browser.session_transaction() as flask_session:
        token = flask_session["csrf_token"]
    form = {"email": "carol@example.com", "password": "carol-demo-pass", "csrf_token": token}
    browser.post("/login", data=form, headers=from_place(VICTIM))

    # same browser and cookie, but now the request comes from the attacker
    response = browser.get("/", headers=from_place(ATTACKER))
    return response.status_code == 200


def main():
    """Run with binding on and off, save the CSV and chart."""
    rows = []
    for binding_on in [True, False]:
        worked = try_stolen_cookie(binding_on)
        rows.append({
            "session_binding": "on" if binding_on else "off",
            "cookie_worked_elsewhere": "yes" if worked else "no",
            "stopped_by": "none (cookie accepted)" if worked else "session binding",
        })

    with open(CSV_PATH, "w", newline="", encoding="utf-8") as file:
        writer = csv.DictWriter(file, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)

    cells = []
    for row in rows:
        cells.append([row["session_binding"], row["cookie_worked_elsewhere"], row["stopped_by"]])
    figure, axes = plt.subplots(figsize=(8, 1.6))
    axes.axis("off")
    axes.table(cellText=cells, colLabels=["session binding", "stolen cookie worked", "stopped by"], loc="center", cellLoc="center")
    axes.set_title("E4: a stolen cookie used from another device")
    figure.savefig(CHART_PATH, dpi=120, bbox_inches="tight")
    plt.close(figure)

    for row in rows:
        print("session binding", row["session_binding"], "| stolen cookie worked:", row["cookie_worked_elsewhere"])


if __name__ == "__main__":
    main()
