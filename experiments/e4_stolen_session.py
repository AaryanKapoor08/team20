"""E4: does a stolen session cookie still work from another device?

Malware (an infostealer) can copy a logged-in user's session cookie. The question
is whether that cookie is still useful once it leaves the victim's machine. We log
a victim in, take their cookie, then replay it from a different browser, OS and
network. We do this twice: once with SESSION_BINDING on (the app's default) and
once with it off, to show exactly what the binding buys us.

The binding ties a cookie to the browser, OS and network prefix it was made on
(see app/sessions.py), so a cookie used from somewhere else is dropped.

This drives the real app in-process with Flask's test client, so the result is the
same every run and needs no separate server.

Run from the project root:  python experiments/e4_stolen_session.py
"""

import csv
import json
import sys
import tempfile
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt

from app import config

# Point the app at a throwaway database and turn on the adaptive profile and lab
# mode before importing routes, which builds the tables and demo users on startup.
config.DB_PATH = Path(tempfile.mkdtemp(prefix="team20_e4_")) / "startup.db"
config.SECURITY_PROFILE = "ADAPTIVE"
config.LAB_MODE = True

from app import db
from app import routes

RESULTS_DIR = PROJECT_ROOT / "results"
CSV_PATH = RESULTS_DIR / "e4_stolen_session.csv"
CHART_PATH = RESULTS_DIR / "e4_stolen_session.png"

# The victim and their correct password; the cookie is born on their machine
VICTIM_EMAIL = "carol@example.com"
VICTIM_PASSWORD = "carol-demo-pass"

# Where the cookie is made, and where the attacker replays it from (a different
# country, network and browser). Only the lab header changes, so the same cookie
# travels from one context to the other.
VICTIM_CONTEXT = {
    "ip": "24.70.15.5",
    "country": "CA",
    "asn": "AS852-Telus",
    "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/124.0 Safari/537.36",
}
ATTACKER_CONTEXT = {
    "ip": "185.199.84.7",
    "country": "DE",
    "asn": "AS14061-DigitalOcean",
    "user_agent": "Mozilla/5.0 (X11; Linux x86_64) Firefox/125.0",
}


def lab_headers(context: dict) -> dict:
    """Return the header that fakes where a request comes from (read in lab mode)."""
    return {"X-Lab-Client": json.dumps(context)}


def fresh_database() -> None:
    """Give the app a brand new empty database with the demo users added."""
    config.DB_PATH = Path(tempfile.mkdtemp(prefix="team20_e4_")) / "experiment.db"
    db.create_tables()
    db.seed_demo_users(routes.keys["pepper"])


def csrf_token(client) -> str:
    """Return the CSRF token this test browser holds (after loading a form page)."""
    with client.session_transaction() as flask_session:
        return flask_session["csrf_token"]


def log_in_victim(client) -> None:
    """Log the victim in from their own machine, so the browser gets a session cookie."""
    client.get("/login", headers=lab_headers(VICTIM_CONTEXT))
    form = {"email": VICTIM_EMAIL, "password": VICTIM_PASSWORD, "csrf_token": csrf_token(client)}
    client.post("/login", data=form, headers=lab_headers(VICTIM_CONTEXT))


def cookie_still_works(client, context: dict) -> bool:
    """Return True if the home page opens with this cookie from the given context."""
    # The test browser already carries the session cookie; only the context changes.
    response = client.get("/", headers=lab_headers(context))
    return response.status_code == 200


def run_scenario(session_binding: bool) -> dict:
    """Log in, then replay the cookie from the attacker's context with this setting."""
    fresh_database()
    config.SESSION_BINDING = session_binding

    victim_browser = routes.app.test_client()
    log_in_victim(victim_browser)
    worked = cookie_still_works(victim_browser, ATTACKER_CONTEXT)

    return {
        "session_binding": "on" if session_binding else "off",
        "cookie_worked_elsewhere": "yes" if worked else "no",
        "stopped_by": "none (cookie accepted)" if worked else "session binding",
    }


def collect_rows() -> list:
    """Run the replay with binding on, then off, and return one row each."""
    rows = []
    for session_binding in [True, False]:
        print(f"  replaying the stolen cookie with SESSION_BINDING {'on' if session_binding else 'off'} ...")
        rows.append(run_scenario(session_binding))
    return rows


def write_csv(rows: list) -> None:
    """Save the result rows to the E4 CSV."""
    RESULTS_DIR.mkdir(exist_ok=True)
    with open(CSV_PATH, "w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)


def draw_chart(rows: list) -> None:
    """Draw one cell per setting: red if the stolen cookie worked, green if it was dropped."""
    figure, axes = plt.subplots(figsize=(8, 3.2))
    for column, row in enumerate(rows):
        worked = row["cookie_worked_elsewhere"] == "yes"
        color = "#e74c3c" if worked else "#27ae60"
        axes.add_patch(plt.Rectangle((column, 0), 1, 1, facecolor=color, edgecolor="white"))
        label = "cookie worked\n(got in)" if worked else "cookie dropped\n(session binding)"
        axes.text(column + 0.5, 0.5, label, ha="center", va="center", color="white", fontsize=11)

    axes.set_xlim(0, len(rows))
    axes.set_ylim(0, 1)
    axes.set_xticks([column + 0.5 for column in range(len(rows))])
    axes.set_xticklabels([f"SESSION_BINDING {row['session_binding']}" for row in rows])
    axes.set_yticks([])
    axes.set_title("E4: a stolen cookie replayed from another device")
    figure.tight_layout()
    figure.savefig(CHART_PATH, dpi=120)
    plt.close(figure)


def run() -> None:
    """Run both scenarios, save the CSV and chart, and print a summary."""
    print("E4: replaying a stolen session cookie from a different context")
    rows = collect_rows()
    write_csv(rows)
    draw_chart(rows)

    print()
    for row in rows:
        verdict = "cookie worked (got in)" if row["cookie_worked_elsewhere"] == "yes" else f"stopped by {row['stopped_by']}"
        print(f"  SESSION_BINDING {row['session_binding']:>3} | {verdict}")
    print()
    print(f"Saved {CSV_PATH.name} and {CHART_PATH.name} in results/.")


if __name__ == "__main__":
    run()
