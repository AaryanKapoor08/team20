"""E5: can an attacker lock a real user out?

The same attack, wrong passwords for someone else's account, is run twice: once with
the plain lockout and once with the risk-based handling. We then check whether the
real owner can still get in.

Run from the project root:  python experiments/e5_lockout_abuse.py
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

from experiments import chart_style
import pyotp

from app import client_context
from app import config

# set up the throwaway database and the profile before the app is imported
config.DB_PATH = Path(tempfile.mkdtemp(prefix="team20_e5_")) / "startup.db"
config.SECURITY_PROFILE = "ADAPTIVE"
config.LAB_MODE = True

from app import db
from app import routes
from app import totp

RESULTS_DIR = PROJECT_ROOT / "results"
CSV_PATH = RESULTS_DIR / "e5_lockout_abuse.csv"
CHART_PATH = RESULTS_DIR / "e5_lockout_abuse.png"

# the account under attack, and the wrong passwords spent on it
VICTIM_EMAIL = "alice@example.com"
VICTIM_PASSWORD = "alice-demo-pass"
WRONG_PASSWORDS = ["wrong1", "wrong2", "wrong3", "wrong4", "wrong5"]
# enough tries to lock it, but we stop as soon as it locks
MAX_ABUSE_TRIES = 12

# the owner's usual device, and the attacker's one IP
VICTIM_CONTEXT = {
    "ip": "24.70.15.5",
    "country": "CA",
    "asn": "AS852-Telus",
    "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/124.0 Safari/537.36",
}
ATTACKER_CONTEXT = {
    "ip": "198.51.100.200",
    "country": "US",
    "asn": "AS1200",
    "user_agent": "Mozilla/5.0 (python lockout abuser)",
}

# so high it is never reached, which means no hard lockout
NO_LOCKOUT = 1_000_000


def lab_headers(context: dict) -> dict:
    """Return the header that fakes where a request comes from (read in lab mode)."""
    return {"X-Lab-Client": json.dumps(context)}


def full_context(lab_client: dict) -> dict:
    """Turn a lab header into the full context (with browser, os and device) for the database."""
    context = {"ip": lab_client["ip"], "country": lab_client["country"], "asn": lab_client["asn"]}
    context.update(client_context.parse_user_agent(lab_client["user_agent"]))
    return context


def fresh_database() -> None:
    """Give the app a brand new empty database with the demo users added."""
    config.DB_PATH = Path(tempfile.mkdtemp(prefix="team20_e5_")) / "experiment.db"
    db.create_tables()
    db.seed_demo_users(routes.keys["pepper"])


def set_up_victim() -> str:
    """Give the victim a usual-device history and an authenticator app, and return its secret."""
    user_id = db.get_user_by_email(VICTIM_EMAIL)["id"]
    home = full_context(VICTIM_CONTEXT)
    # a few past logins, so the engine knows the owner's usual device
    for _ in range(5):
        db.record_login_attempt(user_id, home, True)
    # the owner has an app set up, so a code can be entered later
    secret = totp.new_secret()
    connection = db.get_connection()
    connection.execute(
        "UPDATE users SET totp_secret_encrypted = ? WHERE id = ?",
        (totp.encrypt_secret(secret, routes.keys["aes_key"]), user_id),
    )
    connection.commit()
    connection.close()
    return secret


def csrf_token(client) -> str:
    """Return the CSRF token this test browser holds (after loading a form page)."""
    with client.session_transaction() as flask_session:
        return flask_session["csrf_token"]


def post_login(client, password: str, context: dict):
    """Send one login attempt for the victim from the given context."""
    client.get("/login", headers=lab_headers(context))
    form = {"email": VICTIM_EMAIL, "password": password, "csrf_token": csrf_token(client)}
    return client.post("/login", data=form, headers=lab_headers(context))


def abuse_until_locked() -> bool:
    """Send wrong passwords from the attacker's IP; return True if the account locked."""
    for attempt in range(MAX_ABUSE_TRIES):
        password = WRONG_PASSWORDS[attempt % len(WRONG_PASSWORDS)]
        attacker = routes.app.test_client()
        response = post_login(attacker, password, ATTACKER_CONTEXT)
        # this page means the account is now locked
        if response.status_code == 429:
            return True
    return False


def owner_logs_in(secret: str) -> str:
    """Try to log the real owner in from their usual device; return a short outcome."""
    owner = routes.app.test_client()
    response = post_login(owner, VICTIM_PASSWORD, VICTIM_CONTEXT)

    if response.status_code == 429:
        return "locked out (refused)"
    # the failures raised the risk, so the owner is asked for a code
    if response.status_code == 302 and response.headers.get("Location") == "/verify/totp":
        owner.get("/verify/totp", headers=lab_headers(VICTIM_CONTEXT))
        code = pyotp.TOTP(secret).now()
        form = {"code": code, "csrf_token": csrf_token(owner)}
        owner.post("/verify/totp", data=form, headers=lab_headers(VICTIM_CONTEXT))
        if owner.get("/", headers=lab_headers(VICTIM_CONTEXT)).status_code == 200:
            return "logged in (via a one-time code)"
        return "code step failed"
    if response.status_code == 302 and response.headers.get("Location") == "/":
        return "logged in"
    return f"refused (status {response.status_code})"


def run_scenario(name: str, lockout_failures: int) -> dict:
    """Run the abuse then the owner's login with this lockout setting, and return a row."""
    fresh_database()
    config.LOCKOUT_FAILURES = lockout_failures
    secret = set_up_victim()
    locked = abuse_until_locked()
    owner_outcome = owner_logs_in(secret)
    return {
        "handling": name,
        "account_locked_by_attacker": "yes" if locked else "no",
        "owner_can_log_in": "no" if owner_outcome == "locked out (refused)" else "yes",
        "owner_outcome": owner_outcome,
    }


def collect_rows() -> list:
    """Run the plain-lockout scenario, then the risk-based one."""
    rows = []
    print("  plain lockout: attacker floods wrong passwords, then the owner tries ...")
    rows.append(run_scenario("plain lockout", config.LOCKOUT_FAILURES))
    print("  risk-based (no hard lockout): same attack, then the owner tries ...")
    rows.append(run_scenario("risk-based", NO_LOCKOUT))
    return rows


def write_csv(rows: list) -> None:
    """Save the result rows to the E5 CSV."""
    RESULTS_DIR.mkdir(exist_ok=True)
    with open(CSV_PATH, "w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)


def draw_chart(rows: list) -> None:
    """Draw one cell per handling: red if the owner is locked out, green if they get in."""
    chart_style.use_plain_style()
    figure, axes = plt.subplots(figsize=(8.5, 3.4))
    for column, row in enumerate(rows):
        owner_out = row["owner_can_log_in"] == "no"
        label = f"owner {row['owner_outcome']}"
        fill = "dark" if owner_out else "light"
        chart_style.draw_cell(axes, column, 0, label, fill)

    axes.set_xlim(0, len(rows))
    axes.set_ylim(0, 1)
    axes.set_xticks([column + 0.5 for column in range(len(rows))])
    axes.set_xticklabels([row["handling"] for row in rows])
    axes.set_yticks([])
    chart_style.hide_axis_lines(axes)
    axes.set_title("E5: after a lockout attack, can the real owner still get in?")
    figure.tight_layout()
    figure.savefig(CHART_PATH, dpi=120)
    plt.close(figure)


def run() -> None:
    """Run both scenarios, save the CSV and chart, and print a summary."""
    print("E5: lockout as a denial of service vs risk-based handling")
    rows = collect_rows()
    write_csv(rows)
    draw_chart(rows)

    print()
    for row in rows:
        print(f"  {row['handling']:>13} | account locked: {row['account_locked_by_attacker']:>3} | owner {row['owner_outcome']}")
    print()
    print(f"Saved {CSV_PATH.name} and {CHART_PATH.name} in results/.")


if __name__ == "__main__":
    run()
