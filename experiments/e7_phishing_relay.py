"""E7: a TOTP code can be phished, but a passkey only works on the real site.

Both a TOTP code and a passkey are "something you have". The difference is what
they are tied to. A TOTP code is just six digits, so an attacker who tricks the
victim into reading one out can relay it and log in. A passkey signs the exact web
address it is used on, so a signature made on a look-alike phishing site does not
match the real site and is rejected.

Two parts, each on its own throwaway database, driving the real app in-process:

1. Phishing relay vs TOTP: a login from an unusual place is asked for a code. The
   attacker relays a live code (in the lab, read from the victim's secret) and gets in.
2. Phishing relay vs passkey: a high-risk login is asked for a passkey. The victim's
   device signs the challenge for a phishing origin (our fake device, tests/fake_passkey),
   and the real server refuses it.

Run from the project root:  python experiments/e7_phishing_relay.py
"""

import csv
import html
import json
import re
import sys
import tempfile
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))
# tests/fake_passkey.py is our stand-in passkey device, also used by the test suite
sys.path.insert(0, str(PROJECT_ROOT / "tests"))

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
import pyotp

from app import client_context
from app import config

config.DB_PATH = Path(tempfile.mkdtemp(prefix="team20_e7_")) / "startup.db"
config.SECURITY_PROFILE = "ADAPTIVE"
config.LAB_MODE = True

from app import db
from app import routes
from app import totp
import fake_passkey

RESULTS_DIR = PROJECT_ROOT / "results"
CSV_PATH = RESULTS_DIR / "e7_phishing_relay.csv"
CHART_PATH = RESULTS_DIR / "e7_phishing_relay.png"

CHROME_WINDOWS = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/124.0 Safari/537.36"
FIREFOX_WINDOWS = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:130.0) Gecko/20100101 Firefox/130.0"
FIREFOX_ANDROID = "Mozilla/5.0 (Android 14; Mobile; rv:130.0) Gecko/130.0 Firefox/130.0"

# The victim's usual device, built once and reused as their login history
HOME = {"ip": "24.70.15.5", "country": "CA", "asn": "AS852-Telus", "user_agent": CHROME_WINDOWS}
# Same country and OS, different network and browser: unusual enough to ask for a code (medium)
TOTP_ATTACK = {"ip": "24.70.99.9", "country": "CA", "asn": "AS9999-VPN", "user_agent": FIREFOX_WINDOWS}
# Everything different: risky enough to ask for a passkey (high)
PASSKEY_ATTACK = {"ip": "45.9.9.9", "country": "RU", "asn": "AS9009", "user_agent": FIREFOX_ANDROID}

# A look-alike site the victim's browser was tricked into signing for
PHISHING_ORIGIN = "http://localhost-login.example"

TOTP_VICTIM = "bob@example.com"
TOTP_VICTIM_PASSWORD = "bob-demo-pass"
PASSKEY_VICTIM = "carol@example.com"
PASSKEY_VICTIM_PASSWORD = "carol-demo-pass"


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
    config.DB_PATH = Path(tempfile.mkdtemp(prefix="team20_e7_")) / "experiment.db"
    db.create_tables()
    db.seed_demo_users(routes.keys["pepper"])


def give_history(email: str) -> int:
    """Record a few usual-device logins for a user and return their id."""
    user_id = db.get_user_by_email(email)["id"]
    home = full_context(HOME)
    for _ in range(5):
        db.record_login_attempt(user_id, home, True)
    return user_id


def csrf_token(client) -> str:
    """Return the CSRF token this test browser holds (after loading a form page)."""
    with client.session_transaction() as flask_session:
        return flask_session["csrf_token"]


def post_login(client, email: str, password: str, context: dict):
    """Send one login for a user from the given context."""
    client.get("/login", headers=lab_headers(context))
    form = {"email": email, "password": password, "csrf_token": csrf_token(client)}
    return client.post("/login", data=form, headers=lab_headers(context))


def options_from_page(client, path: str, context: dict) -> str:
    """Open a passkey page and return the options the server put in its button."""
    response = client.get(path, headers=lab_headers(context))
    match = re.search(r'data-options="([^"]*)"', response.get_data(as_text=True))
    return html.unescape(match.group(1))


def run_totp_part() -> dict:
    """Show a phished TOTP code let the attacker finish an unusual login."""
    fresh_database()
    user_id = give_history(TOTP_VICTIM)
    # The victim has an authenticator app; store its secret so we can relay a live code
    secret = totp.new_secret()
    connection = db.get_connection()
    connection.execute(
        "UPDATE users SET totp_secret_encrypted = ? WHERE id = ?",
        (totp.encrypt_secret(secret, routes.keys["aes_key"]), user_id),
    )
    connection.commit()
    connection.close()

    attacker = routes.app.test_client()
    response = post_login(attacker, TOTP_VICTIM, TOTP_VICTIM_PASSWORD, TOTP_ATTACK)
    asked_for_code = response.status_code == 302 and response.headers.get("Location") == "/verify/totp"
    if not asked_for_code:
        return totp_row("no code asked (login was not treated as risky)", False)

    # The phished code: the attacker tricked the victim into reading out a live code
    attacker.get("/verify/totp", headers=lab_headers(TOTP_ATTACK))
    phished_code = pyotp.TOTP(secret).now()
    form = {"code": phished_code, "csrf_token": csrf_token(attacker)}
    attacker.post("/verify/totp", data=form, headers=lab_headers(TOTP_ATTACK))
    got_in = attacker.get("/", headers=lab_headers(TOTP_ATTACK)).status_code == 200
    return totp_row("relayed a live code and got in" if got_in else "code refused", got_in)


def totp_row(outcome: str, got_in: bool) -> dict:
    """Build the E7 result row for the TOTP part."""
    return {"factor": "TOTP code", "attack": "phishing relay", "attacker_got_in": "yes" if got_in else "no", "outcome": outcome}


def register_passkey(user_id: int) -> dict:
    """Log the victim in from home and register our fake passkey device for them."""
    victim = routes.app.test_client()
    post_login(victim, PASSKEY_VICTIM, PASSKEY_VICTIM_PASSWORD, HOME)
    device = fake_passkey.new_device()
    options_json = options_from_page(victim, "/setup/passkey", HOME)
    answer = fake_passkey.register(device, options_json)
    form = {"credential": answer, "csrf_token": csrf_token(victim)}
    victim.post("/setup/passkey", data=form, headers=lab_headers(HOME))
    return device


def run_passkey_part() -> dict:
    """Show a passkey signed for a phishing site is refused by the real server."""
    fresh_database()
    user_id = give_history(PASSKEY_VICTIM)
    device = register_passkey(user_id)

    attacker = routes.app.test_client()
    response = post_login(attacker, PASSKEY_VICTIM, PASSKEY_VICTIM_PASSWORD, PASSKEY_ATTACK)
    asked_for_passkey = response.status_code == 302 and response.headers.get("Location") == "/verify/passkey"
    if not asked_for_passkey:
        return passkey_row("no passkey asked (login was not treated as risky)", True)

    # The victim's device signs the challenge, but for the phishing origin, not the real site
    options_json = options_from_page(attacker, "/verify/passkey", PASSKEY_ATTACK)
    answer = fake_passkey.sign_in(device, options_json, origin=PHISHING_ORIGIN)
    form = {"credential": answer, "csrf_token": csrf_token(attacker)}
    check = attacker.post("/verify/passkey", data=form, headers=lab_headers(PASSKEY_ATTACK))
    got_in = attacker.get("/", headers=lab_headers(PASSKEY_ATTACK)).status_code == 200
    outcome = "got in" if got_in else "wrong-origin signature refused"
    return passkey_row(outcome, got_in)


def passkey_row(outcome: str, got_in: bool) -> dict:
    """Build the E7 result row for the passkey part."""
    return {"factor": "passkey", "attack": "phishing relay", "attacker_got_in": "yes" if got_in else "no", "outcome": outcome}


def write_csv(rows: list) -> None:
    """Save the result rows to the E7 CSV."""
    RESULTS_DIR.mkdir(exist_ok=True)
    with open(CSV_PATH, "w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)


def draw_chart(rows: list) -> None:
    """Draw one cell per factor: red if the phishing relay got in, green if it was refused."""
    figure, axes = plt.subplots(figsize=(9, 3.4))
    for column, row in enumerate(rows):
        got_in = row["attacker_got_in"] == "yes"
        color = "#e74c3c" if got_in else "#27ae60"
        axes.add_patch(plt.Rectangle((column, 0), 1, 1, facecolor=color, edgecolor="white"))
        label = f"{row['outcome']}"
        axes.text(column + 0.5, 0.5, label, ha="center", va="center", color="white", fontsize=10, wrap=True)

    axes.set_xlim(0, len(rows))
    axes.set_ylim(0, 1)
    axes.set_xticks([column + 0.5 for column in range(len(rows))])
    axes.set_xticklabels([row["factor"] for row in rows])
    axes.set_yticks([])
    axes.set_title("E7: phishing relay beats a TOTP code but not a passkey")
    figure.tight_layout()
    figure.savefig(CHART_PATH, dpi=120)
    plt.close(figure)


def run() -> None:
    """Run both parts, save the CSV and chart, and print a summary."""
    print("E7: phishing a TOTP code vs a passkey")
    print("  part 1: relaying a phished TOTP code ...")
    totp_result = run_totp_part()
    print("  part 2: a passkey signed for a phishing site ...")
    passkey_result = run_passkey_part()
    rows = [totp_result, passkey_result]

    write_csv(rows)
    draw_chart(rows)

    print()
    for row in rows:
        print(f"  {row['factor']:>10} | attacker got in: {row['attacker_got_in']:>3} | {row['outcome']}")
    print()
    print(f"Saved {CSV_PATH.name} and {CHART_PATH.name} in results/.")


if __name__ == "__main__":
    run()
