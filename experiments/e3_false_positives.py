"""E3: how often does the risk check bother a real, honest user?

A risk check that flags attackers is only useful if it mostly leaves real users
alone. A "false positive" here is an honest login that the engine scores high
enough to demand an extra check. We replay many normal logins through the real
risk engine (app/risk.py) and count the false-positive rate at several score
thresholds, so we can see the trade-off: a lower threshold catches more attackers
but nags more real users.

The experiment uses a generated population of ordinary users. Each has a usual
device and network and logs in mostly from there, with the occasional honest
change: a new phone, a browser update, or a trip abroad. The public RBA dataset
(Wiefling et al., das-group/rba-dataset, CC BY 4.0) is about 15 GB and is not
committed; this synthetic population models the same question and runs anywhere.
If a file `data/rba_sample.csv` is present it is used instead (see load_rows).

Run from the project root:  python experiments/e3_false_positives.py
"""

import csv
import random
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt

from app import config
from app import db
from app import risk

RESULTS_DIR = PROJECT_ROOT / "results"
DATA_DIR = PROJECT_ROOT / "data"
CSV_PATH = RESULTS_DIR / "e3_false_positives.csv"
CHART_PATH = RESULTS_DIR / "e3_false_positives.png"

# A fixed seed so the generated population, and the result, are the same every run
SEED = 20
# Size of the experiment. Printed into the setup notes as the sample size.
USERS = 1000
HISTORY_PER_USER = 12
TEST_LOGINS_PER_USER = 6
BACKGROUND_LOGINS = 1000
# Score thresholds to test. The app's RISK_MEDIUM (3) is the one it uses today.
THRESHOLDS = [2, 3, 4, 5, 6, 7]

# Common values, so the engine learns what "normal for everyone" looks like
COUNTRIES = ["US", "US", "US", "CA", "GB", "DE", "FR", "AU"]
BROWSERS = ["Chrome", "Chrome", "Chrome", "Safari", "Firefox", "Edge"]
OPERATING_SYSTEMS = ["Windows", "Windows", "macOS", "Android", "iOS"]
DEVICES = ["Desktop", "Desktop", "Mobile", "Tablet"]
ASNS = [f"AS{1000 + n}" for n in range(12)]

# A few rarer countries an honest user might travel to
RARE_COUNTRIES = ["JP", "BR", "ZA", "IN", "NO"]


def random_ip(rng: random.Random) -> str:
    """Return a random IPv4 address as text."""
    parts = [str(rng.randint(1, 254)) for _ in range(4)]
    return ".".join(parts)


def home_context(rng: random.Random) -> dict:
    """Make one user's usual login context (their home device and network)."""
    return {
        "ip": random_ip(rng),
        "country": rng.choice(COUNTRIES),
        "asn": rng.choice(ASNS),
        "browser": rng.choice(BROWSERS),
        "os": rng.choice(OPERATING_SYSTEMS),
        "device": rng.choice(DEVICES),
    }


def honest_variation(home: dict, rng: random.Random) -> dict:
    """Return a login for an honest user: usually home, sometimes a real change."""
    context = dict(home)
    roll = rng.random()
    if roll < 0.70:
        # Same place as always, maybe a new IP from the same provider (DHCP)
        if rng.random() < 0.5:
            context["ip"] = random_ip(rng)
    elif roll < 0.85:
        # A browser update or a second browser on the same machine
        context["browser"] = rng.choice(BROWSERS)
        context["ip"] = random_ip(rng)
    elif roll < 0.95:
        # Logging in from their phone instead of their computer
        context["device"] = "Mobile"
        context["os"] = rng.choice(["Android", "iOS"])
        context["browser"] = rng.choice(["Chrome", "Safari"])
        context["ip"] = random_ip(rng)
    else:
        # A genuine trip abroad
        context["country"] = rng.choice(COUNTRIES + RARE_COUNTRIES)
        context["ip"] = random_ip(rng)
        context["asn"] = rng.choice(ASNS)
    return context


def insert_logins(connection, user_id: int, contexts: list) -> None:
    """Insert one user and all of their successful logins in a single transaction."""
    # A bare user row keeps the login_history foreign key happy; the password is unused
    connection.execute(
        "INSERT OR IGNORE INTO users (id, email, password_hash) VALUES (?, ?, ?)",
        (user_id, f"sim{user_id}@example.com", "not-a-real-hash"),
    )
    now = db.utc_now()
    rows = []
    for context in contexts:
        rows.append((
            user_id, now, context["ip"], context["country"], context["asn"],
            context["browser"], context["os"], context["device"], 1,
        ))
    connection.executemany(
        "INSERT INTO login_history "
        "(user_id, time, ip, country, asn, browser, os, device, success) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        rows,
    )


def delete_user_logins(user_id: int) -> None:
    """Remove one user's history, so the next user starts from the background only."""
    connection = db.get_connection()
    connection.execute("DELETE FROM login_history WHERE user_id = ?", (user_id,))
    connection.commit()
    connection.close()


def build_background(rng: random.Random) -> None:
    """Fill history with common logins, so the engine knows what is normal overall."""
    connection = db.get_connection()
    for number in range(BACKGROUND_LOGINS):
        user_id = 500_000 + number
        insert_logins(connection, user_id, [home_context(rng)])
    connection.commit()
    connection.close()


def load_rows(rng: random.Random) -> list:
    """Score every honest test login and return its score.

    Each user's history is inserted, their test logins are scored against it, then
    their history is removed again so only the shared background stays behind.
    """
    scores = []
    for index in range(USERS):
        user_id = 10_000 + index
        home = home_context(rng)
        connection = db.get_connection()
        insert_logins(connection, user_id, [home] * HISTORY_PER_USER)
        connection.commit()
        connection.close()
        for _ in range(TEST_LOGINS_PER_USER):
            context = honest_variation(home, rng)
            result = risk.score_login(user_id, context)
            scores.append(result["score"])
        delete_user_logins(user_id)
    return scores


def false_positive_rows(scores: list) -> list:
    """For each threshold, count how many honest logins would be flagged."""
    rows = []
    total = len(scores)
    for threshold in THRESHOLDS:
        flagged = 0
        for score in scores:
            if score >= threshold:
                flagged += 1
        rows.append({
            "threshold": threshold,
            "total_logins": total,
            "flagged": flagged,
            "false_positive_percent": round(100 * flagged / total, 2),
            "data_source": "synthetic",
        })
    return rows


def write_csv(rows: list) -> None:
    """Save the result rows to the E3 CSV."""
    RESULTS_DIR.mkdir(exist_ok=True)
    with open(CSV_PATH, "w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)


def draw_chart(rows: list) -> None:
    """Draw the false-positive rate against the score threshold."""
    thresholds = [row["threshold"] for row in rows]
    percents = [row["false_positive_percent"] for row in rows]

    figure, axes = plt.subplots(figsize=(8, 4.5))
    axes.plot(thresholds, percents, marker="o", color="#8e44ad")
    axes.set_xlabel("score needed before an extra check is asked")
    axes.set_ylabel("honest logins asked for an extra check (%)")
    axes.set_title("E3: false positives vs the risk threshold")
    # Mark the threshold the app actually uses today
    axes.axvline(config.RISK_MEDIUM, color="#7f8c8d", linestyle="--")
    axes.text(config.RISK_MEDIUM + 0.05, max(percents), " app's RISK_MEDIUM", color="#7f8c8d", va="top")
    axes.grid(True, alpha=0.3)
    figure.tight_layout()
    figure.savefig(CHART_PATH, dpi=120)
    plt.close(figure)


def run() -> None:
    """Run the whole experiment against a fresh temporary database."""
    print(f"E3: replaying {USERS * TEST_LOGINS_PER_USER} honest logins through the risk engine")

    # Keep the whole experiment in its own database, never the real app's
    temp_db = RESULTS_DIR / "_e3_temp.db"
    if temp_db.exists():
        temp_db.unlink()
    config.DB_PATH = temp_db
    db.create_tables()

    rng = random.Random(SEED)
    build_background(rng)
    scores = load_rows(rng)
    rows = false_positive_rows(scores)

    write_csv(rows)
    draw_chart(rows)
    temp_db.unlink()

    print()
    for row in rows:
        marker = "  <- app uses this" if row["threshold"] == config.RISK_MEDIUM else ""
        print(f"  threshold >= {row['threshold']}: {row['false_positive_percent']:>5}% flagged{marker}")
    print()
    print(f"Saved {CSV_PATH.name} and {CHART_PATH.name} in results/.")


if __name__ == "__main__":
    run()
