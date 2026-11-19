"""E3: how often does the risk check bother an honest user?

Thousands of ordinary logins are replayed through the real risk engine, and we count
how many would be asked for an extra check at several score thresholds. The lower the
threshold, the more attackers are caught and the more real users are nagged.

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

from experiments import chart_style

from app import config
from app import db
from app import risk

RESULTS_DIR = PROJECT_ROOT / "results"
DATA_DIR = PROJECT_ROOT / "data"
CSV_PATH = RESULTS_DIR / "e3_false_positives.csv"
CHART_PATH = RESULTS_DIR / "e3_false_positives.png"

# a fixed seed, so every run gives the same people and the same result
SEED = 20
# how big the experiment is
USERS = 1000
HISTORY_PER_USER = 12
TEST_LOGINS_PER_USER = 6
BACKGROUND_LOGINS = 1000
# the thresholds to try. The app uses RISK_MEDIUM today.
THRESHOLDS = [2, 3, 4, 5, 6, 7]

# common values, so the engine learns what normal looks like
COUNTRIES = ["US", "US", "US", "CA", "GB", "DE", "FR", "AU"]
BROWSERS = ["Chrome", "Chrome", "Chrome", "Safari", "Firefox", "Edge"]
OPERATING_SYSTEMS = ["Windows", "Windows", "macOS", "Android", "iOS"]
DEVICES = ["Desktop", "Desktop", "Mobile", "Tablet"]
ASNS = [f"AS{1000 + n}" for n in range(12)]

# rarer countries an honest user might travel to
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
        # same place as always, maybe a new IP from the same provider
        if rng.random() < 0.5:
            context["ip"] = random_ip(rng)
    elif roll < 0.85:
        # a browser update, or a second browser on the same machine
        context["browser"] = rng.choice(BROWSERS)
        context["ip"] = random_ip(rng)
    elif roll < 0.95:
        # logging in from their phone instead
        context["device"] = "Mobile"
        context["os"] = rng.choice(["Android", "iOS"])
        context["browser"] = rng.choice(["Chrome", "Safari"])
        context["ip"] = random_ip(rng)
    else:
        # a real trip abroad
        context["country"] = rng.choice(COUNTRIES + RARE_COUNTRIES)
        context["ip"] = random_ip(rng)
        context["asn"] = rng.choice(ASNS)
    return context


def insert_logins(connection, user_id: int, contexts: list) -> None:
    """Insert one user and all of their successful logins in a single transaction."""
    # a bare user row, because login_history points at one
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

    chart_style.use_plain_style()
    figure, axes = plt.subplots(figsize=(8, 4.5))
    axes.plot(thresholds, percents, marker="o", color=chart_style.INK, linewidth=2, markersize=5)
    axes.set_xlabel("score needed before an extra check is asked")
    axes.set_ylabel("honest logins asked for an extra check (%)")
    axes.set_title("E3: false positives vs the risk threshold")
    # mark the threshold the app uses today
    axes.axvline(config.RISK_MEDIUM, color=chart_style.MID, linestyle="--")
    axes.text(config.RISK_MEDIUM + 0.05, max(percents), " app's RISK_MEDIUM", color=chart_style.MID, va="top")
    axes.grid(True, linewidth=0.8)
    axes.set_axisbelow(True)
    figure.tight_layout()
    figure.savefig(CHART_PATH, dpi=120)
    plt.close(figure)


def run() -> None:
    """Run the whole experiment against a fresh temporary database."""
    print(f"E3: replaying {USERS * TEST_LOGINS_PER_USER} honest logins through the risk engine")

    # its own database, never the real one
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
