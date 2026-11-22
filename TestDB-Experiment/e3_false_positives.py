"""E3: how often does the risk check ask an honest user for an extra code?

Run from the project root:  python experiments/e3_false_positives.py
"""

import csv
import random
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

from app import config
from app import db
from app import risk

CSV_PATH = ROOT / "results" / "e3_false_positives.csv"
CHART_PATH = ROOT / "results" / "e3_false_positives.png"
TEMP_DB = ROOT / "results" / "_e3_temp.db"

SEED = 20
USERS = 1000
HISTORY_PER_USER = 12
TEST_LOGINS_PER_USER = 6
BACKGROUND_LOGINS = 1000
THRESHOLDS = [2, 3, 4, 5, 6, 7]

COUNTRIES = ["US", "US", "US", "CA", "GB", "DE", "FR", "AU"]
RARE_COUNTRIES = ["JP", "BR", "ZA", "IN", "NO"]
BROWSERS = ["Chrome", "Chrome", "Chrome", "Safari", "Firefox", "Edge"]
SYSTEMS = ["Windows", "Windows", "macOS", "Android", "iOS"]
DEVICES = ["Desktop", "Desktop", "Mobile", "Tablet"]
ASNS = ["AS1000", "AS1001", "AS1002", "AS1003", "AS1004", "AS1005",
        "AS1006", "AS1007", "AS1008", "AS1009", "AS1010", "AS1011"]


def random_ip(rng):
    """Return a random IP address like 12.200.7.45."""
    parts = []
    for _ in range(4):
        parts.append(str(rng.randint(1, 254)))
    return ".".join(parts)


def home_login(rng):
    """Make one user's usual login: their home device and network."""
    return {
        "ip": random_ip(rng),
        "country": rng.choice(COUNTRIES),
        "asn": rng.choice(ASNS),
        "browser": rng.choice(BROWSERS),
        "os": rng.choice(SYSTEMS),
        "device": rng.choice(DEVICES),
    }


def honest_login(home, rng):
    """Return a normal login: mostly from home, sometimes a real change."""
    login = dict(home)
    roll = rng.random()
    if roll < 0.70:
        # at home, maybe with a new IP
        if rng.random() < 0.5:
            login["ip"] = random_ip(rng)
    elif roll < 0.85:
        # a different browser
        login["browser"] = rng.choice(BROWSERS)
        login["ip"] = random_ip(rng)
    elif roll < 0.95:
        # on their phone
        login["device"] = "Mobile"
        login["os"] = rng.choice(["Android", "iOS"])
        login["browser"] = rng.choice(["Chrome", "Safari"])
        login["ip"] = random_ip(rng)
    else:
        # a trip abroad
        login["country"] = rng.choice(COUNTRIES + RARE_COUNTRIES)
        login["ip"] = random_ip(rng)
        login["asn"] = rng.choice(ASNS)
    return login


def save_logins(user_id, logins):
    """Add a user and their past logins to the database."""
    connection = db.get_connection()
    connection.execute(
        "INSERT OR IGNORE INTO users (id, email, password_hash) VALUES (?, ?, ?)",
        (user_id, "sim" + str(user_id) + "@example.com", "not-a-real-hash"),
    )
    for login in logins:
        connection.execute(
            "INSERT INTO login_history (user_id, time, ip, country, asn, browser, os, device, success) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1)",
            (user_id, db.utc_now(), login["ip"], login["country"], login["asn"],
             login["browser"], login["os"], login["device"]),
        )
    connection.commit()
    connection.close()


def score_honest_logins(rng):
    """Give each user a history, score their honest logins, then remove the history."""
    scores = []
    for number in range(USERS):
        user_id = 10000 + number
        home = home_login(rng)
        save_logins(user_id, [home] * HISTORY_PER_USER)
        for _ in range(TEST_LOGINS_PER_USER):
            result = risk.score_login(user_id, honest_login(home, rng))
            scores.append(result["score"])
        connection = db.get_connection()
        connection.execute("DELETE FROM login_history WHERE user_id = ?", (user_id,))
        connection.commit()
        connection.close()
    return scores


def count_flagged(scores):
    """For each threshold, count how many honest logins would be asked for a code."""
    rows = []
    for threshold in THRESHOLDS:
        flagged = 0
        for score in scores:
            if score >= threshold:
                flagged += 1
        percent = round(100 * flagged / len(scores), 2)
        rows.append({"threshold": threshold, "total_logins": len(scores), "flagged": flagged,
                     "false_positive_percent": percent, "data_source": "synthetic"})
    return rows


def save_results(rows):
    """Write the CSV and draw the chart for analysis."""
    with open(CSV_PATH, "w", newline="", encoding="utf-8") as file:
        writer = csv.DictWriter(file, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)

    thresholds = []
    percents = []
    for row in rows:
        thresholds.append(row["threshold"])
        percents.append(row["false_positive_percent"])
    plt.figure(figsize=(8, 4.5))
    plt.plot(thresholds, percents, marker="o", color="black")
    plt.axvline(config.RISK_MEDIUM, color="grey", linestyle="--")
    plt.xlabel("score needed before an extra check is asked")
    plt.ylabel("honest logins asked for a code (%)")
    plt.title("E3: false positives vs the risk threshold")
    plt.savefig(CHART_PATH, dpi=120)
    plt.close()


def main():
    """Run E3 on a throwaway database and print the result."""
    if TEMP_DB.exists():
        TEMP_DB.unlink()
    config.DB_PATH = TEMP_DB
    db.create_tables()

    rng = random.Random(SEED)
    # 1000 ordinary logins, so the risk check knows what normal looks like
    for number in range(BACKGROUND_LOGINS):
        save_logins(500000 + number, [home_login(rng)])

    rows = count_flagged(score_honest_logins(rng))
    save_results(rows)
    TEMP_DB.unlink()

    for row in rows:
        print("threshold", row["threshold"], ":", row["false_positive_percent"], "% flagged")


if __name__ == "__main__":
    main()
