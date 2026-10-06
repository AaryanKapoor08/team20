"""Login risk: a score, a level (low, medium, high) and plain-English reasons.

A simple version of Freeman et al. (2016): a login that does not look like this
user's past logins is risky, unless that value is common for everyone.
"""

import sqlite3

from app import config
from app import db
from app import limits

FEATURES = ["ip", "asn", "country", "browser", "os", "device"]
FEATURE_LABELS = {
    "ip": "IP address",
    "asn": "network (ASN)",
    "country": "country",
    "browser": "browser",
    "os": "operating system",
    "device": "device type",
}

# Counts past successful logins, and how many of them match each feature of this login
USER_MATCHES_SQL = """
SELECT COUNT(*) AS total,
       SUM(ip = ?) AS ip, SUM(asn = ?) AS asn, SUM(country = ?) AS country,
       SUM(browser = ?) AS browser, SUM(os = ?) AS os, SUM(device = ?) AS device
FROM login_history
WHERE success = 1 AND user_id = ?
"""
ALL_MATCHES_SQL = """
SELECT COUNT(*) AS total,
       SUM(ip = ?) AS ip, SUM(asn = ?) AS asn, SUM(country = ?) AS country,
       SUM(browser = ?) AS browser, SUM(os = ?) AS os, SUM(device = ?) AS device
FROM login_history
WHERE success = 1
"""


def count_matches(context: dict, user_id: int | None = None) -> sqlite3.Row:
    """Count past successful logins (one user's, or everyone's) matching each feature."""
    values = []
    for feature in FEATURES:
        values.append(context[feature])

    connection = db.get_connection()
    if user_id is None:
        counts = connection.execute(ALL_MATCHES_SQL, values).fetchone()
    else:
        values.append(user_id)
        counts = connection.execute(USER_MATCHES_SQL, values).fetchone()
    connection.close()
    return counts


def feature_risk(feature: str, user_counts: sqlite3.Row, all_counts: sqlite3.Row) -> int:
    """Return the points for one feature: more when the value is rare for this user."""
    user_share = user_counts[feature] / user_counts["total"]
    if user_share >= config.USUAL_SHARE:
        return 0

    points = config.FEATURE_POINTS[feature]
    # A value common for everyone (like Chrome) is less suspicious than one nobody uses
    all_share = all_counts[feature] / all_counts["total"]
    if all_share >= config.USUAL_SHARE:
        points = points // 2
    return points


def feature_reason(feature: str, user_counts: sqlite3.Row) -> str:
    """Return a reason like "new country for this user"."""
    label = FEATURE_LABELS[feature]
    if user_counts[feature] == 0:
        return f"new {label} for this user"
    return f"rare {label} for this user"


def count_recent(sql: str, values: tuple) -> int:
    """Run a COUNT query and return the number."""
    connection = db.get_connection()
    count = connection.execute(sql, values).fetchone()[0]
    connection.close()
    return count


def velocity_risk(user_id: int, ip: str) -> tuple[int, list]:
    """Return points and reasons for too many recent failures or accounts tried."""
    window_start = limits.time_in_minutes(-config.RISK_WINDOW_MINUTES)
    minutes = config.RISK_WINDOW_MINUTES
    points = 0
    reasons = []

    site_fails = count_recent(
        "SELECT COUNT(*) FROM login_history WHERE success = 0 AND time >= ?", (window_start,)
    )
    if site_fails >= config.SITE_FAIL_LIMIT:
        points += config.VELOCITY_POINTS
        reasons.append(f"{site_fails} failed logins on the site in the last {minutes} minutes")

    account_fails = count_recent(
        "SELECT COUNT(*) FROM login_history WHERE success = 0 AND user_id = ? AND time >= ?",
        (user_id, window_start),
    )
    if account_fails >= config.ACCOUNT_FAIL_LIMIT:
        points += config.VELOCITY_POINTS
        reasons.append(f"{account_fails} failed logins on this account in the last {minutes} minutes")

    # Credential stuffing: one IP failing on many different accounts.
    # Only failures count, so one person logging in to a few demo accounts is fine.
    ip_accounts = count_recent(
        "SELECT COUNT(DISTINCT user_id) FROM login_history "
        "WHERE success = 0 AND ip = ? AND time >= ?",
        (ip, window_start),
    )
    if ip_accounts >= config.IP_ACCOUNTS_LIMIT:
        points += config.VELOCITY_POINTS
        reasons.append(f"this IP failed on {ip_accounts} accounts in the last {minutes} minutes")

    return points, reasons


def risk_level(score: int) -> str:
    """Turn a score into "low", "medium" or "high" using the config thresholds."""
    if score >= config.RISK_HIGH:
        return "high"
    if score >= config.RISK_MEDIUM:
        return "medium"
    return "low"


def choose_step(level: str, has_totp: bool, has_passkey: bool) -> str:
    """Pick what happens next: "login", "totp", "passkey" or "block"."""
    if level == "low":
        return "login"
    # A medium login with no authenticator app has no code to ask for, so it is treated as high
    if level == "medium" and has_totp:
        return "totp"
    if has_passkey:
        return "passkey"
    return "block"


def score_login(user_id: int, context: dict) -> dict:
    """Score a login whose password was correct. Returns score, level and reasons."""
    score = 0
    reasons = []

    user_counts = count_matches(context, user_id)
    if user_counts["total"] == 0:
        # Nothing to compare with yet, so only velocity counts
        reasons.append("no login history yet")
    else:
        all_counts = count_matches(context)
        for feature in FEATURES:
            points = feature_risk(feature, user_counts, all_counts)
            if points > 0:
                score += points
                reasons.append(feature_reason(feature, user_counts))

    velocity_points, velocity_reasons = velocity_risk(user_id, context["ip"])
    score += velocity_points
    reasons.extend(velocity_reasons)
    return {"score": score, "level": risk_level(score), "reasons": reasons}
