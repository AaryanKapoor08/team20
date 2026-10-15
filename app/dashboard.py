"""Reads the numbers and lists shown on the admin dashboard."""

from app import config
from app import db

RISK_LEVELS = ["low", "medium", "high"]


def recent_logins(limit: int = 20) -> list:
    """Return the newest login attempts with the account's email, newest first."""
    connection = db.get_connection()
    # LEFT JOIN keeps attempts on unknown emails; their email comes back as None
    rows = connection.execute(
        "SELECT login_history.*, users.email FROM login_history "
        "LEFT JOIN users ON users.id = login_history.user_id "
        "ORDER BY login_history.id DESC LIMIT ?",
        (limit,),
    ).fetchall()
    connection.close()
    return rows


def risk_level_counts() -> dict:
    """Return how many scored logins were low, medium and high."""
    counts = {}
    for level in RISK_LEVELS:
        counts[level] = 0
    connection = db.get_connection()
    rows = connection.execute(
        "SELECT risk_level, COUNT(*) AS total FROM login_history "
        "WHERE risk_level IS NOT NULL GROUP BY risk_level"
    ).fetchall()
    connection.close()
    for row in rows:
        counts[row["risk_level"]] = row["total"]
    return counts


def chart_names() -> list:
    """Return the file names of the experiment charts in results/, or [] if there are none."""
    if not config.RESULTS_DIR.is_dir():
        return []
    names = []
    for path in sorted(config.RESULTS_DIR.glob("*.png")):
        names.append(path.name)
    return names
