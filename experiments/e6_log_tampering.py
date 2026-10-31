"""E6: can someone quietly edit the audit log without being caught?

The audit log is hash-chained: each row stores the hash of the row before it, and
its own hash covers its contents (see app/audit_log.py). We build a clean chain,
check it, then change one row's details directly in the database with plain SQL and
check again. verify_chain() should report the exact row that was edited, because a
changed row no longer matches its stored hash.

This runs entirely against a throwaway database; no server is needed.

Run from the project root:  python experiments/e6_log_tampering.py
"""

import csv
import sys
import tempfile
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt

from app import config

config.DB_PATH = Path(tempfile.mkdtemp(prefix="team20_e6_")) / "experiment.db"

from app import audit_log
from app import db

RESULTS_DIR = PROJECT_ROOT / "results"
CSV_PATH = RESULTS_DIR / "e6_log_tampering.csv"
CHART_PATH = RESULTS_DIR / "e6_log_tampering.png"

# A realistic run of security events to fill the log
EVENTS = [
    ("login_success", {"user_id": 2, "ip": "24.70.15.5"}),
    ("login_failed", {"user_id": 3, "ip": "203.0.113.9", "reason": "wrong password"}),
    ("step_up_asked", {"user_id": 3, "ip": "203.0.113.9", "risk_level": "medium"}),
    ("step_up_passed", {"user_id": 3, "ip": "203.0.113.9", "check": "TOTP"}),
    ("login_blocked", {"user_id": 4, "ip": "45.9.9.9", "risk_level": "high"}),
    ("ip_blocked", {"ip": "45.9.9.9", "reason": "login risk score 13"}),
    ("session_ended", {"user_id": 2, "ip": "185.199.84.7", "reason": "used from another device"}),
]

# The row an attacker tries to rewrite (for example, to hide that they were blocked)
EDITED_ROW = 5


def build_chain() -> None:
    """Write every event into the hash-chained audit log in order."""
    for event, details in EVENTS:
        audit_log.add_event(event, details)


def tamper_with_row(row_id: int) -> None:
    """Change one row's details directly in the database, like an attacker would."""
    connection = db.get_connection()
    connection.execute(
        "UPDATE audit_log SET details = ? WHERE id = ?",
        ('{"ip": "0.0.0.0", "user_id": 0}', row_id),
    )
    connection.commit()
    connection.close()


def collect_rows() -> list:
    """Build the chain, check it, tamper with one row, and check again."""
    config.DB_PATH = Path(tempfile.mkdtemp(prefix="team20_e6_")) / "experiment.db"
    db.create_tables()
    build_chain()

    clean_break = audit_log.verify_chain()
    tamper_with_row(EDITED_ROW)
    tampered_break = audit_log.verify_chain()

    return [
        {
            "scenario": "clean chain",
            "rows_in_log": len(EVENTS),
            "edited_row": "-",
            "verify_chain_reports": "no break" if clean_break is None else f"row {clean_break}",
            "tampering_detected": "n/a",
        },
        {
            "scenario": "one row edited",
            "rows_in_log": len(EVENTS),
            "edited_row": EDITED_ROW,
            "verify_chain_reports": "no break" if tampered_break is None else f"row {tampered_break}",
            "tampering_detected": "yes" if tampered_break == EDITED_ROW else "no",
        },
    ]


def write_csv(rows: list) -> None:
    """Save the result rows to the E6 CSV."""
    RESULTS_DIR.mkdir(exist_ok=True)
    with open(CSV_PATH, "w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)


def draw_chart(rows: list) -> None:
    """Draw the log as a row of cells: green verified, red the edited row, grey after it."""
    total = len(EVENTS)
    figure, axes = plt.subplots(figsize=(10, 2.6))
    for index in range(total):
        row_id = index + 1
        if row_id < EDITED_ROW:
            color, label = "#27ae60", "ok"
        elif row_id == EDITED_ROW:
            color, label = "#e74c3c", "edited"
        else:
            color, label = "#95a5a6", "unchecked"
        axes.add_patch(plt.Rectangle((index, 0), 1, 1, facecolor=color, edgecolor="white"))
        axes.text(index + 0.5, 0.5, f"row {row_id}\n{label}", ha="center", va="center", color="white", fontsize=9)

    axes.set_xlim(0, total)
    axes.set_ylim(0, 1)
    axes.set_xticks([])
    axes.set_yticks([])
    axes.set_title(f"E6: editing row {EDITED_ROW} breaks the hash chain at row {EDITED_ROW}")
    figure.tight_layout()
    figure.savefig(CHART_PATH, dpi=120)
    plt.close(figure)


def run() -> None:
    """Run the experiment, save the CSV and chart, and print a summary."""
    print("E6: editing one audit-log row and running the chain check")
    rows = collect_rows()
    write_csv(rows)
    draw_chart(rows)

    print()
    for row in rows:
        print(f"  {row['scenario']:>15} | verify_chain reports: {row['verify_chain_reports']}")
    print()
    print(f"Saved {CSV_PATH.name} and {CHART_PATH.name} in results/.")


if __name__ == "__main__":
    run()
