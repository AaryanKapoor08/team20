"""E6: can someone quietly edit the audit log?

Writes 7 events, checks the hash chain, edits row 5 with plain SQL, checks again.
Run from the project root:  python experiments/e6_log_tampering.py
"""

import csv
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

from app import config

config.DB_PATH = Path(tempfile.mkdtemp()) / "experiment.db"

from app import audit_log
from app import db

CSV_PATH = ROOT / "results" / "e6_log_tampering.csv"
CHART_PATH = ROOT / "results" / "e6_log_tampering.png"
EDITED_ROW = 5

EVENTS = [
    ("login_success", {"user_id": 2, "ip": "24.70.15.5"}),
    ("login_failed", {"user_id": 3, "ip": "203.0.113.9", "reason": "wrong password"}),
    ("step_up_asked", {"user_id": 3, "ip": "203.0.113.9", "risk_level": "medium"}),
    ("step_up_passed", {"user_id": 3, "ip": "203.0.113.9", "check": "TOTP"}),
    ("login_blocked", {"user_id": 4, "ip": "45.9.9.9", "risk_level": "high"}),
    ("ip_blocked", {"ip": "45.9.9.9", "reason": "login risk score 13"}),
    ("session_ended", {"user_id": 2, "ip": "185.199.84.7", "reason": "used from another device"}),
]


def describe(broken_row):
    """Turn verify_chain's answer into text."""
    if broken_row is None:
        return "no break"
    return "row " + str(broken_row)


def main():
    """Build the log, check it, edit one row, check again, save the result."""
    db.create_tables()
    for event, details in EVENTS:
        audit_log.add_event(event, details)

    before = audit_log.verify_chain()

    # the attacker edits row 5 straight in the database
    connection = db.get_connection()
    connection.execute("UPDATE audit_log SET details = ? WHERE id = ?", ('{"ip": "0.0.0.0", "user_id": 0}', EDITED_ROW))
    connection.commit()
    connection.close()

    after = audit_log.verify_chain()

    rows = [
        {"scenario": "clean chain", "rows_in_log": len(EVENTS), "edited_row": "-",
         "verify_chain_reports": describe(before), "tampering_detected": "n/a"},
        {"scenario": "one row edited", "rows_in_log": len(EVENTS), "edited_row": EDITED_ROW,
         "verify_chain_reports": describe(after), "tampering_detected": "yes" if after == EDITED_ROW else "no"},
    ]

    with open(CSV_PATH, "w", newline="", encoding="utf-8") as file:
        writer = csv.DictWriter(file, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)

    cells = []
    for row in rows:
        cells.append([row["scenario"], row["verify_chain_reports"], row["tampering_detected"]])
    figure, axes = plt.subplots(figsize=(8, 1.6))
    axes.axis("off")
    axes.table(cellText=cells, colLabels=["log", "chain check says", "edit caught"], loc="center", cellLoc="center")
    axes.set_title("E6: editing row 5 of the audit log")
    figure.savefig(CHART_PATH, dpi=120, bbox_inches="tight")
    plt.close(figure)

    for row in rows:
        print(row["scenario"], "| chain check says:", row["verify_chain_reports"])


if __name__ == "__main__":
    main()
