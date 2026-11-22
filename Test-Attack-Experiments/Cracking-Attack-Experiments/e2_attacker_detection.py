"""E2: which attackers get in, with and without the risk check?

Runs the botnet, VPN and targeted attackers against BASELINE, then ADAPTIVE.
Run from the project root, with nothing else on port 8000:
    python experiments/e2_attacker_detection.py
"""

import contextlib
import csv
import importlib
import io
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "attacks"))

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

from experiments import lab_server

CSV_PATH = ROOT / "results" / "e2_attacker_detection.csv"
CHART_PATH = ROOT / "results" / "e2_attacker_detection.png"

PROFILES = ["BASELINE", "ADAPTIVE"]
ATTACKERS = ["naive_botnet", "vpn_attacker", "targeted_attacker"]


def run_attacker(name):
    """Run one attack script and return its last summary line."""
    attack = importlib.import_module(name)
    printed = io.StringIO()
    with contextlib.redirect_stdout(printed):
        attack.run()
    last_line = ""
    for line in printed.getvalue().splitlines():
        if line.startswith(name + ":"):
            last_line = line.strip()
    return last_line


def read_result(line):
    """Turn the summary line into (got in yes/no, what stopped it)."""
    if "GOT IN" in line or "WARNING" in line:
        return "yes", "none (logged in)"
    if "stopped by " in line:
        return "no", line.split("stopped by ", 1)[1].strip()
    if "stopped (" in line:
        return "no", "wrong password (all guesses failed)"
    return "no", line


def main():
    """Run every attacker under both profiles, save the CSV and chart."""
    rows = []
    for profile in PROFILES:
        for name in ATTACKERS:
            print(profile, ": running", name, "...")
            # a fresh server and empty database every time
            server = lab_server.start_server(profile)
            try:
                line = run_attacker(name)
            finally:
                lab_server.stop_server(server)
            got_in, stopped_by = read_result(line)
            rows.append({"profile": profile, "attacker": name, "got_in": got_in, "stopped_by": stopped_by})

    with open(CSV_PATH, "w", newline="", encoding="utf-8") as file:
        writer = csv.DictWriter(file, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)

    # the chart is a simple table: one row per attacker, one column per profile
    cells = []
    for name in ATTACKERS:
        cell_row = []
        for row in rows:
            if row["attacker"] == name:
                if row["got_in"] == "yes":
                    cell_row.append("GOT IN")
                else:
                    cell_row.append("stopped: " + row["stopped_by"])
        cells.append(cell_row)
    figure, axes = plt.subplots(figsize=(9, 2.5))
    axes.axis("off")
    axes.table(cellText=cells, rowLabels=ATTACKERS, colLabels=PROFILES, loc="center", cellLoc="center")
    axes.set_title("E2: who got in")
    figure.savefig(CHART_PATH, dpi=120, bbox_inches="tight")
    plt.close(figure)

    for row in rows:
        print(row["profile"], "|", row["attacker"], "| got in:", row["got_in"])


if __name__ == "__main__":
    main()
