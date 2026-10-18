"""E2: which attackers get in under BASELINE, and which the adaptive defense stops.

We run the first three attack scripts against our own app twice: once with
SECURITY_PROFILE=BASELINE (rate limit and lockout only, like most sites) and once
with ADAPTIVE (the risk check and step-up from Part 2). For each run we record
whether the attacker got in and, if not, which layer stopped them.

Each attacker runs against a fresh, empty database so one run never affects the next.

Run from the project root, with nothing else on port 8000:
    python experiments/e2_attacker_detection.py
"""

import contextlib
import csv
import importlib
import io
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
ATTACKS_DIR = PROJECT_ROOT / "attacks"
# The attack scripts do `import common`, so attacks/ must be on the path
sys.path.insert(0, str(PROJECT_ROOT))
sys.path.insert(0, str(ATTACKS_DIR))

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt

from experiments import lab_server

RESULTS_DIR = PROJECT_ROOT / "results"
CSV_PATH = RESULTS_DIR / "e2_attacker_detection.csv"
CHART_PATH = RESULTS_DIR / "e2_attacker_detection.png"

PROFILES = ["BASELINE", "ADAPTIVE"]
# Attackers 1 to 3 (the credential attackers). The cookie and lockout attackers
# belong to E4 and E5, where session binding and lockout are the point.
ATTACKERS = ["naive_botnet", "vpn_attacker", "targeted_attacker"]


def run_attacker(name: str) -> str:
    """Run one attacker's run() and return everything it printed."""
    module = importlib.import_module(name)
    captured = io.StringIO()
    with contextlib.redirect_stdout(captured):
        module.run()
    return captured.getvalue()


def final_line(name: str, output: str) -> str:
    """Return the attacker's last summary line (the one that starts with its name)."""
    result = ""
    for line in output.splitlines():
        if line.startswith(f"{name}:"):
            result = line.strip()
    return result


def classify(name: str, output: str) -> tuple:
    """Turn an attacker's output into (got_in: bool, defense: str)."""
    line = final_line(name, output)
    got_in = "GOT IN" in line or "WARNING" in line
    if got_in:
        return True, "none (logged in)"
    if "stopped by " in line:
        return False, line.split("stopped by ", 1)[1].strip()
    if "stopped (" in line:
        return False, "wrong password (all guesses failed)"
    return False, line


def collect_rows() -> list:
    """Run every attacker under every profile and return one row per run."""
    rows = []
    for profile in PROFILES:
        for name in ATTACKERS:
            print(f"  {profile}: running {name} ...")
            # A fresh server and empty database for every single run
            with lab_server.running(profile):
                output = run_attacker(name)
            got_in, defense = classify(name, output)
            rows.append({
                "profile": profile,
                "attacker": name,
                "got_in": "yes" if got_in else "no",
                "stopped_by": defense,
            })
    return rows


def write_csv(rows: list) -> None:
    """Save the result rows to the E2 CSV."""
    RESULTS_DIR.mkdir(exist_ok=True)
    with open(CSV_PATH, "w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)


def draw_chart(rows: list) -> None:
    """Draw a grid: red cell if the attacker got in, green if a layer stopped it."""
    # Look up each result by (profile, attacker) so we can place it in the grid
    by_cell = {}
    for row in rows:
        by_cell[(row["profile"], row["attacker"])] = row

    figure, axes = plt.subplots(figsize=(9, 3.6))
    for column, profile in enumerate(PROFILES):
        for grid_row, attacker in enumerate(ATTACKERS):
            row = by_cell[(profile, attacker)]
            got_in = row["got_in"] == "yes"
            color = "#e74c3c" if got_in else "#27ae60"
            axes.add_patch(plt.Rectangle((column, grid_row), 1, 1, facecolor=color, edgecolor="white"))
            label = "GOT IN" if got_in else row["stopped_by"]
            axes.text(
                column + 0.5, grid_row + 0.5, label,
                ha="center", va="center", color="white", fontsize=8, wrap=True,
            )

    axes.set_xlim(0, len(PROFILES))
    axes.set_ylim(0, len(ATTACKERS))
    axes.set_xticks([c + 0.5 for c in range(len(PROFILES))])
    axes.set_xticklabels(PROFILES)
    axes.set_yticks([r + 0.5 for r in range(len(ATTACKERS))])
    axes.set_yticklabels(ATTACKERS)
    axes.invert_yaxis()
    axes.set_title("E2: red = attacker got in, green = stopped (and by what)")
    figure.tight_layout()
    figure.savefig(CHART_PATH, dpi=120)
    plt.close(figure)


def run() -> None:
    """Run the whole experiment, save the CSV and chart, and print a summary."""
    print("E2: running attackers 1 to 3 against BASELINE, then ADAPTIVE")
    rows = collect_rows()
    write_csv(rows)
    draw_chart(rows)

    print()
    for row in rows:
        verdict = "GOT IN" if row["got_in"] == "yes" else f"stopped by {row['stopped_by']}"
        print(f"  {row['profile']:>8} | {row['attacker']:<18} | {verdict}")
    print()
    print(f"Saved {CSV_PATH.name} and {CHART_PATH.name} in results/.")


if __name__ == "__main__":
    run()
