"""Run every experiment (E1 to E7) and redraw all the charts in one command.

Each experiment is run as its own process, so one never affects the next: each
makes its own throwaway database and writes its CSV and chart into results/.

E1's real version uses hashcat (a GPU cracking tool) and is the only experiment
that needs an extra install. If hashcat is not on PATH we skip E1 and keep the E1
results already committed in results/, so the rest still runs anywhere.

Run from the project root, with nothing else on port 8000 (E2 needs it):
    python experiments/run_experiments.py
"""

import shutil
import subprocess
import sys
import time
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
EXPERIMENTS_DIR = Path(__file__).resolve().parent

# (label, script file). E1 is handled on its own because it depends on hashcat.
EXPERIMENTS = [
    ("E2 attacker detection", "e2_attacker_detection.py"),
    ("E3 false positives", "e3_false_positives.py"),
    ("E4 stolen session", "e4_stolen_session.py"),
    ("E5 lockout abuse", "e5_lockout_abuse.py"),
    ("E6 log tampering", "e6_log_tampering.py"),
    ("E7 phishing relay", "e7_phishing_relay.py"),
]


def run_one(label: str, script: str) -> bool:
    """Run one experiment as its own process and return True if it finished cleanly."""
    print()
    print("=" * 70)
    print(f"Running {label}  ({script})")
    print("=" * 70)
    # sys.executable is this same Python, so the child uses the project's packages
    result = subprocess.run([sys.executable, str(EXPERIMENTS_DIR / script)], cwd=str(PROJECT_ROOT))
    return result.returncode == 0


def run_e1_if_possible(results: list) -> None:
    """Run E1 only if hashcat is installed; otherwise skip it and keep its results."""
    if shutil.which("hashcat") is None:
        print()
        print("=" * 70)
        print("Skipping E1 hash cracking: hashcat is not on PATH.")
        print("Keeping the E1 results already in results/ (see experiments/e1_hash_cracking.py).")
        print("=" * 70)
        results.append(("E1 hash cracking", "skipped (no hashcat)"))
        return
    ok = run_one("E1 hash cracking", "e1_hash_cracking.py")
    results.append(("E1 hash cracking", "ok" if ok else "FAILED"))


def run() -> None:
    """Run E1 (if possible) then E2 to E7, and print a summary of what passed."""
    start = time.perf_counter()
    results = []

    run_e1_if_possible(results)
    for label, script in EXPERIMENTS:
        ok = run_one(label, script)
        results.append((label, "ok" if ok else "FAILED"))

    elapsed = time.perf_counter() - start
    print()
    print("=" * 70)
    print("Summary")
    print("=" * 70)
    for label, status in results:
        print(f"  {label:<24} {status}")
    print()
    print(f"Done in {elapsed:.0f} s. Charts and CSVs are in results/.")

    # A non-zero exit code if anything actually failed, so a script can tell
    if any(status == "FAILED" for _, status in results):
        sys.exit(1)


if __name__ == "__main__":
    run()
