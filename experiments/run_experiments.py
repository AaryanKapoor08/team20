"""Run every experiment (E1 to E7) and redraw all the charts in one command.

Each experiment is run as its own process, so one never affects the next: each
makes its own throwaway database and writes its CSV and chart into results/.

E1's real version uses hashcat (a GPU cracking tool) and is the only experiment
that needs an extra install. If hashcat is not on PATH we skip E1 and keep the E1
results already committed in results/, so the rest still runs anywhere.

Run from the project root, with the app NOT running (the experiments start their
own copy on port 8000):
    python experiments/run_experiments.py
"""

import shutil
import socket
import subprocess
import sys
import time
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
EXPERIMENTS_DIR = Path(__file__).resolve().parent

# The experiments start their own copy of the app here, so it has to be free
SERVER_PORT = 8000

# (label, script file). E1 is handled on its own because it depends on hashcat.
EXPERIMENTS = [
    ("E2 attacker detection", "e2_attacker_detection.py"),
    ("E3 false positives", "e3_false_positives.py"),
    ("E4 stolen session", "e4_stolen_session.py"),
    ("E5 lockout abuse", "e5_lockout_abuse.py"),
    ("E6 log tampering", "e6_log_tampering.py"),
    ("E7 phishing relay", "e7_phishing_relay.py"),
]


def print_install_help() -> None:
    """Print the one install command that fixes a missing package."""
    print("Install the packages from the project root, then run this again:")
    print("    uv sync")
    print("  or, without uv:")
    print(r"    Windows:  .venv\Scripts\python -m pip install -r requirements-dev.txt")
    print("    Mac:      .venv/bin/python -m pip install -r requirements-dev.txt")


def check_packages() -> None:
    """Stop with one clear message if a needed package is missing, not 7 tracebacks."""
    try:
        import flask
    except ImportError:
        print("Flask is not installed, so this is not the project's Python.")
        print()
        print("Run the experiments with the Python inside the project's .venv folder:")
        print(r"    Windows:  .venv\Scripts\python experiments\run_experiments.py")
        print("    Mac:      .venv/bin/python experiments/run_experiments.py")
        sys.exit(1)

    try:
        import matplotlib
    except ImportError:
        print("matplotlib is not installed, so the charts cannot be drawn.")
        print()
        print("It is in the dev package list, which `run.py` does not install")
        print("(the app itself does not need it).")
        print()
        print_install_help()
        sys.exit(1)


def check_port_is_free() -> None:
    """Stop if something already answers on port 8000, or the results would be wrong."""
    probe = socket.socket()
    probe.settimeout(1)
    # connect_ex returns 0 only when something is already listening there
    is_busy = probe.connect_ex(("127.0.0.1", SERVER_PORT)) == 0
    probe.close()
    if not is_busy:
        return

    print(f"Something is already using port {SERVER_PORT}, most likely the app.")
    print()
    print("Each experiment starts its own copy of the app on that port with a fresh")
    print("temporary database. If another app is already there, the experiments would")
    print("quietly measure that one instead and the numbers would be wrong.")
    print()
    print("Stop the running app (Ctrl+C in its terminal), then run this again.")
    sys.exit(1)


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
    check_packages()
    check_port_is_free()

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
