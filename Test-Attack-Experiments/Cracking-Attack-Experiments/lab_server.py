"""Starts and stops the app in the background, for E2."""

import os
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SERVE_SCRIPT = ROOT / "experiments" / "_serve.py"


def start_server(profile):
    """Start the app with this profile and lab mode on. Return the process."""
    settings = dict(os.environ)
    settings["EXP_DB_PATH"] = str(Path(tempfile.mkdtemp()) / "experiment.db")
    settings["SECURITY_PROFILE"] = profile
    settings["LAB_MODE"] = "1"
    process = subprocess.Popen([sys.executable, str(SERVE_SCRIPT)], cwd=str(ROOT), env=settings,
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    # wait up to 20 seconds for the login page to answer
    for _ in range(60):
        try:
            urllib.request.urlopen("http://localhost:8000/login", timeout=1)
            return process
        except (urllib.error.URLError, ConnectionError):
            time.sleep(0.3)
    process.terminate()
    raise RuntimeError("The server did not start.")


def stop_server(process):
    """Stop the app."""
    process.terminate()
    process.wait(timeout=10)
