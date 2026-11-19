"""Starts and stops the app for the experiments that need a real server.

It launches _serve.py in its own process, waits for the port to answer, and shuts it
down again afterwards.
"""

import contextlib
import os
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
SERVE_SCRIPT = Path(__file__).resolve().parent / "_serve.py"
BASE_URL = "http://localhost:8000"

# how long to wait for the server before giving up
START_TIMEOUT_SECONDS = 20


def wait_until_up() -> None:
    """Poll the login page until it answers, or raise if it never does."""
    deadline = time.time() + START_TIMEOUT_SECONDS
    while time.time() < deadline:
        try:
            with urllib.request.urlopen(BASE_URL + "/login", timeout=1) as response:
                if response.status == 200:
                    return
        except (urllib.error.URLError, ConnectionError):
            # not up yet, wait and try again
            time.sleep(0.3)
    raise RuntimeError("The experiment server did not start in time.")


@contextlib.contextmanager
def running(profile: str):
    """Run the app with this security profile and lab mode on, then stop it."""
    temp_dir = tempfile.mkdtemp(prefix="team20_exp_")
    db_path = Path(temp_dir) / "experiment.db"

    environment = dict(os.environ)
    environment["EXP_DB_PATH"] = str(db_path)
    environment["SECURITY_PROFILE"] = profile
    environment["LAB_MODE"] = "1"

    # quiet, or the server logs would bury the experiment output
    process = subprocess.Popen(
        [sys.executable, str(SERVE_SCRIPT)],
        cwd=str(PROJECT_ROOT),
        env=environment,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    try:
        wait_until_up()
        yield
    finally:
        process.terminate()
        process.wait(timeout=10)
