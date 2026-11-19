"""Starts the real app for an experiment, on a throwaway database.

E2 runs this as its own process so the attack scripts talk to a real server. It is
only a test helper, never part of the app the professor runs.
"""

import os
import sys
from pathlib import Path

# add the project root, so the app package can be imported
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from app import config

# point the app at the temporary database first
db_path = os.environ.get("EXP_DB_PATH")
if db_path:
    config.DB_PATH = Path(db_path)

# this builds the app, so it must come after the line above
from app import routes

if __name__ == "__main__":
    # the reloader would start a second copy, so it stays off
    routes.app.run(host="localhost", port=8000, use_reloader=False)
