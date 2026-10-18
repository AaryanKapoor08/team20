"""Start the real app for an experiment, using a throwaway database.

The E2 experiment launches this file as a separate process so the attack scripts
talk to a real HTTP server, firewall and all. The database path, security profile
and lab mode are passed in through environment variables set by lab_server.py.

This is a test harness, never part of the app the professor runs.
"""

import os
import sys
from pathlib import Path

# Run as a plain script, so add the project root to import the app package
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from app import config

# Point the app at the temporary database before anything opens a connection
db_path = os.environ.get("EXP_DB_PATH")
if db_path:
    config.DB_PATH = Path(db_path)

# Importing routes builds the Flask app and makes the tables and demo users,
# so it must come after the database path is set above.
from app import routes

if __name__ == "__main__":
    # use_reloader off: the reloader would start a second process on a fresh import
    routes.app.run(host="localhost", port=8000, use_reloader=False)
