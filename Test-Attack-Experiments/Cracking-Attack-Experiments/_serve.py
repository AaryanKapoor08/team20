"""Starts the real app on a throwaway database, for E2."""

import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app import config

# point the app at the temp database before the app is built
if os.environ.get("EXP_DB_PATH"):
    config.DB_PATH = Path(os.environ["EXP_DB_PATH"])

from app import routes

if __name__ == "__main__":
    routes.app.run(host="localhost", port=8000, use_reloader=False)
