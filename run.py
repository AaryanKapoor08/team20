"""One command to set up and start the app: python run.py"""

import shutil
import subprocess
import sys
from pathlib import Path

PROJECT_DIR = Path(__file__).resolve().parent
VENV_DIR = PROJECT_DIR / ".venv"
# Written only after the install finishes, so a stopped install is tried again
INSTALL_MARKER = VENV_DIR / "packages-installed.txt"
# localhost, not 127.0.0.1: passkeys refuse to work on an IP address
HOST = "localhost"
# 8000, not 5000: recent Macs already use port 5000 for AirPlay
PORT = 8000


def check_python_version():
    """Stop with a clear message if Python is older than 3.11."""
    if sys.version_info < (3, 11):
        print("Please install Python 3.11 or newer.")
        sys.exit(1)


def venv_python() -> Path:
    """Return the path of the Python inside .venv (different on Windows and Mac)."""
    if sys.platform == "win32":
        return VENV_DIR / "Scripts" / "python.exe"
    return VENV_DIR / "bin" / "python"


def running_inside_venv() -> bool:
    """Return True if this script is already being run by the .venv Python."""
    return Path(sys.prefix).resolve() == VENV_DIR.resolve()


def install_packages():
    """Make .venv and install the app packages, with uv if it is installed, else pip."""
    print("First run: installing packages, this can take a minute...", flush=True)
    if shutil.which("uv"):
        # --inexact keeps extra packages (like pytest) that the team installed
        uv_sync = ["uv", "sync", "--no-dev", "--inexact", "--locked"]
        subprocess.run(uv_sync, cwd=PROJECT_DIR, check=True)
    else:
        if not venv_python().exists():
            subprocess.run([sys.executable, "-m", "venv", str(VENV_DIR)], check=True)
        pip_install = [str(venv_python()), "-m", "pip", "install", "-r", "requirements.txt"]
        subprocess.run(pip_install, cwd=PROJECT_DIR, check=True)
    INSTALL_MARKER.write_text("ok\n", encoding="utf-8")


def start_app():
    """Start the Flask app on localhost:8000."""
    # Imported here because Flask only exists inside .venv
    from app import routes

    print(f"Open http://{HOST}:{PORT} in your browser. Press Ctrl+C to stop.")
    # debug stays off: debug mode lets anyone who sees an error page run code
    routes.app.run(host=HOST, port=PORT, debug=False)


def main():
    """Set up .venv if needed, then start the app inside it."""
    check_python_version()
    if running_inside_venv():
        start_app()
        return

    if not INSTALL_MARKER.exists():
        try:
            install_packages()
        except subprocess.CalledProcessError:
            print("Installing packages failed. Check your internet and run this again.")
            sys.exit(1)

    # Run this same file again, but with the .venv Python
    try:
        result = subprocess.run([str(venv_python()), str(Path(__file__).resolve())])
    except KeyboardInterrupt:
        return
    sys.exit(result.returncode)


if __name__ == "__main__":
    main()
