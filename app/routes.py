"""Creates the Flask app and holds all the page routes."""

from flask import Flask

from app import config

app = Flask(__name__)

# Flask signs its own cookie with this key, so nobody can fake one.
# It comes from keys.json, never from the code.
keys = config.load_keys()
app.secret_key = keys["flask_secret_key"]


@app.route("/")
def home():
    """Show the home page."""
    return "Hello"
