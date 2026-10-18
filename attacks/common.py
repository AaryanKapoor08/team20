"""Shared helpers for the attack scripts: talk to our own login page over HTTP.

Every attacker sends a fake client context (IP, country, ASN, browser) in the
X-Lab-Client header. The app only trusts that header when LAB_MODE is on, so start
the app with `python run.py --lab` before running any of these scripts.

Only ever point these at our own app on localhost.
"""

import http.cookiejar
import json
import re
import sys
import urllib.error
import urllib.parse
import urllib.request

# The app always runs here. The localhost check below refuses any other target.
BASE_URL = "http://localhost:8000"

# Pieces of the app's own messages, so a script can tell what stopped it
UNUSUAL_LOGIN = "This login looks unusual"
TOO_MANY_ATTEMPTS = "Too many attempts"
LOGIN_ERROR = "Wrong email or password"

# Pulls the CSRF token out of the hidden field on a form page
CSRF_PATTERN = re.compile(r'name="csrf_token" value="([^"]+)"')


class NoRedirect(urllib.request.HTTPRedirectHandler):
    """Stops urllib following the redirect after a login, so we can read where it points."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        """Return None so the 302 is handed back to us instead of being followed."""
        return None


def require_localhost() -> None:
    """Stop the program unless the target is our own machine."""
    host = urllib.parse.urlparse(BASE_URL).hostname
    if host not in ("localhost", "127.0.0.1"):
        print(f"Refusing to run: {host} is not localhost. These scripts attack our own app only.")
        sys.exit(1)


def make_opener(lab_client: dict) -> urllib.request.OpenerDirector:
    """Return a fresh browser (its own cookies) that sends this fake client context."""
    cookie_jar = http.cookiejar.CookieJar()
    opener = urllib.request.build_opener(
        urllib.request.HTTPCookieProcessor(cookie_jar),
        NoRedirect(),
    )
    # Every request from this opener carries the same fake identity
    opener.addheaders = [("X-Lab-Client", json.dumps(lab_client))]
    # Kept so a script can read the session cookie back out of the jar
    opener.cookie_jar = cookie_jar
    return opener


def send(opener, path: str, data: dict = None, extra_headers: dict = None) -> dict:
    """Send one request and return its status, redirect target and body as a dict."""
    url = BASE_URL + path
    body = None
    if data is not None:
        body = urllib.parse.urlencode(data).encode("utf-8")

    request = urllib.request.Request(url, data=body)
    if extra_headers is not None:
        for name, value in extra_headers.items():
            request.add_header(name, value)

    # A 302 or a 4xx comes back as an HTTPError, which carries the same info as a response
    try:
        response = opener.open(request)
        return read_response(response.status, response, response.read())
    except urllib.error.HTTPError as error:
        return read_response(error.code, error, error.read())


def read_response(status: int, source, raw: bytes) -> dict:
    """Pack a status code, its Location header and its body text into one dict."""
    return {
        "status": status,
        "location": source.headers.get("Location", ""),
        "body": raw.decode("utf-8", errors="replace"),
    }


def get_csrf_token(opener) -> str:
    """Load a form page and return its CSRF token, so our POST is accepted."""
    page = send(opener, "/login")
    match = CSRF_PATTERN.search(page["body"])
    if match is None:
        raise RuntimeError("Could not find the CSRF token on the login page.")
    return match.group(1)


def attempt_login(opener, email: str, password: str) -> dict:
    """Try to log in with one email and password. Returns the response dict."""
    token = get_csrf_token(opener)
    form = {"email": email, "password": password, "csrf_token": token}
    return send(opener, "/login", form)


def describe_outcome(response: dict) -> str:
    """Turn a login response into a short plain-English result."""
    status = response["status"]
    location = response["location"]
    body = response["body"]

    if status == 302 and "/verify/totp" in location:
        return "risk step-up: TOTP code asked"
    if status == 302 and "/verify/passkey" in location:
        return "risk step-up: passkey asked"
    if status == 302:
        return "logged in"
    if TOO_MANY_ATTEMPTS in body:
        return "rate limit or account lockout"
    if UNUSUAL_LOGIN in body:
        return "risk block: login refused as too risky"
    if status == 403:
        return "firewall: IP already on the blocklist"
    if LOGIN_ERROR in body:
        return "wrong email or password"
    return f"unexpected response (status {status})"


def session_cookie(opener) -> str:
    """Return the session_token cookie this opener holds, or an empty string."""
    for cookie in opener.cookie_jar:
        if cookie.name == "session_token":
            return cookie.value
    return ""


def logged_in(opener, cookie: str = None) -> bool:
    """Return True if the home page opens (we are logged in) with this opener or cookie."""
    extra_headers = None
    if cookie is not None:
        extra_headers = {"Cookie": f"session_token={cookie}"}
    response = send(opener, "/", extra_headers=extra_headers)
    return response["status"] == 200


def establish_victim_history(email: str, password: str, victim_context: dict, times: int = 3) -> None:
    """Lab setup: log the victim in a few times from their usual device.

    The risk check compares a login to the user's past logins, so without this the
    app has nothing to flag an attacker against. A real user builds this history by
    logging in normally; here we create it quickly so the attack is realistic.
    """
    for _ in range(times):
        opener = make_opener(victim_context)
        attempt_login(opener, email, password)


def warn_lab_mode() -> None:
    """Remind the user the app must be in lab mode for the fake context to be read."""
    print("Note: start the app with `python run.py --lab`, or these fake contexts are ignored.")
    print(f"Target: {BASE_URL}")
    print()
