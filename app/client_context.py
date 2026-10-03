"""Works out where a request comes from: IP, country, ASN, browser, OS and device."""

import json

from flask import Request, abort

from app import config

LAB_HEADER = "X-Lab-Client"
# The app only runs on localhost, so there is no real country or network to look up
LOCAL = "local"

# Checked in order: Edge also says "Chrome", and Chrome also says "Safari"
BROWSERS = [
    ("Edg/", "Edge"),
    ("OPR/", "Opera"),
    ("Firefox/", "Firefox"),
    ("Chrome/", "Chrome"),
    ("Safari/", "Safari"),
    ("python", "Python script"),
    ("curl", "curl"),
]
# Checked in order: iPhones also say "Mac OS X", and Android also says "Linux"
SYSTEMS = [
    ("iPhone", "iOS"),
    ("iPad", "iOS"),
    ("Android", "Android"),
    ("Windows", "Windows"),
    ("Mac OS X", "macOS"),
    ("Linux", "Linux"),
]


def find_name(user_agent: str, markers: list) -> str:
    """Return the name for the first marker found in the User-Agent, or "Other"."""
    lower_agent = user_agent.lower()
    for marker, name in markers:
        if marker.lower() in lower_agent:
            return name
    return "Other"


def find_device(user_agent: str) -> str:
    """Return "Tablet", "Mobile" or "Desktop" from the User-Agent."""
    if "iPad" in user_agent or "Tablet" in user_agent:
        return "Tablet"
    # Phones say "Mobile" (or "Mobi") in their User-Agent
    if "Mobi" in user_agent:
        return "Mobile"
    return "Desktop"


def parse_user_agent(user_agent: str) -> dict:
    """Return the browser, os and device named in a User-Agent text."""
    return {
        "browser": find_name(user_agent, BROWSERS),
        "os": find_name(user_agent, SYSTEMS),
        "device": find_device(user_agent),
    }


def read_lab_header(header_text: str) -> dict:
    """Return the fake client details sent by an attack script in the lab header."""
    try:
        return json.loads(header_text)
    except json.JSONDecodeError:
        abort(400, "The X-Lab-Client header is not valid JSON.")


def get_context(request: Request) -> dict:
    """Return the ip, country, asn, browser, os and device of this request."""
    ip = request.remote_addr
    country = LOCAL
    asn = LOCAL
    user_agent = request.headers.get("User-Agent", "")

    # The lab header is only read when LAB_MODE is on. If it were trusted in real use,
    # anyone could fake where they are and walk past the risk check.
    if config.LAB_MODE and LAB_HEADER in request.headers:
        lab_client = read_lab_header(request.headers[LAB_HEADER])
        ip = lab_client.get("ip", ip)
        country = lab_client.get("country", country)
        asn = lab_client.get("asn", asn)
        user_agent = lab_client.get("user_agent", user_agent)

    context = {"ip": ip, "country": country, "asn": asn}
    context.update(parse_user_agent(user_agent))
    return context
