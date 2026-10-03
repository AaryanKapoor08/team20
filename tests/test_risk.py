"""Tests for the risk engine, using made-up login history."""

from app import config
from app import db
from app import risk

# Alice's usual way of logging in
HOME = {
    "ip": "24.1.1.1",
    "country": "CA",
    "asn": "AS812",
    "browser": "Chrome",
    "os": "Windows",
    "device": "Desktop",
}


def user_id_for(email: str) -> int:
    """Return the id of a demo user."""
    return db.get_user_by_email(email)["id"]


def add_logins(user_id, context: dict, success: bool, count: int) -> None:
    """Add the same login to the history several times."""
    for attempt in range(count):
        db.record_login_attempt(user_id, context, success)


def changed(**new_values) -> dict:
    """Return a copy of HOME with some values changed."""
    context = dict(HOME)
    context.update(new_values)
    return context


def test_usual_login_is_low(demo_users):
    """A login that matches the user's history gets no points."""
    alice = user_id_for("alice@example.com")
    add_logins(alice, HOME, True, 10)

    result = risk.score_login(alice, HOME)

    assert result["score"] == 0
    assert result["level"] == "low"
    assert result["reasons"] == []


def test_new_country_is_medium(demo_users):
    """A new country (with its new IP and network) is medium, with readable reasons."""
    alice = user_id_for("alice@example.com")
    add_logins(alice, HOME, True, 10)
    abroad = changed(ip="177.2.2.2", country="BR", asn="AS28573")

    result = risk.score_login(alice, abroad)

    assert result["level"] == "medium"
    assert "new country for this user" in result["reasons"]
    assert "new network (ASN) for this user" in result["reasons"]


def test_everything_new_with_many_fails_is_high(demo_users):
    """All new values plus recent failures on the account is high."""
    alice = user_id_for("alice@example.com")
    add_logins(alice, HOME, True, 10)
    attacker = {
        "ip": "45.9.9.9",
        "country": "RU",
        "asn": "AS9009",
        "browser": "Python script",
        "os": "Linux",
        "device": "Mobile",
    }
    add_logins(alice, attacker, False, config.ACCOUNT_FAIL_LIMIT)

    result = risk.score_login(alice, attacker)

    assert result["level"] == "high"
    assert result["score"] >= config.RISK_BLOCK
    assert "3 failed logins on this account in the last 10 minutes" in result["reasons"]


def test_new_user_is_scored_on_velocity_only(demo_users):
    """A user with no past logins is low, with the reason "no login history yet"."""
    bob = user_id_for("bob@example.com")

    result = risk.score_login(bob, HOME)

    assert result["level"] == "low"
    assert result["reasons"] == ["no login history yet"]


def test_value_common_for_everyone_gives_fewer_points(demo_users):
    """A new browser that most users have (Chrome) scores less than one nobody has."""
    alice = user_id_for("alice@example.com")
    bob = user_id_for("bob@example.com")
    add_logins(alice, changed(browser="Firefox"), True, 10)
    add_logins(bob, HOME, True, 30)

    common_browser = risk.score_login(alice, changed(browser="Chrome"))
    rare_browser = risk.score_login(alice, changed(browser="Opera"))

    assert common_browser["score"] < rare_browser["score"]
    assert "new browser for this user" in common_browser["reasons"]


def test_one_ip_failing_on_many_accounts_adds_points(demo_users):
    """An IP that failed on several accounts recently raises the risk (credential stuffing)."""
    alice = user_id_for("alice@example.com")
    add_logins(alice, HOME, True, 10)
    stuffer = changed(ip="45.9.9.9")
    for email in ["bob@example.com", "carol@example.com", "admin@example.com"]:
        add_logins(user_id_for(email), stuffer, False, 1)

    result = risk.score_login(alice, stuffer)

    assert "this IP failed on 3 accounts in the last 10 minutes" in result["reasons"]


def test_one_person_logging_in_to_many_accounts_is_fine(demo_users):
    """Successful logins to several accounts from one IP do not count as stuffing."""
    for email in ["alice@example.com", "bob@example.com", "carol@example.com"]:
        add_logins(user_id_for(email), HOME, True, 1)

    result = risk.score_login(user_id_for("alice@example.com"), HOME)

    assert result["level"] == "low"
