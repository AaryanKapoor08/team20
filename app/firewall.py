"""The small firewall built into the app.

It keeps a list of blocked IPs that are refused on every page, and a list of IPs
that are allowed to open the admin page.
"""

from app import audit_log
from app import config
from app import db


def is_blocked(ip: str) -> bool:
    """Return True if this IP is on the blocklist."""
    connection = db.get_connection()
    row = connection.execute("SELECT ip FROM blocked_ips WHERE ip = ?", (ip,)).fetchone()
    connection.close()
    return row is not None


def block_ip(ip: str, reason: str) -> bool:
    """Add this IP to the blocklist. Returns False if the IP may never be blocked."""
    # the admin's own IPs are never blocked, or nobody could unblock anything
    if is_admin_ip_allowed(ip):
        return False
    connection = db.get_connection()
    # blocking an IP twice keeps the first reason
    connection.execute(
        "INSERT OR IGNORE INTO blocked_ips (ip, reason, time) VALUES (?, ?, ?)",
        (ip, reason, db.utc_now()),
    )
    connection.commit()
    connection.close()
    audit_log.add_event("ip_blocked", {"ip": ip, "reason": reason})
    return True


def unblock_ip(ip: str, admin_user_id: int) -> None:
    """Remove this IP from the blocklist and log which admin did it."""
    connection = db.get_connection()
    connection.execute("DELETE FROM blocked_ips WHERE ip = ?", (ip,))
    connection.commit()
    connection.close()
    audit_log.add_event("ip_unblocked", {"ip": ip, "user_id": admin_user_id})


def list_blocked() -> list:
    """Return every blocked IP, newest first."""
    connection = db.get_connection()
    rows = connection.execute("SELECT * FROM blocked_ips ORDER BY time DESC").fetchall()
    connection.close()
    return rows


def is_admin_ip_allowed(ip: str) -> bool:
    """Return True if the admin page may be opened from this IP."""
    return ip in config.ADMIN_ALLOWED_IPS
