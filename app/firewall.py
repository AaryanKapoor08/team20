"""IP blocklist and admin IP allowlist, so Flask can act as its own firewall."""

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
    # Like fail2ban's "ignoreip": the admin's own IPs are never blocked, otherwise
    # an attacker could get the admin locked out of the page that unblocks IPs
    if is_admin_ip_allowed(ip):
        return False
    connection = db.get_connection()
    # OR IGNORE: blocking an IP that is already blocked keeps the first row and reason
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
