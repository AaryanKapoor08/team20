"""Admin pages: the security dashboard, unblocking IPs and the experiment charts."""

from flask import Blueprint, abort, redirect, render_template, request, send_from_directory, url_for

from app import audit_log
from app import config
from app import dashboard
from app import firewall
from app import sessions

admin = Blueprint("admin", __name__)


def refuse_non_admin(user) -> None:
    """Stop with 403 unless this user is an admin on an allowed IP."""
    if user is None or user["role"] != "admin":
        abort(403)
    # Checks where you are, not just who you are: a stolen admin password is not enough.
    # The real network address is used, never the lab header, so lab mode cannot fake it.
    if not firewall.is_admin_ip_allowed(request.remote_addr):
        abort(403)


@admin.route("/admin")
def dashboard_page():
    """Show recent logins, blocked IPs, the audit chain status and charts."""
    user = sessions.current_user()
    if user is None:
        return redirect(url_for("login"))
    refuse_non_admin(user)
    return render_template(
        "admin.html",
        user=user,
        logins=dashboard.recent_logins(),
        blocked_ips=firewall.list_blocked(),
        changed_row=audit_log.verify_chain(),
        risk_counts=dashboard.risk_level_counts(),
        chart_names=dashboard.chart_names(),
    )


@admin.route("/admin/unblock", methods=["POST"])
def unblock():
    """Take one IP off the blocklist, then go back to the dashboard."""
    user = sessions.current_user()
    refuse_non_admin(user)
    ip = request.form.get("ip", "")
    firewall.unblock_ip(ip, user["id"])
    return redirect(url_for("admin.dashboard_page"))


@admin.route("/admin/charts/<name>")
def chart(name: str):
    """Send one experiment chart image from results/."""
    refuse_non_admin(sessions.current_user())
    # send_from_directory refuses names like "../keys.json", so only files in results/ are sent
    return send_from_directory(config.RESULTS_DIR, name)
