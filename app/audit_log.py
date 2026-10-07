"""Hash chained audit log: every security event is saved so that any later edit can be found."""

import hashlib
import json

from app import db

# The first row has no row before it, so it links to 64 zeros instead
FIRST_PREV_HASH = "0" * 64


def compute_hash(prev_hash: str, row: dict) -> str:
    """Return the SHA-256 of the previous row's hash plus this row as JSON."""
    # sort_keys gives the same text for the same row every time, so the hash can be rebuilt
    row_text = json.dumps(row, sort_keys=True)
    return hashlib.sha256((prev_hash + row_text).encode("utf-8")).hexdigest()


def add_event(event: str, details: dict) -> None:
    """Save one security event at the end of the chain."""
    # Never put passwords, codes, emails or session tokens in details
    row = {"time": db.utc_now(), "event": event, "details": json.dumps(details, sort_keys=True)}
    connection = db.get_connection()
    # IMMEDIATE locks the database for writing now, so two requests at once
    # cannot both read the same last hash and split the chain in two
    connection.execute("BEGIN IMMEDIATE")
    last_row = connection.execute(
        "SELECT hash FROM audit_log ORDER BY id DESC LIMIT 1"
    ).fetchone()
    prev_hash = FIRST_PREV_HASH
    if last_row is not None:
        prev_hash = last_row["hash"]
    connection.execute(
        "INSERT INTO audit_log (time, event, details, prev_hash, hash) VALUES (?, ?, ?, ?, ?)",
        (row["time"], row["event"], row["details"], prev_hash, compute_hash(prev_hash, row)),
    )
    connection.commit()
    connection.close()


def verify_chain() -> int | None:
    """Return the id of the first row that was changed, or None if the whole chain is fine."""
    connection = db.get_connection()
    rows = connection.execute("SELECT * FROM audit_log ORDER BY id").fetchall()
    connection.close()

    # Each row must point at the row before it and its own hash must still match its content.
    # A changed row breaks its own hash; a deleted row breaks the link of the row after it.
    # Known limit: deleting the newest rows leaves a shorter chain that still checks out.
    prev_hash = FIRST_PREV_HASH
    for saved_row in rows:
        row = {"time": saved_row["time"], "event": saved_row["event"], "details": saved_row["details"]}
        if saved_row["prev_hash"] != prev_hash:
            return saved_row["id"]
        if saved_row["hash"] != compute_hash(prev_hash, row):
            return saved_row["id"]
        prev_hash = saved_row["hash"]
    return None
