
import hashlib
import json
from datetime import datetime, timezone


GENESIS_HASH = "0" * 64


def create_audit_hash(
    actor_id,
    action,
    document_id,
    target_user_id,
    outcome,
    details,
    created_at,
    previous_hash,
):
    """Create a deterministic SHA-256 hash for an audit entry."""

    payload = {
        "actor_id": actor_id,
        "action": action,
        "document_id": document_id,
        "target_user_id": target_user_id,
        "outcome": outcome,
        "details": details,
        "created_at": created_at,
        "previous_hash": previous_hash,
    }

    canonical_data = json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )

    return hashlib.sha256(canonical_data.encode("utf-8")).hexdigest()


def write_audit_log(
    connection,
    *,
    actor_id,
    action,
    outcome,
    document_id=None,
    target_user_id=None,
    details=None,
):
    """
    Write one audit record using an existing SQLite connection.

    The caller is responsible for committing or rolling back the
    transaction. Do not include passwords, session secrets, or file
    contents in details.
    """

    if outcome not in ("success", "denied", "failure"):
        raise ValueError("Invalid audit outcome.")

    if not isinstance(action, str) or not action.strip():
        raise ValueError("Audit action is required.")

    if details is None:
        details = {}

    if not isinstance(details, dict):
        raise ValueError("Audit details must be a dictionary.")

    details_json = json.dumps(
        details,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )

    previous_entry = connection.execute(
        """
        SELECT entry_hash
        FROM audit_logs
        ORDER BY id DESC
        LIMIT 1
        """
    ).fetchone()

    previous_hash = (
        previous_entry["entry_hash"]
        if previous_entry
        else GENESIS_HASH
    )

    created_at = datetime.now(timezone.utc).isoformat()

    entry_hash = create_audit_hash(
        actor_id=actor_id,
        action=action.strip(),
        document_id=document_id,
        target_user_id=target_user_id,
        outcome=outcome,
        details=details_json,
        created_at=created_at,
        previous_hash=previous_hash,
    )

    connection.execute(
        """
        INSERT INTO audit_logs (
            actor_id,
            action,
            document_id,
            target_user_id,
            outcome,
            details,
            created_at,
            previous_hash,
            entry_hash
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            actor_id,
            action.strip(),
            document_id,
            target_user_id,
            outcome,
            details_json,
            created_at,
            previous_hash,
            entry_hash,
        ),
    )

    return entry_hash


def verify_audit_chain(connection):
    """
    Verify the stored hash chain and return its status.

    This detects many accidental or unauthorized record changes,
    but cannot prove authenticity if an attacker can rewrite the
    database and recompute the entire chain.
    """

    rows = connection.execute(
        """
        SELECT id, actor_id, action, document_id, target_user_id,
               outcome, details, created_at, previous_hash, entry_hash
        FROM audit_logs
        ORDER BY id ASC
        """
    ).fetchall()

    expected_previous_hash = GENESIS_HASH

    for row in rows:
        record = dict(row)

        if record["previous_hash"] != expected_previous_hash:
            return {
                "valid": False,
                "checked_entries": record["id"],
                "error": "Previous hash does not match.",
            }

        expected_hash = create_audit_hash(
            actor_id=record["actor_id"],
            action=record["action"],
            document_id=record["document_id"],
            target_user_id=record["target_user_id"],
            outcome=record["outcome"],
            details=record["details"],
            created_at=record["created_at"],
            previous_hash=record["previous_hash"],
        )

        if expected_hash != record["entry_hash"]:
            return {
                "valid": False,
                "checked_entries": record["id"],
                "error": "Entry hash does not match.",
            }

        expected_previous_hash = record["entry_hash"]

    return {
        "valid": True,
        "checked_entries": len(rows),
        "error": None,
    }
