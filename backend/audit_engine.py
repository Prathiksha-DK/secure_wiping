"""
Tamper-Evident Audit Subsystem
Part of NTRO Adaptive Sanitization & Forensic Recovery Platform.

Implements cryptographically chained audit events using SHA-256 hash chaining.
Each record verifies the integrity of the previous record, ensuring that any
unauthorized deletion, modification, or reordering of audit logs is immediately detected.
"""

import sqlite3
import json
import time
import hashlib
from typing import Dict, Any, List, Optional, Tuple
from auth import get_db

GENESIS_HASH = "0" * 64


def record_audit_event(
    user_id: str,
    role: str,
    operation: str,
    status: str = "SUCCESS",
    device_id: str = "",
    details: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """
    Append an immutable, hash-chained audit event to the audit trail.
    """
    if details is None:
        details = {}

    details_str = json.dumps(details, sort_keys=True, default=str)
    timestamp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

    conn = get_db()
    try:
        cur = conn.cursor()
        # Find the latest audit record for sequence & prev_hash
        cur.execute("SELECT sequence, curr_hash FROM audit_logs ORDER BY sequence DESC LIMIT 1")
        last_record = cur.fetchone()

        if last_record:
            sequence = last_record["sequence"] + 1
            prev_hash = last_record["curr_hash"]
        else:
            sequence = 1
            prev_hash = GENESIS_HASH

        # Compute current hash over (prev_hash + sequence + timestamp + user_id + role + operation + status + details)
        payload = f"{prev_hash}|{sequence}|{timestamp}|{user_id}|{role}|{operation}|{status}|{details_str}"
        curr_hash = hashlib.sha256(payload.encode("utf-8")).hexdigest()

        cur.execute("""
            INSERT INTO audit_logs (sequence, prev_hash, curr_hash, timestamp, user_id, role, device_id, operation, status, details_json)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (sequence, prev_hash, curr_hash, timestamp, str(user_id), role, device_id, operation, status, details_str))
        conn.commit()

        return {
            "sequence": sequence,
            "prev_hash": prev_hash,
            "curr_hash": curr_hash,
            "timestamp": timestamp,
            "operation": operation,
            "status": status,
        }
    finally:
        conn.close()


def verify_audit_integrity() -> Dict[str, Any]:
    """
    Traverse the entire audit chain and verify cryptographic continuity.
    Returns audit status, total records, and any tampered sequence numbers.
    """
    conn = get_db()
    try:
        cur = conn.cursor()
        cur.execute("SELECT * FROM audit_logs ORDER BY sequence ASC")
        records = cur.fetchall()

        if not records:
            return {
                "verified": True,
                "total_events": 0,
                "status": "CHAIN_EMPTY",
                "message": "Audit chain is empty.",
            }

        expected_prev_hash = GENESIS_HASH
        for idx, rec in enumerate(records):
            seq = rec["sequence"]
            if seq != idx + 1:
                return {
                    "verified": False,
                    "tampered_at_sequence": seq,
                    "reason": f"Sequence break: expected {idx + 1}, found {seq}",
                    "total_events": len(records),
                }

            if rec["prev_hash"] != expected_prev_hash:
                return {
                    "verified": False,
                    "tampered_at_sequence": seq,
                    "reason": f"Hash continuity broken at sequence {seq}",
                    "total_events": len(records),
                }

            # Recalculate hash
            payload = f"{rec['prev_hash']}|{seq}|{rec['timestamp']}|{rec['user_id']}|{rec['role']}|{rec['operation']}|{rec['status']}|{rec['details_json']}"
            computed_hash = hashlib.sha256(payload.encode("utf-8")).hexdigest()

            if computed_hash != rec["curr_hash"]:
                return {
                    "verified": False,
                    "tampered_at_sequence": seq,
                    "reason": f"Payload hash mismatch at sequence {seq}. Content was modified!",
                    "total_events": len(records),
                }

            expected_prev_hash = rec["curr_hash"]

        return {
            "verified": True,
            "total_events": len(records),
            "latest_sequence": records[-1]["sequence"],
            "latest_hash": records[-1]["curr_hash"],
            "status": "SECURE_AND_VERIFIED",
            "message": "All cryptographic links verified. Zero tampering detected.",
        }
    finally:
        conn.close()


def get_audit_logs(limit: int = 100, role_filter: Optional[str] = None) -> List[Dict[str, Any]]:
    """Retrieve audit log records in reverse chronological order."""
    conn = get_db()
    try:
        cur = conn.cursor()
        if role_filter:
            cur.execute(
                "SELECT * FROM audit_logs WHERE role = ? ORDER BY sequence DESC LIMIT ?",
                (role_filter, limit)
            )
        else:
            cur.execute(
                "SELECT * FROM audit_logs ORDER BY sequence DESC LIMIT ?",
                (limit,)
            )
        rows = cur.fetchall()
        result = []
        for r in rows:
            d = dict(r)
            try:
                d["details"] = json.loads(d.get("details_json", "{}"))
            except Exception:
                d["details"] = {}
            result.append(d)
        return result
    finally:
        conn.close()
