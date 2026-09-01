import hashlib
import json
import time
import uuid
from .db import get_db_connection

GENESIS_HASH = "0000000000000000000000000000000000000000000000000000000000000000"

def add_chain_event(case_id: str, action: str, details: str, evidence_id: str = None, actor: str = "Forensic System"):
    conn = get_db_connection()
    try:
        with conn:
            # Find latest event in the case to get prev_hash and sequence_num
            row = conn.execute("""
                SELECT event_hash, sequence_num FROM faris_chain_events
                WHERE case_id = ? ORDER BY sequence_num DESC LIMIT 1
            """, (case_id,)).fetchone()

            if row:
                prev_hash = row["event_hash"]
                seq_num = row["sequence_num"] + 1
            else:
                prev_hash = GENESIS_HASH
                seq_num = 1

            timestamp_str = time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime())
            event_id = f"EVT-{uuid.uuid4().hex[:10].upper()}"

            # Compute hash
            payload = f"{prev_hash}|{seq_num}|{case_id}|{evidence_id or ''}|{timestamp_str}|{action}|{actor}|{details}"
            event_hash = hashlib.sha256(payload.encode("utf-8")).hexdigest().upper()

            conn.execute("""
                INSERT INTO faris_chain_events
                (event_id, case_id, evidence_id, timestamp, action, actor, details, prev_hash, event_hash, sequence_num)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (event_id, case_id, evidence_id, timestamp_str, action, actor, details, prev_hash, event_hash, seq_num))

            return {
                "event_id": event_id,
                "sequence_num": seq_num,
                "timestamp": timestamp_str,
                "action": action,
                "event_hash": event_hash,
                "prev_hash": prev_hash
            }
    finally:
        conn.close()

def get_chain_events(case_id: str):
    conn = get_db_connection()
    try:
        rows = conn.execute("""
            SELECT * FROM faris_chain_events
            WHERE case_id = ? ORDER BY sequence_num ASC
        """, (case_id,)).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()

def verify_chain_integrity(case_id: str):
    events = get_chain_events(case_id)
    if not events:
        return {"verified": True, "event_count": 0, "message": "No events found"}

    expected_prev = GENESIS_HASH
    for ev in events:
        if ev["prev_hash"] != expected_prev:
            return {
                "verified": False,
                "broken_at_sequence": ev["sequence_num"],
                "event_id": ev["event_id"],
                "error": "Previous hash pointer mismatch (Tamper Detected!)"
            }

        payload = f"{ev['prev_hash']}|{ev['sequence_num']}|{ev['case_id']}|{ev['evidence_id'] or ''}|{ev['timestamp']}|{ev['action']}|{ev['actor']}|{ev['details']}"
        recalculated_hash = hashlib.sha256(payload.encode("utf-8")).hexdigest().upper()

        if recalculated_hash != ev["event_hash"]:
            return {
                "verified": False,
                "broken_at_sequence": ev["sequence_num"],
                "event_id": ev["event_id"],
                "error": "Event signature mismatch (Tamper Detected!)"
            }

        expected_prev = ev["event_hash"]

    return {
        "verified": True,
        "event_count": len(events),
        "last_hash": expected_prev,
        "status": "VERIFIED_SECURE"
    }
