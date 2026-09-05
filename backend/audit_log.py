"""
SecureWipe — Tamper-Evident Cryptographic Audit Engine
Implements hash-chained security event logging for forensic integrity and auditability.
Each event is cryptographically bound to its predecessor:
  CurrentEventHash = SHA256(EventID + Timestamp + EventType + Operator + PayloadJSON + PreviousEventHash)
"""

import os
import time
import json
import sqlite3
import hashlib
import uuid
import threading
import tempfile
from typing import Dict, Any, List, Optional, Tuple

def _get_audit_db_path() -> str:
    data_dir = os.environ.get("SECUREWIPE_DATA_DIR")
    if not data_dir:
        data_dir = os.path.join(os.path.dirname(__file__), "data")
        try:
            os.makedirs(data_dir, exist_ok=True)
            test_file = os.path.join(data_dir, ".write_test_audit")
            with open(test_file, "w") as f:
                f.write("ok")
            os.remove(test_file)
        except Exception:
            data_dir = os.path.join(tempfile.gettempdir(), "securewipe_data")
            os.makedirs(data_dir, exist_ok=True)
    os.makedirs(data_dir, exist_ok=True)
    return os.path.join(data_dir, "audit.db")

AUDIT_DB_PATH = _get_audit_db_path()
GENESIS_HASH = "GENESIS_" + ("0" * 56)

_audit_db_lock = threading.Lock()

# ---------------------------------------------------------------------------
# Database Initialization
# ---------------------------------------------------------------------------
def init_audit_db() -> None:
    global AUDIT_DB_PATH
    AUDIT_DB_PATH = _get_audit_db_path()
    with _audit_db_lock:
        conn = sqlite3.connect(AUDIT_DB_PATH)
        try:
            with conn:
                conn.execute("""
                    CREATE TABLE IF NOT EXISTS audit_events (
                        sequence_num INTEGER PRIMARY KEY AUTOINCREMENT,
                        event_id TEXT UNIQUE NOT NULL,
                        timestamp TEXT NOT NULL,
                        timestamp_epoch INTEGER NOT NULL,
                        event_type TEXT NOT NULL,
                        operator TEXT NOT NULL,
                        target TEXT DEFAULT '',
                        client_ip TEXT DEFAULT '',
                        payload_json TEXT NOT NULL,
                        previous_hash TEXT NOT NULL,
                        event_hash TEXT NOT NULL
                    )
                """)
                conn.execute("""
                    CREATE INDEX IF NOT EXISTS idx_audit_event_type ON audit_events(event_type)
                """)
                conn.execute("""
                    CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_events(timestamp_epoch)
                """)
        finally:
            conn.close()

# ---------------------------------------------------------------------------
# Cryptographic Hash Chaining & Event Appending
# ---------------------------------------------------------------------------
def compute_event_hash(
    event_id: str,
    timestamp: str,
    event_type: str,
    operator: str,
    target: str,
    payload_json: str,
    previous_hash: str
) -> str:
    """Compute deterministic SHA-256 hash chaining for an audit event."""
    components = [
        event_id,
        timestamp,
        event_type,
        operator,
        target,
        payload_json,
        previous_hash,
    ]
    raw = "||".join(components)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()

def record_audit_event(
    event_type: str,
    operator: str = "system",
    target: str = "",
    client_ip: str = "127.0.0.1",
    payload: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """
    Append an immutable, cryptographically chained audit event.
    Thread-safe execution.
    """
    init_audit_db()
    
    event_id = f"EVT-{uuid.uuid4().hex[:12].upper()}"
    now_epoch = int(time.time())
    now_iso = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now_epoch))
    payload_dict = payload or {}
    payload_json = json.dumps(payload_dict, separators=(',', ':'), sort_keys=True)
    
    with _audit_db_lock:
        conn = sqlite3.connect(AUDIT_DB_PATH)
        try:
            conn.row_factory = sqlite3.Row
            # Fetch the most recent event hash
            cursor = conn.execute("SELECT event_hash FROM audit_events ORDER BY sequence_num DESC LIMIT 1")
            last_row = cursor.fetchone()
            previous_hash = last_row["event_hash"] if last_row else GENESIS_HASH
            
            # Compute current event hash
            event_hash = compute_event_hash(
                event_id=event_id,
                timestamp=now_iso,
                event_type=event_type,
                operator=operator,
                target=target,
                payload_json=payload_json,
                previous_hash=previous_hash
            )
            
            with conn:
                conn.execute("""
                    INSERT INTO audit_events
                    (event_id, timestamp, timestamp_epoch, event_type, operator, target, client_ip, payload_json, previous_hash, event_hash)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    event_id,
                    now_iso,
                    now_epoch,
                    event_type,
                    operator,
                    target,
                    client_ip,
                    payload_json,
                    previous_hash,
                    event_hash
                ))
                
            return {
                "event_id": event_id,
                "timestamp": now_iso,
                "event_type": event_type,
                "operator": operator,
                "target": target,
                "previous_hash": previous_hash,
                "event_hash": event_hash,
            }
        finally:
            conn.close()

# ---------------------------------------------------------------------------
# Audit Trail Verification & Tamper Detection
# ---------------------------------------------------------------------------
def verify_audit_log_integrity() -> Dict[str, Any]:
    """
    Traverse the entire audit log database and verify the cryptographic integrity of the hash chain.
    Returns PASS, or identifies exact compromised sequence number and reason if tampered.
    """
    init_audit_db()
    with _audit_db_lock:
        conn = sqlite3.connect(AUDIT_DB_PATH)
        try:
            conn.row_factory = sqlite3.Row
            rows = conn.execute("SELECT * FROM audit_events ORDER BY sequence_num ASC").fetchall()
            
            if not rows:
                return {
                    "status": "PASS",
                    "total_events": 0,
                    "verified_events": 0,
                    "chain_valid": True,
                    "message": "Audit log is empty (Genesis state)."
                }
                
            expected_prev_hash = GENESIS_HASH
            for idx, r in enumerate(rows):
                seq = r["sequence_num"]
                # 1. Verify link to previous event
                if r["previous_hash"] != expected_prev_hash:
                    return {
                        "status": "FAIL",
                        "compromised_sequence": seq,
                        "compromised_event_id": r["event_id"],
                        "chain_valid": False,
                        "error_type": "BROKEN_CHAIN_LINK",
                        "message": f"Broken link at sequence #{seq}: stored previous_hash '{r['previous_hash'][:16]}...' does not match expected '{expected_prev_hash[:16]}...'."
                    }
                    
                # 2. Re-compute current event hash from payload
                recalculated = compute_event_hash(
                    event_id=r["event_id"],
                    timestamp=r["timestamp"],
                    event_type=r["event_type"],
                    operator=r["operator"],
                    target=r["target"],
                    payload_json=r["payload_json"],
                    previous_hash=r["previous_hash"]
                )
                
                if recalculated != r["event_hash"]:
                    return {
                        "status": "FAIL",
                        "compromised_sequence": seq,
                        "compromised_event_id": r["event_id"],
                        "chain_valid": False,
                        "error_type": "MODIFIED_EVENT_DATA",
                        "message": f"Tampered data at sequence #{seq} ({r['event_id']}): payload has been modified post-recording."
                    }
                    
                expected_prev_hash = r["event_hash"]
                
            return {
                "status": "PASS",
                "total_events": len(rows),
                "verified_events": len(rows),
                "chain_valid": True,
                "latest_event_hash": expected_prev_hash,
                "message": f"All {len(rows)} audit log events verified successfully with unbroken cryptographic hash chaining."
            }
        finally:
            conn.close()

# ---------------------------------------------------------------------------
# Audit Query Helper
# ---------------------------------------------------------------------------
def get_audit_events(limit: int = 100, event_type: Optional[str] = None) -> List[Dict[str, Any]]:
    """Retrieve audit records for UI and reporting."""
    init_audit_db()
    with _audit_db_lock:
        conn = sqlite3.connect(AUDIT_DB_PATH)
        try:
            conn.row_factory = sqlite3.Row
            if event_type:
                rows = conn.execute(
                    "SELECT * FROM audit_events WHERE event_type = ? ORDER BY sequence_num DESC LIMIT ?",
                    (event_type, limit)
                ).fetchall()
            else:
                rows = conn.execute(
                    "SELECT * FROM audit_events ORDER BY sequence_num DESC LIMIT ?",
                    (limit,)
                ).fetchall()
                
            out = []
            for r in rows:
                item = dict(r)
                try:
                    item["payload"] = json.loads(r["payload_json"])
                except Exception:
                    item["payload"] = {}
                out.append(item)
            return out
        finally:
            conn.close()
