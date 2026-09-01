import re
import time
import uuid
import json
from .db import get_db_connection

ISO_DATE_REGEX = re.compile(r"^\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}")

def extract_timeline_events(case_id: str, job_id: str):
    """Scan all recovered records for timestamp fields and build forensic timeline."""
    conn = get_db_connection()
    try:
        records = conn.execute("""
            SELECT record_id, column_types, column_values, confidence_score, provenance_json
            FROM faris_recovered_records
            WHERE job_id = ?
        """, (job_id,)).fetchall()

        events_created = 0
        with conn:
            for r in records:
                try:
                    types = json.loads(r["column_types"])
                    values = json.loads(r["column_values"])
                    prov = json.loads(r["provenance_json"])
                except Exception:
                    continue

                for idx, val in enumerate(values):
                    timestamp_str = None
                    is_inferred = 0
                    summary = ""

                    if isinstance(val, str) and ISO_DATE_REGEX.match(val):
                        timestamp_str = val
                        is_inferred = 0
                    elif isinstance(val, int) and (946684800 <= val <= 2524608000):
                        # Unix timestamp (2000 - 2050)
                        timestamp_str = time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime(val))
                        is_inferred = 1

                    if timestamp_str:
                        # Construct summary from adjacent text columns
                        text_snippets = [str(v) for v in values if isinstance(v, str) and v != val and len(str(v)) < 120]
                        if text_snippets:
                            summary = " | ".join(text_snippets[:3])
                        else:
                            summary = f"Record event (Row #{prov.get('cell_idx', 0)})"

                        event_id = f"TL-{uuid.uuid4().hex[:8].upper()}"
                        conn.execute("""
                            INSERT INTO faris_timeline_events
                            (event_id, case_id, job_id, record_id, timestamp_str, event_type, summary, confidence, is_inferred, provenance_json, created_at)
                            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """, (
                            event_id,
                            case_id,
                            job_id,
                            r["record_id"],
                            timestamp_str,
                            "Artifact Timestamp",
                            summary,
                            r["confidence_score"],
                            is_inferred,
                            r["provenance_json"],
                            int(time.time())
                        ))
                        events_created += 1

        return events_created
    finally:
        conn.close()

def get_timeline(case_id: str):
    conn = get_db_connection()
    try:
        rows = conn.execute("""
            SELECT * FROM faris_timeline_events
            WHERE case_id = ?
            ORDER BY timestamp_str ASC
        """, (case_id,)).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()
