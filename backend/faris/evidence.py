import os
import re
import uuid
import time
from werkzeug.utils import secure_filename
from .config import FARIS_EVIDENCE_DIR, MAX_UPLOAD_SIZE
from .db import get_db_connection
from .hashing import compute_file_sha256
from .chain_of_custody import add_chain_event

ALLOWED_EXTENSIONS = {".db", ".sqlite", ".sqlite3", ".raw", ".bin", ".img", ".dat", ".dump"}

def sanitize_filename(filename: str) -> str:
    cleaned = secure_filename(filename)
    if not cleaned:
        cleaned = f"evidence_{uuid.uuid4().hex[:8]}.raw"
    return cleaned

def register_evidence_file(case_id: str, uploaded_file_obj, original_filename: str, investigator: str = "Analyst") -> dict:
    os.makedirs(FARIS_EVIDENCE_DIR, exist_ok=True)
    clean_name = sanitize_filename(original_filename)
    evidence_id = f"EVD-{uuid.uuid4().hex[:8].upper()}"
    stored_name = f"{evidence_id}_{clean_name}"
    stored_path = os.path.join(FARIS_EVIDENCE_DIR, stored_name)

    # Save to disk
    uploaded_file_obj.save(stored_path)
    file_size = os.path.getsize(stored_path)

    # Compute SHA-256
    sha256_hash = compute_file_sha256(stored_path)

    # Make file read-only on Windows / POSIX to preserve evidence integrity
    try:
        os.chmod(stored_path, 0o444)
    except Exception:
        pass

    conn = get_db_connection()
    try:
        with conn:
            conn.execute("""
                INSERT INTO faris_evidence
                (evidence_id, case_id, original_filename, stored_filename, file_size, sha256_hash, status, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (evidence_id, case_id, clean_name, stored_name, file_size, sha256_hash, "Preserved", int(time.time())))
    finally:
        conn.close()

    # Log in Chain of Custody
    add_chain_event(
        case_id=case_id,
        action="EVIDENCE_IMPORTED",
        details=f"Imported evidence file '{clean_name}' (Size: {file_size} bytes, SHA-256: {sha256_hash})",
        evidence_id=evidence_id,
        actor=investigator
    )

    return {
        "evidence_id": evidence_id,
        "case_id": case_id,
        "original_filename": clean_name,
        "stored_filename": stored_name,
        "file_size": file_size,
        "sha256_hash": sha256_hash,
        "status": "Preserved",
        "file_path": stored_path
    }

def get_evidence_path(stored_filename: str) -> str:
    path = os.path.join(FARIS_EVIDENCE_DIR, stored_filename)
    if not os.path.exists(path):
        raise FileNotFoundError(f"Evidence file {stored_filename} not found")
    return path
