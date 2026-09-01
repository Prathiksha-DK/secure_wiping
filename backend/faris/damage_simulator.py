import os
import shutil
import uuid
from .config import FARIS_LAB_DIR

def simulate_damage(source_db_path: str, scenario: str = "header_wipe") -> dict:
    """Apply controlled anti-forensic damage to a copy of a synthetic SQLite database for evaluation."""
    if not os.path.exists(source_db_path):
        raise FileNotFoundError(f"Source database not found: {source_db_path}")

    os.makedirs(FARIS_LAB_DIR, exist_ok=True)
    out_id = f"damaged_{scenario}_{uuid.uuid4().hex[:6]}"
    out_filename = f"{out_id}.raw"
    out_path = os.path.join(FARIS_LAB_DIR, out_filename)

    shutil.copy2(source_db_path, out_path)
    file_size = os.path.getsize(out_path)

    damage_description = ""
    bytes_affected = 0

    if scenario == "header_wipe":
        # Overwrite SQLite magic header (first 100 bytes) with zeros
        with open(out_path, "r+b") as f:
            f.seek(0)
            f.write(b"\x00" * 100)
        damage_description = "SQLite 100-byte database header wiped with zeros (anti-forensic header erasure)"
        bytes_affected = 100

    elif scenario == "header_corrupt":
        # Corrupt magic string
        with open(out_path, "r+b") as f:
            f.seek(0)
            f.write(b"CORRUPTED_HDR_XX")
        damage_description = "SQLite magic string overwritten with corrupted data"
        bytes_affected = 16

    elif scenario == "page_corrupt":
        # Corrupt page 2 header (offset 4096)
        if file_size >= 4096 + 8:
            with open(out_path, "r+b") as f:
                f.seek(4096)
                f.write(b"\xFF" * 8)
            damage_description = "Page 2 B-tree header corrupted with 0xFF bytes"
            bytes_affected = 8
        else:
            with open(out_path, "r+b") as f:
                f.seek(0)
                f.write(b"\x00" * 50)
            damage_description = "Header partially zeroed (file under 4096 bytes)"
            bytes_affected = 50

    elif scenario == "fragmented":
        # Extract only raw page fragments from offset 4096 onwards (orphan leaf chunk)
        if file_size > 4096:
            with open(source_db_path, "rb") as f_src:
                f_src.seek(4096)
                fragment_bytes = f_src.read()
            with open(out_path, "wb") as f_dst:
                f_dst.write(fragment_bytes)
            damage_description = f"Orphaned database fragment without Page 1 header ({len(fragment_bytes)} bytes)"
            bytes_affected = 4096
        else:
            damage_description = "Small fragment created"
            bytes_affected = 100

    elif scenario == "partial_overwrite":
        # Overwrite 512 bytes at offset 500
        with open(out_path, "r+b") as f:
            f.seek(min(500, max(0, file_size - 100)))
            f.write(b"\xAA" * min(512, file_size))
        damage_description = "512-byte block overwrite in table structure"
        bytes_affected = 512

    else:
        # Default header wipe
        with open(out_path, "r+b") as f:
            f.seek(0)
            f.write(b"\x00" * 100)
        damage_description = "Default header wipe applied"
        bytes_affected = 100

    # Test standard SQLite opening to demonstrate impairment
    standard_sqlite_status = "UNKNOWN"
    standard_sqlite_error = ""
    try:
        import sqlite3
        conn = sqlite3.connect(out_path)
        cur = conn.cursor()
        cur.execute("SELECT count(*) FROM sqlite_master;")
        cur.fetchall()
        conn.close()
        standard_sqlite_status = "OPENS (Standard parser can read schema)"
    except Exception as sqle:
        standard_sqlite_status = "FAILED"
        standard_sqlite_error = str(sqle)

    return {
        "damaged_filename": out_filename,
        "damaged_path": out_path,
        "file_size": os.path.getsize(out_path),
        "scenario": scenario,
        "damage_description": damage_description,
        "bytes_affected": bytes_affected,
        "standard_sqlite_status": standard_sqlite_status,
        "standard_sqlite_error": standard_sqlite_error
    }
