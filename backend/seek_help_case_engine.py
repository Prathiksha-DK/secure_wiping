"""
Seek Help & Forensic Case Investigation Engine
SecureWipe Defense & Forensic Infrastructure

Strict Additive Module:
- Device selection backed by Central Device Registry (enforcing REGISTERED status).
- Sector-by-sector read-only RAW forensic acquisition (.img/.dd).
- Real-time SHA-256 calculation and immutable case metadata.
- Atomic case locking and anti-double claiming.
- Server-enforced one-active-case rule per Hunter.
- Multi-stage investigation workflow:
  AVAILABLE -> CLAIMED / INVESTIGATION_IN_PROGRESS -> SUBMITTED_FOR_REVIEW -> COMPLETED (or RETURNED_FOR_CORRECTION).
- SHA-256 forward-chained tamper-evident audit logging.
"""

import os
import sys
import time
import json
import uuid
import ctypes
import hashlib
import sqlite3
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple
from flask import Blueprint, jsonify, request, send_file

from auth import get_db, validate_session
from audit_engine import record_audit_event
from central_device_registry import (
    get_registered_device_by_id,
    get_registered_device_by_fingerprint,
    compute_device_fingerprint,
)

seek_help_bp = Blueprint("seek_help_engine", __name__)

DATA_DIR = os.path.join(os.path.dirname(__file__), "data")
CASES_STORAGE_DIR = os.path.join(DATA_DIR, "forensic_cases")
os.makedirs(CASES_STORAGE_DIR, exist_ok=True)


def init_seek_help_db() -> None:
    """Initialize forensic_investigation_cases table in platform.db."""
    conn = get_db()
    try:
        with conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS forensic_investigation_cases (
                    case_id TEXT PRIMARY KEY,
                    title TEXT NOT NULL,
                    device_id TEXT NOT NULL,
                    device_fingerprint TEXT NOT NULL,
                    device_model TEXT NOT NULL DEFAULT 'Unknown Device',
                    device_manufacturer TEXT NOT NULL DEFAULT 'Generic',
                    device_serial TEXT NOT NULL DEFAULT 'UNKNOWN',
                    device_capacity INTEGER NOT NULL DEFAULT 0,
                    device_capacity_readable TEXT NOT NULL DEFAULT '0 B',
                    image_filename TEXT NOT NULL,
                    image_path TEXT NOT NULL,
                    image_format TEXT NOT NULL DEFAULT 'RAW',
                    image_size INTEGER NOT NULL DEFAULT 0,
                    sector_size INTEGER NOT NULL DEFAULT 512,
                    total_sectors INTEGER NOT NULL DEFAULT 0,
                    sha256 TEXT NOT NULL,
                    md5 TEXT DEFAULT '',
                    acquisition_start_time INTEGER NOT NULL,
                    acquisition_end_time INTEGER NOT NULL,
                    acquisition_status TEXT NOT NULL DEFAULT 'ACQUISITION_COMPLETED',
                    case_status TEXT NOT NULL DEFAULT 'AVAILABLE', 
                    -- Statuses: AVAILABLE, INVESTIGATION_IN_PROGRESS, SUBMITTED_FOR_REVIEW, RETURNED_FOR_CORRECTION, COMPLETED
                    assigned_hunter_id TEXT DEFAULT NULL,
                    claimed_at INTEGER DEFAULT NULL,
                    submitted_at INTEGER DEFAULT NULL,
                    reviewed_at INTEGER DEFAULT NULL,
                    completed_at INTEGER DEFAULT NULL,
                    investigation_findings TEXT DEFAULT '',
                    evidence_artifacts TEXT DEFAULT '[]', -- JSON array
                    results_summary TEXT DEFAULT '',
                    supporting_documents TEXT DEFAULT '[]', -- JSON array
                    inspector_notes TEXT DEFAULT '',
                    created_by TEXT NOT NULL DEFAULT 'forensic_analyst',
                    created_at INTEGER NOT NULL
                )
            """)
            conn.execute("CREATE INDEX IF NOT EXISTS idx_case_dev ON forensic_investigation_cases(device_id)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_case_status ON forensic_investigation_cases(case_status)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_case_hunter ON forensic_investigation_cases(assigned_hunter_id)")
    finally:
        conn.close()


def _get_authenticated_user() -> Tuple[str, str]:
    """Extract authenticated username and role from Authorization header or cookies."""
    auth_header = request.headers.get("Authorization", "")
    token = ""
    if auth_header.startswith("Bearer "):
        token = auth_header.split(" ", 1)[1].strip()
    if not token:
        token = request.cookies.get("session_token", "") or request.cookies.get("session", "")
        if token.startswith("{"):
            try:
                data = json.loads(token)
                token = data.get("token", "")
            except Exception:
                pass
    if token:
        sess = validate_session(token)
        if sess and sess.get("username"):
            return sess["username"], sess.get("role", "forensic")

    # Fallback to role cookies or defaults
    user_role = request.cookies.get("userRole", "forensic")
    if user_role == "hunter":
        return "threat_hunter", "hunter"
    return "forensic_analyst", "forensic"


# ---------------------------------------------------------------------------
# Safe RAW Read-Only Forensic Acquisition Function
# ---------------------------------------------------------------------------

def acquire_raw_forensic_image(
    source_target: str,
    output_image_path: str,
    max_bytes_to_acquire: Optional[int] = None,
    chunk_size: int = 65536
) -> Dict[str, Any]:
    """
    Acquires a sector-by-sector RAW forensic bit-stream disk image.
    Strictly READ-ONLY. Zero disk modification, formatting, or temporary writes to source.
    Computes exact SHA-256 and MD5 hashes simultaneously.
    Never creates synthetic or placeholder images if source cannot be opened.
    """
    start_time = int(time.time())
    hasher_sha = hashlib.sha256()
    hasher_md5 = hashlib.md5()
    total_bytes_read = 0
    sector_size = 512

    out_dir = os.path.dirname(output_image_path)
    if out_dir:
        os.makedirs(out_dir, exist_ok=True)

    # Clean target string
    clean_target = str(source_target).strip().strip("\"'")
    if not clean_target or clean_target.lower() in ("none", "null", ""):
        raise ValueError("Source target path is empty or invalid. Acquisition aborted.")

    # Case 1: If source is an existing regular file or test image on disk
    if os.path.isfile(clean_target):
        with open(clean_target, "rb") as f_src, open(output_image_path, "wb") as f_out:
            file_sz = os.path.getsize(clean_target)
            if file_sz == 0:
                raise ValueError("Source evidence file is 0 bytes. Cannot acquire empty source.")
            limit = min(file_sz, max_bytes_to_acquire) if max_bytes_to_acquire else file_sz
            while total_bytes_read < limit:
                to_read = min(chunk_size, limit - total_bytes_read)
                buf = f_src.read(to_read)
                if not buf:
                    break
                f_out.write(buf)
                hasher_sha.update(buf)
                hasher_md5.update(buf)
                total_bytes_read += len(buf)

    # Case 2: Windows PhysicalDrive or Volume (strictly read-only handle)
    elif sys.platform.startswith("win"):
        from ctypes import wintypes
        kernel32 = ctypes.windll.kernel32
        GENERIC_READ = 0x80000000
        FILE_SHARE_READ = 1
        FILE_SHARE_WRITE = 2
        FILE_SHARE_DELETE = 4
        OPEN_EXISTING = 3
        FILE_ATTRIBUTE_NORMAL = 0x80

        # Resolve handle path
        handle_path = clean_target
        if len(handle_path) == 2 and handle_path[1] == ":":
            handle_path = f"\\\\.\\{handle_path.upper()}"
        elif not handle_path.startswith("\\\\.\\"):
            handle_path = f"\\\\.\\{handle_path}"

        h_dev = kernel32.CreateFileW(
            handle_path,
            GENERIC_READ,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            None,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            None
        )

        if h_dev == -1:
            # Retry if drive letter
            drive_letter = clean_target.replace(":", "").replace("\\", "").strip().upper()
            if len(drive_letter) == 1:
                handle_path = f"\\\\.\\{drive_letter}:"
                h_dev = kernel32.CreateFileW(
                    handle_path,
                    GENERIC_READ,
                    FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                    None,
                    OPEN_EXISTING,
                    FILE_ATTRIBUTE_NORMAL,
                    None
                )

        if h_dev == -1:
            err_code = kernel32.GetLastError()
            if err_code == 5:
                raise PermissionError(
                    f"Windows denied read access to physical device '{clean_target}' (Win32 Error: 5 - Access Denied). "
                    "Run SecureWipe with Administrator privileges and ensure the selected registered device is connected and not exclusively locked by another application."
                )
            elif err_code in (2, 3):
                raise FileNotFoundError(
                    f"Physical device '{clean_target}' is not currently connected or recognized by Windows (Win32 Error: {err_code} - Device Not Found). Please reconnect the registered device."
                )
            elif err_code in (32, 33):
                raise PermissionError(
                    f"Physical device '{clean_target}' is exclusively locked by another application (Win32 Error: {err_code} - Sharing Violation)."
                )
            elif err_code == 21:
                raise RuntimeError(
                    f"Physical device '{clean_target}' is not ready (Win32 Error: 21 - Drive Not Ready)."
                )
            else:
                raise RuntimeError(
                    f"Unable to open physical source device '{clean_target}' in read-only mode (Win32 Error: {err_code}). "
                    "Forensic acquisition aborted."
                )

        try:
            with open(output_image_path, "wb") as f_out:
                buf = ctypes.create_string_buffer(chunk_size)
                bytes_read = wintypes.DWORD(0)

                # Acquire device stream with sector alignment
                limit = max_bytes_to_acquire if max_bytes_to_acquire else (1024 * 1024 * 1024)
                while total_bytes_read < limit:
                    to_read = min(chunk_size, limit - total_bytes_read)
                    if to_read % sector_size != 0:
                        to_read = ((to_read + sector_size - 1) // sector_size) * sector_size
                    ok = kernel32.ReadFile(h_dev, buf, to_read, ctypes.byref(bytes_read), None)
                    if not ok or bytes_read.value == 0:
                        break
                    raw_chunk = buf.raw[:bytes_read.value]
                    f_out.write(raw_chunk)
                    hasher_sha.update(raw_chunk)
                    hasher_md5.update(raw_chunk)
                    total_bytes_read += len(raw_chunk)
        finally:
            kernel32.CloseHandle(h_dev)

    # Case 3: Linux / POSIX block device
    else:
        if not os.path.exists(clean_target):
            raise FileNotFoundError(f"Source block device '{clean_target}' does not exist.")
        with open(clean_target, "rb") as f_src, open(output_image_path, "wb") as f_out:
            limit = max_bytes_to_acquire if max_bytes_to_acquire else (1024 * 1024 * 1024)
            while total_bytes_read < limit:
                to_read = min(chunk_size, limit - total_bytes_read)
                buf = f_src.read(to_read)
                if not buf:
                    break
                f_out.write(buf)
                hasher_sha.update(buf)
                hasher_md5.update(buf)
                total_bytes_read += len(buf)

    if total_bytes_read == 0:
        if os.path.exists(output_image_path):
            try:
                os.remove(output_image_path)
            except Exception:
                pass
        raise RuntimeError(
            f"Zero bytes read from source device '{clean_target}'. Forensic acquisition failed."
        )

    end_time = int(time.time())
    sha256_hash = hasher_sha.hexdigest()
    md5_hash = hasher_md5.hexdigest()
    total_sectors = (total_bytes_read + sector_size - 1) // sector_size

    return {
        "image_path": output_image_path,
        "image_filename": os.path.basename(output_image_path),
        "image_size": total_bytes_read,
        "sector_size": sector_size,
        "total_sectors": total_sectors,
        "sha256": sha256_hash,
        "md5": md5_hash,
        "acquisition_start_time": start_time,
        "acquisition_end_time": end_time,
        "acquisition_status": "ACQUISITION_COMPLETED"
    }


# ---------------------------------------------------------------------------
# REST API Endpoints: Seek Help & Investigation Cases
# ---------------------------------------------------------------------------

@seek_help_bp.post("/api/seek-help/acquire-and-create-case")
def api_acquire_and_create_case():
    """
    Forensic Inspector: Verify registered device -> Sector RAW Acquisition -> Calculate SHA-256 -> Create Case (AVAILABLE).
    """
    try:
        from central_device_registry import resolve_registered_device_to_live_path

        body = request.get_json(silent=True) or {}
        device_id = (body.get("device_id") or "").strip()
        custom_title = (body.get("title") or "").strip()
        max_bytes = body.get("max_bytes")

        username, role = _get_authenticated_user()

        if not device_id:
            return jsonify({"status": "error", "message": "SecureWipe Device ID (SW-DEV-XXXXXXXX) is required."}), 400

        # 1. Check Central Device Registry & Resolve exact live connected path
        reg_device = get_registered_device_by_id(device_id)
        if not reg_device or reg_device.get("registration_status") != "REGISTERED":
            return jsonify({
                "status": "error",
                "message": f"Device '{device_id}' is NOT registered in the Central Device Registry. Forensic acquisition blocked."
            }), 403

        # Resolve live path with fingerprint validation (ignore arbitrary client path overrides)
        live_path, live_dev, resolve_err = resolve_registered_device_to_live_path(device_id)
        if resolve_err or not live_path:
            return jsonify({
                "status": "error",
                "message": f"Forensic acquisition blocked: {resolve_err}"
            }), 400

        device_path = live_path

        # Generate unique case identifier: CASE-2026-XXXX
        now = int(time.time())
        rand_suffix = uuid.uuid4().hex[:4].upper()
        case_id = f"CASE-2026-{rand_suffix}"
        case_title = custom_title or f"Forensic Investigation — {reg_device['model']} ({reg_device['device_id']})"

        # Record audit event: Acquisition Started
        record_audit_event(
            user_id=username,
            role="forensic",
            device_id=device_id,
            operation="IMAGE_ACQUISITION_STARTED",
            status="IN_PROGRESS",
            details={
                "case_id": case_id,
                "device_id": device_id,
                "source_path": device_path,
                "model": reg_device["model"]
            }
        )

        # 2. Execute Sector-by-Sector RAW Forensic Image Acquisition
        case_folder = os.path.join(CASES_STORAGE_DIR, case_id)
        image_dir = os.path.join(case_folder, "image")
        metadata_dir = os.path.join(case_folder, "metadata")
        evidence_dir = os.path.join(case_folder, "evidence")
        results_dir = os.path.join(case_folder, "results")
        documents_dir = os.path.join(case_folder, "documents")
        audit_dir = os.path.join(case_folder, "audit")

        for d in (image_dir, metadata_dir, evidence_dir, results_dir, documents_dir, audit_dir):
            os.makedirs(d, exist_ok=True)

        img_filename = f"{case_id}.img"
        img_full_path = os.path.join(image_dir, img_filename)

        try:
            acq_result = acquire_raw_forensic_image(
                source_target=device_path,
                output_image_path=img_full_path,
                max_bytes_to_acquire=int(max_bytes) if max_bytes else None
            )
        except Exception as acq_err:
            record_audit_event(
                user_id=username,
                role="forensic",
                device_id=device_id,
                operation="IMAGE_ACQUISITION_FAILED",
                status="FAILED",
                details={
                    "case_id": case_id,
                    "device_id": device_id,
                    "source_path": device_path,
                    "error": str(acq_err)
                }
            )
            # Ensure partial corrupted files are removed
            if os.path.exists(img_full_path):
                try:
                    os.remove(img_full_path)
                except Exception:
                    pass
            return jsonify({
                "status": "error",
                "message": f"Forensic acquisition failed. {str(acq_err)} No forensic image was created. No case published."
            }), 400

        # Save metadata/acquisition.json
        meta_payload = {
            "case_id": case_id,
            "title": case_title,
            "device_id": device_id,
            "device_fingerprint": reg_device["device_fingerprint"],
            "model": reg_device["model"],
            "manufacturer": reg_device["manufacturer"],
            "serial_number": reg_device["serial_number"],
            "capacity": reg_device["capacity"],
            "capacity_readable": reg_device["capacity_readable"],
            "image_filename": img_filename,
            "image_path": img_full_path,
            "image_format": "RAW",
            "image_size": acq_result["image_size"],
            "sector_size": acq_result["sector_size"],
            "total_sectors": acq_result["total_sectors"],
            "sha256": acq_result["sha256"],
            "md5": acq_result["md5"],
            "acquisition_start_time": acq_result["acquisition_start_time"],
            "acquisition_end_time": acq_result["acquisition_end_time"],
            "acquisition_status": "ACQUISITION_COMPLETED",
            "created_by": username,
            "created_at": now
        }
        with open(os.path.join(metadata_dir, "acquisition.json"), "w", encoding="utf-8") as f_meta:
            json.dump(meta_payload, f_meta, indent=2)

        # Record audit event: Acquisition Completed + Hash Generated
        record_audit_event(
            user_id=username,
            role="forensic",
            device_id=device_id,
            operation="IMAGE_ACQUISITION_COMPLETED",
            status="SUCCESS",
            details={
                "case_id": case_id,
                "image_filename": img_filename,
                "sha256": acq_result["sha256"],
                "image_size": acq_result["image_size"],
                "total_sectors": acq_result["total_sectors"]
            }
        )

        record_audit_event(
            user_id=username,
            role="forensic",
            device_id=device_id,
            operation="CASE_CREATED",
            status="SUCCESS",
            details={
                "case_id": case_id,
                "title": case_title,
                "device_id": device_id
            }
        )

        # 3. Store Case Record in platform.db with status = AVAILABLE
        conn = get_db()
        try:
            with conn:
                conn.execute("""
                    INSERT INTO forensic_investigation_cases (
                        case_id, title, device_id, device_fingerprint, device_model,
                        device_manufacturer, device_serial, device_capacity, device_capacity_readable,
                        image_filename, image_path, image_format, image_size, sector_size,
                        total_sectors, sha256, md5, acquisition_start_time, acquisition_end_time,
                        acquisition_status, case_status, created_by, created_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'RAW', ?, ?, ?, ?, ?, ?, ?, 'ACQUISITION_COMPLETED', 'AVAILABLE', ?, ?)
                """, (
                    case_id, case_title, device_id, reg_device["device_fingerprint"],
                    reg_device["model"], reg_device["manufacturer"], reg_device["serial_number"],
                    reg_device["capacity"], reg_device["capacity_readable"],
                    img_filename, img_full_path, acq_result["image_size"], acq_result["sector_size"],
                    acq_result["total_sectors"], acq_result["sha256"], acq_result["md5"],
                    acq_result["acquisition_start_time"], acq_result["acquisition_end_time"],
                    username, now
                ))
        finally:
            conn.close()

        record_audit_event(
            user_id=username,
            role="forensic",
            device_id=device_id,
            operation="CASE_MADE_AVAILABLE",
            status="SUCCESS",
            details={
                "case_id": case_id,
                "sha256": acq_result["sha256"],
                "initial_status": "AVAILABLE"
            }
        )

        return jsonify({
            "status": "success",
            "message": f"Forensic RAW image acquired and Case '{case_id}' successfully published to Hunters.",
            "case_id": case_id,
            "device_id": device_id,
            "image_filename": img_filename,
            "sha256": acq_result["sha256"],
            "image_size": acq_result["image_size"],
            "total_sectors": acq_result["total_sectors"],
            "case_status": "AVAILABLE",
            "case": {
                "case_id": case_id,
                "title": case_title,
                "device_id": device_id,
                "case_status": "AVAILABLE",
                "sha256": acq_result["sha256"],
                "image_filename": img_filename,
                "image_path": img_full_path,
                "image_size": acq_result["image_size"]
            }
        }), 200

    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


@seek_help_bp.get("/api/seek-help/cases")
def api_list_seek_help_cases():
    """
    List all Seek Help forensic investigation cases.
    Supports filtering by status or hunter.
    """
    status_filter = request.args.get("status")
    hunter_filter = request.args.get("hunter")

    conn = get_db()
    try:
        cur = conn.cursor()
        query = "SELECT * FROM forensic_investigation_cases WHERE 1=1"
        params = []

        if status_filter:
            query += " AND case_status = ?"
            params.append(status_filter)
        if hunter_filter:
            query += " AND assigned_hunter_id = ?"
            params.append(hunter_filter)

        query += " ORDER BY created_at DESC"
        cur.execute(query, params)
        rows = cur.fetchall()

        cases_list = []
        for r in rows:
            c = dict(r)
            c["created_at_human"] = time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime(c["created_at"]))
            if c.get("claimed_at"):
                c["claimed_at_human"] = time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime(c["claimed_at"]))
            if c.get("submitted_at"):
                c["submitted_at_human"] = time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime(c["submitted_at"]))
            if c.get("completed_at"):
                c["completed_at_human"] = time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime(c["completed_at"]))
            try:
                c["evidence_artifacts"] = json.loads(c.get("evidence_artifacts") or "[]")
            except Exception:
                c["evidence_artifacts"] = []
            cases_list.append(c)

        return jsonify({
            "status": "success",
            "cases": cases_list,
            "total": len(cases_list)
        }), 200
    finally:
        conn.close()


@seek_help_bp.get("/api/seek-help/cases/<case_id>")
def api_get_seek_help_case(case_id: str):
    """Retrieve details for a single investigation case."""
    conn = get_db()
    try:
        cur = conn.cursor()
        cur.execute("SELECT * FROM forensic_investigation_cases WHERE case_id = ?", (case_id,))
        row = cur.fetchone()
        if not row:
            return jsonify({"status": "error", "message": f"Case '{case_id}' not found."}), 404

        c = dict(row)
        c["created_at_human"] = time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime(c["created_at"]))
        try:
            c["evidence_artifacts"] = json.loads(c.get("evidence_artifacts") or "[]")
        except Exception:
            c["evidence_artifacts"] = []

        return jsonify({"status": "success", "case": c}), 200
    finally:
        conn.close()


@seek_help_bp.post("/api/seek-help/cases/<case_id>/claim")
def api_claim_seek_help_case(case_id: str):
    """
    Hunter Action: Atomically claim an AVAILABLE case.
    Enforces One-Active-Case Rule and Prevents Double Claiming.
    """
    try:
        body = request.get_json(silent=True) or {}

        # A real, validated session always wins over a client-supplied hunter_id
        # -- a logged-in hunter can never have a claim attributed to someone
        # else. Only when there is no real session do we fall back to the
        # body-supplied identity (preserves prior demo behavior for flows
        # that don't yet send credentials).
        from case_source import get_authenticated_identity
        session_username, session_role = get_authenticated_identity(request)
        if session_username and session_role == "hunter":
            hunter_id = session_username
        else:
            username, role = _get_authenticated_user()
            hunter_id = (body.get("hunter_id") or username).strip()

        if not hunter_id:
            return jsonify({"status": "error", "message": "Hunter identity is required."}), 400

        conn = get_db()
        try:
            cur = conn.cursor()

            # 1. Enforce One-Active-Case Rule for this Hunter
            cur.execute("""
                SELECT case_id, case_status FROM forensic_investigation_cases
                WHERE assigned_hunter_id = ?
                  AND case_status IN ('INVESTIGATION_IN_PROGRESS', 'SUBMITTED_FOR_REVIEW', 'RETURNED_FOR_CORRECTION')
            """, (hunter_id,))
            active_cases = cur.fetchall()
            if active_cases:
                existing_active = active_cases[0]["case_id"]
                return jsonify({
                    "status": "error",
                    "code": "ACTIVE_INVESTIGATION_EXISTS",
                    "message": f"You already have an active case ({existing_active}). Complete and submit this case before claiming another case.",
                    "active_case_id": existing_active
                }), 400

            # 2. Atomic Lock Check on Case
            now = int(time.time())
            with conn:
                cur.execute("""
                    UPDATE forensic_investigation_cases
                    SET case_status = 'INVESTIGATION_IN_PROGRESS',
                        assigned_hunter_id = ?,
                        claimed_at = ?
                    WHERE case_id = ? AND case_status = 'AVAILABLE'
                """, (hunter_id, now, case_id))

                if cur.rowcount == 0:
                    # Check why it failed
                    cur.execute("SELECT case_status, assigned_hunter_id FROM forensic_investigation_cases WHERE case_id = ?", (case_id,))
                    existing = cur.fetchone()
                    if not existing:
                        return jsonify({"status": "error", "message": f"Case '{case_id}' not found."}), 404
                    return jsonify({
                        "status": "error",
                        "code": "CASE_ALREADY_CLAIMED",
                        "message": f"Case already claimed by Hunter: {existing['assigned_hunter_id']}",
                        "assigned_hunter_id": existing["assigned_hunter_id"]
                    }), 409

            record_audit_event(
                user_id=hunter_id,
                role="hunter",
                operation="CASE_CLAIMED",
                status="SUCCESS",
                details={
                    "case_id": case_id,
                    "hunter_id": hunter_id,
                    "claimed_at": now
                }
            )

            record_audit_event(
                user_id=hunter_id,
                role="hunter",
                operation="INVESTIGATION_STARTED",
                status="SUCCESS",
                details={
                    "case_id": case_id,
                    "hunter_id": hunter_id
                }
            )

            return jsonify({
                "status": "success",
                "message": f"Case '{case_id}' successfully locked and claimed. Investigation commenced.",
                "case_id": case_id,
                "assigned_hunter_id": hunter_id,
                "case_status": "INVESTIGATION_IN_PROGRESS",
                "claimed_at": now
            }), 200

        finally:
            conn.close()

    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


@seek_help_bp.post("/api/seek-help/cases/<case_id>/submit")
def api_submit_investigation_findings(case_id: str):
    """
    Hunter Action: Submit findings, discovered evidence, and reports to the Forensic Inspector.
    Transitions status to SUBMITTED_FOR_REVIEW.
    """
    try:
        body = request.get_json(silent=True) or {}

        from case_source import get_authenticated_identity
        session_username, session_role = get_authenticated_identity(request)
        if session_username and session_role == "hunter":
            hunter_id = session_username
        else:
            username, role = _get_authenticated_user()
            hunter_id = (body.get("hunter_id") or username).strip()

        findings = (body.get("findings") or body.get("investigation_findings") or "").strip()
        results_summary = (body.get("results_summary") or "").strip()
        evidence_artifacts = body.get("evidence_artifacts") or []
        supporting_docs = body.get("supporting_documents") or []

        if isinstance(evidence_artifacts, list):
            evidence_str = json.dumps(evidence_artifacts)
        else:
            evidence_str = str(evidence_artifacts)

        if isinstance(supporting_docs, list):
            docs_str = json.dumps(supporting_docs)
        else:
            docs_str = str(supporting_docs)

        conn = get_db()
        try:
            cur = conn.cursor()
            cur.execute("SELECT * FROM forensic_investigation_cases WHERE case_id = ?", (case_id,))
            case_row = cur.fetchone()
            if not case_row:
                return jsonify({"status": "error", "message": f"Case '{case_id}' not found."}), 404

            case_data = dict(case_row)
            if case_data.get("assigned_hunter_id") != hunter_id:
                return jsonify({
                    "status": "error",
                    "message": "Only the assigned Hunter can submit investigation findings for this case."
                }), 403

            if case_data["case_status"] not in ("INVESTIGATION_IN_PROGRESS", "RETURNED_FOR_CORRECTION"):
                return jsonify({
                    "status": "error",
                    "message": f"Cannot submit findings for case in state '{case_data['case_status']}'."
                }), 400

            now = int(time.time())
            with conn:
                conn.execute("""
                    UPDATE forensic_investigation_cases
                    SET case_status = 'SUBMITTED_FOR_REVIEW',
                        submitted_at = ?,
                        investigation_findings = ?,
                        results_summary = ?,
                        evidence_artifacts = ?,
                        supporting_documents = ?
                    WHERE case_id = ?
                """, (now, findings, results_summary, evidence_str, docs_str, case_id))

            record_audit_event(
                user_id=hunter_id,
                role="hunter",
                operation="EVIDENCE_SUBMITTED",
                status="SUCCESS",
                details={
                    "case_id": case_id,
                    "hunter_id": hunter_id,
                    "artifacts_count": len(evidence_artifacts) if isinstance(evidence_artifacts, list) else 1
                }
            )

            record_audit_event(
                user_id=hunter_id,
                role="hunter",
                operation="CASE_SUBMITTED_FOR_REVIEW",
                status="SUCCESS",
                details={
                    "case_id": case_id,
                    "hunter_id": hunter_id,
                    "submitted_at": now
                }
            )

            return jsonify({
                "status": "success",
                "message": f"Investigation findings for '{case_id}' successfully submitted for Inspector review.",
                "case_id": case_id,
                "case_status": "SUBMITTED_FOR_REVIEW",
                "submitted_at": now
            }), 200

        finally:
            conn.close()

    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


@seek_help_bp.post("/api/seek-help/cases/<case_id>/review")
def api_review_seek_help_case(case_id: str):
    """
    Forensic Inspector Action: ACCEPT (COMPLETED) or RETURN_FOR_CORRECTION.
    """
    try:
        body = request.get_json(silent=True) or {}

        from case_source import get_authenticated_identity
        session_username, session_role = get_authenticated_identity(request)
        if session_username and session_role == "forensic":
            inspector = session_username
        else:
            username, role = _get_authenticated_user()
            inspector = (body.get("inspector") or username).strip()
        decision = (body.get("decision") or body.get("action") or "").upper().strip()  # ACCEPT or RETURN_FOR_CORRECTION
        notes = (body.get("notes") or body.get("inspector_notes") or "").strip()

        if decision not in ("ACCEPT", "COMPLETE", "COMPLETED", "RETURN", "RETURN_FOR_CORRECTION", "CORRECTION"):
            return jsonify({"status": "error", "message": "Decision must be ACCEPT or RETURN_FOR_CORRECTION."}), 400

        is_accepted = decision in ("ACCEPT", "COMPLETE", "COMPLETED")
        new_status = "COMPLETED" if is_accepted else "RETURNED_FOR_CORRECTION"

        conn = get_db()
        try:
            cur = conn.cursor()
            cur.execute("SELECT * FROM forensic_investigation_cases WHERE case_id = ?", (case_id,))
            case_row = cur.fetchone()
            if not case_row:
                return jsonify({"status": "error", "message": f"Case '{case_id}' not found."}), 404

            case_data = dict(case_row)
            if case_data["case_status"] != "SUBMITTED_FOR_REVIEW":
                return jsonify({
                    "status": "error",
                    "message": f"Case '{case_id}' is in status '{case_data['case_status']}', not SUBMITTED_FOR_REVIEW."
                }), 400

            now = int(time.time())
            with conn:
                conn.execute("""
                    UPDATE forensic_investigation_cases
                    SET case_status = ?,
                        reviewed_at = ?,
                        completed_at = ?,
                        inspector_notes = ?
                    WHERE case_id = ?
                """, (new_status, now, now if is_accepted else None, notes, case_id))

            record_audit_event(
                user_id=inspector,
                role="forensic",
                operation="CASE_COMPLETED" if is_accepted else "CASE_RETURNED_FOR_CORRECTION",
                status="SUCCESS",
                details={
                    "case_id": case_id,
                    "decision": new_status,
                    "inspector": inspector,
                    "assigned_hunter_id": case_data.get("assigned_hunter_id"),
                    "notes": notes
                }
            )

            msg = f"Case '{case_id}' marked as COMPLETED. Hunter {case_data.get('assigned_hunter_id')} is now released." if is_accepted else f"Case '{case_id}' returned for correction."

            return jsonify({
                "status": "success",
                "message": msg,
                "case_id": case_id,
                "case_status": new_status,
                "reviewed_at": now
            }), 200

        finally:
            conn.close()

    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


@seek_help_bp.get("/api/seek-help/cases/<case_id>/download-image")
def api_download_case_image(case_id: str):
    """
    Download the immutable RAW forensic disk image (.img) directly.
    A Hunter with a real, validated session may only download their own
    active case's image -- never another case's raw evidence bytes.
    """
    from case_source import get_authenticated_identity, resolve_hunter_case_source
    session_username, session_role = get_authenticated_identity(request)
    if session_role == "hunter":
        case_source = resolve_hunter_case_source(session_username)
        if not case_source or case_source.get("case_id") != case_id:
            return jsonify({
                "status": "error",
                "message": f"Access Denied: As a Threat & Forensic Hunter, you are strictly scoped to your own active case.",
            }), 403

    conn = get_db()
    try:
        cur = conn.cursor()
        cur.execute("SELECT image_filename, image_path FROM forensic_investigation_cases WHERE case_id = ?", (case_id,))
        row = cur.fetchone()
        if not row:
            return jsonify({"status": "error", "message": f"Case '{case_id}' not found."}), 404

        img_filename, img_path = row[0], row[1]
        if not img_path or not os.path.isfile(img_path):
            # Check fallback in cases dir
            potential1 = os.path.join(CASES_STORAGE_DIR, case_id, "image", img_filename)
            potential2 = os.path.join(CASES_STORAGE_DIR, case_id, img_filename)
            if os.path.isfile(potential1):
                img_path = potential1
            elif os.path.isfile(potential2):
                img_path = potential2
            else:
                return jsonify({"status": "error", "message": "Forensic image file not found on disk."}), 404

        return send_file(
            img_path,
            as_attachment=True,
            download_name=img_filename,
            mimetype="application/octet-stream"
        )
    finally:
        conn.close()
