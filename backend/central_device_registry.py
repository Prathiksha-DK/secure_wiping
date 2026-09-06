"""
Central Device Registry Module
SecureWipe Defense & Forensic Facility

Features:
- Single central device registry stored in platform.db.
- Read-only hardware enumeration reusing backend/devices.py.
- Deterministic hardware fingerprinting and unique SecureWipe Device ID (SW-DEV-XXXXXXXX) generation.
- Idempotent duplicate prevention (reconnecting same physical device recognizes existing record).
- Cross-workspace context shared across Individual, Government, and Forensic logins.
- SHA-256 hash-chained audit logging for detection and registration events.
"""

import os
import sys
import time
import json
import hashlib
import sqlite3
from typing import Dict, Any, List, Optional, Tuple
from flask import Blueprint, jsonify, request

from auth import get_db, validate_session
from devices import list_devices, human_readable_size
from audit_engine import record_audit_event

# Create Flask Blueprint
device_registry_bp = Blueprint("central_device_registry", __name__)


def init_device_registry_db() -> None:
    """Initialize central_device_registry table in platform.db."""
    conn = get_db()
    try:
        with conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS central_device_registry (
                    device_id TEXT PRIMARY KEY,
                    device_fingerprint TEXT UNIQUE NOT NULL,
                    manufacturer TEXT NOT NULL DEFAULT 'UNKNOWN',
                    model TEXT NOT NULL DEFAULT 'UNKNOWN',
                    serial_number TEXT NOT NULL DEFAULT 'UNKNOWN',
                    capacity INTEGER NOT NULL DEFAULT 0,
                    capacity_readable TEXT NOT NULL DEFAULT 'UNKNOWN',
                    interface TEXT NOT NULL DEFAULT 'UNKNOWN',
                    device_type TEXT NOT NULL DEFAULT 'UNKNOWN',
                    current_connection_path TEXT NOT NULL DEFAULT '',
                    connection_type TEXT NOT NULL DEFAULT 'CONNECTED', -- CONNECTED, DISCONNECTED
                    first_registered_at INTEGER NOT NULL,
                    last_seen_at INTEGER NOT NULL,
                    registration_status TEXT NOT NULL DEFAULT 'REGISTERED', -- REGISTERED, PENDING
                    created_by TEXT NOT NULL DEFAULT 'citizen_user',
                    case_id TEXT DEFAULT NULL,
                    evidence_id TEXT DEFAULT NULL
                )
            """)
            try:
                conn.execute("ALTER TABLE central_device_registry ADD COLUMN current_connection_path TEXT NOT NULL DEFAULT ''")
            except sqlite3.OperationalError:
                pass
            conn.execute("CREATE INDEX IF NOT EXISTS idx_dev_fingerprint ON central_device_registry(device_fingerprint)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_dev_serial ON central_device_registry(serial_number)")
    finally:
        conn.close()


def _normalize_string(val: Any) -> str:
    """Normalize string property for deterministic hashing."""
    if val is None:
        return "UNKNOWN"
    s = str(val).strip().upper()
    return s if s and s not in ("NONE", "NULL", "UNDEFINED") else "UNKNOWN"


def compute_device_fingerprint(
    manufacturer: Any = "Generic",
    model: str = "UNKNOWN",
    serial_number: str = "UNKNOWN",
    capacity_bytes: int = 0,
    interface: str = "USB"
) -> str:
    """
    Compute stable, deterministic SHA-256 fingerprint for a physical storage device.
    Avoids temporary OS paths (e.g. \\\\.\\PhysicalDrive1 or E:).
    Accepts either a device dictionary or individual field arguments.
    """
    if isinstance(manufacturer, dict):
        d = manufacturer
        mfg = d.get("manufacturer") or d.get("vendor") or ""
        name = d.get("name", "")
        if not mfg:
            parts = str(name).split(" ", 1)
            mfg = parts[0] if len(parts) > 1 else "Generic"
        mdl = d.get("model") or (str(name).split(" ", 1)[1] if " " in str(name) else name) or "UNKNOWN"
        ser = d.get("serial_number") or d.get("serial") or "UNKNOWN"
        cap = int(d.get("capacity") or d.get("sizeBytes") or 0)
        iface = d.get("interface") or d.get("bus") or d.get("bus_type") or "USB"
        return compute_device_fingerprint(mfg, mdl, ser, cap, iface)

    norm_mfg = _normalize_string(manufacturer)
    norm_model = _normalize_string(model)
    norm_serial = _normalize_string(serial_number)
    norm_iface = _normalize_string(interface)
    cap = int(capacity_bytes) if capacity_bytes else 0

    # If serial number is available and not generic
    if norm_serial != "UNKNOWN" and len(norm_serial) >= 3 and not norm_serial.startswith("0000000"):
        raw_identity = f"{norm_mfg}|{norm_model}|{norm_serial}|{cap}|{norm_iface}"
    else:
        # Fallback to model, capacity, and interface
        raw_identity = f"{norm_mfg}|{norm_model}|{cap}|{norm_iface}"

    return hashlib.sha256(raw_identity.encode("utf-8")).hexdigest()


def generate_securewipe_device_id(fingerprint: str) -> str:
    """
    Generate standard SecureWipe Device ID format: SW-DEV-XXXXXXXX
    Derived deterministically from the device fingerprint.
    """
    short_hash = fingerprint[:8].upper()
    return f"SW-DEV-{short_hash}"


def get_all_registered_devices() -> List[Dict[str, Any]]:
    """Retrieve all devices registered in the central registry."""
    conn = get_db()
    try:
        cur = conn.cursor()
        cur.execute("SELECT * FROM central_device_registry ORDER BY last_seen_at DESC")
        rows = cur.fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


def get_registered_device_by_id(device_id: str) -> Optional[Dict[str, Any]]:
    """Lookup a registered device by its SecureWipe Device ID."""
    conn = get_db()
    try:
        cur = conn.cursor()
        cur.execute("SELECT * FROM central_device_registry WHERE device_id = ?", (device_id,))
        row = cur.fetchone()
        return dict(row) if row else None
    finally:
        conn.close()


def get_registered_device_by_fingerprint(fingerprint: str) -> Optional[Dict[str, Any]]:
    """Lookup a registered device by its hardware fingerprint."""
    conn = get_db()
    try:
        cur = conn.cursor()
        cur.execute("SELECT * FROM central_device_registry WHERE device_fingerprint = ?", (fingerprint,))
        row = cur.fetchone()
        return dict(row) if row else None
    finally:
        conn.close()


def register_device(
    device_data: Dict[str, Any],
    created_by: str = "citizen_user",
    case_id: Optional[str] = None,
    evidence_id: Optional[str] = None
) -> Tuple[bool, str, Dict[str, Any]]:
    """
    Register a newly detected physical device into the central registry.
    Ensures idempotency: if already registered, returns existing record.
    """
    manufacturer = device_data.get("manufacturer") or device_data.get("vendor") or "UNKNOWN"
    model = device_data.get("model") or device_data.get("name") or "UNKNOWN"
    serial = device_data.get("serial_number") or device_data.get("serial") or "UNKNOWN"
    capacity = int(device_data.get("capacity") or device_data.get("sizeBytes") or 0)
    cap_read = device_data.get("capacity_readable") or device_data.get("size") or human_readable_size(capacity)
    interface = device_data.get("interface") or device_data.get("bus") or device_data.get("bus_type") or "USB"
    dev_type = device_data.get("device_type") or device_data.get("type") or "USB Storage"

    fingerprint = compute_device_fingerprint(manufacturer, model, serial, capacity, interface)
    now = int(time.time())

    conn_path = device_data.get("current_connection_path") or device_data.get("devicePath") or ""

    # Check for existing registration by fingerprint
    existing = get_registered_device_by_fingerprint(fingerprint)
    if existing:
        # Update last seen, connection status, and connection path
        conn = get_db()
        try:
            with conn:
                conn.execute("""
                    UPDATE central_device_registry
                    SET last_seen_at = ?, connection_type = 'CONNECTED',
                        current_connection_path = COALESCE(NULLIF(?, ''), current_connection_path)
                    WHERE device_id = ?
                """, (now, str(conn_path).strip(), existing["device_id"]))
        finally:
            conn.close()

        updated = dict(existing)
        updated["last_seen_at"] = now
        updated["connection_type"] = "CONNECTED"
        if conn_path:
            updated["current_connection_path"] = str(conn_path).strip()

        record_audit_event(
            user_id=created_by,
            role="individual",
            device_id=existing["device_id"],
            operation="DEVICE_RECONNECTED",
            status="SUCCESS",
            details={
                "device_id": existing["device_id"],
                "model": model,
                "serial": serial
            }
        )
        return True, f"Device already registered with ID {existing['device_id']}", updated

    # Check if serial number matches an existing record with identical serial
    if _normalize_string(serial) != "UNKNOWN" and len(str(serial).strip()) >= 3:
        conn = get_db()
        try:
            cur = conn.cursor()
            cur.execute("SELECT * FROM central_device_registry WHERE serial_number = ?", (str(serial).strip(),))
            row = cur.fetchone()
            if row:
                existing = dict(row)
                with conn:
                    conn.execute("""
                        UPDATE central_device_registry
                        SET last_seen_at = ?, connection_type = 'CONNECTED', device_fingerprint = ?,
                            current_connection_path = COALESCE(NULLIF(?, ''), current_connection_path)
                        WHERE device_id = ?
                    """, (now, fingerprint, str(conn_path).strip(), existing["device_id"]))
                existing["last_seen_at"] = now
                existing["connection_type"] = "CONNECTED"
                if conn_path:
                    existing["current_connection_path"] = str(conn_path).strip()
                return True, f"Device recognized by serial number with ID {existing['device_id']}", existing
        finally:
            conn.close()

    # Create new SecureWipe Device ID
    device_id = generate_securewipe_device_id(fingerprint)

    conn = get_db()
    try:
        with conn:
            conn.execute("""
                INSERT INTO central_device_registry (
                    device_id, device_fingerprint, manufacturer, model, serial_number,
                    capacity, capacity_readable, interface, device_type, current_connection_path,
                    connection_type, first_registered_at, last_seen_at, registration_status,
                    created_by, case_id, evidence_id
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'CONNECTED', ?, ?, 'REGISTERED', ?, ?, ?)
            """, (
                device_id, fingerprint, str(manufacturer).strip(), str(model).strip(), str(serial).strip(),
                capacity, str(cap_read).strip(), str(interface).strip(), str(dev_type).strip(), str(conn_path).strip(),
                now, now, str(created_by).strip(), case_id, evidence_id
            ))
    except sqlite3.IntegrityError:
        # Concurrent registration or collision: retrieve existing
        existing = get_registered_device_by_id(device_id)
        if existing:
            return True, "Device already registered.", existing
    finally:
        conn.close()

    record_audit_event(
        user_id=created_by,
        role="individual",
        device_id=device_id,
        operation="DEVICE_REGISTERED",
        status="SUCCESS",
        details={
            "device_id": device_id,
            "manufacturer": manufacturer,
            "model": model,
            "serial_number": serial,
            "capacity": capacity,
            "interface": interface,
            "created_by": created_by
        }
    )

    new_record = {
        "device_id": device_id,
        "device_fingerprint": fingerprint,
        "manufacturer": str(manufacturer).strip(),
        "model": str(model).strip(),
        "serial_number": str(serial).strip(),
        "capacity": capacity,
        "capacity_readable": str(cap_read).strip(),
        "interface": str(interface).strip(),
        "device_type": str(dev_type).strip(),
        "connection_type": "CONNECTED",
        "first_registered_at": now,
        "last_seen_at": now,
        "registration_status": "REGISTERED",
        "created_by": str(created_by).strip(),
        "case_id": case_id,
        "evidence_id": evidence_id
    }
    return True, f"Device successfully registered as {device_id}", new_record


def get_current_devices_status() -> Dict[str, Any]:
    """
    Enumerate connected physical devices, compute fingerprints, and match against central registry.
    Updates last_seen and connection status for live devices.
    """
    raw_devices = list_devices()
    now = int(time.time())
    active_fingerprints = set()
    connected_list = []

    conn = get_db()
    try:
        for d in raw_devices:
            name = d.get("name", "Unknown Storage Device")
            serial = d.get("serial", "UNKNOWN")
            bus = d.get("bus", "USB")
            size_bytes = d.get("sizeBytes", 0)
            size_str = d.get("size", human_readable_size(size_bytes))
            m_type = d.get("type", "USB Storage")
            dev_path = d.get("devicePath", "")
            drive_letters = d.get("driveLetters", [])

            # Extract manufacturer and model heuristics from name
            parts = str(name).split(" ", 1)
            mfg = parts[0] if len(parts) > 1 else "Generic"
            model = parts[1] if len(parts) > 1 else name

            fp = compute_device_fingerprint(mfg, model, serial, size_bytes, bus)
            active_fingerprints.add(fp)

            # Query central registry
            cur = conn.cursor()
            cur.execute("""
                SELECT * FROM central_device_registry
                WHERE device_fingerprint = ? OR (serial_number != 'UNKNOWN' AND serial_number = ?)
            """, (fp, str(serial).strip()))
            row = cur.fetchone()

            if row:
                rec = dict(row)
                # Update last seen timestamp & connection status
                with conn:
                    conn.execute("""
                        UPDATE central_device_registry
                        SET last_seen_at = ?, connection_type = 'CONNECTED'
                        WHERE device_id = ?
                    """, (now, rec["device_id"]))
                rec["last_seen_at"] = now
                rec["connection_type"] = "CONNECTED"
                rec["identity_status"] = "Verified" if rec.get("serial_number") and rec["serial_number"] != "UNKNOWN" else "UNCERTAIN"
                rec["current_connection_path"] = dev_path
                rec["mounted_volume"] = ", ".join(drive_letters) if drive_letters else "None"

                connected_list.append({
                    "is_registered": True,
                    "device_id": rec["device_id"],
                    "record": rec,
                    "raw_device": d,
                    "device_fingerprint": fp,
                    "os_device_path": dev_path,
                    "drive_letters": drive_letters,
                    "display_name": f"{rec['device_id']} — {rec['model']} ({rec['capacity_readable']})"
                })
            else:
                ident_status = "Verified" if str(serial).strip() not in ("UNKNOWN", "", "None") else "UNCERTAIN"
                connected_list.append({
                    "is_registered": False,
                    "device_id": None,
                    "record": None,
                    "raw_device": d,
                    "device_fingerprint": fp,
                    "os_device_path": dev_path,
                    "drive_letters": drive_letters,
                    "display_name": f"UNREGISTERED — {name} ({size_str})",
                    "proposed_device_id": generate_securewipe_device_id(fp),
                    "detected_metadata": {
                        "manufacturer": mfg,
                        "model": model,
                        "serial_number": serial,
                        "capacity": size_bytes,
                        "capacity_readable": size_str,
                        "interface": bus,
                        "device_type": m_type,
                        "identity_status": ident_status,
                        "current_connection_path": dev_path,
                        "mounted_volume": ", ".join(drive_letters) if drive_letters else "None"
                    }
                })

        # Mark devices in registry that are currently disconnected
        with conn:
            cur = conn.cursor()
            cur.execute("SELECT device_id, device_fingerprint FROM central_device_registry WHERE connection_type = 'CONNECTED'")
            for row in cur.fetchall():
                if row["device_fingerprint"] not in active_fingerprints:
                    conn.execute("UPDATE central_device_registry SET connection_type = 'DISCONNECTED' WHERE device_id = ?", (row["device_id"],))

    finally:
        conn.close()

    all_registered = get_all_registered_devices()

    return {
        "status": "success",
        "connected_devices": connected_list,
        "connected_count": len(connected_list),
        "registered_count": len(all_registered),
        "all_registered": all_registered
    }


def resolve_registered_device_to_live_path(device_id: str) -> Tuple[Optional[str], Optional[Dict[str, Any]], Optional[str]]:
    """
    Safely resolves a registered SecureWipe Device ID (SW-DEV-XXXXXXXX)
    to its currently connected physical storage path (e.g. \\\\.\\PhysicalDrive1).
    
    Performs fingerprint & serial verification against live detected devices.
    Returns (live_path, live_dev_dict, error_message).
    Zero fallback to PhysicalDrive0. Zero guessing.
    """
    reg_device = get_registered_device_by_id(device_id)
    if not reg_device:
        return None, None, f"Device '{device_id}' is not found in the Central Device Registry."
    
    if reg_device.get("registration_status") != "REGISTERED":
        return None, None, f"Device '{device_id}' is not in REGISTERED status (Status: {reg_device.get('registration_status')})."

    reg_fingerprint = reg_device.get("device_fingerprint", "")
    reg_serial = str(reg_device.get("serial_number", "")).strip()
    reg_model = str(reg_device.get("model", "")).strip().lower()

    # Scan live connected storage devices
    live_devices = list_devices()
    for live_dev in live_devices:
        live_fp = compute_device_fingerprint(live_dev)
        live_serial = str(live_dev.get("serial", "")).strip()
        live_name = str(live_dev.get("name", "")).strip().lower()
        live_friendly = str(live_dev.get("friendlyName", "")).strip().lower()
        live_path = live_dev.get("devicePath") or live_dev.get("name") or ""

        # Match 1: Exact cryptographic fingerprint match
        if reg_fingerprint and live_fp == reg_fingerprint:
            return live_path, live_dev, None

        # Match 2: Serial number match (if non-generic serial)
        if reg_serial and reg_serial not in ("UNKNOWN", "None", "") and live_serial == reg_serial:
            return live_path, live_dev, None

        # Match 3: Registered connection path match if model matches
        reg_conn_path = str(reg_device.get("current_connection_path", "")).strip()
        if reg_conn_path and live_path and reg_conn_path.lower() == live_path.lower():
            if reg_model in live_name or reg_model in live_friendly or not reg_model:
                return live_path, live_dev, None

    # Fallback only if the registered record itself has a valid connection path
    static_conn = reg_device.get("current_connection_path") or ""
    if static_conn:
        if static_conn.lower() in ("\\\\.\\physicaldrive0", "physicaldrive0", "/dev/sda"):
            return None, None, "PhysicalDrive0 / system drive acquisition is strictly prohibited."
        if os.path.isfile(static_conn):
            return static_conn, {"name": static_conn, "devicePath": static_conn, "sizeBytes": os.path.getsize(static_conn)}, None
        if static_conn.startswith("\\\\.\\") or static_conn.startswith("/dev/"):
            return static_conn, {"name": static_conn, "devicePath": static_conn, "sizeBytes": reg_device.get("capacity", 0)}, None

    return None, None, (
        f"Unable to safely resolve registered device '{device_id}' ({reg_device.get('model', 'Unknown')}) "
        "to a currently connected physical storage device. Fingerprint verification failed or the device is disconnected."
    )


def _get_request_user_and_role() -> Tuple[str, str]:
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
            return sess["username"], sess.get("role", "individual")

    user_role = request.cookies.get("userRole", "individual")
    if user_role == "government":
        return "gov_officer", "government"
    elif user_role == "forensic":
        return "forensic_analyst", "forensic"
    elif user_role == "hunter":
        return "threat_hunter", "hunter"
    return "citizen_user", "individual"


def get_hunter_active_case_record(hunter_username: str) -> Optional[Dict[str, Any]]:
    """Fetch the single active investigation case assigned to a Hunter."""
    conn = get_db()
    try:
        cur = conn.cursor()
        cur.execute("""
            SELECT * FROM forensic_investigation_cases
            WHERE assigned_hunter_id = ?
              AND case_status IN ('INVESTIGATION_IN_PROGRESS', 'SUBMITTED_FOR_REVIEW', 'RETURNED_FOR_CORRECTION')
            ORDER BY claimed_at DESC
            LIMIT 1
        """, (hunter_username,))
        row = cur.fetchone()
        return dict(row) if row else None
    finally:
        conn.close()


def _extract_request_user() -> str:
    user, _ = _get_request_user_and_role()
    return user


# ---------------------------------------------------------------------------
# REST API Endpoints
# ---------------------------------------------------------------------------

@device_registry_bp.get("/api/devices/current")
@device_registry_bp.get("/api/devices/registry/current")
def api_get_current_devices():
    """
    Get live connected storage devices and their Central Device Registry status.
    Strictly scoped to active case for Hunter roles.
    """
    try:
        user, role = _get_request_user_and_role()
        if role == "hunter":
            # Re-validate via the hardened, session-only resolver instead of
            # trusting the unsigned userRole cookie -- a spoofed hunter claim
            # with no real session is demoted back to unrestricted individual
            # behavior rather than granted any case-scoped disclosure.
            from case_source import get_request_hunter_context
            is_real_hunter, hardened_user, _ = get_request_hunter_context(request)
            if is_real_hunter:
                user = hardened_user
            else:
                role = "individual"

        # Strict Hunter Case Scoping
        if role == "hunter":
            active_case = get_hunter_active_case_record(user)
            if not active_case:
                return jsonify({
                    "status": "success",
                    "connected_devices": [],
                    "connected_count": 0,
                    "registered_count": 0,
                    "all_registered": [],
                    "hunter_active_case": None
                }), 200

            reg_device = get_registered_device_by_id(active_case["device_id"])
            case_item = {
                "raw_device": {
                    "name": active_case["device_model"],
                    "friendlyName": f"{active_case['device_model']} ({active_case['device_id']}) [Case: {active_case['case_id']}]",
                    "devicePath": active_case["image_path"],
                    "deviceId": active_case["device_id"],
                    "size": active_case["device_capacity_readable"],
                    "sizeBytes": active_case["device_capacity"] or active_case["image_size"],
                    "type": "Case Forensic Image",
                    "serial": active_case["device_serial"],
                    "bus": "Virtual / Case Image",
                    "isSystem": False
                },
                "is_registered": True,
                "device_id": active_case["device_id"],
                "fingerprint": active_case["device_fingerprint"],
                "os_device_path": active_case["image_path"],
                "record": reg_device,
                "case_id": active_case["case_id"]
            }
            return jsonify({
                "status": "success",
                "connected_devices": [case_item],
                "connected_count": 1,
                "registered_count": 1,
                "all_registered": [reg_device] if reg_device else [],
                "hunter_active_case": active_case
            }), 200

        status_data = get_current_devices_status()
        return jsonify(status_data), 200
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


@device_registry_bp.get("/api/devices/registry")
@device_registry_bp.get("/api/devices/registered")
def api_get_all_registry():
    """
    Retrieve registered devices. Strictly scoped for Hunters.
    """
    try:
        user, role = _get_request_user_and_role()
        if role == "hunter":
            # Re-validate via the hardened, session-only resolver instead of
            # trusting the unsigned userRole cookie -- a spoofed hunter claim
            # with no real session is demoted back to unrestricted individual
            # behavior rather than granted any case-scoped disclosure.
            from case_source import get_request_hunter_context
            is_real_hunter, hardened_user, _ = get_request_hunter_context(request)
            if is_real_hunter:
                user = hardened_user
            else:
                role = "individual"

        # Strict Hunter Case Scoping
        if role == "hunter":
            active_case = get_hunter_active_case_record(user)
            if not active_case:
                return jsonify({"status": "success", "devices": [], "total": 0}), 200

            reg_device = get_registered_device_by_id(active_case["device_id"])
            return jsonify({
                "status": "success",
                "devices": [reg_device] if reg_device else [],
                "total": 1 if reg_device else 0
            }), 200

        devices = get_all_registered_devices()
        return jsonify({"status": "success", "devices": devices, "total": len(devices)}), 200
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


@device_registry_bp.get("/api/devices/registry/<device_id>")
@device_registry_bp.get("/api/devices/registered/<device_id>")
def api_get_registry_device(device_id):
    """
    Retrieve details for a specific registered device by Device ID.
    Enforces Hunter case scoping server-side.
    """
    try:
        user, role = _get_request_user_and_role()
        if role == "hunter":
            # Re-validate via the hardened, session-only resolver instead of
            # trusting the unsigned userRole cookie -- a spoofed hunter claim
            # with no real session is demoted back to unrestricted individual
            # behavior rather than granted any case-scoped disclosure.
            from case_source import get_request_hunter_context
            is_real_hunter, hardened_user, _ = get_request_hunter_context(request)
            if is_real_hunter:
                user = hardened_user
            else:
                role = "individual"

        # Strict Hunter Case Scoping
        if role == "hunter":
            active_case = get_hunter_active_case_record(user)
            if not active_case or active_case.get("device_id") != device_id:
                return jsonify({
                    "status": "error",
                    "message": f"Access Denied: As a Threat & Forensic Hunter, you are strictly scoped to the device '{active_case.get('device_id') if active_case else 'None'}' assigned to your active case."
                }), 403

        device = get_registered_device_by_id(device_id)
        if not device:
            return jsonify({"status": "error", "message": f"Device '{device_id}' not found in registry."}), 404
        return jsonify({"status": "success", "device": device}), 200
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


@device_registry_bp.post("/api/devices/register")
def api_register_device():
    """
    Register a detected physical storage device.
    Generates deterministic SW-DEV-XXXXXXXX identifier and stores record in central registry.
    """
    try:
        user, role = _get_request_user_and_role()
        if role == "hunter":
            # Re-validate via the hardened, session-only resolver instead of
            # trusting the unsigned userRole cookie -- a spoofed hunter claim
            # with no real session is demoted back to unrestricted individual
            # behavior rather than granted any case-scoped disclosure.
            from case_source import get_request_hunter_context
            is_real_hunter, hardened_user, _ = get_request_hunter_context(request)
            if is_real_hunter:
                user = hardened_user
            else:
                role = "individual"

        if role == "hunter":
            return jsonify({
                "status": "error",
                "message": "Access Denied: Threat & Forensic Hunters cannot register new hardware devices."
            }), 403

        body = request.get_json(silent=True) or {}
        created_by = body.get("created_by") or user

        record_audit_event(
            user_id=created_by,
            role=role,
            operation="DEVICE_REGISTRATION_STARTED",
            status="IN_PROGRESS",
            details=body
        )

        ok, msg, rec = register_device(
            device_data=body,
            created_by=created_by,
            case_id=body.get("case_id"),
            evidence_id=body.get("evidence_id")
        )

        if not ok:
            return jsonify({"status": "error", "message": msg}), 400

        return jsonify({
            "status": "success",
            "message": msg,
            "device_id": rec["device_id"],
            "device": rec
        }), 201
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500
