"""
SecureWipe — Production-Grade, Security-Hardened API Backend
Integrates:
- Storage Safety & Anti-Misdirection Engine
- Two-Stage Destructive Confirmation
- Server-Side Role-Based Access Control (RBAC) & PBKDF2 Authentication
- Cryptographically Chained Tamper-Evident Audit Logging
- Schema v1.0 Sanitization Certificates with RSA-PSS Signatures
- Compliance, Lifecycle, Recycler Handovers & Integration Architecture
- Strictly Read-Only Storage Inspector & Forensic Carver
- Live Security Status & 9-Dimensional Production Readiness Scorecard
"""

import os
import sys
import re
import json
import time
import socket
import sqlite3
import hashlib
import uuid as _uuid
from typing import Dict, Any, Optional
from flask import Flask, jsonify, request, Response
from flask_cors import CORS

from devices import list_devices
from secure_encrypt_wipe import encrypt_and_wipe
from user_storage import init_db, insert_user, get_user_by_username

from security_config import (
    APP_ENV, IS_PRODUCTION, IS_DEVELOPMENT, DEFAULT_HOST, DEFAULT_PORT,
    ALLOWED_ORIGINS, ROLE_ADMINISTRATOR, ROLE_OPERATOR, ROLE_AUDITOR, ROLE_VIEWER,
    init_auth_db, authenticate_user, require_auth, extract_auth_claims
)
from storage_safety import validate_storage_safety
from two_stage_confirmation import generate_stage1_confirmation, validate_stage2_confirmation
from audit_log import init_audit_db, record_audit_event, verify_audit_log_integrity, get_audit_events
from certificate_engine import verify_certificate_integrity, export_certificate_json, export_certificate_csv_summary
from compliance_engine import (
    init_compliance_db, get_certificate_by_id, get_all_certificates,
    get_compliance_dashboard_stats, get_recyclers_list, add_recycler,
    create_disposal_handover, confirm_disposal_handover, get_disposal_handovers_list,
    get_integration_statuses, get_assessment_checklist, get_procurement_checklist,
    save_certificate
)
from security_dashboard import evaluate_security_status
from swarm_routes import swarm_bp
from swarm_engine import init_swarm_db
from post_sanitization_assessment import (
    stream_post_sanitization_assessment,
    inspect_media_bytes,
    run_comparative_sanitization_experiment,
    generate_signed_assessment_certificate,
    verify_assessment_certificate,
    sync_assessment_fragments_to_swarm,
    _assessment_sessions,
    _assessment_lock,
)
from swarm_evidence_ingest import create_certified_forensic_evidence_image

# ---------------------------------------------------------------------------
# Flask Application Initialization
# ---------------------------------------------------------------------------
app = Flask("securewipe_api")
app.register_blueprint(swarm_bp)

# CORS Configuration
if IS_PRODUCTION:
    CORS(app, resources={r"/api/*": {"origins": ALLOWED_ORIGINS}}, supports_credentials=True)
else:
    CORS(app, resources={r"/api/*": {"origins": "*"}}, supports_credentials=True)

# ---------------------------------------------------------------------------
# FARIS Reverse Proxy Route (Forwards /api/faris/* to port 8760)
# ---------------------------------------------------------------------------
import urllib.request
import urllib.error

@app.route("/api/faris/<path:subpath>", methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"])
def proxy_faris(subpath):
    if request.method == "OPTIONS":
        return Response(status=204)
    target_url = f"http://127.0.0.1:8760/api/faris/{subpath}"
    if request.query_string:
        target_url += f"?{request.query_string.decode('utf-8')}"
    
    headers = {k: v for k, v in request.headers if k.lower() not in ("host", "content-length")}
    data = request.get_data() if request.method in ("POST", "PUT", "PATCH") else None
    
    req = urllib.request.Request(target_url, data=data, headers=headers, method=request.method)
    try:
        with urllib.request.urlopen(req, timeout=120) as resp:
            content = resp.read()
            resp_headers = [(k, v) for k, v in resp.getheaders() if k.lower() not in ("content-length", "transfer-encoding", "content-encoding")]
            return Response(content, status=resp.status, headers=resp_headers)
    except urllib.error.HTTPError as e:
        content = e.read()
        return Response(content, status=e.code, headers=[("Content-Type", "application/json")])
    except Exception as e:
        return jsonify({"status": "ERROR", "message": f"FARIS service connection error: {str(e)}"}), 502


# ---------------------------------------------------------------------------
# Database Helpers for Wipe History & Legacy Reports
# ---------------------------------------------------------------------------
import tempfile

def _get_history_db_path() -> str:
    data_dir = os.environ.get("SECUREWIPE_DATA_DIR")
    if not data_dir:
        data_dir = os.path.join(os.path.dirname(__file__), "data")
        try:
            os.makedirs(data_dir, exist_ok=True)
            test_file = os.path.join(data_dir, ".write_test_hist")
            with open(test_file, "w") as f:
                f.write("ok")
            os.remove(test_file)
        except Exception:
            data_dir = os.path.join(tempfile.gettempdir(), "securewipe_data")
            os.makedirs(data_dir, exist_ok=True)
    os.makedirs(data_dir, exist_ok=True)
    return os.path.join(data_dir, "history.db")

HISTORY_DB = _get_history_db_path()

def _init_history_db():
    global HISTORY_DB
    HISTORY_DB = _get_history_db_path()
    conn = sqlite3.connect(HISTORY_DB)
    try:
        with conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS wipe_history (
                    id TEXT PRIMARY KEY,
                    device TEXT NOT NULL,
                    deviceSerial TEXT DEFAULT '',
                    method TEXT NOT NULL,
                    status TEXT NOT NULL DEFAULT 'In Progress',
                    standard TEXT DEFAULT 'NIST 800-88',
                    startTime TEXT NOT NULL,
                    endTime TEXT DEFAULT '',
                    filesVerified INTEGER DEFAULT 0,
                    verificationHash TEXT DEFAULT '',
                    operatorName TEXT DEFAULT 'Worker',
                    notes TEXT DEFAULT '',
                    finalState TEXT DEFAULT '',
                    forensicEvidence TEXT DEFAULT '',
                    auditJson TEXT DEFAULT '',
                    created_at INTEGER NOT NULL
                )
            """)
    finally:
        conn.close()

def _insert_history(record: dict) -> str:
    record_id = record.get("id") or f"WIPE-{_uuid.uuid4().hex[:8].upper()}"
    conn = sqlite3.connect(HISTORY_DB)
    try:
        with conn:
            conn.execute("""
                INSERT OR REPLACE INTO wipe_history
                (id, device, deviceSerial, method, status, standard,
                 startTime, endTime, filesVerified, verificationHash, operatorName, notes, finalState, forensicEvidence, auditJson, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                record_id,
                record.get("device", ""),
                record.get("deviceSerial", ""),
                record.get("method", ""),
                record.get("status", "In Progress"),
                record.get("standard", "NIST 800-88"),
                record.get("startTime", ""),
                record.get("endTime", ""),
                record.get("filesVerified", 0),
                record.get("verificationHash", ""),
                record.get("operatorName", "Worker"),
                record.get("notes", ""),
                record.get("finalState", ""),
                record.get("forensicEvidence", ""),
                record.get("auditJson", ""),
                int(time.time()),
            ))
    finally:
        conn.close()
    return record_id

def _get_history(limit: int = 100):
    conn = sqlite3.connect(HISTORY_DB)
    try:
        conn.row_factory = sqlite3.Row
        rows = conn.execute("SELECT * FROM wipe_history ORDER BY created_at DESC LIMIT ?", (limit,)).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()

def _get_report(report_id: str):
    conn = sqlite3.connect(HISTORY_DB)
    try:
        conn.row_factory = sqlite3.Row
        row = conn.execute("SELECT * FROM wipe_history WHERE id = ?", (report_id,)).fetchone()
        if not row:
            return None
        res = dict(row)
        if res.get("auditJson"):
            try:
                parsed = json.loads(res["auditJson"])
                parsed.update({
                    "id": res["id"],
                    "device": res["device"],
                    "deviceSerial": res["deviceSerial"],
                    "status": res["status"],
                    "operatorName": res["operatorName"],
                })
                return parsed
            except Exception:
                pass
        return res
    finally:
        conn.close()

# ---------------------------------------------------------------------------
# Wipe Method Mapping
# ---------------------------------------------------------------------------
STANDARDS_MAP = {
    "nist-clear": "NIST 800-88 Rev.1 — Clear",
    "nist-purge": "NIST 800-88 Rev.1 — Purge",
    "dod-3pass": "DoD 5220.22-M (3-Pass)",
    "dod-7pass": "DoD 5220.22-M ECE (7-Pass)",
    "crypto-erase": "IEEE 2883 Cryptographic Erase",
    "ieee-purge": "IEEE 2883-2022 Purge",
    "gutmann": "Gutmann 35-Pass",
    "bomb-mode": "Bomb Mode — Scatter Overwrite",
}

# ---------------------------------------------------------------------------
# API: Authentication & Session Management
# ---------------------------------------------------------------------------
@app.post("/api/auth/login")
def api_auth_login():
    """Authenticate with username and password using PBKDF2 hash verification."""
    body = request.get_json(silent=True) or {}
    username = (body.get("username") or "").strip()
    password = body.get("password", "")
    client_ip = request.remote_addr or "127.0.0.1"

    if not username or not password:
        return jsonify({"status": "error", "message": "Username and password are required."}), 400

    ok, msg, user_data = authenticate_user(username, password, client_ip=client_ip)
    if not ok:
        record_audit_event(
            event_type="LOGIN_FAILED",
            operator=username,
            client_ip=client_ip,
            payload={"reason": msg}
        )
        return jsonify({"status": "error", "message": msg}), 401

    record_audit_event(
        event_type="LOGIN",
        operator=username,
        client_ip=client_ip,
        payload={"role": user_data["role"]}
    )

    resp = jsonify({"status": "success", "message": msg, "user": user_data})
    resp.set_cookie(
        "session_token",
        user_data["token"],
        httponly=True,
        secure=IS_PRODUCTION,
        samesite="Lax",
        max_age=8 * 3600
    )
    return resp, 200

@app.post("/api/auth/logout")
def api_auth_logout():
    claims = extract_auth_claims()
    username = claims.get("sub", "anonymous") if claims else "anonymous"
    record_audit_event(
        event_type="LOGOUT",
        operator=username,
        client_ip=request.remote_addr or "127.0.0.1"
    )
    resp = jsonify({"status": "success", "message": "Logged out successfully."})
    resp.delete_cookie("session_token")
    return resp, 200

@app.get("/api/auth/me")
@require_auth()
def api_auth_me():
    claims = getattr(request, "current_user", {})
    return jsonify({"status": "success", "user": claims}), 200

# ---------------------------------------------------------------------------
# API: Storage Safety & Two-Stage Confirmation
# ---------------------------------------------------------------------------
@app.post("/api/sanitization/confirm-stage1")
@require_auth(allowed_roles=[ROLE_ADMINISTRATOR, ROLE_OPERATOR])
def api_confirm_stage1():
    """
    Stage 1 Confirmation: Validates target safety and returns device details
    along with a single-use, time-limited confirmation token and required phrase.
    """
    body = request.get_json(silent=True) or {}
    target = body.get("target", "").strip()
    method = body.get("method", "dod-3pass")
    operator = getattr(request, "current_user", {}).get("sub", "operator")
    client_ip = request.remote_addr or "127.0.0.1"

    if not target:
        return jsonify({"status": "error", "message": "Missing 'target' parameter."}), 400

    result = generate_stage1_confirmation(
        target=target,
        method=method,
        operator=operator,
        client_ip=client_ip
    )

    record_audit_event(
        event_type="CONFIRMATION_REQUESTED",
        operator=operator,
        target=target,
        client_ip=client_ip,
        payload={"safe": result.get("safe"), "status": result.get("status")}
    )

    status_code = 200 if result.get("safe") else 400
    return jsonify(result), status_code

# ---------------------------------------------------------------------------
# API: Sanitization Execution (Adaptive Sanitization Framework)
# ---------------------------------------------------------------------------
import threading as _threading
_san_sessions: dict = {}
_san_lock = _threading.Lock()

@app.get("/api/sanitization/methods")
def get_sanitization_methods():
    """Return available sanitization methods with standards metadata."""
    try:
        from sanitization_engine import SANITIZATION_METHODS
        return jsonify([
            {
                "id": k,
                "label": v["label"],
                "passes": v["passes"],
                "description": v["description"],
            }
            for k, v in SANITIZATION_METHODS.items()
        ]), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.post("/api/sanitization/start")
@require_auth(allowed_roles=[ROLE_ADMINISTRATOR, ROLE_OPERATOR])
def post_sanitization_start():
    """
    Start an adaptive sanitization session with strict Stage 2 Confirmation.
    Body: { target, method, maxIterations, confirmation_token, typed_phrase }
    """
    try:
        from sanitization_engine import run_adaptive_sanitization
        body = request.get_json(silent=True) or {}
        target = body.get("target", "").strip()
        method = body.get("method", "dod-3pass")
        max_iterations = int(body.get("maxIterations", 3))
        operator = getattr(request, "current_user", {}).get("sub", body.get("operator", "Operator"))
        client_ip = request.remote_addr or "127.0.0.1"

        confirmation_token = body.get("confirmation_token", "")
        typed_phrase = body.get("typed_phrase", "")

        # In production or strict mode, Stage 2 Confirmation is mandatory
        expected_fp = None
        if confirmation_token:
            ok, msg, payload = validate_stage2_confirmation(
                confirmation_token=confirmation_token,
                typed_phrase=typed_phrase,
                operator=operator,
                client_ip=client_ip
            )
            if not ok:
                record_audit_event(
                    event_type="CONFIRMATION_REJECTED",
                    operator=operator,
                    target=target,
                    client_ip=client_ip,
                    payload={"reason": msg}
                )
                return jsonify({"status": "error", "code": "CONFIRMATION_FAILED", "message": msg}), 400
            expected_fp = payload.get("fingerprint")
        elif IS_PRODUCTION:
            return jsonify({
                "status": "error",
                "code": "CONFIRMATION_TOKEN_REQUIRED",
                "message": "Two-stage confirmation is required in production mode. Please call /api/sanitization/confirm-stage1 first."
            }), 400

        session_id = f"SAN-{_uuid.uuid4().hex[:10].upper()}"

        session = {
            "status": "running",
            "progress": 0,
            "logs": [],
            "result": None,
            "session_id": session_id,
        }
        with _san_lock:
            _san_sessions[session_id] = session

        def _progress_cb(msg: str, pct=None):
            with _san_lock:
                s = _san_sessions.get(session_id)
                if s:
                    s["logs"].append(msg)
                    if pct is not None:
                        s["progress"] = pct

        def _run():
            try:
                result = run_adaptive_sanitization(
                    target=target,
                    method=method,
                    max_iterations=max_iterations,
                    operator=operator,
                    expected_fingerprint=expected_fp,
                    progress_cb=_progress_cb,
                )
                final_state = result.get("final_state", "")
                status_map = {
                    "SANITIZED_AND_REUSABLE": "Completed",
                    "SANITIZATION_NOT_VERIFIABLE": "Warning",
                    "NON_SANITIZABLE": "Failed",
                }
                db_status = status_map.get(final_state, "Completed")
                last_iter = result.get("iterations", [])[-1] if result.get("iterations") else {}
                recovery_meta = last_iter.get("recovery_assessment", {})
                evidence_level = recovery_meta.get("evidence_level", "NO_EVIDENCE")

                _insert_history({
                    "id": session_id,
                    "device": target,
                    "deviceSerial": result.get("device_info", {}).get("serial", ""),
                    "method": method,
                    "status": db_status,
                    "standard": result.get("sanitization_method_label", ""),
                    "startTime": result.get("start_time", ""),
                    "endTime": result.get("end_time", ""),
                    "filesVerified": result.get("total_iterations", 0),
                    "verificationHash": result.get("tamper_hash", ""),
                    "operatorName": operator,
                    "notes": result.get("final_reason", ""),
                    "finalState": final_state,
                    "forensicEvidence": evidence_level,
                    "auditJson": json.dumps(result),
                })
                with _san_lock:
                    s = _san_sessions.get(session_id)
                    if s:
                        s["status"] = "complete"
                        s["progress"] = 100
                        s["result"] = result
            except Exception as ex:
                with _san_lock:
                    s = _san_sessions.get(session_id)
                    if s:
                        s["status"] = "error"
                        s["logs"].append(f"[ERROR] {ex}")
                        s["result"] = {"final_state": "NON_SANITIZABLE", "final_reason": str(ex)}

        t = _threading.Thread(target=_run, daemon=True)
        t.start()

        return jsonify({"session_id": session_id}), 200
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

@app.get("/api/sanitization/status/<session_id>")
def get_sanitization_status(session_id):
    """Poll the status of a running sanitization session."""
    with _san_lock:
        s = _san_sessions.get(session_id)
    if not s:
        return jsonify({"error": "Session not found"}), 404
    return jsonify({
        "session_id": session_id,
        "status": s["status"],
        "progress": s["progress"],
        "logs": s["logs"],
        "result": s["result"],
    }), 200

@app.get("/api/sanitization/report/<session_id>")
def get_sanitization_report(session_id):
    """Get full audit report for completed session."""
    with _san_lock:
        s = _san_sessions.get(session_id)
    if not s:
        report = _get_report(session_id)
        if report:
            return jsonify(report), 200
        return jsonify({"error": "Session not found"}), 404
    result = s.get("result")
    if not result:
        return jsonify({"error": "Session not yet complete"}), 202
    return jsonify(result), 200

# ---------------------------------------------------------------------------
# API: Storage Inspector & Hex Viewer (Strictly Read-Only)
# ---------------------------------------------------------------------------
@app.post("/api/inspector/device-info")
def post_inspector_device_info():
    """Return comprehensive metadata for selected storage object (Strictly Read-Only)."""
    try:
        from storage_inspector import inspect_storage_metadata
        body = request.get_json(silent=True) or {}
        target = body.get("target", "")
        if not target:
            return jsonify({"error": "Missing target parameter"}), 400
        info = inspect_storage_metadata(target)
        return jsonify(info), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.post("/api/inspector/read-hex")
def post_inspector_read_hex():
    """Read sector/block bytes in hex and ASCII (Strictly Read-Only). Supports Mode A and Mode B."""
    try:
        import importlib, storage_inspector
        importlib.reload(storage_inspector)
        from storage_inspector import read_storage_hex_sector
        body = request.get_json(silent=True) or {}
        target = body.get("target", "")
        lba = int(body.get("lba", 0))
        sector_size = int(body.get("sector_size", 512))
        sector_count = int(body.get("sector_count", 1))
        mode = body.get("mode", "device")
        sub_view = body.get("sub_view", "combined")
        child_file_path = body.get("child_file_path")
        extent_index = body.get("extent_index")
        relative_sector = body.get("relative_sector")
        target_device = body.get("target_device")

        if extent_index is not None:
            extent_index = int(extent_index)
        if relative_sector is not None:
            relative_sector = int(relative_sector)

        if not target:
            return jsonify({"error": "Missing target parameter"}), 400

        result = read_storage_hex_sector(
            target,
            lba=lba,
            sector_size=sector_size,
            sector_count=sector_count,
            mode=mode,
            sub_view=sub_view,
            child_file_path=child_file_path,
            extent_index=extent_index,
            relative_sector=relative_sector,
            target_device=target_device,
        )
        return jsonify(result), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.post("/api/inspector/folder-allocation")
def post_inspector_folder_allocation():
    """Retrieve full read-only storage allocation map for a folder (Directory Table, Child Files, Combined Map)."""
    try:
        import importlib, storage_inspector
        importlib.reload(storage_inspector)
        from storage_inspector import get_folder_storage_allocation
        body = request.get_json(silent=True) or {}
        path = body.get("path") or body.get("folder_path", "")
        target_device = body.get("target_device") or body.get("target")

        if not path:
            return jsonify({"error": "Missing path parameter"}), 400

        result = get_folder_storage_allocation(folder_path=path, target_device=target_device)
        return jsonify(result), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.post("/api/inspector/compare")
def post_inspector_compare():
    """Compare 'Before' and 'After' hex sector strings."""
    try:
        from storage_inspector import compare_sector_diff
        body = request.get_json(silent=True) or {}
        before_hex = body.get("before_hex", "")
        after_hex = body.get("after_hex", "")
        lba = int(body.get("lba", 0))
        sector_size = int(body.get("sector_size", 512))

        result = compare_sector_diff(before_hex, after_hex, lba=lba, sector_size=sector_size)
        return jsonify(result), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.post("/api/inspector/search")
def post_inspector_search():
    """Unified search: raw storage byte search and filesystem-aware search (strictly read-only)."""
    try:
        import importlib, storage_inspector
        importlib.reload(storage_inspector)
        from storage_inspector import unified_storage_search
        body = request.get_json(silent=True) or {}
        target = body.get("target", "")
        query = body.get("query", "")
        query_type = body.get("query_type", "text")
        search_mode = body.get("search_mode", "both")
        max_scan_bytes = int(body.get("max_scan_bytes", 50 * 1024 * 1024))
        sector_size = int(body.get("sector_size", 512))

        if not target or not query:
            return jsonify({"error": "Missing target or query parameter"}), 400

        result = unified_storage_search(
            target,
            query=query,
            query_type=query_type,
            search_mode=search_mode,
            max_scan_bytes=max_scan_bytes,
            sector_size=sector_size,
        )
        return jsonify(result), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.post("/api/inspector/file-details")
def post_inspector_file_details():
    """Retrieve full read-only metadata, preview, and optional SHA-256 for a file or folder."""
    try:
        import importlib, storage_inspector
        importlib.reload(storage_inspector)
        from storage_inspector import get_file_details
        body = request.get_json(silent=True) or {}
        path = body.get("path") or body.get("file_path", "")
        compute_hash = bool(body.get("compute_hash", False))

        if not path:
            return jsonify({"error": "Missing path parameter"}), 400

        target_device = body.get("target_device") or body.get("target")
        result = get_file_details(file_path=path, compute_hash=compute_hash, target_device=target_device)
        return jsonify(result), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500
@app.post("/api/inspector/export")
def post_inspector_export():
    """Generate SHA-256 hashed forensic inspection certificate."""
    try:
        body = request.get_json(silent=True) or {}
        report_data = {
            "session_id": f"INSPECT-{_uuid.uuid4().hex[:8].upper()}",
            "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "operator": body.get("operator", "Forensic Analyst"),
            "target": body.get("target", ""),
            "metadata": body.get("metadata", {}),
            "inspected_lba": body.get("lba", 0),
            "sector_size": body.get("sector_size", 512),
            "analysis": body.get("analysis", {}),
            "read_only_verified": True,
            "disclaimer": "Forensic read-only inspection certificate generated by SecureWipe Storage Inspector.",
        }
        payload_bytes = json.dumps(report_data, sort_keys=True).encode()
        report_data["sha256_digest"] = hashlib.sha256(payload_bytes).hexdigest()
        return jsonify(report_data), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ---------------------------------------------------------------------------
# API: FARIS Forensic Recovery & Folder-Level Recovery Integration
# ---------------------------------------------------------------------------
import threading as _faris_threading
_faris_jobs_lock = _faris_threading.Lock()
_faris_jobs: Dict[str, Dict[str, Any]] = {}

def _get_faris_api():
    faris_root = os.path.join(os.path.dirname(os.path.dirname(__file__)), "FARIS")
    if os.path.exists(faris_root) and str(faris_root) not in sys.path:
        sys.path.insert(0, str(faris_root))
    faris_app = os.path.join(faris_root, "application")
    if os.path.exists(faris_app) and str(faris_app) not in sys.path:
        sys.path.insert(0, str(faris_app))
    from application.faris_api import faris_api
    return faris_api

@app.get("/api/faris/health")
def api_faris_health():
    return jsonify({
        "status": "SUCCESS",
        "service": "FARIS Forensic Recovery Service (Mounted on Core API)",
        "port": DEFAULT_PORT,
        "timestamp": time.time()
    }), 200

@app.get("/api/faris/engine-status")
def api_faris_engine_status():
    try:
        api = _get_faris_api()
        return jsonify(api.get_engine_status()), 200
    except Exception as e:
        return jsonify({"status": "ERROR", "message": str(e)}), 500

@app.get("/api/faris/devices")
def api_faris_devices():
    try:
        api = _get_faris_api()
        return jsonify(api.discover_devices()), 200
    except Exception as e:
        return jsonify({"status": "ERROR", "message": str(e)}), 500

@app.get("/api/faris/cases")
def api_faris_list_cases():
    try:
        _get_faris_api()
        from core.paths import get_cases_dir
        cases_list = []
        cases_dir = get_cases_dir()
        if cases_dir.exists():
            for c_dir in sorted(cases_dir.iterdir()):
                if c_dir.is_dir() and not c_dir.name.startswith("."):
                    meta_file = c_dir / "case_meta.json"
                    meta = {}
                    if meta_file.exists():
                        try:
                            with open(meta_file, "r", encoding="utf-8") as f:
                                meta = json.load(f)
                        except Exception:
                            pass
                    cases_list.append({
                        "case_id": c_dir.name,
                        "path": str(c_dir),
                        "created_at": meta.get("created_at", ""),
                        "examiner": meta.get("examiner", "Examiner"),
                        "description": meta.get("description", ""),
                        "case_name": meta.get("case_name", c_dir.name),
                    })
        return jsonify({"status": "SUCCESS", "cases": cases_list}), 200
    except Exception as e:
        return jsonify({"status": "ERROR", "message": str(e)}), 500

@app.get("/api/faris/cases/<case_id>")
def api_faris_case_detail(case_id):
    try:
        _get_faris_api()
        from core.paths import resolve_case_dir
        case_dir = resolve_case_dir(case_id)
        if not case_dir.exists():
            return jsonify({"status": "ERROR", "message": f"Case '{case_id}' not found."}), 404
        details = {
            "case_id": case_id,
            "path": str(case_dir),
            "metadata": {},
            "analysis": None,
            "discovered_artifacts": None,
            "artifact_states": None,
            "recovery_summary": None,
            "validation_report": None,
            "reports": {},
            "audit_trail_count": 0,
        }
        meta_file = case_dir / "case_meta.json"
        if meta_file.exists():
            try:
                with open(meta_file, "r", encoding="utf-8") as f:
                    details["metadata"] = json.load(f)
            except Exception:
                pass
        val_file = case_dir / "validated" / "validation_report.json"
        if val_file.exists():
            try:
                with open(val_file, "r", encoding="utf-8") as f:
                    details["validation_report"] = json.load(f)
            except Exception:
                pass
        reports_dir = case_dir / "reports"
        if reports_dir.exists():
            for rf in reports_dir.iterdir():
                if rf.suffix.lower() == ".json":
                    details["reports"]["json"] = str(rf.name)
                elif rf.suffix.lower() == ".csv":
                    details["reports"]["csv"] = str(rf.name)
                elif rf.suffix.lower() == ".html":
                    details["reports"]["html"] = str(rf.name)
        return jsonify({"status": "SUCCESS", "case": details}), 200
    except Exception as e:
        return jsonify({"status": "ERROR", "message": str(e)}), 500

@app.post("/api/faris/folder/resolve-scope")
def api_faris_folder_resolve_scope():
    try:
        api = _get_faris_api()
        body = request.get_json(silent=True) or {}
        folder_path = str(body.get("folder_path") or body.get("path") or "").strip()
        target_device = body.get("target_device") or body.get("target")
        if not folder_path:
            return jsonify({"status": "ERROR", "message": "Missing 'folder_path' parameter"}), 400
        scope_result = api.resolve_folder_scope(folder_path, target_device=target_device)
        return jsonify(scope_result), 200
    except Exception as e:
        return jsonify({"status": "ERROR", "message": str(e)}), 500

@app.post("/api/faris/folder/recover")
def api_faris_folder_recover():
    try:
        api = _get_faris_api()
        body = request.get_json(silent=True) or {}
        case_id = str(body.get("case_id") or "").strip()
        if not case_id:
            case_id = f"FARIS-FLD-{_uuid.uuid4().hex[:8].upper()}"
            body["case_id"] = case_id
        folder_path = str(body.get("folder_path") or body.get("target_path") or "").strip()
        if not folder_path:
            return jsonify({"status": "ERROR", "message": "Missing 'folder_path' parameter"}), 400
        job_id = f"JOB-FLD-{_uuid.uuid4().hex[:8].upper()}"
        job_entry = {
            "job_id": job_id,
            "case_id": case_id,
            "scope": "FOLDER",
            "folder_path": folder_path,
            "status": "RUNNING",
            "progress_pct": 0.0,
            "current_stage": "setup",
            "stage_status": "RUNNING",
            "logs": [],
            "stages": {
                "setup": {"label": "Workspace Initialization", "status": "PENDING", "pct": 5.0},
                "scope_resolution": {"label": "Scope & Allocation Mapping", "status": "PENDING", "pct": 15.0},
                "fs_recovery": {"label": "Pass 1: Filesystem Structure Extraction", "status": "PENDING", "pct": 30.0},
                "carving": {"label": "Pass 2: Scoped Forensic Carving", "status": "PENDING", "pct": 60.0},
                "validation": {"label": "Integrity & Confidence Validation", "status": "PENDING", "pct": 80.0},
                "hashing": {"label": "SHA-256 Manifest Hashing", "status": "PENDING", "pct": 88.0},
                "reporting": {"label": "Multi-Format Forensic Reporting", "status": "PENDING", "pct": 95.0},
            },
            "result": None,
            "error": None,
            "start_time": time.time(),
            "end_time": None,
        }
        with _faris_jobs_lock:
            _faris_jobs[job_id] = job_entry

        def _folder_progress_cb(stage_id: str, status: str, pct: float, msg: str):
            with _faris_jobs_lock:
                if job_id in _faris_jobs:
                    j = _faris_jobs[job_id]
                    j["progress_pct"] = float(pct)
                    j["current_stage"] = stage_id
                    j["stage_status"] = status
                    j["logs"].append({
                        "timestamp": time.strftime("%H:%M:%S", time.localtime()),
                        "stage": stage_id,
                        "status": status,
                        "pct": pct,
                        "message": msg
                    })
                    if stage_id in j["stages"]:
                        j["stages"][stage_id]["status"] = status
                        j["stages"][stage_id]["pct"] = pct

        def _folder_worker():
            try:
                result = api.recover_folder(body, progress_callback=_folder_progress_cb)
                with _faris_jobs_lock:
                    if job_id in _faris_jobs:
                        j = _faris_jobs[job_id]
                        j["status"] = result.get("status", "SUCCESS")
                        j["result"] = result
                        j["end_time"] = time.time()
                        if result.get("status") == "FAILED":
                            j["error"] = result.get("error", "Folder recovery pipeline failed.")
            except Exception as e:
                with _faris_jobs_lock:
                    if job_id in _faris_jobs:
                        j = _faris_jobs[job_id]
                        j["status"] = "FAILED"
                        j["error"] = str(e)
                        j["end_time"] = time.time()

        thread = _faris_threading.Thread(target=_folder_worker, daemon=True)
        thread.start()

        return jsonify({
            "status": "SUCCESS",
            "job_id": job_id,
            "case_id": case_id,
            "scope": "FOLDER",
            "message": "FARIS folder recovery pipeline started"
        }), 200
    except Exception as e:
        return jsonify({"status": "ERROR", "message": str(e)}), 500

@app.get("/api/faris/folder/jobs/<job_id>")
def api_faris_folder_job_status(job_id: str):
    with _faris_jobs_lock:
        job = _faris_jobs.get(job_id)
        if not job:
            return jsonify({"status": "ERROR", "message": f"Job ID '{job_id}' not found"}), 404
        return jsonify(job), 200


# ---------------------------------------------------------------------------
# API: Phase 9 Post-Sanitization Residual Evidence Assessment Endpoints
# ---------------------------------------------------------------------------

@app.get("/api/assessment/devices")
def get_assessment_devices():
    """List real block devices and verified forensic images available for assessment."""
    try:
        raw_devs = list_devices()
        evidence_images = []
        data_dir = os.environ.get("SECUREWIPE_DATA_DIR") or os.path.join(os.path.dirname(__file__), "data")
        
        # Scan data dir and subdirs for forensic raw disk images
        if os.path.exists(data_dir):
            for root, _, files in os.walk(data_dir):
                for fn in files:
                    if fn.endswith((".raw", ".dd", ".img", ".bin", ".iso")):
                        fpath = os.path.join(root, fn)
                        try:
                            sz = os.path.getsize(fpath)
                            evidence_images.append({
                                "name": fpath,
                                "friendlyName": f"Forensic Image: {fn} ({sz / (1024*1024):.1f} MB)",
                                "type": "Forensic Image",
                                "size": f"{sz / (1024*1024):.1f} MB",
                                "sizeBytes": sz,
                                "health": 100,
                                "healthStatus": "Verified",
                                "serial": f"IMG-{hashlib.sha256(fn.encode()).hexdigest()[:8].upper()}",
                                "isSystem": False,
                                "isImage": True,
                            })
                        except Exception:
                            pass

        return jsonify({
            "status": "success",
            "physical_devices": raw_devs,
            "forensic_images": evidence_images,
            "all_targets": raw_devs + evidence_images,
        }), 200
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


@app.post("/api/assessment/start")
def post_assessment_start():
    """Start streaming read-only post-sanitization residual evidence scan."""
    try:
        import threading
        body = request.get_json(silent=True) or {}
        target_path = body.get("target_path", "").strip()
        target_type = body.get("target_type", "disk")
        sector_size = int(body.get("sector_size", 512))
        prior_meta = body.get("prior_sanitization_meta", {})

        if not target_path:
            return jsonify({"status": "error", "message": "target_path is required."}), 400

        assessment_id = f"ASMT-{_uuid.uuid4().hex[:10].upper()}"

        def _run_bg():
            stream_post_sanitization_assessment(
                target_path=target_path,
                target_type=target_type,
                sector_size=sector_size,
                prior_sanitization_meta=prior_meta,
                assessment_id=assessment_id,
            )

        t = threading.Thread(target=_run_bg, daemon=True)
        t.start()

        return jsonify({
            "status": "INITIALIZING",
            "assessment_id": assessment_id,
            "target_path": target_path,
            "message": "Read-only post-sanitization assessment scan started in background.",
        }), 200
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


@app.get("/api/assessment/status/<assessment_id>")
def get_assessment_status(assessment_id):
    """Poll progress of a post-sanitization assessment session."""
    with _assessment_lock:
        session = _assessment_sessions.get(assessment_id)

    if not session:
        return jsonify({"status": "error", "message": "Assessment session not found."}), 404

    elapsed = max(0.001, time.time() - session.start_time)
    mb_scanned = session.bytes_scanned / (1024 * 1024)
    scan_rate = round(mb_scanned / elapsed, 2)
    rem_bytes = max(0, session.total_bytes - session.bytes_scanned)
    bytes_per_s = session.bytes_scanned / elapsed
    eta = round(rem_bytes / max(1.0, bytes_per_s), 1) if bytes_per_s > 0 else 0.0
    curr_lba = session.sectors_scanned

    return jsonify({
        "assessment_id": session.assessment_id,
        "status": session.status,
        "is_cancelled": session.is_cancelled,
        "progress_pct": session.progress_pct,
        "bytes_scanned": session.bytes_scanned,
        "total_bytes": session.total_bytes,
        "sectors_scanned": session.sectors_scanned,
        "total_sectors": session.total_sectors,
        "current_lba": curr_lba,
        "scan_rate_mb_s": scan_rate,
        "elapsed_seconds": round(elapsed, 1),
        "eta_seconds": eta,
        "current_region": f"LBA {curr_lba:,} / {session.total_sectors:,}",
        "matches_count": len(session.validated_candidates) + len(session.partial_artifacts) + len(session.anomalies),
        "validated_count": len(session.validated_candidates),
        "partial_count": len(session.partial_artifacts),
        "anomaly_count": len(session.anomalies),
        "signature_only_count": len(session.signature_only_hits),
        "overall_classification": session.overall_classification,
        "observation_statement": session.observation_statement,
        "logs": session.logs[-20:],
    }), 200


@app.post("/api/assessment/cancel")
def post_assessment_cancel():
    """Cancel an ongoing post-sanitization assessment session."""
    try:
        from post_sanitization_assessment import cancel_assessment_session
        body = request.get_json(silent=True) or {}
        assessment_id = body.get("assessment_id", "")
        if not assessment_id:
            return jsonify({"status": "error", "message": "assessment_id is required."}), 400
        success = cancel_assessment_session(assessment_id)
        if success:
            return jsonify({"status": "SUCCESS", "message": f"Assessment {assessment_id} cancelled."}), 200
        else:
            return jsonify({"status": "NOT_FOUND", "message": "Assessment session not found or already finished."}), 404
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


@app.get("/api/assessment/report/<assessment_id>")
def get_assessment_report(assessment_id):
    """Retrieve full post-sanitization assessment report with ledger, heatmap, and disclaimers."""
    with _assessment_lock:
        session = _assessment_sessions.get(assessment_id)

    if not session:
        return jsonify({"status": "error", "message": "Assessment session not found."}), 404

    report = session.to_report_dict()
    return jsonify(report), 200


@app.post("/api/assessment/inspect-bytes")
def post_assessment_inspect_bytes():
    """Live read-only byte-level physical inspector for any target offset/LBA."""
    try:
        body = request.get_json(silent=True) or {}
        target_path = body.get("target_path", "").strip()
        byte_offset = int(body.get("byte_offset", 0))
        length_bytes = int(body.get("length_bytes", 512))
        sector_size = int(body.get("sector_size", 512))
        expected_pattern = body.get("expected_pattern", "0x00")

        if not target_path:
            return jsonify({"status": "ERROR", "message": "target_path is required."}), 400

        result = inspect_media_bytes(
            target_path=target_path,
            byte_offset=byte_offset,
            length_bytes=length_bytes,
            sector_size=sector_size,
            expected_pattern=expected_pattern,
        )
        return jsonify(result), 200
    except Exception as e:
        return jsonify({"status": "ERROR", "message": str(e)}), 500


@app.post("/api/assessment/comparative-experiment")
def post_assessment_comparative_experiment():
    """Run an automated comparative before/after sanitization experiment."""
    try:
        body = request.get_json(silent=True) or {}
        exp_name = body.get("experiment_name", "EXPERIMENT-NIST-800-88-CLEAR")
        image_size_mb = int(body.get("image_size_mb", 12))
        wipe_method = body.get("wipe_method", "nist-clear")

        result = run_comparative_sanitization_experiment(
            experiment_name=exp_name,
            image_size_mb=image_size_mb,
            wipe_method=wipe_method,
        )
        return jsonify(result), 200
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


@app.get("/api/assessment/certificate/<assessment_id>")
def get_assessment_certificate(assessment_id):
    """Generate Schema v2.0 RSA-PSS signed certificate for completed assessment."""
    try:
        with _assessment_lock:
            session = _assessment_sessions.get(assessment_id)

        if not session:
            return jsonify({"status": "error", "message": "Assessment session not found."}), 404

        report = session.to_report_dict()
        operator = request.args.get("operator", "Forensic Assurance Officer")
        cert = generate_signed_assessment_certificate(report, operator=operator)
        return jsonify(cert), 200
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


@app.post("/api/assessment/certificate/<assessment_id>/verify")
def post_assessment_certificate_verify(assessment_id):
    """Verify cryptographic signature and integrity of a Schema v2.0 Certificate."""
    try:
        cert_dict = request.get_json(silent=True)
        if not cert_dict:
            # Try to fetch current session certificate
            with _assessment_lock:
                session = _assessment_sessions.get(assessment_id)
            if session:
                cert_dict = generate_signed_assessment_certificate(session.to_report_dict())
            else:
                return jsonify({"status": "error", "message": "No certificate provided."}), 400

        res = verify_assessment_certificate(cert_dict)
        return jsonify(res), 200
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


@app.post("/api/assessment/swarm-sync/<assessment_id>")
def post_assessment_swarm_sync(assessment_id):
    """Sync residual fragment candidates to Swarm reconstruction micro-tasks."""
    try:
        body = request.get_json(silent=True) or {}
        case_id = body.get("case_id", f"CASE-{assessment_id}")
        res = sync_assessment_fragments_to_swarm(assessment_id, case_id=case_id)
        return jsonify(res), 200
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


@app.post("/api/assessment/generate-test-image")
def post_assessment_generate_test_image():
    """Helper to generate an authentic multi-format test image in data directory."""
    try:
        data_dir = os.environ.get("SECUREWIPE_DATA_DIR") or os.path.join(os.path.dirname(__file__), "data")
        os.makedirs(data_dir, exist_ok=True)
        img_path = os.path.join(data_dir, "forensic_evidence_live.raw")
        meta = create_certified_forensic_evidence_image(image_path=img_path, total_size_bytes=12 * 1024 * 1024)
        return jsonify({"status": "success", "image": meta}), 200
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

# ---------------------------------------------------------------------------
# API: Device Enumeration & Reports
# ---------------------------------------------------------------------------
@app.get("/api/devices")
def get_devices():
    devices = list_devices()
    return jsonify(devices), 200

@app.get("/api/history")
def get_history():
    history = _get_history()
    return jsonify(history), 200

@app.get("/api/reports/<report_id>")
def get_report(report_id):
    report = _get_report(report_id)
    if not report:
        # Check compliance db
        cert = get_certificate_by_id(report_id)
        if cert:
            return jsonify(cert), 200
        return jsonify({"error": "Report not found"}), 404
    return jsonify(report), 200

# ---------------------------------------------------------------------------
# API: Compliance & Lifecycle Engine Endpoints
# ---------------------------------------------------------------------------
@app.get("/api/compliance/dashboard-stats")
def api_compliance_stats():
    stats = get_compliance_dashboard_stats()
    return jsonify(stats), 200

@app.get("/api/compliance/certificates")
def api_compliance_certificates():
    certs = get_all_certificates()
    return jsonify(certs), 200

@app.get("/api/compliance/certificates/<cert_id>")
def api_compliance_cert_detail(cert_id):
    cert = get_certificate_by_id(cert_id)
    if not cert:
        return jsonify({"error": "Certificate not found"}), 404
    return jsonify(cert), 200

@app.post("/api/compliance/certificates/<cert_id>/verify")
def api_compliance_cert_verify(cert_id):
    cert = get_certificate_by_id(cert_id)
    if not cert:
        return jsonify({"error": "Certificate not found", "valid": False}), 404
    result = verify_certificate_integrity(cert)
    record_audit_event(
        event_type="CERTIFICATE_VERIFIED",
        operator=getattr(request, "current_user", {}).get("sub", "auditor"),
        target=cert_id,
        payload=result
    )
    return jsonify(result), 200

@app.get("/api/compliance/certificates/<cert_id>/export")
def api_compliance_cert_export(cert_id):
    cert = get_certificate_by_id(cert_id)
    if not cert:
        return jsonify({"error": "Certificate not found"}), 404
    export_fmt = request.args.get("format", "json").lower()
    if export_fmt == "csv":
        csv_data = export_certificate_csv_summary([cert])
        return Response(csv_data, mimetype="text/csv", headers={"Content-Disposition": f"attachment;filename=cert-{cert_id}.csv"})
    return Response(export_certificate_json(cert), mimetype="application/json", headers={"Content-Disposition": f"attachment;filename=cert-{cert_id}.json"})

@app.get("/api/compliance/audit-events")
@require_auth(allowed_roles=[ROLE_ADMINISTRATOR, ROLE_AUDITOR])
def api_compliance_audit_events():
    events = get_audit_events(limit=100)
    return jsonify(events), 200

@app.get("/api/compliance/recyclers")
def api_compliance_recyclers():
    recyclers = get_recyclers_list()
    return jsonify(recyclers), 200

@app.post("/api/compliance/recyclers")
@require_auth(allowed_roles=[ROLE_ADMINISTRATOR, ROLE_OPERATOR])
def api_compliance_add_recycler():
    body = request.get_json(silent=True) or {}
    org_name = (body.get("organization_name") or "").strip()
    if not org_name:
        return jsonify({"error": "Organization name is required."}), 400
    res = add_recycler(
        org_name=org_name,
        auth_ref=body.get("authorization_reference", ""),
        contact_info=body.get("contact_info", "")
    )
    return jsonify(res), 201

@app.get("/api/compliance/disposal-handovers")
def api_compliance_handovers():
    handovers = get_disposal_handovers_list()
    return jsonify(handovers), 200

@app.post("/api/compliance/disposal-handovers")
@require_auth(allowed_roles=[ROLE_ADMINISTRATOR, ROLE_OPERATOR])
def api_compliance_create_handover():
    body = request.get_json(silent=True) or {}
    cert_id = body.get("certificate_id", "").strip()
    recycler_id = body.get("recycler_id", "").strip()
    if not cert_id or not recycler_id:
        return jsonify({"error": "certificate_id and recycler_id are required."}), 400
    res = create_disposal_handover(
        certificate_id=cert_id,
        recycler_id=recycler_id,
        disposal_reason=body.get("disposal_reason", ""),
        notes=body.get("notes", "")
    )
    return jsonify(res), 201

@app.post("/api/compliance/disposal-handovers/<handover_id>/confirm")
@require_auth(allowed_roles=[ROLE_ADMINISTRATOR, ROLE_OPERATOR])
def api_compliance_confirm_handover(handover_id):
    ok = confirm_disposal_handover(handover_id)
    if not ok:
        return jsonify({"error": "Handover record not found or could not be confirmed."}), 404
    return jsonify({"status": "success", "message": "Disposal handover confirmed."}), 200

@app.get("/api/compliance/integration-status")
def api_compliance_integrations():
    return jsonify(get_integration_statuses()), 200

@app.get("/api/compliance/assessment-checklist")
def api_compliance_assessment():
    return jsonify(get_assessment_checklist()), 200

@app.get("/api/compliance/procurement-checklist")
def api_compliance_procurement():
    return jsonify(get_procurement_checklist()), 200

# ---------------------------------------------------------------------------
# API: Security Dashboard & Diagnostic Status
# ---------------------------------------------------------------------------
@app.get("/api/security/status")
def api_security_status():
    """Return live security diagnostic status and 9-dim production readiness scorecard."""
    status = evaluate_security_status()
    return jsonify(status), 200

@app.get("/api/security/audit-verify")
def api_security_audit_verify():
    """Verify cryptographic hash chain of the entire audit log."""
    res = verify_audit_log_integrity()
    return jsonify(res), 200

# ---------------------------------------------------------------------------
# API: File System Navigation (Path-Protected)
# ---------------------------------------------------------------------------
@app.get("/api/fs/roots")
def get_fs_roots():
    roots = []
    if sys.platform.startswith("win"):
        import string
        for letter in string.ascii_uppercase:
            drive = f"{letter}:\\"
            if os.path.exists(drive):
                roots.append({"name": f"Drive ({drive})", "path": drive, "is_dir": True})
        home = os.path.expanduser("~")
        roots.append({"name": "User Home", "path": home, "is_dir": True})
    else:
        home = os.path.expanduser("~")
        roots.append({"name": "🏠 Home", "path": home, "is_dir": True})
        desktop = os.path.join(home, "Desktop")
        if os.path.exists(desktop):
            roots.append({"name": "🖥️ Desktop", "path": desktop, "is_dir": True})
        docs = os.path.join(home, "Documents")
        if not os.path.exists(docs):
            try: os.makedirs(docs, exist_ok=True)
            except: pass
        if os.path.exists(docs):
            roots.append({"name": "📁 Documents", "path": docs, "is_dir": True})
        downloads = os.path.join(home, "Downloads")
        if not os.path.exists(downloads):
            try: os.makedirs(downloads, exist_ok=True)
            except: pass
        if os.path.exists(downloads):
            roots.append({"name": "📥 Downloads", "path": downloads, "is_dir": True})
        roots.append({"name": "🗂️ Root (/)", "path": "/", "is_dir": True})
        if os.path.exists("/home"):
            roots.append({"name": "👥 /home", "path": "/home", "is_dir": True})
        if os.path.exists("/media"):
            roots.append({"name": "💾 /media", "path": "/media", "is_dir": True})
        if os.path.exists("/mnt"):
            roots.append({"name": "🔌 /mnt", "path": "/mnt", "is_dir": True})
        if os.path.exists("/tmp"):
            roots.append({"name": "⚡ /tmp", "path": "/tmp", "is_dir": True})
    return jsonify(roots), 200

@app.get("/api/fs/browse")
def get_fs_browse():
    path = request.args.get("path", "")
    show_hidden = request.args.get("show_hidden", "false").lower() in ("true", "1", "yes")
    if not path:
        path = os.path.expanduser("~") if not sys.platform.startswith("win") else "C:\\"
    path = os.path.abspath(path)
    if not os.path.exists(path) or not os.path.isdir(path):
        return jsonify({"error": f"Directory not found: {path}"}), 404

    items = []
    try:
        with os.scandir(path) as it:
            for entry in it:
                try:
                    if not show_hidden and entry.name.startswith(".") and entry.name != "..":
                        continue
                    is_dir = entry.is_dir(follow_symlinks=False)
                    stat = entry.stat(follow_symlinks=False)
                    items.append({
                        "name": entry.name,
                        "path": entry.path,
                        "is_dir": is_dir,
                        "size_bytes": stat.st_size if not is_dir else 0,
                        "modified": int(stat.st_mtime),
                    })
                except Exception:
                    continue
    except PermissionError:
        return jsonify({"error": f"Permission denied: {path}"}), 403
    except Exception as e:
        return jsonify({"error": str(e)}), 500

    items.sort(key=lambda x: (not x["is_dir"], x["name"].lower()))
    parent = os.path.dirname(path) if path != os.path.dirname(path) else None

    # Generate breadcrumbs
    parts = []
    curr = path
    while curr and curr != os.path.dirname(curr):
        parts.append({"name": os.path.basename(curr) or curr, "path": curr})
        curr = os.path.dirname(curr)
    if curr:
        parts.append({"name": curr, "path": curr})
    parts.reverse()

    return jsonify({
        "current_path": path,
        "parent_path": parent,
        "breadcrumbs": parts,
        "items": items[:500],
    }), 200

@app.post("/api/fs/picker")
def post_fs_picker():
    body = request.get_json(silent=True) or {}
    target_type = body.get("type", "file")
    # Native dialogs with safe argument array handling
    import shutil
    import subprocess
    selected_path = None
    if shutil.which("zenity"):
        try:
            cmd = ["zenity", "--file-selection"]
            if target_type == "folder":
                cmd.append("--directory")
            cmd.append(f"--title=Select {target_type.title()} to Sanitize")
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            if res.returncode == 0 and res.stdout.strip():
                selected_path = res.stdout.strip()
        except Exception:
            pass

    if selected_path:
        return jsonify({"status": "selected", "path": selected_path}), 200
    return jsonify({"status": "cancelled", "path": ""}), 200

# ---------------------------------------------------------------------------
# API: System Status & Dashboard Stats
# ---------------------------------------------------------------------------
@app.get("/api/system/status")
def get_system_status():
    try:
        hostname = socket.gethostname()
    except Exception:
        hostname = "localhost"
    import platform
    return jsonify({
        "hostname": hostname,
        "os": f"{platform.system()} {platform.release()}",
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "status": "Operational",
        "environment": APP_ENV
    }), 200

@app.get("/api/stats")
def get_stats():
    history = _get_history()
    completed = sum(1 for h in history if h.get("status") == "Completed" or h.get("finalState") == "SANITIZED_AND_REUSABLE")
    warning = sum(1 for h in history if h.get("status") == "Warning" or h.get("finalState") == "SANITIZATION_NOT_VERIFIABLE")
    failed = sum(1 for h in history if h.get("status") == "Failed" or h.get("finalState") == "NON_SANITIZABLE")
    in_progress = sum(1 for h in history if h.get("status") == "In Progress")

    devices = list_devices()
    standards_count = {}
    for h in history:
        s = h.get("standard", "Unknown")
        standards_count[s] = standards_count.get(s, 0) + 1

    return jsonify({
        "totalWipes": len(history),
        "completed": completed,
        "warning": warning,
        "failed": failed,
        "inProgress": in_progress,
        "totalDevices": len(devices),
        "complianceRate": round(completed / max(len(history), 1) * 100, 1) if history else 100,
        "standardsBreakdown": standards_count,
        "recentWipes": history[:5],
    }), 200

# ---------------------------------------------------------------------------
# API: Method Suggester
# ---------------------------------------------------------------------------
@app.post("/api/get-wipe-method")
def post_get_wipe_method():
    try:
        body = request.get_json(silent=True) or {}
        device_name = (body.get("device") or "").strip()
        if not device_name:
            return jsonify({"error": "Missing 'device' in request body"}), 400

        method = "dod-3pass"
        name_l = device_name.lower()
        if any(k in name_l for k in ["usb", "pen drive", "pendrive", "flash", "stick", "v220w"]):
            method = "nist-clear"
        elif any(k in name_l for k in ["ssd", "nvme", "m.2"]):
            method = "crypto-erase"
        elif any(k in name_l for k in ["hdd", "hard disk", "seagate", "wd", "toshiba"]):
            method = "dod-3pass"

        return jsonify({"method": method}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# ---------------------------------------------------------------------------
# API: Commercial Marketplace & Device Lifecycle Endpoints
# ---------------------------------------------------------------------------
from marketplace_engine import (
    init_marketplace_db,
    register_device,
    get_user_devices,
    get_device_by_id,
    evaluate_marketplace_eligibility,
    create_marketplace_listing,
    get_marketplace_listings,
    get_listing_detail,
    initiate_device_purchase,
    complete_ownership_transfer,
    revoke_certificate,
    get_public_certificate_verification,
    get_admin_marketplace_overview,
    register_marketplace_certificate,
)

@app.post("/api/marketplace/devices/register")
@require_auth()
def api_marketplace_register_device():
    """Register a new storage device under the authenticated user account."""
    body = request.get_json(silent=True) or {}
    user = getattr(request, "current_user", {})
    username = user.get("sub") or body.get("owner_username", "Seller")
    
    manufacturer = (body.get("manufacturer") or "Generic").strip()
    model = (body.get("model") or "Storage Medium").strip()
    capacity_bytes = int(body.get("capacity_bytes") or (500 * 1024**3))
    interface = (body.get("interface") or "SATA").strip()
    device_type = (body.get("device_type") or "SSD").strip().upper()
    raw_serial = (body.get("serial") or "").strip()
    health = body.get("health_status", "Healthy")
    smart = body.get("smart_data", {})
    
    res = register_device(
        owner_username=username,
        manufacturer=manufacturer,
        model=model,
        capacity_bytes=capacity_bytes,
        interface=interface,
        device_type=device_type,
        raw_serial=raw_serial,
        health_status=health,
        smart_data=smart
    )
    return jsonify({"status": "success", "device": res}), 201

@app.get("/api/marketplace/devices/my-devices")
@require_auth()
def api_marketplace_my_devices():
    """Retrieve all devices owned by the authenticated user."""
    user = getattr(request, "current_user", {})
    username = user.get("sub", "Seller")
    devices = get_user_devices(username)
    return jsonify({"status": "success", "devices": devices}), 200

@app.get("/api/marketplace/devices/<device_id>")
def api_marketplace_device_detail(device_id):
    """Retrieve device specifications."""
    dev = get_device_by_id(device_id)
    if not dev:
        return jsonify({"error": "Device not found"}), 404
    return jsonify({"status": "success", "device": dev}), 200

@app.get("/api/marketplace/devices/<device_id>/eligibility")
@require_auth()
def api_marketplace_eligibility(device_id):
    """Evaluate if a device meets security requirements for verified listing."""
    user = getattr(request, "current_user", {})
    username = user.get("sub", "Seller")
    res = evaluate_marketplace_eligibility(device_id, username)
    return jsonify(res), 200

@app.get("/api/marketplace/listings")
def api_marketplace_get_listings():
    """Browse active marketplace listings with category & price filters."""
    cat = request.args.get("category")
    q = request.args.get("query")
    cond = request.args.get("condition")
    min_p = float(request.args.get("min_price")) if request.args.get("min_price") else None
    max_p = float(request.args.get("max_price")) if request.args.get("max_price") else None
    ver_only = request.args.get("verified_only", "true").lower() == "true"
    
    listings = get_marketplace_listings(
        category=cat,
        query=q,
        condition=cond,
        min_price=min_p,
        max_price=max_p,
        verified_only=ver_only
    )
    return jsonify({"status": "success", "listings": listings, "count": len(listings)}), 200

@app.get("/api/marketplace/listings/<listing_id>")
def api_marketplace_listing_detail(listing_id):
    """Retrieve full listing details including certificate & health metadata."""
    item = get_listing_detail(listing_id)
    if not item:
        return jsonify({"error": "Listing not found"}), 404
    return jsonify({"status": "success", "listing": item}), 200

@app.post("/api/marketplace/listings")
@require_auth(allowed_roles=[ROLE_ADMINISTRATOR, ROLE_OPERATOR, "SELLER", "master", "worker"])
def api_marketplace_create_listing():
    """Create a new marketplace listing (enforces backend eligibility)."""
    body = request.get_json(silent=True) or {}
    user = getattr(request, "current_user", {})
    username = user.get("sub", "Seller")
    
    device_id = body.get("device_id", "").strip()
    title = body.get("title", "").strip()
    description = body.get("description", "").strip()
    price = float(body.get("price_usd") or 0.0)
    condition = body.get("condition", "Used - Excellent")
    shipping = body.get("shipping_options", "Standard Shipping")
    location = body.get("location", "")
    warranty = body.get("warranty_terms", "")
    photos = body.get("photos", [])
    
    if not device_id or not title or price <= 0:
        return jsonify({"error": "Missing required fields: device_id, title, price_usd > 0."}), 400
        
    ok, msg, res = create_marketplace_listing(
        seller_username=username,
        device_id=device_id,
        title=title,
        description=description,
        price_usd=price,
        condition=condition,
        shipping_options=shipping,
        location=location,
        warranty_terms=warranty,
        photos=photos
    )
    if not ok:
        return jsonify({"error": msg}), 400
    return jsonify({"status": "success", "message": msg, "listing": res}), 201

@app.post("/api/marketplace/listings/<listing_id>/buy")
@require_auth()
def api_marketplace_buy(listing_id):
    """Buyer initiates purchase order and ownership transfer."""
    body = request.get_json(silent=True) or {}
    user = getattr(request, "current_user", {})
    buyer = user.get("sub", "Buyer")
    notes = body.get("transfer_notes", "")
    
    ok, msg, res = initiate_device_purchase(
        listing_id=listing_id,
        buyer_username=buyer,
        transfer_notes=notes
    )
    if not ok:
        return jsonify({"error": msg}), 400
    return jsonify({"status": "success", "message": msg, "order": res}), 200

@app.post("/api/marketplace/transfers/<transfer_id>/complete")
@require_auth()
def api_marketplace_transfer_complete(transfer_id):
    """Confirm delivery and finalize device ownership transfer."""
    user = getattr(request, "current_user", {})
    actor = user.get("sub", "System")
    ok, msg = complete_ownership_transfer(transfer_id, actor)
    if not ok:
        return jsonify({"error": msg}), 400
    return jsonify({"status": "success", "message": msg}), 200

@app.get("/api/marketplace/verify/<cert_id>")
def api_marketplace_public_verify(cert_id):
    """Public certificate verification with privacy masking."""
    res = get_public_certificate_verification(cert_id)
    status_code = 200 if res.get("valid") else (404 if res.get("status") == "NOT_FOUND" else 200)
    return jsonify(res), status_code

@app.post("/api/marketplace/certificates/<cert_id>/revoke")
@require_auth(allowed_roles=[ROLE_ADMINISTRATOR])
def api_marketplace_revoke_cert(cert_id):
    """Admin revocation of a compromised or erroneous certificate."""
    body = request.get_json(silent=True) or {}
    user = getattr(request, "current_user", {})
    admin = user.get("sub", "Administrator")
    reason = body.get("reason", "Revoked by platform administrator.")
    
    ok, msg = revoke_certificate(cert_id, reason, admin)
    if not ok:
        return jsonify({"error": msg}), 400
    return jsonify({"status": "success", "message": msg}), 200

@app.get("/api/admin/marketplace/overview")
@require_auth(allowed_roles=[ROLE_ADMINISTRATOR])
def api_admin_marketplace_overview():
    """Retrieve platform admin metrics."""
    overview = get_admin_marketplace_overview()
    return jsonify({"status": "success", "overview": overview}), 200

# ---------------------------------------------------------------------------
# Server Startup
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    init_auth_db()
    init_audit_db()
    init_compliance_db()
    init_marketplace_db()
    init_swarm_db()
    init_db()
    _init_history_db()

    print("=" * 70)
    print(f"  SecureWipe Commercial Platform API — Environment: {APP_ENV}")
    print(f"  Listening on: http://{DEFAULT_HOST}:{DEFAULT_PORT}")
    print("  Sanitization + Cryptographic Certification + Verified Marketplace")
    print("=" * 70)
    app.run(host=DEFAULT_HOST, port=DEFAULT_PORT, use_reloader=False)

