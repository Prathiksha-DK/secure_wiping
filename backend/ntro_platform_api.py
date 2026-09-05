"""
NTRO Adaptive Sanitization & Forensic Recovery Platform API Blueprint
Integrates Auth & RBAC, Device Management, Tamper-Evident Audit,
Pre-Wipe Forensic Advisor, Certificates, and Asset Lifecycle.
"""

import os
import json
import time
import uuid
import hashlib
from flask import Blueprint, jsonify, request

from auth import (
    init_platform_db,
    authenticate_user,
    register_user,
    validate_session,
    terminate_session,
    ROLES,
)
from audit_engine import (
    record_audit_event,
    verify_audit_integrity,
    get_audit_logs,
)
from device_manager import (
    sync_local_devices,
    discover_gov_lan_devices,
    register_remote_agent,
    authorize_device,
    get_all_devices,
)
from pre_wipe_advisor import conduct_pre_wipe_assessment
from reporting_engine import (
    generate_sanitization_certificate,
    generate_forensic_case_report,
    get_certificate_by_id,
)
from health_valuation import (
    evaluate_device_health,
    create_marketplace_listing,
    get_marketplace_listings,
)

# Create Blueprint
ntro_bp = Blueprint("ntro_platform", __name__)


def _get_current_user():
    """Extract session token from Authorization header or cookies."""
    auth_header = request.headers.get("Authorization", "")
    token = ""
    if auth_header.startswith("Bearer "):
        token = auth_header.split(" ", 1)[1].strip()
    if not token:
        token = request.cookies.get("session_token", "") or request.cookies.get("session", "")
        # If cookie has JSON, try to extract token
        if token.startswith("{"):
            try:
                data = json.loads(token)
                token = data.get("token", "")
            except Exception:
                pass
    if token:
        return validate_session(token)
    return None


# ---------------------------------------------------------------------------
# 1. Authentication & RBAC Endpoints
# ---------------------------------------------------------------------------

@ntro_bp.post("/api/auth/login")
def api_auth_login():
    """
    Authenticate user and issue session token.
    Body: { username, password }
    """
    try:
        body = request.get_json(silent=True) or {}
        username = (body.get("username") or "").strip()
        password = body.get("password", "")

        if not username or not password:
            return jsonify({"status": "error", "message": "Username and password are required."}), 400

        ok, msg, session_info = authenticate_user(username, password)
        if not ok:
            record_audit_event(
                user_id=username or "anonymous",
                role="unknown",
                operation="LOGIN_FAILED",
                status="FAILED",
                details={"reason": msg, "ip": request.remote_addr}
            )
            return jsonify({"status": "error", "message": msg}), 401

        record_audit_event(
            user_id=str(session_info["user_id"]),
            role=session_info["role"],
            operation="LOGIN_SUCCESS",
            status="SUCCESS",
            details={"username": session_info["username"], "ip": request.remote_addr}
        )

        return jsonify({
            "status": "success",
            "message": "Authenticated successfully",
            "session": session_info
        }), 200
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


@ntro_bp.post("/api/auth/register")
def api_auth_register():
    """Register a new user account with enforced role."""
    try:
        body = request.get_json(silent=True) or {}
        username = (body.get("username") or "").strip()
        password = body.get("password", "")
        role = body.get("role", "individual")
        email = body.get("email", "")
        org = body.get("organization", "")

        if not username or not password:
            return jsonify({"status": "error", "message": "Username and password are required."}), 400

        ok, msg = register_user(username, password, role, email, org)
        if not ok:
            return jsonify({"status": "error", "message": msg}), 400

        record_audit_event(
            user_id=username,
            role=role,
            operation="USER_REGISTER",
            status="SUCCESS",
            details={"email": email, "organization": org}
        )

        return jsonify({"status": "success", "message": msg}), 201
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


@ntro_bp.post("/api/auth/logout")
def api_auth_logout():
    """Terminate current session."""
    user = _get_current_user()
    if user:
        terminate_session(user["token"])
        record_audit_event(
            user_id=str(user["user_id"]),
            role=user["role"],
            operation="LOGOUT",
            status="SUCCESS"
        )
    return jsonify({"status": "success", "message": "Logged out successfully"}), 200


@ntro_bp.get("/api/auth/me")
def api_auth_me():
    """Retrieve current authenticated user context and role."""
    user = _get_current_user()
    if not user:
        return jsonify({"authenticated": False, "user": None}), 200

    role_info = ROLES.get(user["role"], {})
    return jsonify({
        "authenticated": True,
        "user": {
            "user_id": user["user_id"],
            "username": user["username"],
            "role": user["role"],
            "role_label": role_info.get("label", user["role"]),
            "role_description": role_info.get("description", ""),
            "email": user["email"],
            "organization": user["organization"]
        }
    }), 200


# ---------------------------------------------------------------------------
# 2. Device Management Layer Endpoints
# ---------------------------------------------------------------------------

@ntro_bp.get("/api/devices/managed")
def api_devices_managed():
    """Retrieve all synchronized local, Gov-LAN, and remote devices."""
    try:
        conn_type = request.args.get("type")
        sync_local_devices()
        devs = get_all_devices(connection_type=conn_type)
        return jsonify(devs), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@ntro_bp.get("/api/devices/discover-lan")
def api_devices_discover_lan():
    """Discover authenticated agents on the Government/Organization LAN."""
    try:
        user = _get_current_user()
        devs = discover_gov_lan_devices()

        record_audit_event(
            user_id=str(user["user_id"]) if user else "anonymous",
            role=user["role"] if user else "government",
            operation="LAN_DISCOVERY",
            status="SUCCESS",
            details={"devices_found": len(devs)}
        )
        return jsonify(devs), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@ntro_bp.post("/api/devices/authorize")
def api_devices_authorize():
    """Authorize/pair a LAN or Remote device for managed operations."""
    try:
        user = _get_current_user()
        body = request.get_json(silent=True) or {}
        device_id = body.get("device_id", "")
        operator = user["username"] if user else body.get("operator", "Master Admin")

        if not device_id:
            return jsonify({"status": "error", "message": "Missing 'device_id'"}), 400

        ok, msg = authorize_device(device_id, operator)
        if not ok:
            return jsonify({"status": "error", "message": msg}), 400

        record_audit_event(
            user_id=str(user["user_id"]) if user else operator,
            role=user["role"] if user else "government",
            device_id=device_id,
            operation="DEVICE_AUTHORIZE",
            status="SUCCESS",
            details={"message": msg}
        )
        return jsonify({"status": "success", "message": msg}), 200
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


@ntro_bp.post("/api/devices/register-remote")
def api_devices_register_remote():
    """Register an authorized remote endpoint."""
    try:
        user = _get_current_user()
        body = request.get_json(silent=True) or {}
        ok, msg, dev_id = register_remote_agent(body)
        if not ok:
            return jsonify({"status": "error", "message": msg}), 400

        record_audit_event(
            user_id=str(user["user_id"]) if user else "remote_agent",
            role=user["role"] if user else "remote",
            device_id=dev_id,
            operation="REMOTE_AGENT_REGISTER",
            status="SUCCESS",
            details=body
        )
        return jsonify({"status": "success", "message": msg, "device_id": dev_id}), 201
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


# ---------------------------------------------------------------------------
# 3. Pre-Wipe Forensic Risk Assessment
# ---------------------------------------------------------------------------

@ntro_bp.post("/api/sanitization/pre-wipe-check")
def api_sanitization_pre_wipe_check():
    """
    Non-destructive pre-wipe assessment to identify potential forensic evidence
    before executing irreversible destruction.
    """
    try:
        user = _get_current_user()
        body = request.get_json(silent=True) or {}
        target = body.get("target", "")
        target_type = body.get("target_type", "file")

        if not target:
            return jsonify({"status": "error", "message": "Missing 'target'"}), 400

        assessment = conduct_pre_wipe_assessment(target, target_type)

        record_audit_event(
            user_id=str(user["user_id"]) if user else "operator",
            role=user["role"] if user else "individual",
            operation="PRE_WIPE_ASSESSMENT",
            status="SUCCESS",
            details={
                "target": target,
                "target_type": target_type,
                "risk_level": assessment["risk_level"],
                "can_proceed_safely": assessment["can_proceed_safely"]
            }
        )

        return jsonify(assessment), 200
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


# ---------------------------------------------------------------------------
# 4. Forensic Investigation & Deep Carving Endpoints
# ---------------------------------------------------------------------------

@ntro_bp.post("/api/forensics/carve-stream")
def api_forensics_carve_stream():
    """
    Execute strictly read-only streaming forensic carving across a target.
    Returns multi-tier validated artifacts and confidence score.
    """
    try:
        user = _get_current_user()
        from forensic_carver import scan_file_stream, scan_folder_stream, scan_disk_stream

        body = request.get_json(silent=True) or {}
        target = body.get("target", "")
        target_type = body.get("target_type", "file")

        if not target:
            return jsonify({"status": "error", "message": "Missing 'target'"}), 400

        if target_type == "file":
            result = scan_file_stream(target)
        elif target_type == "folder":
            result = scan_folder_stream(target)
        else:
            result = scan_disk_stream(target, total_bytes=min(50 * 1024 * 1024, os.path.getsize(target) if os.path.isfile(target) else 50 * 1024 * 1024))

        record_audit_event(
            user_id=str(user["user_id"]) if user else "investigator",
            role=user["role"] if user else "forensic",
            operation="FORENSIC_CARVE_SCAN",
            status="SUCCESS",
            details={
                "target": target,
                "evidence_level": result.get("evidence_level"),
                "confidence_score": result.get("confidence_score")
            }
        )

        return jsonify(result), 200
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


@ntro_bp.post("/api/forensics/create-case")
def api_forensics_create_case():
    """Create a documented forensic investigation case and signed report."""
    try:
        user = _get_current_user()
        body = request.get_json(silent=True) or {}
        title = body.get("title", "Forensic Media Acquisition")
        investigator = user["username"] if user else body.get("investigator", "Senior Investigator")
        target_source = body.get("target_source", "Unknown Storage Evidence")
        carve_results = body.get("carve_results", {})
        notes = body.get("notes", "")

        report = generate_forensic_case_report(
            case_title=title,
            investigator_name=investigator,
            target_source=target_source,
            carve_results=carve_results,
            chain_of_custody_notes=notes
        )

        record_audit_event(
            user_id=str(user["user_id"]) if user else investigator,
            role=user["role"] if user else "forensic",
            operation="FORENSIC_REPORT_GEN",
            status="SUCCESS",
            details={"case_id": report["case_id"], "sha256": report["evidence_integrity_sha256"]}
        )

        return jsonify({"status": "success", "report": report}), 201
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


@ntro_bp.get("/api/forensics/cases")
def api_forensics_get_cases():
    """Retrieve all logged forensic cases."""
    from auth import get_db
    conn = get_db()
    try:
        cur = conn.cursor()
        cur.execute("SELECT * FROM forensic_cases ORDER BY created_at DESC")
        rows = cur.fetchall()
        return jsonify([dict(r) for r in rows]), 200
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# 5. Tamper-Evident Audit Logs Endpoints
# ---------------------------------------------------------------------------

@ntro_bp.get("/api/audit/logs")
def api_audit_logs():
    """Retrieve immutable audit log trail."""
    try:
        limit = int(request.args.get("limit", 100))
        role_filter = request.args.get("role")
        logs = get_audit_logs(limit=limit, role_filter=role_filter)
        return jsonify(logs), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@ntro_bp.get("/api/audit/verify-chain")
def api_audit_verify_chain():
    """
    Perform on-demand cryptographic verification of the SHA-256 audit log hash chain.
    """
    try:
        verification = verify_audit_integrity()
        return jsonify(verification), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ---------------------------------------------------------------------------
# 6. Certificates Endpoints
# ---------------------------------------------------------------------------

@ntro_bp.get("/api/certificates/<cert_id>")
def api_get_certificate(cert_id):
    """Retrieve sanitization certificate."""
    try:
        cert = get_certificate_by_id(cert_id)
        if not cert:
            return jsonify({"error": "Certificate not found."}), 404
        return jsonify(cert), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@ntro_bp.post("/api/certificates/generate")
def api_generate_certificate():
    """Generate and sign a new Sanitization Certificate."""
    try:
        user = _get_current_user()
        body = request.get_json(silent=True) or {}
        job_id = body.get("job_id") or f"JOB-{uuid.uuid4().hex[:8].upper()}"
        device_info = body.get("device_info", {})
        method_label = body.get("method_label", "NIST 800-88 Rev.1 — Clear")
        verification = body.get("verification", {"status": "PASS", "mismatches_found": 0})
        recovery = body.get("recovery", {"evidence_level": "NO_EVIDENCE", "confidence_score": 0.0})
        final_state = body.get("final_state", "SANITIZED_AND_REUSABLE")
        operator = user["username"] if user else body.get("operator", "Authorized Operator")

        cert = generate_sanitization_certificate(
            job_id=job_id,
            device_info=device_info,
            method_label=method_label,
            verification_summary=verification,
            recovery_summary=recovery,
            final_state=final_state,
            operator_name=operator
        )

        record_audit_event(
            user_id=str(user["user_id"]) if user else operator,
            role=user["role"] if user else "individual",
            operation="CERTIFICATE_GEN",
            status="SUCCESS",
            details={"certificate_id": cert["certificate_id"], "sha256": cert["digital_signature_sha256"]}
        )

        return jsonify(cert), 200
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


# ---------------------------------------------------------------------------
# 7. Hardware Health & Private Marketplace Endpoints
# ---------------------------------------------------------------------------

@ntro_bp.post("/api/lifecycle/evaluate-health")
def api_lifecycle_evaluate_health():
    """Evaluate device health and compute indicative valuation."""
    try:
        body = request.get_json(silent=True) or {}
        health_assessment = evaluate_device_health(body)
        return jsonify(health_assessment), 200
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


@ntro_bp.post("/api/lifecycle/marketplace/list")
def api_lifecycle_marketplace_list():
    """List a certified sanitized device on the private marketplace."""
    try:
        user = _get_current_user()
        body = request.get_json(silent=True) or {}
        device_id = body.get("device_id", "")
        cert_id = body.get("certificate_id", "")
        seller = user["username"] if user else body.get("seller_name", "Verified Seller")
        title = body.get("device_title", "Certified Sanitized Storage")
        media = body.get("media_type", "SSD")
        capacity = float(body.get("capacity_gb", 500.0))
        health_score = int(body.get("health_score", 95))
        val_inr = int(body.get("estimated_value_inr", 2500))

        if not cert_id:
            return jsonify({"status": "error", "message": "Sanitization Certificate ID is required for marketplace listing."}), 400

        ok, msg, listing = create_marketplace_listing(
            device_id=device_id,
            certificate_id=cert_id,
            seller_name=seller,
            device_title=title,
            media_type=media,
            capacity_gb=capacity,
            health_score=health_score,
            valuation_inr=val_inr
        )

        if not ok:
            return jsonify({"status": "error", "message": msg}), 400

        record_audit_event(
            user_id=str(user["user_id"]) if user else seller,
            role=user["role"] if user else "individual",
            device_id=device_id,
            operation="MARKETPLACE_LIST",
            status="SUCCESS",
            details=listing
        )

        return jsonify({"status": "success", "listing": listing}), 201
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


@ntro_bp.get("/api/lifecycle/marketplace/items")
def api_lifecycle_marketplace_items():
    """Retrieve private marketplace items."""
    try:
        items = get_marketplace_listings()
        return jsonify(items), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500
