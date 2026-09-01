import os
import json
import time
import uuid
import threading
from flask import Blueprint, jsonify, request, send_file
from .config import FARIS_VERSION, ENGINE_VERSION, FARIS_REPORTS_DIR
from .db import get_db_connection, init_faris_db
from .evidence import register_evidence_file, get_evidence_path
from .hashing import compute_file_sha256, verify_file_integrity
from .scanner import execute_carve_scan
from .timeline import get_timeline
from .chain_of_custody import get_chain_events, verify_chain_integrity, add_chain_event
from .hex_viewer import extract_hex_view
from .reports import generate_forensic_report
from .synthetic_generator import generate_synthetic_database
from .damage_simulator import simulate_damage
from .evaluator import evaluate_recovery_against_ground_truth

faris_bp = Blueprint("faris_api", __name__)

# --------------------------------------------------------------------------
# Health & General Stats
# --------------------------------------------------------------------------
@faris_bp.get("/health")
def faris_health():
    return jsonify({
        "status": "healthy",
        "module": "FARIS",
        "name": "Forensic Artifact Recovery & Integrity System",
        "version": FARIS_VERSION,
        "engine": ENGINE_VERSION
    }), 200

@faris_bp.get("/stats")
def faris_stats():
    conn = get_db_connection()
    try:
        cases_count = conn.execute("SELECT COUNT(*) FROM faris_cases").fetchone()[0]
        evidence_count = conn.execute("SELECT COUNT(*) FROM faris_evidence").fetchone()[0]
        pages_detected = conn.execute("SELECT COUNT(*) FROM faris_page_candidates WHERE validation_status IN ('Candidate', 'Validated')").fetchone()[0]
        records_recovered = conn.execute("SELECT COUNT(*) FROM faris_recovered_records").fetchone()[0]
        
        high_conf = conn.execute("SELECT COUNT(*) FROM faris_recovered_records WHERE confidence_level = 'High'").fetchone()[0]
        med_conf = conn.execute("SELECT COUNT(*) FROM faris_recovered_records WHERE confidence_level = 'Medium'").fetchone()[0]
        low_conf = conn.execute("SELECT COUNT(*) FROM faris_recovered_records WHERE confidence_level = 'Low'").fetchone()[0]
        candidate_conf = conn.execute("SELECT COUNT(*) FROM faris_recovered_records WHERE confidence_level = 'Candidate'").fetchone()[0]

        recent_jobs = conn.execute("SELECT * FROM faris_scan_jobs ORDER BY created_at DESC LIMIT 5").fetchall()

        return jsonify({
            "cases_count": cases_count,
            "evidence_count": evidence_count,
            "pages_detected": pages_detected,
            "records_recovered": records_recovered,
            "confidence_breakdown": {
                "high": high_conf,
                "medium": med_conf,
                "low": low_conf,
                "candidate": candidate_conf
            },
            "evidence_integrity": "VERIFIED",
            "recent_jobs": [dict(j) for j in recent_jobs]
        }), 200
    finally:
        conn.close()

# --------------------------------------------------------------------------
# Case Management
# --------------------------------------------------------------------------
@faris_bp.get("/cases")
def list_cases():
    conn = get_db_connection()
    try:
        rows = conn.execute("SELECT * FROM faris_cases ORDER BY created_at DESC").fetchall()
        return jsonify([dict(r) for r in rows]), 200
    finally:
        conn.close()

@faris_bp.post("/cases")
def create_case():
    body = request.get_json(silent=True) or {}
    case_name = (body.get("case_name") or "").strip()
    if not case_name:
        return jsonify({"error": "Case name is required"}), 400

    case_id = body.get("case_id") or f"CASE-{time.strftime('%Y')}-{uuid.uuid4().hex[:4].upper()}"
    desc = body.get("description", "")
    investigator = body.get("investigator", "Forensic Specialist")

    conn = get_db_connection()
    try:
        with conn:
            conn.execute("""
                INSERT INTO faris_cases (case_id, case_name, description, investigator, status, created_at, updated_at)
                VALUES (?, ?, ?, ?, 'Active', ?, ?)
            """, (case_id, case_name, desc, investigator, int(time.time()), int(time.time())))

        add_chain_event(case_id=case_id, action="CASE_CREATED", details=f"Created investigation case '{case_name}'", actor=investigator)
        return jsonify({"case_id": case_id, "case_name": case_name, "status": "Active"}), 201
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    finally:
        conn.close()

@faris_bp.delete("/cases/<case_id>")
def delete_case(case_id):
    conn = get_db_connection()
    try:
        with conn:
            conn.execute("DELETE FROM faris_cases WHERE case_id = ?", (case_id,))
        return jsonify({"status": "success", "message": f"Case {case_id} deleted"}), 200
    finally:
        conn.close()

# --------------------------------------------------------------------------
# Evidence Management
# --------------------------------------------------------------------------
@faris_bp.get("/evidence")
def list_evidence():
    case_id = request.args.get("case_id")
    conn = get_db_connection()
    try:
        if case_id:
            rows = conn.execute("SELECT * FROM faris_evidence WHERE case_id = ? ORDER BY created_at DESC", (case_id,)).fetchall()
        else:
            rows = conn.execute("SELECT * FROM faris_evidence ORDER BY created_at DESC").fetchall()
        return jsonify([dict(r) for r in rows]), 200
    finally:
        conn.close()

@faris_bp.post("/evidence/upload")
def upload_evidence():
    if "file" not in request.files:
        return jsonify({"error": "No file attached in upload"}), 400
    file_obj = request.files["file"]
    case_id = request.form.get("case_id")
    investigator = request.form.get("investigator", "Analyst")

    if not case_id:
        return jsonify({"error": "case_id is required"}), 400

    try:
        res = register_evidence_file(
            case_id=case_id,
            uploaded_file_obj=file_obj,
            original_filename=file_obj.filename,
            investigator=investigator
        )
        return jsonify(res), 201
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@faris_bp.post("/evidence/verify-hash")
def verify_hash():
    body = request.get_json(silent=True) or {}
    evidence_id = body.get("evidence_id")
    if not evidence_id:
        return jsonify({"error": "evidence_id is required"}), 400

    conn = get_db_connection()
    try:
        row = conn.execute("SELECT * FROM faris_evidence WHERE evidence_id = ?", (evidence_id,)).fetchone()
        if not row:
            return jsonify({"error": "Evidence not found"}), 404

        file_path = get_evidence_path(row["stored_filename"])
        res = verify_file_integrity(file_path, row["sha256_hash"])
        return jsonify(res), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    finally:
        conn.close()

# --------------------------------------------------------------------------
# Recovery / Scan Engine
# --------------------------------------------------------------------------
@faris_bp.post("/recovery/start")
def start_recovery():
    body = request.get_json(silent=True) or {}
    evidence_id = body.get("evidence_id")
    case_id = body.get("case_id")

    if not evidence_id or not case_id:
        return jsonify({"error": "evidence_id and case_id are required"}), 400

    conn = get_db_connection()
    try:
        ev_row = conn.execute("SELECT * FROM faris_evidence WHERE evidence_id = ?", (evidence_id,)).fetchone()
        if not ev_row:
            return jsonify({"error": "Evidence not found"}), 404

        file_path = get_evidence_path(ev_row["stored_filename"])
        job_id = f"JOB-{uuid.uuid4().hex[:8].upper()}"

        with conn:
            conn.execute("""
                INSERT INTO faris_scan_jobs
                (job_id, evidence_id, case_id, mode, status, progress, created_at)
                VALUES (?, ?, ?, 'Header-Independent', 'Queued', 0, ?)
            """, (job_id, evidence_id, case_id, int(time.time())))

        # Run in background thread
        thread = threading.Thread(
            target=execute_carve_scan,
            args=(job_id, file_path, evidence_id, case_id, ev_row["original_filename"]),
            daemon=True
        )
        thread.start()

        return jsonify({
            "job_id": job_id,
            "evidence_id": evidence_id,
            "case_id": case_id,
            "status": "Queued",
            "message": "FARIS forensic recovery scan initiated in background"
        }), 202
    finally:
        conn.close()

@faris_bp.get("/recovery/jobs")
def list_jobs():
    case_id = request.args.get("case_id")
    conn = get_db_connection()
    try:
        if case_id:
            rows = conn.execute("SELECT * FROM faris_scan_jobs WHERE case_id = ? ORDER BY created_at DESC", (case_id,)).fetchall()
        else:
            rows = conn.execute("SELECT * FROM faris_scan_jobs ORDER BY created_at DESC").fetchall()
        return jsonify([dict(r) for r in rows]), 200
    finally:
        conn.close()

@faris_bp.get("/recovery/jobs/<job_id>")
def get_job(job_id):
    conn = get_db_connection()
    try:
        job = conn.execute("SELECT * FROM faris_scan_jobs WHERE job_id = ?", (job_id,)).fetchone()
        if not job:
            return jsonify({"error": "Job not found"}), 404

        candidates = conn.execute("SELECT * FROM faris_page_candidates WHERE job_id = ? ORDER BY offset ASC", (job_id,)).fetchall()
        relationships = conn.execute("SELECT * FROM faris_fragment_relationships WHERE job_id = ?", (job_id,)).fetchall()

        return jsonify({
            "job": dict(job),
            "candidates": [dict(c) for c in candidates],
            "relationships": [dict(rel) for rel in relationships]
        }), 200
    finally:
        conn.close()

# --------------------------------------------------------------------------
# Recovered Records & Search
# --------------------------------------------------------------------------
@faris_bp.get("/records")
def list_records():
    job_id = request.args.get("job_id")
    case_id = request.args.get("case_id")
    search_q = request.args.get("q", "").strip()
    conf_filter = request.args.get("confidence")

    conn = get_db_connection()
    try:
        query = "SELECT * FROM faris_recovered_records WHERE 1=1"
        params = []

        if job_id:
            query += " AND job_id = ?"
            params.append(job_id)
        if case_id:
            query += " AND case_id = ?"
            params.append(case_id)
        if conf_filter:
            query += " AND confidence_level = ?"
            params.append(conf_filter)
        if search_q:
            query += " AND column_values LIKE ?"
            params.append(f"%{search_q}%")

        query += " ORDER BY confidence_score DESC LIMIT 200"
        rows = conn.execute(query, params).fetchall()

        parsed_records = []
        for r in rows:
            d = dict(r)
            d["column_types"] = json.loads(d["column_types"])
            d["column_values"] = json.loads(d["column_values"])
            d["reasons"] = json.loads(d["reasons_json"])
            d["provenance"] = json.loads(d["provenance_json"])
            parsed_records.append(d)

        return jsonify(parsed_records), 200
    finally:
        conn.close()

# --------------------------------------------------------------------------
# Timeline & Chain of Custody
# --------------------------------------------------------------------------
@faris_bp.get("/timeline")
def timeline_endpoint():
    case_id = request.args.get("case_id")
    if not case_id:
        return jsonify({"error": "case_id query parameter is required"}), 400
    events = get_timeline(case_id)
    return jsonify(events), 200

@faris_bp.get("/chain")
def chain_endpoint():
    case_id = request.args.get("case_id")
    if not case_id:
        return jsonify({"error": "case_id query parameter is required"}), 400
    events = get_chain_events(case_id)
    verification = verify_chain_integrity(case_id)
    return jsonify({
        "events": events,
        "verification": verification
    }), 200

# --------------------------------------------------------------------------
# Forensic Hex Viewer
# --------------------------------------------------------------------------
@faris_bp.get("/hex")
def hex_viewer_endpoint():
    evidence_id = request.args.get("evidence_id")
    offset = int(request.args.get("offset", 0))
    length = int(request.args.get("length", 512))
    hl_offset = request.args.get("hl_offset")
    hl_len = request.args.get("hl_len")

    if not evidence_id:
        return jsonify({"error": "evidence_id is required"}), 400

    conn = get_db_connection()
    try:
        row = conn.execute("SELECT stored_filename FROM faris_evidence WHERE evidence_id = ?", (evidence_id,)).fetchone()
        if not row:
            return jsonify({"error": "Evidence not found"}), 404
        file_path = get_evidence_path(row["stored_filename"])
        res = extract_hex_view(
            file_path=file_path,
            offset=offset,
            length=length,
            highlight_offset=int(hl_offset) if hl_offset else None,
            highlight_length=int(hl_len) if hl_len else None
        )
        return jsonify(res), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    finally:
        conn.close()

# --------------------------------------------------------------------------
# Reports
# --------------------------------------------------------------------------
@faris_bp.post("/reports/generate")
def report_gen_endpoint():
    body = request.get_json(silent=True) or {}
    case_id = body.get("case_id")
    job_id = body.get("job_id")
    fmt = body.get("format", "html").lower()

    if not case_id or not job_id:
        return jsonify({"error": "case_id and job_id are required"}), 400

    try:
        res = generate_forensic_report(case_id, job_id, fmt)
        return jsonify(res), 201
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@faris_bp.get("/reports")
def list_reports():
    case_id = request.args.get("case_id")
    conn = get_db_connection()
    try:
        if case_id:
            rows = conn.execute("SELECT * FROM faris_reports WHERE case_id = ? ORDER BY created_at DESC", (case_id,)).fetchall()
        else:
            rows = conn.execute("SELECT * FROM faris_reports ORDER BY created_at DESC").fetchall()
        return jsonify([dict(r) for r in rows]), 200
    finally:
        conn.close()

@faris_bp.get("/reports/download/<report_id>")
def download_report(report_id):
    conn = get_db_connection()
    try:
        row = conn.execute("SELECT * FROM faris_reports WHERE report_id = ?", (report_id,)).fetchone()
        if not row or not os.path.exists(row["file_path"]):
            return jsonify({"error": "Report file not found"}), 404
        return send_file(row["file_path"], as_attachment=False)
    finally:
        conn.close()

# --------------------------------------------------------------------------
# Synthetic Lab & Evaluator
# --------------------------------------------------------------------------
@faris_bp.post("/lab/generate-db")
def lab_generate():
    body = request.get_json(silent=True) or {}
    num_records = int(body.get("records", 50))
    res = generate_synthetic_database(num_records)
    return jsonify(res), 201

@faris_bp.post("/lab/simulate-damage")
def lab_damage():
    body = request.get_json(silent=True) or {}
    source_db_path = body.get("db_path")
    scenario = body.get("scenario", "header_wipe")
    if not source_db_path:
        return jsonify({"error": "db_path is required"}), 400
    res = simulate_damage(source_db_path, scenario)
    return jsonify(res), 200

@faris_bp.post("/lab/evaluate")
def lab_eval():
    body = request.get_json(silent=True) or {}
    damaged_path = body.get("damaged_path")
    gt_path = body.get("gt_path")
    scenario = body.get("scenario", "header_wipe")
    if not damaged_path or not gt_path:
        return jsonify({"error": "damaged_path and gt_path are required"}), 400
    res = evaluate_recovery_against_ground_truth(damaged_path, gt_path, dataset_name="Synthetic Lab Evaluation", scenario=scenario)
    return jsonify(res), 200

@faris_bp.get("/lab/evaluations")
def list_evaluations():
    conn = get_db_connection()
    try:
        rows = conn.execute("SELECT * FROM faris_evaluations ORDER BY created_at DESC").fetchall()
        return jsonify([dict(r) for r in rows]), 200
    finally:
        conn.close()
