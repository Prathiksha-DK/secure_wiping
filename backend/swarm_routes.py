"""
SecureWipe — Phase 8: SWARM-CARVING Flask REST API Routes
Provides endpoints for:
- Swarm triage dashboard metrics
- Personalized micro-task distribution with privacy-preserving representations
- Anti-gaming validated task submissions
- Consensus evaluation and queue inspection
- Lead Investigator priority evidence queue and evidentiary verdicts
- Gamified analyst profiles, XP, badges, and team leaderboard
- Controlled benchmark experiments (Exp A vs B vs C)
- Phase 8 forensic report export
- Cryptographic audit trail inspection
- Demo case data seeder
"""

import time
import json
import secrets
from flask import Blueprint, request, jsonify

from security_config import (
    require_auth,
    ROLE_ADMINISTRATOR,
    ROLE_OPERATOR,
    ROLE_AUDITOR,
    ROLE_VIEWER,
    ROLE_LEAD_INVESTIGATOR,
    ROLE_FORENSIC_ANALYST,
    ROLE_TRIAGE_ANALYST,
    ROLE_REVIEWER
)
from swarm_engine import (
    init_swarm_db,
    get_swarm_overview_metrics,
    get_next_task_for_analyst,
    submit_analyst_task,
    get_investigator_priority_queue,
    submit_lead_investigator_verdict,
    get_swarm_leaderboard,
    _get_or_create_analyst_profile,
    generate_swarm_forensic_report,
    verify_swarm_audit_integrity,
    get_recent_audit_events,
    register_evidence_source,
    create_candidate_and_generate_tasks,
    create_golden_validation_task,
    TASK_TYPE_ANOMALY,
    TASK_TYPE_STRUCTURE_VALIDATION,
    TASK_TYPE_FRAGMENT_MATCH,
    TASK_TYPE_FRAGMENT_CLASSIFICATION
)
from swarm_benchmark import execute_full_benchmark_suite, generate_benchmark_dataset
from swarm_evidence_ingest import (
    create_certified_forensic_evidence_image,
    ingest_forensic_image,
    get_candidate_provenance_report,
    clear_swarm_evidence_database
)

swarm_bp = Blueprint("swarm_bp", __name__)

@swarm_bp.route("/api/swarm/overview", methods=["GET"])
def api_swarm_overview():
    """Get high-level Swarm-Carving triage metrics."""
    case_id = request.args.get("case_id")
    metrics = get_swarm_overview_metrics(case_id=case_id)
    return jsonify({"status": "success", "metrics": metrics}), 200

@swarm_bp.route("/api/swarm/evidence/load", methods=["POST"])
def api_swarm_load_evidence():
    """Ingest a real forensic image file strictly in read-only mode, carve candidates, and generate tasks."""
    body = request.get_json(silent=True) or {}
    case_id = body.get("case_id", "CASE-LIVE-FORENSIC-2026")
    image_path = body.get("image_path")
    create_certified = body.get("create_certified", False)

    try:
        if create_certified or not image_path:
            img_meta = create_certified_forensic_evidence_image(image_path)
            image_path = img_meta["image_path"]

        result = ingest_forensic_image(image_path=image_path, case_id=case_id)
        return jsonify({"status": "success", "result": result}), 200
    except Exception as e:
        return jsonify({"status": "error", "error": str(e)}), 400

@swarm_bp.route("/api/swarm/evidence/reset", methods=["POST"])
def api_swarm_reset_evidence():
    """Wipe current candidate/evidence database state for a fresh investigation."""
    res = clear_swarm_evidence_database()
    return jsonify(res), 200

@swarm_bp.route("/api/swarm/audit/events", methods=["GET"])
def api_swarm_audit_events():
    """Retrieve recent cryptographic audit log events for live operations monitoring."""
    limit = int(request.args.get("limit", 20))
    events = get_recent_audit_events(limit=limit)
    return jsonify({"status": "success", "events": events}), 200

@swarm_bp.route("/api/swarm/provenance/candidates", methods=["GET"])
def api_swarm_provenance_candidates():
    """Get byte-level provenance verification report across all carved candidates."""
    case_id = request.args.get("case_id")
    report = get_candidate_provenance_report(case_id=case_id)
    return jsonify({"status": "success", "provenance": report}), 200

@swarm_bp.route("/api/swarm/tasks/next", methods=["GET"])
def api_swarm_next_task():
    """Fetch next micro-task for the active analyst with blind distribution & hidden calibration."""
    username = request.args.get("analyst_id", "CurrentAnalyst")
    role = request.args.get("role", "TRIAGE_ANALYST")
    
    task = get_next_task_for_analyst(username=username, role=role)
    if not task:
        return jsonify({
            "status": "empty",
            "no_evidence": True,
            "message": "NO LIVE EVIDENCE LOADED — LOAD A FORENSIC IMAGE TO START"
        }), 200

    return jsonify({"status": "success", "task": task}), 200

@swarm_bp.route("/api/swarm/tasks/submit", methods=["POST"])
def api_swarm_submit_task():
    """Submit an analyst's triage classification with anti-gaming checks."""
    body = request.get_json(silent=True) or {}
    task_id = body.get("task_id")
    analyst_id = body.get("analyst_id", "AnonymousAnalyst")
    decision = body.get("decision", "UNKNOWN")
    confidence = float(body.get("confidence", 0.8))
    time_spent_ms = int(body.get("time_spent_ms", 2500))
    reason = body.get("reason", "")

    if not task_id:
        return jsonify({"error": "Missing task_id"}), 400

    res = submit_analyst_task(
        task_id=task_id,
        analyst_id=analyst_id,
        decision=decision,
        confidence=confidence,
        time_spent_ms=time_spent_ms,
        reason=reason
    )
    if not res.get("success"):
        return jsonify({"error": res.get("error", "Submission failed")}), 400

    return jsonify({"status": "success", "result": res}), 200

@swarm_bp.route("/api/swarm/investigator/queue", methods=["GET"])
def api_swarm_investigator_queue():
    """Get prioritized evidence queue for the Lead Investigator."""
    case_id = request.args.get("case_id")
    limit = int(request.args.get("limit", 50))
    queue = get_investigator_priority_queue(case_id=case_id, limit=limit)
    return jsonify({"status": "success", "queue": queue}), 200

@swarm_bp.route("/api/swarm/investigator/verdict", methods=["POST"])
def api_swarm_investigator_verdict():
    """Lead Investigator registers authoritative final determination."""
    body = request.get_json(silent=True) or {}
    candidate_id = body.get("candidate_id")
    investigator_id = body.get("investigator_id", "LeadInvestigator_01")
    final_verdict = body.get("final_verdict")
    evidentiary_value = body.get("evidentiary_value", "HIGH")
    notes = body.get("notes", "")

    if not candidate_id or not final_verdict:
        return jsonify({"error": "candidate_id and final_verdict are required"}), 400

    res = submit_lead_investigator_verdict(
        candidate_id=candidate_id,
        investigator_id=investigator_id,
        final_verdict=final_verdict,
        evidentiary_value=evidentiary_value,
        notes=notes
    )
    if not res.get("success"):
        return jsonify({"error": res.get("error", "Verdict submission failed")}), 400

    return jsonify({"status": "success", "result": res}), 200

@swarm_bp.route("/api/swarm/analysts/me", methods=["GET"])
def api_swarm_analyst_profile():
    """Get active analyst gamification profile, XP, level, badges, and streak."""
    analyst_id = request.args.get("analyst_id", "SherlockAnalyst")
    profile = _get_or_create_analyst_profile(analyst_id)
    profile["badges"] = json.loads(profile.get("badges_json", "[]"))
    return jsonify({"status": "success", "profile": profile}), 200

@swarm_bp.route("/api/swarm/analysts/leaderboard", methods=["GET"])
def api_swarm_leaderboard():
    """Get team leaderboard."""
    limit = int(request.args.get("limit", 25))
    leaderboard = get_swarm_leaderboard(limit=limit)
    return jsonify({"status": "success", "leaderboard": leaderboard}), 200

@swarm_bp.route("/api/swarm/benchmark/run", methods=["POST", "GET"])
def api_swarm_benchmark():
    """Execute controlled empirical benchmark (Exp A vs Exp B vs Exp C)."""
    results = execute_full_benchmark_suite()
    return jsonify({"status": "success", "benchmark": results}), 200

@swarm_bp.route("/api/swarm/reports/export", methods=["GET"])
def api_swarm_export_report():
    """Export comprehensive Phase 8 forensic micro-triage report."""
    case_id = request.args.get("case_id", "CASE-SWARM-2026")
    report = generate_swarm_forensic_report(case_id=case_id)
    return jsonify({"status": "success", "report": report}), 200

@swarm_bp.route("/api/swarm/audit", methods=["GET"])
def api_swarm_audit():
    """Verify and retrieve cryptographic audit trail status."""
    is_valid, msg, count = verify_swarm_audit_integrity()
    return jsonify({
        "status": "success",
        "audit": {
            "verified": is_valid,
            "message": msg,
            "event_count": count
        }
    }), 200

@swarm_bp.route("/api/swarm/seed-demo", methods=["POST"])
def api_swarm_seed():
    """Ingest certified multi-format real forensic evidence image."""
    res = _seed_default_swarm_data()
    return jsonify({"status": "success", "message": "Certified forensic evidence ingested successfully.", "result": res}), 200

def _seed_default_swarm_data():
    """Helper to generate and ingest authentic forensic disk image."""
    img_meta = create_certified_forensic_evidence_image()
    return ingest_forensic_image(
        image_path=img_meta["image_path"],
        case_id="CASE-LIVE-FORENSIC-2026"
    )
