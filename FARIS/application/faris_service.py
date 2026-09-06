#!/usr/bin/env python3
"""
FARIS Integration Service & REST Adapter — Port 8760
Provides HTTP REST endpoints for the Wiping Web Application to interact with FARIS.

SAFETY & INTEGRITY GUARANTEES:
- Strictly delegates all forensic operations to FARISAPI (FARIS/application/faris_api.py).
- Contains NO forensic algorithms, NO duplicate recovery logic, and NO mocked outputs.
- Runs full background pipelines with thread-safe telemetry and live progress reporting.
- Protects original evidence by enforcing read-only forensic workflows.
"""

import os
import sys
import json
import uuid
import time
import shutil
import threading
from pathlib import Path
from typing import Dict, Any, Optional

from flask import Flask, request, jsonify, send_file
from flask_cors import CORS

# Add FARIS root, application, and backend directories to sys.path
CURRENT_DIR = Path(__file__).resolve().parent
FARIS_ROOT = CURRENT_DIR.parent
PROJECT_ROOT = FARIS_ROOT.parent
BACKEND_DIR = PROJECT_ROOT / "backend"
if str(FARIS_ROOT) not in sys.path:
    sys.path.insert(0, str(FARIS_ROOT))
if str(CURRENT_DIR) not in sys.path:
    sys.path.insert(0, str(CURRENT_DIR))
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

try:
    from application.faris_api import faris_api
    from core.paths import resolve_case_dir, get_cases_dir, CASES_DIR
except ImportError:
    from faris_api import faris_api
    from core.paths import resolve_case_dir, get_cases_dir, CASES_DIR

app = Flask("faris_integration_service")
CORS(app, resources={r"/api/*": {"origins": "*"}})

# Background Job Registry
_jobs_lock = threading.Lock()
_jobs: Dict[str, Dict[str, Any]] = {}

# ---------------------------------------------------------------------------
# Health & Engine Status Endpoints
# ---------------------------------------------------------------------------

@app.get("/api/faris/health")
@app.get("/status")
@app.get("/health")
def get_health():
    """Health check endpoint."""
    return jsonify({
        "status": "SUCCESS",
        "service": "FARIS Forensic Recovery Service",
        "port": 8760,
        "timestamp": time.time()
    }), 200


@app.get("/api/faris/engine-status")
def get_engine_status():
    """Returns the inventory and status of all bundled forensic engines."""
    try:
        status = faris_api.get_engine_status()
        return jsonify(status), 200
    except Exception as e:
        return jsonify({"status": "ERROR", "message": str(e)}), 500


@app.get("/api/faris/devices")
def get_devices():
    """Discovers connected physical storage drives (SSDs, HDDs, USB pendrives, SD cards)."""
    try:
        devices = faris_api.discover_devices()
        return jsonify(devices), 200
    except Exception as e:
        return jsonify({"status": "ERROR", "message": str(e)}), 500


# ---------------------------------------------------------------------------
# Case Management Endpoints
# ---------------------------------------------------------------------------

@app.get("/api/faris/cases")
def list_cases():
    """Lists all active and existing cases with metadata summaries."""
    cases_list = []
    try:
        # Check active cases directory
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

        # Check legacy case directory (FARIS_ROOT / case001)
        legacy_dir = FARIS_ROOT / "case001"
        if legacy_dir.exists() and legacy_dir.is_dir() and not any(c["case_id"] == "case001" for c in cases_list):
            meta_file = legacy_dir / "case_meta.json"
            meta = {}
            if meta_file.exists():
                try:
                    with open(meta_file, "r", encoding="utf-8") as f:
                        meta = json.load(f)
                except Exception:
                    pass
            cases_list.append({
                "case_id": "case001",
                "path": str(legacy_dir),
                "created_at": meta.get("created_at", ""),
                "examiner": meta.get("examiner", "Examiner"),
                "description": meta.get("description", ""),
                "case_name": meta.get("case_name", "case001"),
            })

        return jsonify({"status": "SUCCESS", "cases": cases_list}), 200
    except Exception as e:
        return jsonify({"status": "ERROR", "message": str(e)}), 500


@app.get("/api/faris/cases/<case_id>")
def get_case_details(case_id: str):
    """Retrieves full case details including analysis, recoveries, validation report, and reports."""
    try:
        case_dir = resolve_case_dir(case_id)
        if not case_dir.exists():
            return jsonify({"status": "ERROR", "message": f"Case '{case_id}' not found"}), 404

        details: Dict[str, Any] = {
            "case_id": case_id,
            "case_dir": str(case_dir),
            "metadata": {},
            "analysis": None,
            "discovered_artifacts": None,
            "artifact_states": None,
            "recovery_summary": None,
            "validation_report": None,
            "reports": {},
            "audit_trail_count": 0,
        }

        # Metadata
        meta_file = case_dir / "case_meta.json"
        if meta_file.exists():
            with open(meta_file, "r", encoding="utf-8") as f:
                details["metadata"] = json.load(f)

        # Image analysis
        analysis_file = case_dir / "analysis" / "image_analysis.json"
        if analysis_file.exists():
            with open(analysis_file, "r", encoding="utf-8") as f:
                details["analysis"] = json.load(f)

        # Discovered artifacts
        disc_file = case_dir / "analysis" / "discovered_artifacts.json"
        if disc_file.exists():
            with open(disc_file, "r", encoding="utf-8") as f:
                details["discovered_artifacts"] = json.load(f)

        # Artifact states
        states_file = case_dir / "analysis" / "artifact_states.json"
        if states_file.exists():
            with open(states_file, "r", encoding="utf-8") as f:
                details["artifact_states"] = json.load(f)

        # Recovery summary
        rec_file = case_dir / "recovery" / "adaptive_recovery_summary.json"
        if rec_file.exists():
            with open(rec_file, "r", encoding="utf-8") as f:
                details["recovery_summary"] = json.load(f)

        # Validation report
        val_file = case_dir / "validated" / "validation_report.json"
        if val_file.exists():
            with open(val_file, "r", encoding="utf-8") as f:
                details["validation_report"] = json.load(f)

        # Reports
        reports_dir = case_dir / "reports"
        if reports_dir.exists():
            for rf in reports_dir.iterdir():
                if rf.suffix.lower() == ".json":
                    details["reports"]["json"] = str(rf.name)
                elif rf.suffix.lower() == ".csv":
                    details["reports"]["csv"] = str(rf.name)
                elif rf.suffix.lower() == ".html":
                    details["reports"]["html"] = str(rf.name)

        # Audit trail count
        audit_file = case_dir / "audit" / "audit_trail.jsonl"
        if audit_file.exists():
            with open(audit_file, "r", encoding="utf-8") as f:
                details["audit_trail_count"] = sum(1 for _ in f)

        return jsonify({"status": "SUCCESS", "case": details}), 200
    except Exception as e:
        return jsonify({"status": "ERROR", "message": str(e)}), 500


@app.post("/api/faris/cases/create")
def create_case():
    """Creates a new case with standardized directory structure."""
    try:
        body = request.get_json(silent=True) or {}
        case_id = str(body.get("case_id") or "").strip()
        case_name = str(body.get("case_name") or "").strip() or f"Forensic Case {case_id}"
        operator = str(body.get("operator") or "Examiner").strip()

        if not case_id:
            return jsonify({"status": "ERROR", "message": "Missing 'case_id'"}), 400

        res = faris_api.create_case(case_id, case_name, operator)
        return jsonify(res), 200
    except Exception as e:
        return jsonify({"status": "ERROR", "message": str(e)}), 500


@app.post("/api/faris/evidence/register")
def register_evidence():
    """Registers an evidence image file into the case registry."""
    try:
        body = request.get_json(silent=True) or {}
        case_id = str(body.get("case_id") or "").strip()
        evidence_path = str(body.get("evidence_path") or "").strip()
        evidence_type = str(body.get("evidence_type") or "Disk Image").strip()

        if not case_id or not evidence_path:
            return jsonify({"status": "ERROR", "message": "Missing 'case_id' or 'evidence_path'"}), 400

        res = faris_api.register_evidence(case_id, evidence_path, evidence_type)
        return jsonify(res), 200
    except Exception as e:
        return jsonify({"status": "ERROR", "message": str(e)}), 500


# ---------------------------------------------------------------------------
# Background Pipeline Execution & Telemetry Endpoints
# ---------------------------------------------------------------------------

@app.post("/api/faris/pipeline/start")
def start_pipeline():
    """
    Launches the full Master Background Forensic Recovery Pipeline via FARISAPI.
    Runs asynchronously and non-blocking in a dedicated thread.
    """
    try:
        body = request.get_json(silent=True) or {}
        case_id = str(body.get("case_id") or "").strip()
        if not case_id:
            case_id = f"FARIS-{uuid.uuid4().hex[:8].upper()}"
            body["case_id"] = case_id

        job_id = f"JOB-{uuid.uuid4().hex[:8].upper()}"

        job_entry = {
            "job_id": job_id,
            "case_id": case_id,
            "status": "RUNNING",
            "progress_pct": 0.0,
            "current_stage": "setup",
            "stage_status": "RUNNING",
            "logs": [],
            "stages": {
                "setup": {"label": "Case Initialization", "status": "PENDING", "pct": 5.0},
                "acquisition": {"label": "Forensic Acquisition (EWF/EnCase 7)", "status": "PENDING", "pct": 15.0},
                "verification": {"label": "Cryptographic Verification (SHA-256)", "status": "PENDING", "pct": 25.0},
                "analysis": {"label": "Partition & Filesystem Analysis", "status": "PENDING", "pct": 40.0},
                "discovery": {"label": "Artifact Discovery (TSK fls)", "status": "PENDING", "pct": 55.0},
                "states": {"label": "Inode State Classification (TSK istat)", "status": "PENDING", "pct": 65.0},
                "recovery": {"label": "10-Branch Adaptive Recovery", "status": "PENDING", "pct": 75.0},
                "sanitization": {"label": "Specialized Sanitization Recovery (Stages A–J)", "status": "PENDING", "pct": 85.0},
                "validation": {"label": "Deep Format Validation", "status": "PENDING", "pct": 90.0},
                "hashing": {"label": "SHA-256 Manifest Hashing", "status": "PENDING", "pct": 94.0},
                "export": {"label": "Verified Artifacts Export", "status": "PENDING", "pct": 97.0},
                "reporting": {"label": "Multi-Format Reporting (JSON/CSV/HTML)", "status": "PENDING", "pct": 99.0},
            },
            "result": None,
            "error": None,
            "start_time": time.time(),
            "end_time": None,
        }

        with _jobs_lock:
            _jobs[job_id] = job_entry

        def _progress_cb(stage_id: str, status: str, pct: float, msg: str):
            with _jobs_lock:
                if job_id in _jobs:
                    j = _jobs[job_id]
                    j["progress_pct"] = float(pct)
                    j["current_stage"] = stage_id
                    j["stage_status"] = status
                    log_entry = {
                        "timestamp": time.strftime("%H:%M:%S", time.localtime()),
                        "stage": stage_id,
                        "status": status,
                        "pct": pct,
                        "message": msg
                    }
                    j["logs"].append(log_entry)
                    if stage_id in j["stages"]:
                        j["stages"][stage_id]["status"] = status
                        j["stages"][stage_id]["pct"] = pct
                    elif stage_id.startswith("sanitization"):
                        if "sanitization" in j["stages"]:
                            j["stages"]["sanitization"]["status"] = "RUNNING" if status == "RUNNING" else "COMPLETED"
                            j["stages"]["sanitization"]["pct"] = pct

        def _worker():
            try:
                result = faris_api.run_full_forensic_pipeline(body, progress_callback=_progress_cb)
                with _jobs_lock:
                    if job_id in _jobs:
                        j = _jobs[job_id]
                        j["status"] = result.get("status", "SUCCESS")
                        j["result"] = result
                        j["end_time"] = time.time()
                        if result.get("status") == "FAILED":
                            j["error"] = result.get("error", "Pipeline execution failed.")
            except Exception as e:
                with _jobs_lock:
                    if job_id in _jobs:
                        j = _jobs[job_id]
                        j["status"] = "FAILED"
                        j["error"] = str(e)
                        j["end_time"] = time.time()

        thread = threading.Thread(target=_worker, daemon=True)
        thread.start()

        return jsonify({
            "status": "SUCCESS",
            "job_id": job_id,
            "case_id": case_id,
            "message": "FARIS forensic pipeline started"
        }), 200

    except Exception as e:
        return jsonify({"status": "ERROR", "message": str(e)}), 500


@app.get("/api/faris/pipeline/status/<job_id>")
def get_pipeline_status(job_id: str):
    """Retrieves live telemetry and execution state for a running or completed pipeline job."""
    with _jobs_lock:
        job = _jobs.get(job_id)
        if not job:
            return jsonify({"status": "ERROR", "message": f"Job ID '{job_id}' not found"}), 404
        return jsonify(job), 200


# ---------------------------------------------------------------------------
# Granular Step Execution Endpoint
# ---------------------------------------------------------------------------

@app.post("/api/faris/pipeline/step")
def run_pipeline_step():
    """Runs an individual granular step of the FARIS recovery workflow."""
    try:
        body = request.get_json(silent=True) or {}
        step = str(body.get("step") or "").strip().lower()
        case_id = str(body.get("case_id") or "").strip()
        image_path = body.get("image_path")
        partition_offset = body.get("partition_offset")
        scan_limit_bytes = body.get("scan_limit_bytes")

        if not case_id:
            return jsonify({"status": "ERROR", "message": "Missing 'case_id'"}), 400

        res: Dict[str, Any] = {}

        if step == "verify":
            res = faris_api.verify_evidence(case_id, stage_label=body.get("stage_label", "PRE_ANALYSIS"))
        elif step == "analyze":
            res = faris_api.analyze_evidence(case_id, image_path=Path(image_path) if image_path else None)
        elif step == "discover":
            res = faris_api.discover_artifacts(case_id, image_path=Path(image_path) if image_path else None, partition_offset=partition_offset)
        elif step == "state_analysis":
            res = faris_api.analyze_artifact_state(case_id, image_path=Path(image_path) if image_path else None, partition_offset=partition_offset)
        elif step == "recover":
            res = faris_api.recover_artifacts(case_id, image_path=Path(image_path) if image_path else None, partition_offset=partition_offset, scan_limit_bytes=scan_limit_bytes)
        elif step == "validate":
            res = faris_api.validate_recovery(case_id)
        elif step == "hashes":
            res = faris_api.calculate_hashes(case_id)
        elif step == "report":
            res = faris_api.generate_report(case_id)
        else:
            return jsonify({"status": "ERROR", "message": f"Unknown step '{step}'"}), 400

        return jsonify(res), 200
    except Exception as e:
        return jsonify({"status": "ERROR", "message": str(e)}), 500


# ---------------------------------------------------------------------------
# Report & Export Endpoints
# ---------------------------------------------------------------------------

@app.get("/api/faris/report/<case_id>/<fmt>")
def get_report(case_id: str, fmt: str):
    """Serves the generated JSON, CSV, or HTML report file for a given case."""
    try:
        case_dir = resolve_case_dir(case_id)
        reports_dir = case_dir / "reports"
        if not reports_dir.exists():
            return jsonify({"status": "ERROR", "message": "No reports directory found"}), 404

        fmt_clean = fmt.lower().strip()
        matched = None
        for rf in reports_dir.iterdir():
            if rf.suffix.lower() == f".{fmt_clean}":
                matched = rf
                break

        if not matched or not matched.exists():
            return jsonify({"status": "ERROR", "message": f"Report in format '{fmt}' not found for case '{case_id}'"}), 404

        if fmt_clean == "json":
            with open(matched, "r", encoding="utf-8") as f:
                return jsonify(json.load(f)), 200
        elif fmt_clean in ["csv", "html"]:
            mimetype = "text/csv" if fmt_clean == "csv" else "text/html"
            return send_file(str(matched), mimetype=mimetype)
        else:
            return send_file(str(matched))
    except Exception as e:
        return jsonify({"status": "ERROR", "message": str(e)}), 500


@app.post("/api/faris/export")
def export_artifacts():
    """Safely exports verified recovered artifacts to a user-specified destination folder on separate media."""
    try:
        body = request.get_json(silent=True) or {}
        case_id = str(body.get("case_id") or "").strip()
        destination_dir = str(body.get("destination_dir") or "").strip()

        if not case_id or not destination_dir:
            return jsonify({"status": "ERROR", "message": "Missing 'case_id' or 'destination_dir'"}), 400

        res = faris_api.export_verified_artifacts(case_id, destination_dir)
        return jsonify(res), 200
    except Exception as e:
        return jsonify({"status": "ERROR", "message": str(e)}), 500


@app.get("/api/faris/audit/<case_id>")
def get_audit_trail(case_id: str):
    """Returns the immutable SHA-256 hash-chained audit trail for a case."""
    try:
        case_dir = resolve_case_dir(case_id)
        audit_file = case_dir / "audit" / "audit_trail.jsonl"
        if not audit_file.exists():
            return jsonify({"status": "SUCCESS", "case_id": case_id, "entries": []}), 200

        entries = []
        with open(audit_file, "r", encoding="utf-8") as f:
            for line in f:
                line_str = line.strip()
                if line_str:
                    try:
                        entries.append(json.loads(line_str))
                    except Exception:
                        pass

        return jsonify({"status": "SUCCESS", "case_id": case_id, "entries": entries}), 200
    except Exception as e:
        return jsonify({"status": "ERROR", "message": str(e)}), 500


# ---------------------------------------------------------------------------
# Folder-Level Forensic Recovery Endpoints
# ---------------------------------------------------------------------------

@app.post("/api/faris/folder/resolve-scope")
def resolve_folder_scope_endpoint():
    """
    Resolves storage allocation, directory cluster chain, child items, and logical LBAs for a folder.
    """
    try:
        body = request.get_json(silent=True) or {}
        folder_path = str(body.get("folder_path") or body.get("path") or "").strip()
        target_device = body.get("target_device") or body.get("target")

        if not folder_path:
            return jsonify({"status": "ERROR", "message": "Missing 'folder_path' parameter"}), 400

        scope_result = faris_api.resolve_folder_scope(folder_path, target_device=target_device)
        return jsonify(scope_result), 200
    except Exception as e:
        return jsonify({"status": "ERROR", "message": str(e)}), 500


@app.post("/api/faris/folder/recover")
def start_folder_recovery_endpoint():
    """
    Launches asynchronous background Folder Recovery Pipeline via FARISAPI.
    """
    try:
        body = request.get_json(silent=True) or {}
        case_id = str(body.get("case_id") or "").strip()
        if not case_id:
            case_id = f"FARIS-FLD-{uuid.uuid4().hex[:8].upper()}"
            body["case_id"] = case_id

        folder_path = str(body.get("folder_path") or body.get("target_path") or "").strip()
        if not folder_path:
            return jsonify({"status": "ERROR", "message": "Missing 'folder_path' parameter"}), 400

        job_id = f"JOB-FLD-{uuid.uuid4().hex[:8].upper()}"

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

        with _jobs_lock:
            _jobs[job_id] = job_entry

        def _folder_progress_cb(stage_id: str, status: str, pct: float, msg: str):
            with _jobs_lock:
                if job_id in _jobs:
                    j = _jobs[job_id]
                    j["progress_pct"] = float(pct)
                    j["current_stage"] = stage_id
                    j["stage_status"] = status
                    log_entry = {
                        "timestamp": time.strftime("%H:%M:%S", time.localtime()),
                        "stage": stage_id,
                        "status": status,
                        "pct": pct,
                        "message": msg
                    }
                    j["logs"].append(log_entry)
                    if stage_id in j["stages"]:
                        j["stages"][stage_id]["status"] = status
                        j["stages"][stage_id]["pct"] = pct

        def _folder_worker():
            try:
                result = faris_api.recover_folder(body, progress_callback=_folder_progress_cb)
                with _jobs_lock:
                    if job_id in _jobs:
                        j = _jobs[job_id]
                        j["status"] = result.get("status", "SUCCESS")
                        j["result"] = result
                        j["end_time"] = time.time()
                        if result.get("status") == "FAILED":
                            j["error"] = result.get("error", "Folder recovery pipeline failed.")
            except Exception as e:
                with _jobs_lock:
                    if job_id in _jobs:
                        j = _jobs[job_id]
                        j["status"] = "FAILED"
                        j["error"] = str(e)
                        j["end_time"] = time.time()

        thread = threading.Thread(target=_folder_worker, daemon=True)
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
def get_folder_job_status(job_id: str):
    """Retrieves live telemetry and execution state for a folder recovery job."""
    with _jobs_lock:
        job = _jobs.get(job_id)
        if not job:
            return jsonify({"status": "ERROR", "message": f"Job ID '{job_id}' not found"}), 404
        return jsonify(job), 200


# ---------------------------------------------------------------------------
# Runner Entry Point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    print("=" * 65)
    print("  FARIS Forensic Recovery Service — Port 8760")
    print("  Unified Public Integration REST Adapter")
    print("=" * 65)
    app.run(host="0.0.0.0", port=8760, debug=False, use_reloader=False)
