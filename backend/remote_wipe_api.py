from flask import Blueprint, jsonify, request
import time
import uuid
import threading

remote_wipe_bp = Blueprint('remote_wipe', __name__, url_prefix='/api/remote-wipe')

# Isolated Data Stores
registered_computers = {}
active_jobs = {}

@remote_wipe_bp.route('/computers', methods=['GET'])
def get_computers():
    return jsonify(list(registered_computers.values())), 200

@remote_wipe_bp.route('/register', methods=['POST'])
def register_computer():
    data = request.get_json() or {}
    comp_id = data.get('id', f"COMP-{uuid.uuid4().hex[:6].upper()}")
    registered_computers[comp_id] = {
        "id": comp_id,
        "name": data.get("name", "Unknown PC"),
        "os": data.get("os", "Unknown OS"),
        "status": "Online",
        "agent": data.get("agent_version", "1.0.0"),
        "devices": data.get("devices", []),
        "last_seen": time.time()
    }
    return jsonify({"status": "success", "id": comp_id}), 200

@remote_wipe_bp.route('/auth-request', methods=['POST'])
def request_auth():
    data = request.get_json() or {}
    job_id = data.get("job_id") or f"JOB-{uuid.uuid4().hex[:8].upper()}"
    active_jobs[job_id] = {
        "job_id": job_id,
        "target": data.get("target"),
        "computer_id": data.get("computer_id"),
        "status": "pending_auth",
        "progress": 0,
        "logs": []
    }
    return jsonify({"job_id": job_id, "status": "pending_auth"}), 200

@remote_wipe_bp.route('/job/<job_id>', methods=['GET'])
def get_job(job_id):
    if job_id not in active_jobs:
        return jsonify({"error": "Job not found"}), 404
    return jsonify(active_jobs[job_id]), 200

@remote_wipe_bp.route('/agent/poll', methods=['GET'])
def agent_poll():
    comp_id = request.args.get("computer_id")
    if comp_id in registered_computers:
        registered_computers[comp_id]["last_seen"] = time.time()
        
    # Find jobs for this computer
    for j_id, job in active_jobs.items():
        if job["computer_id"] == comp_id and job["status"] == "pending_auth":
            return jsonify({"action": "request_auth", "job_id": j_id, "target": job["target"]}), 200
        elif job["computer_id"] == comp_id and job["status"] == "start_wipe":
            # Change status to wiping so we don't start it multiple times
            job["status"] = "wiping"
            return jsonify({"action": "start_wipe", "job_id": j_id, "target": job["target"]}), 200
    return jsonify({"action": "none"}), 200

@remote_wipe_bp.route('/agent/auth-response', methods=['POST'])
def agent_auth_response():
    data = request.get_json() or {}
    job_id = data.get("job_id")
    action = data.get("action")
    if job_id in active_jobs:
        active_jobs[job_id]["status"] = "approved" if action == "approve" else "denied"
        return jsonify({"status": "updated"}), 200
    return jsonify({"error": "Job not found"}), 404

@remote_wipe_bp.route('/job/<job_id>/start', methods=['POST'])
def admin_start_job(job_id):
    if job_id in active_jobs and active_jobs[job_id]["status"] == "approved":
        active_jobs[job_id]["status"] = "start_wipe"
        return jsonify({"status": "started"}), 200
    return jsonify({"error": "Job not approved or not found"}), 400

@remote_wipe_bp.route('/agent/job-update', methods=['POST'])
def agent_job_update():
    data = request.get_json() or {}
    job_id = data.get("job_id")
    if job_id in active_jobs:
        active_jobs[job_id]["progress"] = data.get("progress", active_jobs[job_id]["progress"])
        if "log" in data:
            active_jobs[job_id]["logs"].append(data["log"])
        if data.get("complete"):
            active_jobs[job_id]["status"] = "complete"
        return jsonify({"status": "updated"}), 200
    return jsonify({"error": "Job not found"}), 404
