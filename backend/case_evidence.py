"""
Floating Evidence Workspace — per-case evidence ledger, chain-of-custody,
and case-level conclusions.

Design constraints (mirrors the existing platform conventions -- see
case_source.py and evidence_graph.py for the same principles applied
elsewhere in this codebase):
  - Reuses the existing platform database (auth.get_db() / platform.db) --
    no second database.
  - Reuses the existing tamper-evident audit chain
    (audit_engine.record_audit_event) -- no second audit system.
  - Reuses the existing case-source resolver (case_source.py) for Hunter
    access control -- no second authorization scheme.
  - Evidence artifact files are stored under the Seek Help case's own
    directory tree (CASES_STORAGE_DIR/<case_id>/evidence/E<n>/), which is
    already provisioned by seek_help_case_engine.py but was unused.
  - The original forensic image is NEVER copied or modified -- evidence
    that IS the case image is referenced by path, reusing its already-known
    acquisition hash rather than re-hashing a multi-gigabyte file.
"""

import os
import json
import time
import shutil
import sqlite3
from typing import Any, Dict, List, Optional, Tuple

from flask import Blueprint, jsonify, request

from auth import get_db
from audit_engine import record_audit_event
from case_source import get_authenticated_identity, resolve_hunter_case_source, authorize_forensic_target
from hashing_utils import compute_sha256_md5
from seek_help_case_engine import CASES_STORAGE_DIR

case_evidence_bp = Blueprint("case_evidence", __name__)

EVIDENCE_TYPES = [
    "Forensic Image", "Recovered File", "Recovered Folder", "Deleted File",
    "Memory Image", "Carved Artifact", "Filesystem Artifact",
    "Metadata Artifact", "Hash Result", "Timeline Artifact",
    "Tool Analysis Result", "Investigation Report",
]

VALID_STATUSES = [
    "COLLECTED", "RECOVERED", "VERIFIED", "ANALYZED", "CORRELATED",
    "SUBMITTED", "ACCEPTED", "REQUIRES_REVIEW",
]

# Allowed forward status transitions. A status may always stay unchanged.
STATUS_TRANSITIONS = {
    "COLLECTED": {"RECOVERED", "VERIFIED", "ANALYZED", "REQUIRES_REVIEW"},
    "RECOVERED": {"VERIFIED", "ANALYZED", "REQUIRES_REVIEW"},
    "VERIFIED": {"ANALYZED", "CORRELATED", "REQUIRES_REVIEW"},
    "ANALYZED": {"CORRELATED", "SUBMITTED", "REQUIRES_REVIEW"},
    "CORRELATED": {"SUBMITTED", "REQUIRES_REVIEW"},
    "SUBMITTED": {"ACCEPTED", "REQUIRES_REVIEW"},
    "REQUIRES_REVIEW": {"COLLECTED", "RECOVERED", "VERIFIED", "ANALYZED", "CORRELATED", "SUBMITTED"},
    "ACCEPTED": set(),
}

CONFIDENCE_LEVELS = ["HIGH", "MEDIUM", "LOW", "UNCONFIRMED"]

RELATIONSHIP_TYPES = [
    "RELATED_TO", "DERIVED_FROM", "RECOVERED_FROM", "GENERATED_BY",
    "CORROBORATES", "CONTRADICTS",
]

VERIFIED_LIKE_STATUSES = {"VERIFIED", "ANALYZED", "CORRELATED", "SUBMITTED", "ACCEPTED"}


def init_case_evidence_db() -> None:
    conn = get_db()
    try:
        with conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS case_evidence_items (
                    evidence_id TEXT PRIMARY KEY,
                    case_id TEXT NOT NULL,
                    evidence_number INTEGER NOT NULL,
                    name TEXT NOT NULL,
                    description TEXT DEFAULT '',
                    evidence_type TEXT NOT NULL,
                    source TEXT DEFAULT '',
                    source_path TEXT DEFAULT '',
                    source_image TEXT DEFAULT '',
                    device_id TEXT DEFAULT '',
                    file_path TEXT DEFAULT '',
                    file_size INTEGER,
                    sha256 TEXT,
                    md5 TEXT,
                    status TEXT NOT NULL DEFAULT 'COLLECTED',
                    confidence TEXT,
                    conclusion TEXT DEFAULT '',
                    notes TEXT DEFAULT '',
                    added_by TEXT NOT NULL,
                    created_at INTEGER NOT NULL,
                    updated_at INTEGER NOT NULL,
                    UNIQUE(case_id, evidence_number)
                )
            """)
            conn.execute("CREATE INDEX IF NOT EXISTS idx_case_evidence_case ON case_evidence_items(case_id)")

            conn.execute("""
                CREATE TABLE IF NOT EXISTS case_conclusions (
                    case_id TEXT PRIMARY KEY,
                    conclusion TEXT DEFAULT '',
                    confidence TEXT,
                    supporting_evidence_ids TEXT DEFAULT '[]',
                    investigator_notes TEXT DEFAULT '',
                    updated_by TEXT,
                    updated_at INTEGER
                )
            """)

            conn.execute("""
                CREATE TABLE IF NOT EXISTS case_evidence_relationships (
                    rel_id TEXT PRIMARY KEY,
                    case_id TEXT NOT NULL,
                    source_evidence_id TEXT NOT NULL,
                    target_evidence_id TEXT NOT NULL,
                    relationship_type TEXT NOT NULL,
                    notes TEXT DEFAULT '',
                    created_by TEXT NOT NULL,
                    created_at INTEGER NOT NULL
                )
            """)
            conn.execute("CREATE INDEX IF NOT EXISTS idx_case_evidence_rel_case ON case_evidence_relationships(case_id)")
    finally:
        conn.close()


def _get_case_row(case_id: str) -> Optional[Dict[str, Any]]:
    conn = get_db()
    try:
        row = conn.execute(
            "SELECT * FROM forensic_investigation_cases WHERE case_id = ?", (case_id,)
        ).fetchone()
        return dict(row) if row else None
    finally:
        conn.close()


def _authorize_case_access(case_id: str) -> Tuple[Optional[str], Optional[str], Optional[Tuple[Any, int]]]:
    """
    Returns (username, role, error_response_or_None). Evidence Workspace is
    available to Hunters (scoped strictly to their own active case) and
    Forensic Investigators (consistent with their existing broad review
    access elsewhere in this app) -- no other role.
    """
    username, role = get_authenticated_identity(request)
    if not username:
        return None, None, (jsonify({"status": "error", "message": "Authentication required."}), 401)
    if role == "hunter":
        case_source = resolve_hunter_case_source(username)
        if not case_source or case_source.get("case_id") != case_id:
            return None, None, (jsonify({
                "status": "error",
                "message": "Access Denied: As a Threat & Forensic Hunter, you are strictly scoped to your own active case.",
            }), 403)
        return username, role, None
    if role == "forensic":
        return username, role, None
    return None, None, (jsonify({
        "status": "error",
        "message": "Access Denied: The Evidence Workspace is available to Hunters and Forensic Investigators only.",
    }), 403)


def _evidence_row_to_dict(row: sqlite3.Row) -> Dict[str, Any]:
    d = dict(row)
    d["label"] = f"E{d['evidence_number']}"
    d["sha256"] = d.get("sha256") or "Not calculated"
    d["md5"] = d.get("md5") or "Not calculated"
    return d


@case_evidence_bp.get("/api/case-evidence/<case_id>")
def api_list_case_evidence(case_id: str):
    _username, _role, err = _authorize_case_access(case_id)
    if err:
        return err

    search = (request.args.get("search") or "").strip().lower()
    type_filter = request.args.get("type")
    status_filter = request.args.get("status")
    confidence_filter = request.args.get("confidence")
    sort = request.args.get("sort", "evidence_number")

    conn = get_db()
    try:
        rows = conn.execute(
            "SELECT * FROM case_evidence_items WHERE case_id = ?", (case_id,)
        ).fetchall()
    finally:
        conn.close()

    items = [_evidence_row_to_dict(r) for r in rows]

    if search:
        items = [i for i in items if search in i["name"].lower() or search in (i.get("description") or "").lower()]
    if type_filter:
        items = [i for i in items if i["evidence_type"] == type_filter]
    if status_filter:
        items = [i for i in items if i["status"] == status_filter]
    if confidence_filter:
        items = [i for i in items if (i.get("confidence") or "UNCONFIRMED") == confidence_filter]

    if sort == "timestamp":
        items.sort(key=lambda i: i["created_at"])
    else:
        items.sort(key=lambda i: i["evidence_number"])

    return jsonify({"status": "success", "case_id": case_id, "evidence": items, "total": len(items)}), 200


@case_evidence_bp.post("/api/case-evidence/<case_id>")
def api_add_case_evidence(case_id: str):
    username, role, err = _authorize_case_access(case_id)
    if err:
        return err

    case_row = _get_case_row(case_id)
    if not case_row:
        return jsonify({"status": "error", "message": f"Case '{case_id}' not found."}), 404

    body = request.get_json(silent=True) or {}
    name = (body.get("name") or "").strip()
    evidence_type = (body.get("evidence_type") or "").strip()
    description = (body.get("description") or "").strip()
    source_path_raw = (body.get("source_path") or "").strip()
    confidence = body.get("confidence")
    notes = (body.get("notes") or "").strip()

    if not name:
        return jsonify({"status": "error", "message": "Evidence 'name' is required."}), 400
    if evidence_type not in EVIDENCE_TYPES:
        return jsonify({"status": "error", "message": f"'evidence_type' must be one of: {', '.join(EVIDENCE_TYPES)}"}), 400

    # "Forensic Image" evidence with no explicit source defaults to the
    # case's own acquired image, so its already-known acquisition hash is
    # picked up automatically instead of requiring the caller to retype the path.
    if evidence_type == "Forensic Image" and not source_path_raw:
        source_path_raw = str(case_row.get("image_path") or "")
    if confidence is not None and confidence not in CONFIDENCE_LEVELS:
        return jsonify({"status": "error", "message": f"'confidence' must be one of: {', '.join(CONFIDENCE_LEVELS)}"}), 400

    # Resolve and authorize the evidence source. For a Hunter this can only
    # ever be their own case's image or a path inside their own case's
    # storage directory -- never an arbitrary local path.
    resolved_source = ""
    if source_path_raw:
        allowed, resolved_source, auth_err = authorize_forensic_target(request, source_path_raw)
        if not allowed:
            return jsonify({"status": "error", "message": auth_err}), 403

    file_path_final = ""
    sha256_val = None
    md5_val = None
    file_size_val = None
    source_image = case_row.get("image_filename") or ""

    conn = get_db()
    try:
        for _attempt in range(3):
            row = conn.execute(
                "SELECT COALESCE(MAX(evidence_number), 0) + 1 AS n FROM case_evidence_items WHERE case_id = ?",
                (case_id,),
            ).fetchone()
            evidence_number = row["n"]
            evidence_id = f"{case_id}-E{evidence_number}"

            # Resolve the physical artifact for this evidence item, if any.
            case_image_path = os.path.abspath(case_row.get("image_path") or "") if case_row.get("image_path") else ""
            if resolved_source and case_image_path and os.path.normcase(os.path.abspath(resolved_source)) == os.path.normcase(case_image_path):
                # This evidence item *is* the case's original forensic image --
                # never copy a multi-gigabyte image; reference it directly and
                # reuse its already-known acquisition hash instead of re-hashing.
                file_path_final = resolved_source
                sha256_val = case_row.get("sha256")
                md5_val = case_row.get("md5")
                file_size_val = case_row.get("image_size")
            elif resolved_source and os.path.isfile(resolved_source):
                dest_dir = os.path.join(CASES_STORAGE_DIR, case_id, "evidence", f"E{evidence_number}")
                os.makedirs(dest_dir, exist_ok=True)
                dest_path = os.path.join(dest_dir, os.path.basename(resolved_source))
                shutil.copy2(resolved_source, dest_path)
                hashes = compute_sha256_md5(dest_path)
                file_path_final = dest_path
                sha256_val = hashes["sha256"]
                md5_val = hashes["md5"]
                file_size_val = os.path.getsize(dest_path)

            now = int(time.time())
            try:
                with conn:
                    conn.execute("""
                        INSERT INTO case_evidence_items (
                            evidence_id, case_id, evidence_number, name, description, evidence_type,
                            source, source_path, source_image, device_id, file_path, file_size,
                            sha256, md5, status, confidence, conclusion, notes, added_by,
                            created_at, updated_at
                        ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                    """, (
                        evidence_id, case_id, evidence_number, name, description, evidence_type,
                        body.get("source", "").strip(), resolved_source, source_image,
                        case_row.get("device_id", ""), file_path_final, file_size_val,
                        sha256_val, md5_val, "COLLECTED", confidence, "", notes, username,
                        now, now,
                    ))
                break
            except sqlite3.IntegrityError:
                continue
        else:
            return jsonify({"status": "error", "message": "Could not allocate a unique evidence number. Please retry."}), 500

        row = conn.execute("SELECT * FROM case_evidence_items WHERE evidence_id = ?", (evidence_id,)).fetchone()
    finally:
        conn.close()

    record_audit_event(
        user_id=username, role=role, operation="EVIDENCE_ITEM_ADDED", status="SUCCESS",
        device_id=case_row.get("device_id", ""),
        details={"case_id": case_id, "evidence_id": evidence_id, "evidence_type": evidence_type, "sha256": sha256_val},
    )

    return jsonify({"status": "success", "evidence": _evidence_row_to_dict(row)}), 201


@case_evidence_bp.get("/api/case-evidence/<case_id>/<evidence_id>")
def api_get_case_evidence_item(case_id: str, evidence_id: str):
    _username, _role, err = _authorize_case_access(case_id)
    if err:
        return err
    conn = get_db()
    try:
        row = conn.execute(
            "SELECT * FROM case_evidence_items WHERE case_id = ? AND evidence_id = ?", (case_id, evidence_id)
        ).fetchone()
    finally:
        conn.close()
    if not row:
        return jsonify({"status": "error", "message": f"Evidence '{evidence_id}' not found in case '{case_id}'."}), 404
    return jsonify({"status": "success", "evidence": _evidence_row_to_dict(row)}), 200


@case_evidence_bp.patch("/api/case-evidence/<case_id>/<evidence_id>")
def api_update_case_evidence_item(case_id: str, evidence_id: str):
    username, role, err = _authorize_case_access(case_id)
    if err:
        return err

    conn = get_db()
    try:
        row = conn.execute(
            "SELECT * FROM case_evidence_items WHERE case_id = ? AND evidence_id = ?", (case_id, evidence_id)
        ).fetchone()
        if not row:
            return jsonify({"status": "error", "message": f"Evidence '{evidence_id}' not found in case '{case_id}'."}), 404
        current = dict(row)

        body = request.get_json(silent=True) or {}
        updates: Dict[str, Any] = {}
        audit_ops: List[str] = []

        if "description" in body:
            updates["description"] = str(body["description"]).strip()
        if "notes" in body:
            updates["notes"] = str(body["notes"]).strip()
        if "conclusion" in body:
            updates["conclusion"] = str(body["conclusion"]).strip()
            audit_ops.append("EVIDENCE_CONCLUSION_RECORDED")
        if "confidence" in body:
            conf = body["confidence"]
            if conf is not None and conf not in CONFIDENCE_LEVELS:
                return jsonify({"status": "error", "message": f"'confidence' must be one of: {', '.join(CONFIDENCE_LEVELS)}"}), 400
            updates["confidence"] = conf
        if "status" in body:
            new_status = str(body["status"]).strip().upper()
            if new_status not in VALID_STATUSES:
                return jsonify({"status": "error", "message": f"'status' must be one of: {', '.join(VALID_STATUSES)}"}), 400
            if new_status != current["status"] and new_status not in STATUS_TRANSITIONS.get(current["status"], set()):
                return jsonify({
                    "status": "error",
                    "message": f"Cannot transition evidence from '{current['status']}' to '{new_status}'.",
                }), 400
            updates["status"] = new_status
            audit_ops.append("EVIDENCE_STATUS_CHANGED")

        if not updates:
            return jsonify({"status": "error", "message": "No updatable fields provided."}), 400

        updates["updated_at"] = int(time.time())
        set_clause = ", ".join(f"{k} = ?" for k in updates)
        with conn:
            conn.execute(
                f"UPDATE case_evidence_items SET {set_clause} WHERE evidence_id = ?",
                (*updates.values(), evidence_id),
            )
        updated_row = conn.execute("SELECT * FROM case_evidence_items WHERE evidence_id = ?", (evidence_id,)).fetchone()
    finally:
        conn.close()

    for op in (audit_ops or ["EVIDENCE_ITEM_UPDATED"]):
        record_audit_event(
            user_id=username, role=role, operation=op, status="SUCCESS",
            device_id=current.get("device_id", ""),
            details={"case_id": case_id, "evidence_id": evidence_id, "fields": list(updates.keys())},
        )

    return jsonify({"status": "success", "evidence": _evidence_row_to_dict(updated_row)}), 200


@case_evidence_bp.get("/api/case-evidence/<case_id>/conclusion")
def api_get_case_conclusion(case_id: str):
    _username, _role, err = _authorize_case_access(case_id)
    if err:
        return err

    conn = get_db()
    try:
        items = conn.execute("SELECT status, confidence FROM case_evidence_items WHERE case_id = ?", (case_id,)).fetchall()
        concl_row = conn.execute("SELECT * FROM case_conclusions WHERE case_id = ?", (case_id,)).fetchone()
    finally:
        conn.close()

    stats = {
        "evidence_count": len(items),
        "verified_count": sum(1 for i in items if i["status"] in VERIFIED_LIKE_STATUSES),
        "high_confidence": sum(1 for i in items if i["confidence"] == "HIGH"),
        "medium_confidence": sum(1 for i in items if i["confidence"] == "MEDIUM"),
        "low_confidence": sum(1 for i in items if i["confidence"] == "LOW"),
        "unconfirmed_confidence": sum(1 for i in items if not i["confidence"] or i["confidence"] == "UNCONFIRMED"),
    }

    conclusion = dict(concl_row) if concl_row else {
        "case_id": case_id, "conclusion": "", "confidence": None,
        "supporting_evidence_ids": "[]", "investigator_notes": "", "updated_by": None, "updated_at": None,
    }
    try:
        conclusion["supporting_evidence_ids"] = json.loads(conclusion.get("supporting_evidence_ids") or "[]")
    except Exception:
        conclusion["supporting_evidence_ids"] = []

    return jsonify({"status": "success", "case_id": case_id, "stats": stats, "conclusion": conclusion}), 200


@case_evidence_bp.put("/api/case-evidence/<case_id>/conclusion")
def api_put_case_conclusion(case_id: str):
    username, role, err = _authorize_case_access(case_id)
    if err:
        return err

    body = request.get_json(silent=True) or {}
    conclusion_text = str(body.get("conclusion") or "").strip()
    confidence = body.get("confidence")
    investigator_notes = str(body.get("investigator_notes") or "").strip()
    supporting_ids = body.get("supporting_evidence_ids") or []

    if confidence is not None and confidence not in CONFIDENCE_LEVELS:
        return jsonify({"status": "error", "message": f"'confidence' must be one of: {', '.join(CONFIDENCE_LEVELS)}"}), 400
    if not isinstance(supporting_ids, list):
        return jsonify({"status": "error", "message": "'supporting_evidence_ids' must be a list."}), 400

    conn = get_db()
    try:
        valid_ids = {r["evidence_id"] for r in conn.execute(
            "SELECT evidence_id FROM case_evidence_items WHERE case_id = ?", (case_id,)
        ).fetchall()}
        unknown = [i for i in supporting_ids if i not in valid_ids]
        if unknown:
            return jsonify({"status": "error", "message": f"Unknown evidence IDs for this case: {unknown}"}), 400

        now = int(time.time())
        with conn:
            conn.execute("""
                INSERT INTO case_conclusions (case_id, conclusion, confidence, supporting_evidence_ids, investigator_notes, updated_by, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(case_id) DO UPDATE SET
                    conclusion = excluded.conclusion,
                    confidence = excluded.confidence,
                    supporting_evidence_ids = excluded.supporting_evidence_ids,
                    investigator_notes = excluded.investigator_notes,
                    updated_by = excluded.updated_by,
                    updated_at = excluded.updated_at
            """, (case_id, conclusion_text, confidence, json.dumps(supporting_ids), investigator_notes, username, now))
    finally:
        conn.close()

    record_audit_event(
        user_id=username, role=role, operation="CASE_CONCLUSION_RECORDED", status="SUCCESS",
        details={"case_id": case_id, "confidence": confidence, "supporting_evidence_ids": supporting_ids},
    )

    return jsonify({"status": "success", "message": "Case conclusion recorded."}), 200


@case_evidence_bp.get("/api/case-evidence/<case_id>/relationships")
def api_list_case_evidence_relationships(case_id: str):
    _username, _role, err = _authorize_case_access(case_id)
    if err:
        return err
    conn = get_db()
    try:
        rows = conn.execute(
            "SELECT * FROM case_evidence_relationships WHERE case_id = ?", (case_id,)
        ).fetchall()
    finally:
        conn.close()
    return jsonify({"status": "success", "relationships": [dict(r) for r in rows]}), 200


@case_evidence_bp.post("/api/case-evidence/<case_id>/<evidence_id>/relationships")
def api_add_case_evidence_relationship(case_id: str, evidence_id: str):
    username, role, err = _authorize_case_access(case_id)
    if err:
        return err

    body = request.get_json(silent=True) or {}
    target_evidence_id = (body.get("target_evidence_id") or "").strip()
    relationship_type = (body.get("relationship_type") or "").strip().upper()
    notes = (body.get("notes") or "").strip()

    if relationship_type not in RELATIONSHIP_TYPES:
        return jsonify({"status": "error", "message": f"'relationship_type' must be one of: {', '.join(RELATIONSHIP_TYPES)}"}), 400
    if not target_evidence_id:
        return jsonify({"status": "error", "message": "'target_evidence_id' is required."}), 400

    conn = get_db()
    try:
        valid_ids = {r["evidence_id"] for r in conn.execute(
            "SELECT evidence_id FROM case_evidence_items WHERE case_id = ?", (case_id,)
        ).fetchall()}
        if evidence_id not in valid_ids or target_evidence_id not in valid_ids:
            return jsonify({"status": "error", "message": "Both evidence items must belong to this case."}), 400

        rel_id = f"REL-{case_id}-{evidence_id}-{target_evidence_id}-{int(time.time())}"
        now = int(time.time())
        with conn:
            conn.execute("""
                INSERT INTO case_evidence_relationships
                (rel_id, case_id, source_evidence_id, target_evidence_id, relationship_type, notes, created_by, created_at)
                VALUES (?,?,?,?,?,?,?,?)
            """, (rel_id, case_id, evidence_id, target_evidence_id, relationship_type, notes, username, now))
    finally:
        conn.close()

    record_audit_event(
        user_id=username, role=role, operation="EVIDENCE_RELATIONSHIP_RECORDED", status="SUCCESS",
        details={"case_id": case_id, "source": evidence_id, "target": target_evidence_id, "relationship_type": relationship_type},
    )

    return jsonify({"status": "success", "rel_id": rel_id}), 201
