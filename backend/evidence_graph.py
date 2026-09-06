"""
Evidence Relationship Graph — Read/Derive Reconciliation Layer
Part of NTRO Adaptive Sanitization & Forensic Recovery Platform.

This module never creates a new source of truth. It opens the platform's
existing, already-populated stores (platform.db, faris.db, swarm_carving.db)
read-only and derives a bounded node/edge graph for a single case.

Every relationship type emitted here is backed by a real, joinable field in
one of those stores (device_id, sha256, job_id, case_id). Relationship types
with no backing data source anywhere in this codebase today (browser-history
downloads, USB file-copy events, email artifacts) are never fabricated —
they are reported back in `unavailable_relationship_types` with a specific
reason instead, so the frontend can render an honest, specific empty state.
"""

import os
import json
import sqlite3
from typing import Any, Dict, List, Optional, Tuple

from flask import Blueprint, jsonify, request

from auth import get_db as get_platform_db
from swarm_engine import get_swarm_db_path

try:
    from faris.db import get_db_connection as get_faris_db
except Exception:  # pragma: no cover - faris subpackage optional at import time
    get_faris_db = None

evidence_graph_bp = Blueprint("evidence_graph", __name__)

MAX_NODES = 250

# Relationship types this codebase cannot honestly derive today, and why.
_UNSUPPORTED_RELATIONSHIP_TYPES = [
    {
        "relationship_type": "FILE_DOWNLOADED_FROM_URL",
        "reason": "No browser-history artifact table exists in this codebase today.",
    },
    {
        "relationship_type": "FILE_COPIED_TO_USB",
        "reason": "No USB file-transfer/copy log table exists in this codebase today "
                  "(central_device_registry only records device connection, not file movement).",
    },
    {
        "relationship_type": "EMAIL_REFERENCE",
        "reason": "No email artifact parser/table exists in this codebase today.",
    },
]


def _get_swarm_db() -> sqlite3.Connection:
    conn = sqlite3.connect(get_swarm_db_path())
    conn.row_factory = sqlite3.Row
    return conn


def _row(r: Optional[sqlite3.Row]) -> Optional[Dict[str, Any]]:
    return dict(r) if r is not None else None


def _rows(rs: List[sqlite3.Row]) -> List[Dict[str, Any]]:
    return [dict(r) for r in rs]


def _parse_evidence_artifacts(raw: Optional[str]) -> List[Dict[str, Any]]:
    """Accepts both the legacy `lba` key and the Hunter dashboard's `offset_lba` key."""
    if not raw:
        return []
    try:
        parsed = json.loads(raw)
    except Exception:
        return []
    if not isinstance(parsed, list):
        return []
    out = []
    for item in parsed:
        if not isinstance(item, dict):
            continue
        offset = item.get("offset_lba", item.get("lba"))
        out.append({
            "name": item.get("name", "Unnamed artifact"),
            "offset": offset,
            "type": item.get("type"),
            "confidence": item.get("confidence"),
            "raw": item,
        })
    return out


def _node(node_id: str, node_type: str, label: str, confidence: str, **extra) -> Dict[str, Any]:
    n = {"id": node_id, "type": node_type, "label": label, "confidence": confidence}
    n.update(extra)
    return n


def _edge(edge_id: str, source: str, target: str, relationship_type: str,
          confidence_level: str, evidence_source: str, **extra) -> Dict[str, Any]:
    e = {
        "id": edge_id,
        "source": source,
        "target": target,
        "relationship_type": relationship_type,
        "confidence_level": confidence_level,
        "evidence_source": evidence_source,
    }
    e.update(extra)
    return e


def build_case_graph(case_id: str, depth: int = 1, node_types: Optional[List[str]] = None) -> Optional[Dict[str, Any]]:
    """
    Pure read/derive layer. Returns None if case_id doesn't exist in
    forensic_investigation_cases at all. Otherwise returns:
    {case_id, nodes[], edges[], unavailable_relationship_types[], node_count, truncated, depth_applied}
    """
    depth = max(1, min(2, int(depth or 1)))
    nodes: Dict[str, Dict[str, Any]] = {}
    edges: List[Dict[str, Any]] = []
    unavailable: List[Dict[str, Any]] = list(_UNSUPPORTED_RELATIONSHIP_TYPES)

    platform_conn = get_platform_db()
    try:
        case = _row(platform_conn.execute(
            "SELECT * FROM forensic_investigation_cases WHERE case_id = ?", (case_id,)
        ).fetchone())
        if case is None:
            return None

        case_node_id = f"case:{case_id}"
        nodes[case_node_id] = _node(
            case_node_id, "case", case_id, "DIRECT",
            source_ref={"table": "forensic_investigation_cases", "primary_key": case_id},
            case_status=case.get("case_status"),
            device_id=case.get("device_id"),
            sha256=case.get("sha256"),
        )

        # --- case -> device -------------------------------------------------
        device = _row(platform_conn.execute(
            "SELECT * FROM central_device_registry WHERE device_id = ?", (case.get("device_id"),)
        ).fetchone())
        if device:
            device_node_id = f"device:{device['device_id']}"
            nodes[device_node_id] = _node(
                device_node_id, "device", device["device_id"], "DIRECT",
                source_ref={"table": "central_device_registry", "primary_key": device["device_id"]},
                model=device.get("model"), manufacturer=device.get("manufacturer"),
            )
            edges.append(_edge(
                f"edge:{case_node_id}->{device_node_id}", case_node_id, device_node_id,
                "HAS_DEVICE", "DIRECT",
                "forensic_investigation_cases.device_id = central_device_registry.device_id",
                supporting_evidence={"case_device_id": case.get("device_id"), "matched_device_id": device["device_id"]},
            ))
        else:
            unavailable.append({
                "relationship_type": "HAS_DEVICE",
                "reason": f"No central_device_registry row matches device_id '{case.get('device_id')}'.",
            })

        # --- case -> evidence artifacts -------------------------------------
        artifacts = _parse_evidence_artifacts(case.get("evidence_artifacts"))
        if artifacts:
            for idx, art in enumerate(artifacts):
                art_node_id = f"artifact:{case_id}:{idx}"
                nodes[art_node_id] = _node(
                    art_node_id, "artifact", art["name"], "DIRECT",
                    source_ref={"table": "forensic_investigation_cases.evidence_artifacts", "index": idx, "case_id": case_id},
                    offset=art["offset"], artifact_type=art.get("type"), confidence=art.get("confidence"),
                )
                edges.append(_edge(
                    f"edge:{case_node_id}->{art_node_id}", case_node_id, art_node_id,
                    "HAS_EVIDENCE_ARTIFACT", "DIRECT",
                    "forensic_investigation_cases.evidence_artifacts[]",
                    supporting_evidence=art["raw"],
                ))
        else:
            unavailable.append({
                "relationship_type": "HAS_EVIDENCE_ARTIFACT",
                "reason": "evidence_artifacts is empty for this case (no Hunter has submitted artifacts yet).",
            })

        # --- case -> ISO image (by sha256, then loose case_ref_id match) ----
        iso_rows = []
        if case.get("sha256"):
            iso_rows = _rows(platform_conn.execute(
                "SELECT * FROM forensic_iso_images WHERE sha256_hash = ?", (case["sha256"],)
            ).fetchall())
        iso_confidence = "DIRECT"
        if not iso_rows:
            like_case = f"%{case_id}%"
            like_device = f"%{case.get('device_id') or ''}%"
            iso_rows = _rows(platform_conn.execute(
                "SELECT * FROM forensic_iso_images WHERE case_ref_id LIKE ? OR case_ref_id LIKE ?",
                (like_case, like_device),
            ).fetchall())
            iso_confidence = "POTENTIAL"
        if iso_rows:
            for iso in iso_rows:
                iso_node_id = f"iso:{iso['id']}"
                nodes[iso_node_id] = _node(
                    iso_node_id, "iso_image", iso.get("image_name", iso["id"]), iso_confidence,
                    source_ref={"table": "forensic_iso_images", "primary_key": iso["id"]},
                    sha256=iso.get("sha256_hash"), case_ref_id=iso.get("case_ref_id"),
                )
                edges.append(_edge(
                    f"edge:{case_node_id}->{iso_node_id}", case_node_id, iso_node_id,
                    "HAS_ISO_IMAGE", iso_confidence,
                    "forensic_iso_images.sha256_hash" if iso_confidence == "DIRECT" else "forensic_iso_images.case_ref_id (text match)",
                    supporting_evidence={"case_sha256": case.get("sha256"), "iso_sha256": iso.get("sha256_hash"), "case_ref_id": iso.get("case_ref_id")},
                ))
        else:
            unavailable.append({
                "relationship_type": "HAS_ISO_IMAGE",
                "reason": "No forensic_iso_images row matches this case by SHA-256 or by case reference text.",
            })

        # --- evidence dedup: same sha256 in FARIS / Swarm evidence stores ---
        matched_faris_evidence = None
        if case.get("sha256"):
            if get_faris_db is not None:
                faris_conn = get_faris_db()
                try:
                    matched_faris_evidence = _row(faris_conn.execute(
                        "SELECT * FROM faris_evidence WHERE sha256_hash = ?", (case["sha256"],)
                    ).fetchone())
                    if matched_faris_evidence:
                        fe_node_id = f"evidence:faris:{matched_faris_evidence['evidence_id']}"
                        nodes[fe_node_id] = _node(
                            fe_node_id, "evidence", matched_faris_evidence.get("original_filename", matched_faris_evidence["evidence_id"]), "DIRECT",
                            source_ref={"table": "faris_evidence", "primary_key": matched_faris_evidence["evidence_id"]},
                            sha256=matched_faris_evidence.get("sha256_hash"),
                        )
                        edges.append(_edge(
                            f"edge:{case_node_id}->{fe_node_id}", case_node_id, fe_node_id,
                            "SAME_CONTENT_AS", "DIRECT", "sha256 equality (forensic_investigation_cases.sha256 = faris_evidence.sha256_hash)",
                            supporting_evidence={"sha256": case["sha256"]},
                        ))
                finally:
                    faris_conn.close()

            swarm_conn = _get_swarm_db()
            try:
                matched_swarm_evidence = _row(swarm_conn.execute(
                    "SELECT * FROM swarm_evidence WHERE sha256_hash = ? OR case_id = ?",
                    (case["sha256"], case_id),
                ).fetchone())
                if matched_swarm_evidence:
                    se_node_id = f"evidence:swarm:{matched_swarm_evidence['evidence_id']}"
                    same_hash = matched_swarm_evidence.get("sha256_hash") == case.get("sha256")
                    nodes[se_node_id] = _node(
                        se_node_id, "evidence", matched_swarm_evidence["evidence_id"], "DIRECT" if same_hash else "CORRELATED",
                        source_ref={"table": "swarm_evidence", "primary_key": matched_swarm_evidence["evidence_id"]},
                        sha256=matched_swarm_evidence.get("sha256_hash"),
                    )
                    edges.append(_edge(
                        f"edge:{case_node_id}->{se_node_id}", case_node_id, se_node_id,
                        "SAME_CONTENT_AS" if same_hash else "REFERENCED_BY_CASE_ID",
                        "DIRECT" if same_hash else "CORRELATED",
                        "sha256 equality (swarm_evidence.sha256_hash)" if same_hash else "swarm_evidence.case_id string match",
                        supporting_evidence={"sha256": case.get("sha256"), "case_id": case_id},
                    ))

                    # --- swarm candidates + consensus + investigator review ---
                    candidates = _rows(swarm_conn.execute(
                        "SELECT * FROM swarm_candidates WHERE case_id = ? OR evidence_id = ?",
                        (case_id, matched_swarm_evidence["evidence_id"]),
                    ).fetchall())
                    if candidates:
                        for cand in candidates:
                            cand_node_id = f"candidate:{cand['candidate_id']}"
                            nodes[cand_node_id] = _node(
                                cand_node_id, "forensic_artifact", f"{cand.get('format_type', 'candidate')} @ offset {cand.get('byte_offset')}", "DIRECT",
                                source_ref={"table": "swarm_candidates", "primary_key": cand["candidate_id"]},
                                byte_offset=cand.get("byte_offset"), lba_start=cand.get("lba_start"),
                                automated_confidence=cand.get("automated_confidence"),
                            )
                            edges.append(_edge(
                                f"edge:{se_node_id}->{cand_node_id}", se_node_id, cand_node_id,
                                "CANDIDATE_DERIVED_FROM_EVIDENCE", "DIRECT", "swarm_candidates.evidence_id",
                                supporting_evidence={"evidence_id": matched_swarm_evidence["evidence_id"], "candidate_id": cand["candidate_id"]},
                            ))

                            if depth >= 2:
                                consensus = _row(swarm_conn.execute(
                                    "SELECT * FROM swarm_consensus WHERE candidate_id = ?", (cand["candidate_id"],)
                                ).fetchone())
                                reviews = _rows(swarm_conn.execute(
                                    "SELECT * FROM swarm_investigator_reviews WHERE candidate_id = ?", (cand["candidate_id"],)
                                ).fetchall())
                                if consensus:
                                    consensus_node_id = f"verdict:{cand['candidate_id']}"
                                    verdict_confidence = "DIRECT" if reviews else "CORRELATED"
                                    nodes[consensus_node_id] = _node(
                                        consensus_node_id, "review_verdict", consensus.get("dominant_decision", "UNKNOWN"), verdict_confidence,
                                        source_ref={"table": "swarm_consensus", "primary_key": cand["candidate_id"]},
                                        swarm_confidence=consensus.get("swarm_confidence"), total_reviews=consensus.get("total_reviews"),
                                    )
                                    edges.append(_edge(
                                        f"edge:{cand_node_id}->{consensus_node_id}", cand_node_id, consensus_node_id,
                                        "REVIEWED_AS", verdict_confidence,
                                        "swarm_investigator_reviews" if reviews else "swarm_consensus (no investigator review yet)",
                                        supporting_evidence={"consensus": consensus, "investigator_reviews": reviews},
                                    ))
                    else:
                        unavailable.append({
                            "relationship_type": "CANDIDATE_DERIVED_FROM_EVIDENCE",
                            "reason": "No swarm-carved candidates recorded for this evidence in swarm_candidates.",
                        })
                else:
                    unavailable.append({
                        "relationship_type": "SAME_CONTENT_AS (swarm)",
                        "reason": "No swarm_evidence row matches this case by SHA-256 or case_id.",
                    })
            finally:
                swarm_conn.close()

            if not matched_faris_evidence:
                unavailable.append({
                    "relationship_type": "SAME_CONTENT_AS (faris)",
                    "reason": "No faris_evidence row matches this case's SHA-256.",
                })

        # --- FARIS fragment relationships + timeline events (depth 2) -------
        if matched_faris_evidence and get_faris_db is not None and depth >= 2:
            faris_conn = get_faris_db()
            try:
                jobs = _rows(faris_conn.execute(
                    "SELECT * FROM faris_scan_jobs WHERE evidence_id = ?", (matched_faris_evidence["evidence_id"],)
                ).fetchall())
                if jobs:
                    for job in jobs:
                        frags = _rows(faris_conn.execute(
                            "SELECT * FROM faris_fragment_relationships WHERE job_id = ?", (job["job_id"],)
                        ).fetchall())
                        for frag in frags:
                            a_id = f"fragment:{job['job_id']}:{frag['frag_a_offset']}"
                            b_id = f"fragment:{job['job_id']}:{frag['frag_b_offset']}"
                            nodes.setdefault(a_id, _node(
                                a_id, "fragment", f"Fragment @ {frag['frag_a_offset']}", "DIRECT",
                                source_ref={"table": "faris_fragment_relationships", "field": "frag_a_offset", "job_id": job["job_id"]},
                                byte_offset=frag["frag_a_offset"],
                            ))
                            nodes.setdefault(b_id, _node(
                                b_id, "fragment", f"Fragment @ {frag['frag_b_offset']}", "DIRECT",
                                source_ref={"table": "faris_fragment_relationships", "field": "frag_b_offset", "job_id": job["job_id"]},
                                byte_offset=frag["frag_b_offset"],
                            ))
                            try:
                                reasons = json.loads(frag.get("reasons_json") or "[]")
                            except Exception:
                                reasons = []
                            edges.append(_edge(
                                f"edge:{frag['rel_id']}", a_id, b_id,
                                "CORRELATES_WITH", "DIRECT", "faris_fragment_relationships.reasons_json",
                                supporting_evidence={"correlation_score": frag.get("correlation_score"), "reasons": reasons, "rel_id": frag["rel_id"]},
                            ))

                        events = _rows(faris_conn.execute(
                            "SELECT * FROM faris_timeline_events WHERE job_id = ?", (job["job_id"],)
                        ).fetchall())
                        for ev in events:
                            ev_node_id = f"timeline:{ev['event_id']}"
                            ev_confidence = "CORRELATED" if ev.get("is_inferred") else "DIRECT"
                            try:
                                prov = json.loads(ev.get("provenance_json") or "{}")
                            except Exception:
                                prov = {}
                            nodes[ev_node_id] = _node(
                                ev_node_id, "timeline_event", ev.get("summary") or ev["event_id"], ev_confidence,
                                source_ref={"table": "faris_timeline_events", "primary_key": ev["event_id"]},
                                timestamp=ev.get("timestamp_str"), event_type=ev.get("event_type"),
                            )
                            evidence_node_id = f"evidence:faris:{matched_faris_evidence['evidence_id']}"
                            edges.append(_edge(
                                f"edge:{evidence_node_id}->{ev_node_id}", evidence_node_id, ev_node_id,
                                "OCCURRED_AT", ev_confidence, "faris_timeline_events.provenance_json",
                                supporting_evidence=prov,
                            ))
                    if not any(_rows(faris_conn.execute(
                        "SELECT 1 FROM faris_fragment_relationships WHERE job_id = ?", (j["job_id"],)
                    ).fetchall()) for j in jobs):
                        unavailable.append({
                            "relationship_type": "CORRELATES_WITH",
                            "reason": "Matching FARIS evidence has scan jobs but no recorded fragment relationships.",
                        })
                else:
                    unavailable.append({
                        "relationship_type": "CORRELATES_WITH / OCCURRED_AT",
                        "reason": "Matching FARIS evidence has no scan jobs, so no fragment relationships or timeline events exist yet.",
                    })
            finally:
                faris_conn.close()
        elif not matched_faris_evidence:
            unavailable.append({
                "relationship_type": "CORRELATES_WITH / OCCURRED_AT",
                "reason": "No matching FARIS evidence (by SHA-256) found; fragment relationships and timeline events "
                          "require a FARIS scan job for this evidence.",
            })

        # --- Evidence Workspace items + analyst-asserted relationships ------
        # Same platform.db connection -- case_evidence_items/relationships
        # (backend/case_evidence.py) live in the same database as everything
        # else queried above, not a separate store.
        evidence_items = _rows(platform_conn.execute(
            "SELECT * FROM case_evidence_items WHERE case_id = ?", (case_id,)
        ).fetchall())
        if evidence_items:
            for item in evidence_items:
                ev_item_node_id = f"case_evidence:{item['evidence_id']}"
                nodes[ev_item_node_id] = _node(
                    ev_item_node_id, "case_evidence_item", f"E{item['evidence_number']} {item['name']}", "DIRECT",
                    source_ref={"table": "case_evidence_items", "primary_key": item["evidence_id"]},
                    evidence_type=item.get("evidence_type"), status=item.get("status"),
                    evidence_confidence=item.get("confidence"), sha256=item.get("sha256"),
                )
                edges.append(_edge(
                    f"edge:{case_node_id}->{ev_item_node_id}", case_node_id, ev_item_node_id,
                    "HAS_EVIDENCE_ITEM", "DIRECT", "case_evidence_items.case_id",
                    supporting_evidence={"evidence_id": item["evidence_id"], "added_by": item.get("added_by")},
                ))

            relationships = _rows(platform_conn.execute(
                "SELECT * FROM case_evidence_relationships WHERE case_id = ?", (case_id,)
            ).fetchall())
            for rel in relationships:
                src_id = f"case_evidence:{rel['source_evidence_id']}"
                tgt_id = f"case_evidence:{rel['target_evidence_id']}"
                if src_id in nodes and tgt_id in nodes:
                    # Analyst-asserted, not statistically derived -- always DIRECT
                    # since a human investigator recorded it, never auto-inferred.
                    edges.append(_edge(
                        f"edge:{rel['rel_id']}", src_id, tgt_id,
                        rel["relationship_type"], "DIRECT",
                        "case_evidence_relationships (analyst-asserted)",
                        supporting_evidence={"notes": rel.get("notes"), "created_by": rel.get("created_by"), "rel_id": rel["rel_id"]},
                    ))
        else:
            unavailable.append({
                "relationship_type": "HAS_EVIDENCE_ITEM",
                "reason": "No evidence items have been added to this case's Evidence Workspace yet.",
            })

    finally:
        platform_conn.close()

    all_nodes = list(nodes.values())
    if node_types:
        wanted = set(node_types)
        keep_ids = {case_node_id} | {n["id"] for n in all_nodes if n["type"] in wanted}
        all_nodes = [n for n in all_nodes if n["id"] in keep_ids]
        edges = [e for e in edges if e["source"] in keep_ids and e["target"] in keep_ids]

    truncated = len(all_nodes) > MAX_NODES
    node_count = len(all_nodes)
    if truncated:
        keep_ids = {n["id"] for n in all_nodes[:MAX_NODES]}
        all_nodes = all_nodes[:MAX_NODES]
        edges = [e for e in edges if e["source"] in keep_ids and e["target"] in keep_ids]

    return {
        "case_id": case_id,
        "nodes": all_nodes,
        "edges": edges,
        "unavailable_relationship_types": unavailable,
        "node_count": node_count,
        "truncated": truncated,
        "depth_applied": depth,
    }


# ---------------------------------------------------------------------------
# REST API
# ---------------------------------------------------------------------------

@evidence_graph_bp.get("/api/evidence-graph/<case_id>")
def api_get_case_graph(case_id):
    depth = request.args.get("depth", default=1, type=int)
    types_param = request.args.get("types")
    node_types = [t.strip() for t in types_param.split(",") if t.strip()] if types_param else None

    graph = build_case_graph(case_id, depth=depth, node_types=node_types)
    if graph is None:
        return jsonify({"status": "error", "message": f"Case '{case_id}' was not found."}), 404
    return jsonify({"status": "success", **graph}), 200


@evidence_graph_bp.get("/api/evidence-graph/<case_id>/node/<path:node_id>")
def api_get_node_detail(case_id, node_id):
    graph = build_case_graph(case_id, depth=2)
    if graph is None:
        return jsonify({"status": "error", "message": f"Case '{case_id}' was not found."}), 404
    node = next((n for n in graph["nodes"] if n["id"] == node_id), None)
    if node is None:
        return jsonify({"status": "error", "message": f"Node '{node_id}' was not found in case '{case_id}'."}), 404
    connected_edges = [e for e in graph["edges"] if e["source"] == node_id or e["target"] == node_id]
    return jsonify({"status": "success", "node": node, "connected_edges": connected_edges}), 200


@evidence_graph_bp.get("/api/evidence-graph/<case_id>/edge/<path:edge_id>/why")
def api_get_edge_why(case_id, edge_id):
    graph = build_case_graph(case_id, depth=2)
    if graph is None:
        return jsonify({"status": "error", "message": f"Case '{case_id}' was not found."}), 404
    edge = next((e for e in graph["edges"] if e["id"] == edge_id), None)
    if edge is None:
        return jsonify({"status": "error", "message": f"Edge '{edge_id}' was not found in case '{case_id}'."}), 404
    return jsonify({"status": "success", "edge": edge}), 200


@evidence_graph_bp.get("/api/evidence-graph/<case_id>/search")
def api_search_case_graph(case_id):
    query = (request.args.get("q") or "").strip().lower()
    graph = build_case_graph(case_id, depth=2)
    if graph is None:
        return jsonify({"status": "error", "message": f"Case '{case_id}' was not found."}), 404
    if not query:
        return jsonify({"status": "success", "results": []}), 200
    results = [
        n for n in graph["nodes"]
        if query in str(n.get("label", "")).lower() or query in str(n.get("id", "")).lower()
    ]
    return jsonify({"status": "success", "results": results}), 200
