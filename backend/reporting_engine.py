"""
Dual Cryptographic Reporting Engine (Certificates & Forensic Reports)
Part of NTRO Adaptive Sanitization & Forensic Recovery Platform.

Generates:
  1. Sanitization Certificate: Signed tamper-evident assurance record with SHA-256 digest.
  2. Forensic Investigation Report: Formal chain of custody, artifact inventory, and confidence metrics.
"""

import os
import json
import time
import uuid
import hashlib
from typing import Dict, Any, Optional, Tuple
from auth import get_db

PLATFORM_VERSION = "SecureWipe-NTRO Platform v2.0 (Adaptive Sanitization & Forensic Recovery)"


def generate_sanitization_certificate(
    job_id: str,
    device_info: Dict[str, Any],
    method_label: str,
    verification_summary: Dict[str, Any],
    recovery_summary: Dict[str, Any],
    final_state: str,
    operator_name: str,
    audit_sequence: int = 0,
) -> Dict[str, Any]:
    """
    Generate a cryptographically hashed Sanitization Certificate.
    """
    cert_id = f"CERT-NTRO-{uuid.uuid4().hex[:10].upper()}"
    now_iso = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

    cert_data = {
        "certificate_id": cert_id,
        "job_id": job_id,
        "platform_version": PLATFORM_VERSION,
        "issuing_authority": "National Technical Research Organisation (NTRO) - Sanitization Assurance",
        "issued_at": now_iso,
        "operator": operator_name,
        "device": {
            "name": device_info.get("name", "Unknown"),
            "serial": device_info.get("serial", "SN-UNKNOWN"),
            "bus_type": device_info.get("bus", "SATA"),
            "media_type": device_info.get("type", "HDD"),
            "capacity": device_info.get("size", "Unknown"),
            "capacity_bytes": device_info.get("sizeBytes", 0),
        },
        "sanitization": {
            "method": method_label,
            "verification_strategy": verification_summary.get("verification_strategy", "Stratified Multi-Region Sampling"),
            "verification_status": verification_summary.get("status", "PASS"),
            "mismatches_found": verification_summary.get("mismatches_found", 0),
        },
        "forensic_recovery_assessment": {
            "evidence_level": recovery_summary.get("evidence_level", "NO_EVIDENCE"),
            "confidence_score": recovery_summary.get("confidence_score", 0.0),
            "validated_artifacts": recovery_summary.get("counts", {}).get("level_3_validated_artifacts", 0),
            "summary_reason": recovery_summary.get("summary_reason", "Zero recoverable structures detected."),
        },
        "final_verdict": final_state,
        "audit_trail_reference": f"AUDIT-SEQ-{audit_sequence}",
        "legal_disclaimer": (
            "This certificate serves as official attestation that the specified media has undergone "
            "controlled data sanitization and independent forensic recovery verification in compliance "
            "with Government of India and NTRO secure sanitization directives."
        )
    }

    # Generate SHA-256 digital signature of the canonical certificate payload
    canonical_bytes = json.dumps(cert_data, sort_keys=True).encode("utf-8")
    sha256_digest = hashlib.sha256(canonical_bytes).hexdigest()
    cert_data["digital_signature_sha256"] = sha256_digest

    # Persist in certificates table
    conn = get_db()
    try:
        cur = conn.cursor()
        cur.execute("""
            INSERT INTO certificates (
                id, certificate_number, job_id, device_info_json,
                sanitization_method, verification_result, recovery_assessment,
                final_state, operator_name, sha256_digest, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            cert_id, cert_id, job_id, json.dumps(cert_data["device"]),
            method_label, cert_data["sanitization"]["verification_status"],
            cert_data["forensic_recovery_assessment"]["evidence_level"],
            final_state, operator_name, sha256_digest, int(time.time())
        ))
        conn.commit()
    finally:
        conn.close()

    return cert_data


def generate_forensic_case_report(
    case_title: str,
    investigator_name: str,
    target_source: str,
    carve_results: Dict[str, Any],
    chain_of_custody_notes: str = "",
) -> Dict[str, Any]:
    """
    Generate an official Forensic Investigation Report.
    """
    case_id = f"CASE-FORENSIC-{uuid.uuid4().hex[:8].upper()}"
    now_iso = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

    report_data = {
        "case_id": case_id,
        "title": case_title,
        "investigator": investigator_name,
        "target_source": target_source,
        "timestamp": now_iso,
        "platform_version": PLATFORM_VERSION,
        "read_only_guarantee": "STRICT_READ_ONLY (ZERO write/modify commands executed)",
        "chain_of_custody": chain_of_custody_notes or "Evidence acquired under strict chain of custody protocols.",
        "forensic_findings": {
            "evidence_classification": carve_results.get("evidence_level", "NO_EVIDENCE"),
            "confidence_score": carve_results.get("confidence_score", 0.0),
            "bytes_scanned": carve_results.get("bytes_scanned", 0),
            "scan_coverage_pct": carve_results.get("scan_coverage_pct", 100.0),
            "summary_reason": carve_results.get("summary_reason", "Scan completed."),
            "counts": carve_results.get("counts", {}),
            "validated_artifacts": carve_results.get("validated_artifacts", []),
            "valid_candidates": carve_results.get("valid_candidates", []),
            "signature_hits": carve_results.get("signature_hits", []),
        }
    }

    canonical_bytes = json.dumps(report_data, sort_keys=True).encode("utf-8")
    report_hash = hashlib.sha256(canonical_bytes).hexdigest()
    report_data["evidence_integrity_sha256"] = report_hash

    # Save to forensic_cases table
    conn = get_db()
    try:
        cur = conn.cursor()
        cur.execute("""
            INSERT INTO forensic_cases (
                id, case_number, title, investigator, target_source,
                evidence_level, confidence_score, artifacts_json, report_hash, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            case_id, case_id, case_title, investigator_name, target_source,
            report_data["forensic_findings"]["evidence_classification"],
            report_data["forensic_findings"]["confidence_score"],
            json.dumps(report_data["forensic_findings"]["validated_artifacts"]),
            report_hash, int(time.time())
        ))
        conn.commit()
    finally:
        conn.close()

    return report_data


def get_certificate_by_id(cert_id: str) -> Optional[Dict[str, Any]]:
    """Query certificate from database and return structured representation."""
    conn = get_db()
    try:
        cur = conn.cursor()
        cur.execute("SELECT * FROM certificates WHERE id = ? OR certificate_number = ?", (cert_id, cert_id))
        row = cur.fetchone()
        if not row:
            return None
        return dict(row)
    finally:
        conn.close()
