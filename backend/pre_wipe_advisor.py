"""
Pre-Wipe Forensic Risk Assessment Module
Part of NTRO Adaptive Sanitization & Forensic Recovery Platform.

Performs non-destructive, read-only forensic triage on the sanitization target
prior to executing permanent wipe operations.
Helps operators avoid the catastrophic accidental destruction of evidentiary material.
"""

import os
from typing import Dict, Any
from forensic_carver import (
    scan_file_stream,
    scan_folder_stream,
    scan_disk_stream,
    EVIDENCE_NO_EVIDENCE,
    EVIDENCE_LOW_CONFIDENCE,
    EVIDENCE_PROBABLE,
    EVIDENCE_VALIDATED,
)


def conduct_pre_wipe_assessment(target: str, target_type: str = "file") -> Dict[str, Any]:
    """
    Execute non-destructive triage scan before destructive wipe operations.
    Evaluates whether candidate forensic structures or intact documents exist.
    """
    if not os.path.exists(target):
        return {
            "risk_level": "UNKNOWN",
            "evidence_detected": False,
            "can_proceed_safely": True,
            "message": f"Target {target} does not currently exist on filesystem.",
            "details": {}
        }

    # Execute read-only forensic carver stream
    if target_type == "file":
        carve_result = scan_file_stream(target)
    elif target_type == "folder":
        carve_result = scan_folder_stream(target)
    else:
        # Disk or partition
        carve_result = scan_disk_stream(target, total_bytes=min(50 * 1024 * 1024, os.path.getsize(target) if os.path.isfile(target) else 50 * 1024 * 1024))

    evidence_level = carve_result.get("evidence_level", EVIDENCE_NO_EVIDENCE)
    confidence = carve_result.get("confidence_score", 0.0)
    validated_count = len(carve_result.get("validated_artifacts", []))
    candidates_count = len(carve_result.get("valid_candidates", []))

    if evidence_level in (EVIDENCE_PROBABLE, EVIDENCE_VALIDATED):
        return {
            "risk_level": "CRITICAL_EVIDENCE_FOUND",
            "evidence_detected": True,
            "can_proceed_safely": False,
            "requires_operator_override": True,
            "evidence_level": evidence_level,
            "confidence_score": confidence,
            "summary": (
                f"PRE-WIPE ALERT: Found {validated_count} validated file structure(s) and {candidates_count} candidate(s). "
                "Target may contain intact documents, images, or records. Manual forensic review recommended prior to wipe."
            ),
            "carve_details": carve_result
        }
    elif evidence_level == EVIDENCE_LOW_CONFIDENCE:
        return {
            "risk_level": "LOW_FRAGMENTARY_TRACE",
            "evidence_detected": True,
            "can_proceed_safely": True,
            "requires_operator_override": False,
            "evidence_level": evidence_level,
            "confidence_score": confidence,
            "summary": "Isolated magic byte fragments detected (likely noise/residual slack). Sanitization may proceed.",
            "carve_details": carve_result
        }
    else:
        return {
            "risk_level": "NO_EVIDENCE",
            "evidence_detected": False,
            "can_proceed_safely": True,
            "requires_operator_override": False,
            "evidence_level": evidence_level,
            "confidence_score": 0.0,
            "summary": "Pre-wipe assessment clean: no organized forensic structures detected.",
            "carve_details": carve_result
        }
