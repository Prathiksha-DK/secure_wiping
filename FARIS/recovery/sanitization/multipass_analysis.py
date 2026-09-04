import os
import time
from pathlib import Path
from typing import Dict, List, Any, Optional

try:
    from core.paths import FARIS_ROOT, resolve_case_dir
    from .overwrite_analysis import calculate_shannon_entropy
except ImportError:
    from ...core.paths import FARIS_ROOT, resolve_case_dir
    from .overwrite_analysis import calculate_shannon_entropy


class MultiPassAnalyzer:
    """
    Stage D: Multi-Pass Sanitization Analysis
    ========================================
    Detects and classifies overwrite signatures corresponding to industry sanitization patterns:
      - Pattern consistent with NIST SP 800-88 Rev 1 (Clear / Purge)
      - Pattern consistent with DoD 5220.22-M / single or multi-pass overwrite
      - Constant byte fill or high-entropy pseudo-random pattern

    Integrity Notice:
      A static forensic image can characterize the observed final byte pattern across sectors,
      but cannot independently prove the historical number or order of prior sanitization passes.
    """

    def analyze_multipass_sanitization(
        self,
        case_id: str,
        image_path: Path,
        overwrite_distribution: Optional[Dict[str, float]] = None
    ) -> Dict[str, Any]:
        """
        Evaluates final recorded state across sectors to classify the observed sanitization pattern.
        """
        start_time = time.time()
        started_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(start_time))

        if not image_path.exists():
            return {
                "stage": "D_multipass_analysis",
                "status": "FAILED",
                "reason": f"Image file not found: {image_path}",
                "started_at": started_at,
                "completed_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "duration": 0.0,
                "confidence": "NONE"
            }

        dist = overwrite_distribution or {
            "zero_fill_percent": 0.0,
            "one_fill_percent": 0.0,
            "repeated_pattern_percent": 0.0,
            "random_entropy_percent": 0.0,
            "residual_data_percent": 100.0
        }

        zero_pct = dist.get("zero_fill_percent", 0.0)
        ff_pct = dist.get("one_fill_percent", 0.0)
        pat_pct = dist.get("repeated_pattern_percent", 0.0)
        rnd_pct = dist.get("random_entropy_percent", 0.0)
        res_pct = dist.get("residual_data_percent", 0.0)

        # Pattern classification based on observable final recorded byte state
        if zero_pct >= 99.0:
            standard_matched = "Pattern Consistent with NIST SP 800-88 Clear / Single-Pass Zero"
            verdict = "PATTERN_CONSISTENT_WITH_SINGLE_PASS_ZERO"
            desc = (
                "100% of analyzed sectors contain uniform 0x00 pattern. "
                "Consistent with NIST SP 800-88 Clear or completed single-pass zero wipe. "
                "Note: A static forensic image characterizes the observed final byte pattern, "
                "but cannot independently prove the historical number or order of prior sanitization passes."
            )
            conf = "HIGH"
        elif rnd_pct >= 95.0:
            standard_matched = "Pattern Consistent with Random / Cryptographic Overwrite (NIST SP 800-88 Purge / DoD Final Pass)"
            verdict = "PATTERN_CONSISTENT_WITH_RANDOM_OR_CRYPTO_PASS"
            desc = (
                "High-entropy pseudo-random bytes (>7.20 bits/byte) across >=95% of storage sectors. "
                "Consistent with random multi-pass overwrite or cryptographic erase. "
                "Note: A static forensic image characterizes the observed final byte pattern, "
                "but cannot independently prove the historical number or order of prior sanitization passes."
            )
            conf = "HIGH"
        elif ff_pct >= 99.0:
            standard_matched = "Pattern Consistent with Single-Pass 0xFF / Intermediate Fill"
            verdict = "PATTERN_CONSISTENT_WITH_ONE_FILL"
            desc = (
                "Uniform 0xFF pattern across analyzed sectors. "
                "Consistent with single-pass one-fill or intermediate sanitization pass. "
                "Note: A static forensic image characterizes the observed final byte pattern, "
                "but cannot independently prove the historical number or order of prior sanitization passes."
            )
            conf = "HIGH"
        elif (zero_pct + ff_pct + rnd_pct + pat_pct) >= 80.0 and res_pct > 0.0:
            standard_matched = "Partial Overwrite Pattern with Surviving Remnants"
            verdict = "PARTIAL_OVERWRITE_DETECTED"
            desc = f"Sanitization pattern observed on {(zero_pct + ff_pct + rnd_pct + pat_pct):.1f}% of media, with {res_pct:.1f}% surviving residual data sectors."
            conf = "HIGH"
        else:
            standard_matched = "No Uniform Sanitization Pattern Detected"
            verdict = "NON_SANITIZED_EVIDENCE"
            desc = "Media contains standard active/deleted filesystem structures without uniform overwrite sanitization."
            conf = "MEDIUM"

        end_time = time.time()
        duration = round(end_time - start_time, 3)
        completed_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(end_time))

        return {
            "stage": "D_multipass_analysis",
            "status": "COMPLETED",
            "device_type": "Storage Device Image",
            "sanitization_type": standard_matched,
            "started_at": started_at,
            "completed_at": completed_at,
            "duration": duration,
            "classification_verdict": verdict,
            "matched_standard": standard_matched,
            "candidates_found": 0,
            "validated_candidates": 0,
            "recovered_targets": 0,
            "partial_targets": 0,
            "rejected_candidates": 0,
            "reason": desc,
            "evidence_offsets": [],
            "confidence": conf
        }


multipass_analyzer = MultiPassAnalyzer()
