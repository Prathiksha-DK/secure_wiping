import os
import time
from pathlib import Path
from typing import Dict, List, Any, Optional

try:
    from core.paths import FARIS_ROOT, resolve_case_dir
except ImportError:
    from ...core.paths import FARIS_ROOT, resolve_case_dir


class WearLevelingAnalyzer:
    """
    Stage G: Wear-Leveling Analysis
    ==============================
    Analyzes potential wear-leveling, block erase cycles, and physical block allocation.

    CRITICAL FORENSIC LIMITATION & INTEGRITY PRINCIPLE:
      Standard forensic bit-stream disk images (.E01 / .raw / .dd) capture only the
      Logical Block Addressing (LBA) layer presented by the storage controller interface.

      Physical wear-leveling pools, dynamic erase block mappings, program/erase (P/E) cycle counts,
      and spare block reserve tables reside exclusively inside the solid-state controller's internal
      firmware (FTL / ASIC). They are physically shielded by hardware and are NOT transmitted
      over SATA/NVMe/USB host protocols.

      Therefore:
        - For SSD / Flash Media: returns STATUS = NOT_ACCESSIBLE (honest forensic disclosure; no fabrication).
        - For Magnetic HDD: returns STATUS = NOT_APPLICABLE (magnetic platters do not use wear leveling).
    """

    def analyze_wear_leveling(
        self,
        case_id: str,
        image_path: Path,
        device_type_hint: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Evaluates wear-leveling architecture accessibility from the acquired image.
        """
        start_time = time.time()
        started_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(start_time))

        hint = (device_type_hint or "").lower() + " " + image_path.name.lower()
        if "hdd" in hint or "hard disk" in hint or "rotational" in hint or "barracuda" in hint:
            media_type = "HDD"
        elif "nvme" in hint or "ssd" in hint or "solid" in hint:
            media_type = "SSD"
        elif "usb" in hint or "flash" in hint or "pendrive" in hint or "thumb" in hint:
            media_type = "USB Flash"
        elif "sd" in hint or "mmc" in hint or "card" in hint:
            media_type = "Memory Card"
        else:
            media_type = "Unknown Storage Media"

        if not image_path.exists():
            return {
                "stage": "G_wear_leveling_analysis",
                "status": "FAILED",
                "device_type": media_type,
                "reason": f"Evidence image not found: {image_path}",
                "started_at": started_at,
                "completed_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "duration": 0.0,
                "confidence": "NONE"
            }

        end_time = time.time()
        duration = round(end_time - start_time, 3)
        completed_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(end_time))

        if media_type == "HDD":
            status = "NOT_APPLICABLE"
            reason = "N/A — Rotating magnetic media (HDD) does not utilize NAND flash wear-leveling algorithms."
            conf = "HIGH"
        else:
            status = "NOT_ACCESSIBLE"
            reason = (
                f"Physical wear-leveling pool allocation tables and block erase cycle counters are managed internally "
                f"by the storage controller firmware ({media_type}). They cannot be extracted from a standard logical LBA "
                f"bit-stream (.E01 / raw). Hardware chip-off or vendor JTAG diagnostics required for controller-internal metrics."
            )
            conf = "HIGH"

        return {
            "stage": "G_wear_leveling_analysis",
            "status": status,
            "device_type": media_type,
            "sanitization_type": f"{media_type} Wear-Leveling Architecture Evaluation",
            "started_at": started_at,
            "completed_at": completed_at,
            "duration": duration,
            "wear_leveling_accessible": False,
            "controller_firmware_shielded": True,
            "candidates_found": 0,
            "validated_candidates": 0,
            "recovered_targets": 0,
            "partial_targets": 0,
            "rejected_candidates": 0,
            "reason": reason,
            "evidence_offsets": [],
            "confidence": conf
        }


wear_leveling_analyzer = WearLevelingAnalyzer()
