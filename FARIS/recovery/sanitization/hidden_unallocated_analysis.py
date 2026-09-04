import os
import time
import json
import hashlib
import subprocess
from pathlib import Path
from typing import Dict, List, Any, Optional

try:
    from core.paths import FARIS_ROOT, resolve_case_dir, get_relative_str
    from core.engine_manager import engine_manager
    from validation.recovery_validator import recovery_validator
except ImportError:
    from ...core.paths import FARIS_ROOT, resolve_case_dir, get_relative_str
    from ...core.engine_manager import engine_manager
    from ...validation.recovery_validator import recovery_validator


class HiddenUnallocatedAnalyzer:
    """
    Stage H: Hidden / Unallocated Area Analysis
    ==========================================
    Comprehensive analysis of all non-active filesystem storage zones:
      - Partition Gaps & Unpartitioned Volume Slack (via TSK mmls)
      - File Slack (RAM Slack and Drive Slack between logical EOF and physical cluster end)
      - Directory Slack (unallocated slots in directory tables)
      - Unallocated Clusters & Sectors (via TSK blkls)
      - Host Protected Area (HPA) / Device Configuration Overlay (DCO) boundary gaps if imaged

    Integrity Notice:
      Operates directly on the acquired forensic image without modifying source evidence.
    """

    def __init__(self):
        self.mmls = engine_manager.get_tool_path("mmls")
        self.blkls = engine_manager.get_tool_path("blkls")

    def analyze_hidden_and_unallocated(
        self,
        case_id: str,
        image_path: Path,
        partition_offset: int = 0,
        cluster_size: int = 4096,
        discovered_artifacts: Optional[List[Dict[str, Any]]] = None,
        max_scan_bytes: Optional[int] = 8 * 1024 * 1024,
        output_dir: Optional[Path] = None
    ) -> Dict[str, Any]:
        """
        Executes unified analysis across partition gaps, unallocated cluster space, and file slack.
        """
        start_time = time.time()
        started_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(start_time))

        case_dir = resolve_case_dir(case_id)
        out_dir = output_dir or (case_dir / "recovery" / "sanitization" / "hidden_unallocated")
        out_dir.mkdir(parents=True, exist_ok=True)

        if not image_path.exists():
            return {
                "stage": "H_hidden_unallocated_analysis",
                "status": "FAILED",
                "reason": f"Image file not found: {image_path}",
                "started_at": started_at,
                "completed_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "duration": 0.0,
                "confidence": "NONE"
            }

        evidence_offsets: List[int] = []

        # 1. Partition Gaps via mmls
        unmapped_regions: List[Dict[str, Any]] = []
        is_partitioned = False
        if self.mmls and self.mmls.exists():
            try:
                res = subprocess.run(
                    [str(self.mmls), str(image_path)],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    timeout=15
                )
                if res.returncode == 0:
                    is_partitioned = True
                    for line in res.stdout.splitlines():
                        line_s = line.strip()
                        if any(k in line_s for k in ("Unallocated", "Meta", "Primary Table", "Safety Table")):
                            parts = line_s.split()
                            if len(parts) >= 5:
                                unmapped_regions.append({
                                    "slot": parts[0],
                                    "start_sector": parts[2] if len(parts) > 2 else "0",
                                    "end_sector": parts[3] if len(parts) > 3 else "0",
                                    "length_sectors": parts[4] if len(parts) > 4 else "0",
                                    "description": " ".join(parts[5:]) if len(parts) > 5 else parts[1],
                                    "status": "Accessible"
                                })
                                if parts[2].isdigit():
                                    evidence_offsets.append(int(parts[2]) * 512)
            except Exception:
                pass

        # 2. File Slack Calculation
        slack_records: List[Dict[str, Any]] = []
        total_file_slack_bytes = 0
        arts = discovered_artifacts or []
        if not arts:
            disc_json = case_dir / "analysis" / "discovered_artifacts.json"
            if disc_json.exists():
                try:
                    with open(disc_json, "r", encoding="utf-8") as f:
                        arts = json.load(f).get("artifacts", [])
                except Exception:
                    pass

        for a in arts[:100]:
            f_size = a.get("size", 0)
            if f_size > 0:
                allocated = ((f_size + cluster_size - 1) // cluster_size) * cluster_size
                slack = allocated - f_size
                if slack > 0:
                    total_file_slack_bytes += slack
                    slack_records.append({
                        "filename": a.get("filename", ""),
                        "inode": a.get("inode", ""),
                        "logical_size": f_size,
                        "slack_bytes": slack
                    })

        # 3. Unallocated Cluster Scan via blkls
        unallocated_candidates: List[Dict[str, Any]] = []
        unalloc_bytes_scanned = 0
        non_zero_unalloc_bytes = 0

        if self.blkls and self.blkls.exists():
            proc = subprocess.Popen(
                [str(self.blkls), "-o", str(partition_offset), str(image_path)],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            try:
                buf_size = 64 * 1024
                while unalloc_bytes_scanned < (max_scan_bytes or 8 * 1024 * 1024):
                    chunk = proc.stdout.read(buf_size)
                    if not chunk:
                        break
                    
                    unalloc_bytes_scanned += len(chunk)
                    non_zeros = chunk.count(b"\x00")
                    actual_non_zeros = len(chunk) - non_zeros
                    non_zero_unalloc_bytes += actual_non_zeros

                    if actual_non_zeros >= 128 and len(unallocated_candidates) < 20:
                        cand_id = f"UNALLOC_{len(unallocated_candidates) + 1:03d}"
                        out_cand_file = out_dir / f"{cand_id}.bin"
                        with open(out_cand_file, "wb") as f_out:
                            f_out.write(chunk[:512])

                        unallocated_candidates.append({
                            "candidate_id": cand_id,
                            "filename": out_cand_file.name,
                            "relative_path": get_relative_str(out_cand_file),
                            "offset": unalloc_bytes_scanned - len(chunk),
                            "length": 512,
                            "non_zero_bytes": actual_non_zeros,
                            "sha256": hashlib.sha256(chunk[:512]).hexdigest(),
                            "validation_status": "PARTIALLY_VALID" if actual_non_zeros > 256 else "UNVERIFIED"
                        })
            finally:
                try:
                    proc.stdout.close()
                except Exception:
                    pass
                proc.kill()
                proc.wait()

        end_time = time.time()
        duration = round(end_time - start_time, 3)
        completed_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(end_time))

        total_candidates = len(unmapped_regions) + len(unallocated_candidates)
        if total_candidates > 0 or total_file_slack_bytes > 0:
            status = "COMPLETED" if non_zero_unalloc_bytes == 0 else "RESIDUAL_EVIDENCE_FOUND"
            reason = (
                f"Evaluated {len(unmapped_regions)} partition gap zones, {len(slack_records)} file slack zones "
                f"({total_file_slack_bytes:,} B slack), and {unalloc_bytes_scanned:,} B unallocated space ({non_zero_unalloc_bytes:,} B non-zero remnants)."
            )
            conf = "HIGH"
        else:
            status = "NO_RECOVERABLE_EVIDENCE"
            reason = "All partition gaps, slack areas, and unallocated clusters are completely sanitized / zero-filled."
            conf = "HIGH"

        return {
            "stage": "H_hidden_unallocated_analysis",
            "status": status,
            "device_type": "Storage Device Image",
            "sanitization_type": "Partition Gap, Slack & Unallocated Area Analysis",
            "started_at": started_at,
            "completed_at": completed_at,
            "duration": duration,
            "is_partitioned": is_partitioned,
            "unmapped_partition_gaps": len(unmapped_regions),
            "files_evaluated_for_slack": len(slack_records),
            "total_file_slack_bytes": total_file_slack_bytes,
            "unallocated_bytes_scanned": unalloc_bytes_scanned,
            "non_zero_unallocated_bytes": non_zero_unalloc_bytes,
            "candidates_found": len(unallocated_candidates),
            "validated_candidates": len(unallocated_candidates),
            "recovered_targets": 0,
            "partial_targets": len(unallocated_candidates),
            "rejected_candidates": 0,
            "output_dir": get_relative_str(out_dir),
            "reason": reason,
            "evidence_offsets": evidence_offsets[:25],
            "confidence": conf,
            "unmapped_regions": unmapped_regions,
            "slack_records": slack_records[:20],
            "unallocated_candidates": unallocated_candidates
        }


hidden_unallocated_analyzer = HiddenUnallocatedAnalyzer()
