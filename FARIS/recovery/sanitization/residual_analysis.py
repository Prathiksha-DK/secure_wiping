import os
import hashlib
import time
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


class ResidualDataAnalyzer:
    """
    Stage B: Residual / Remnant Data Analysis
    ========================================
    Searches the forensic image for surviving fragments or remnants that may remain
    outside completely overwritten regions (e.g. in cluster slack, unallocated gaps,
    partially wiped sectors, or orphaned metadata blocks).

    Feeds legitimate remnants into the validation and correlation pipelines.
    """

    def __init__(self):
        self.img_cat = engine_manager.get_tool_path("img_cat")
        self.blkls = engine_manager.get_tool_path("blkls")

    def _open_image_stream(self, image_path: Path):
        """Opens stream using img_cat for E01 or native file read."""
        if str(image_path).lower().endswith((".e01", ".ewf")) and self.img_cat and self.img_cat.exists():
            proc = subprocess.Popen(
                [str(self.img_cat), str(image_path)],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                bufsize=4 * 1024 * 1024
            )
            return proc, proc.stdout
        else:
            f = open(image_path, "rb")
            return None, f

    def analyze_residuals(
        self,
        case_id: str,
        image_path: Path,
        non_pattern_extents: Optional[List[Dict[str, Any]]] = None,
        max_scan_bytes: Optional[int] = 32 * 1024 * 1024,
        output_dir: Optional[Path] = None
    ) -> Dict[str, Any]:
        """
        Scans residual candidate extents for viable data fragments and valid file headers.
        """
        start_time = time.time()
        started_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(start_time))

        case_dir = resolve_case_dir(case_id)
        out_dir = output_dir or (case_dir / "recovery" / "sanitization" / "residuals")
        out_dir.mkdir(parents=True, exist_ok=True)

        if not image_path.exists():
            return {
                "stage": "B_residual_remnant_analysis",
                "status": "FAILED",
                "reason": f"Image path not found: {image_path}",
                "started_at": started_at,
                "completed_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "duration": 0.0,
                "candidates_found": 0,
                "validated_candidates": 0,
                "confidence": "NONE"
            }

        # Known file signatures to check in residual streams
        KNOWN_SIGNATURES = [
            (b"\xFF\xD8\xFF", ".jpg", "JPEG Image"),
            (b"\x89PNG\r\n\x1a\n", ".png", "PNG Image"),
            (b"%PDF-", ".pdf", "PDF Document"),
            (b"PK\x03\x04", ".zip", "ZIP/Office Document"),
            (b"SQLite format 3\x00", ".db", "SQLite 3 Database"),
            (b"7z\xbc\xaf\x27\x1c", ".7z", "7-Zip Archive"),
            (b"ID3", ".mp3", "MPEG Audio Layer III"),
            (b"\xeb\x3c\x90", ".bin", "FAT Filesystem Boot Sector"),
            (b"\xeb\x58\x90", ".bin", "FAT32/exFAT Boot Sector"),
            (b"\xeb\x52\x90NTFS", ".bin", "NTFS Boot Sector"),
        ]

        proc, stream = self._open_image_stream(image_path)
        surviving_candidates: List[Dict[str, Any]] = []
        evidence_offsets: List[int] = []

        chunk_size = 256 * 1024  # 256 KB
        bytes_read = 0
        limit = max_scan_bytes or (64 * 1024 * 1024)

        try:
            while bytes_read < limit:
                chunk = stream.read(chunk_size)
                if not chunk:
                    break
                
                c_len = len(chunk)
                current_base_offset = bytes_read
                bytes_read += c_len

                # Scan chunk for signatures
                for sig, ext, desc in KNOWN_SIGNATURES:
                    pos = 0
                    while True:
                        idx = chunk.find(sig, pos)
                        if idx == -1 or idx >= c_len - 16:
                            break
                        
                        abs_offset = current_base_offset + idx
                        evidence_offsets.append(abs_offset)

                        # Extract preview candidate based on footer or boundary
                        max_len = min(64 * 1024, c_len - idx)
                        cand_slice = chunk[idx:idx + max_len]
                        
                        if ext == ".png" and b"IEND\xaeB`\x82" in cand_slice:
                            iend_pos = cand_slice.find(b"IEND\xaeB`\x82") + 8
                            candidate_data = cand_slice[:iend_pos]
                        elif ext in (".jpg", ".jpeg") and b"\xFF\xD9" in cand_slice:
                            eoi_pos = cand_slice.find(b"\xFF\xD9") + 2
                            candidate_data = cand_slice[:eoi_pos]
                        elif ext == ".pdf" and b"%%EOF" in cand_slice:
                            eof_pos = cand_slice.find(b"%%EOF") + 5
                            candidate_data = cand_slice[:eof_pos]
                        else:
                            # Strip trailing null padding if present
                            r_trimmed = cand_slice.rstrip(b"\x00")
                            candidate_data = r_trimmed if len(r_trimmed) >= 32 else cand_slice
                        
                        candidate_id = f"RESIDUAL_{len(surviving_candidates) + 1:04d}"
                        out_filename = f"{candidate_id}_{abs_offset}{ext}"
                        out_path = out_dir / out_filename

                        # Save extracted candidate
                        with open(out_path, "wb") as f_cand:
                            f_cand.write(candidate_data)

                        cand_sha = hashlib.sha256(candidate_data).hexdigest()
                        val_res = recovery_validator.validate_file(out_path)

                        surviving_candidates.append({
                            "candidate_id": candidate_id,
                            "filename": out_filename,
                            "relative_path": get_relative_str(out_path),
                            "offset": abs_offset,
                            "length_bytes": len(candidate_data),
                            "content_type": desc,
                            "evidence_source": f"Image offset 0x{abs_offset:X}",
                            "sha256": cand_sha,
                            "validation_status": val_res.get("validation_status", "UNVERIFIED"),
                            "confidence": val_res.get("confidence", "LOW"),
                            "reason": val_res.get("reason", desc)
                        })

                        pos = idx + len(sig) + 16

        finally:
            if stream:
                try:
                    stream.close()
                except Exception:
                    pass
            if proc:
                try:
                    proc.kill()
                    proc.wait()
                except Exception:
                    pass

        end_time = time.time()
        duration = round(end_time - start_time, 3)
        completed_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(end_time))

        valid_count = sum(1 for c in surviving_candidates if c["validation_status"] in ("VALID", "PARTIALLY_VALID"))
        
        if valid_count > 0:
            status = "RESIDUAL_EVIDENCE_FOUND"
            reason = f"Identified {len(surviving_candidates)} residual candidate fragments ({valid_count} structurally validated)."
            conf = "HIGH"
        elif len(surviving_candidates) > 0:
            status = "RESIDUAL_EVIDENCE_FOUND"
            reason = f"Identified {len(surviving_candidates)} unvalidated raw data remnants."
            conf = "MEDIUM"
        else:
            status = "NO_RECOVERABLE_EVIDENCE"
            reason = "No surviving signatures or structured file remnants detected in unallocated space."
            conf = "HIGH"

        return {
            "stage": "B_residual_remnant_analysis",
            "status": status,
            "device_type": "Storage Device Image",
            "sanitization_type": "Residual Analysis",
            "started_at": started_at,
            "completed_at": completed_at,
            "duration": duration,
            "candidates_found": len(surviving_candidates),
            "validated_candidates": valid_count,
            "recovered_targets": valid_count,
            "partial_targets": sum(1 for c in surviving_candidates if c["validation_status"] == "PARTIALLY_VALID"),
            "rejected_candidates": sum(1 for c in surviving_candidates if c["validation_status"] == "REJECTED"),
            "output_dir": get_relative_str(out_dir),
            "reason": reason,
            "evidence_offsets": evidence_offsets[:25],
            "confidence": conf,
            "candidates": surviving_candidates[:30]
        }


residual_analyzer = ResidualDataAnalyzer()
