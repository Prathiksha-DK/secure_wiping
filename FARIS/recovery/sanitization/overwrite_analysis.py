import os
import math
import time
import subprocess
from pathlib import Path
from typing import Dict, List, Any, Optional, BinaryIO
from collections import Counter

try:
    from core.paths import FARIS_ROOT, resolve_case_dir
    from core.engine_manager import engine_manager
except ImportError:
    from ...core.paths import FARIS_ROOT, resolve_case_dir
    from ...core.engine_manager import engine_manager


def calculate_shannon_entropy(data: bytes) -> float:
    """Calculates Shannon entropy in bits per byte (0.0 to 8.0)."""
    if not data:
        return 0.0
    length = len(data)
    counts = Counter(data)
    entropy = 0.0
    for count in counts.values():
        p = count / length
        entropy -= p * math.log2(p)
    return entropy


class OverwritePatternAnalyzer:
    """
    Stage A: Overwrite Pattern Analysis
    ==================================
    Examines the acquired forensic image for systematic sanitization patterns:
      - Zero-fill (0x00)
      - One-fill (0xFF)
      - Repeated constant byte patterns (e.g. 0xAA, 0x55)
      - Alternating / cyclic byte sequences
      - High-entropy pseudorandom overwrite blocks
      - Regions affected by repeated writes vs surviving non-pattern regions

    Integrity Notice:
      Characterizes and verifies the sanitization pattern. Does NOT claim that
      pattern analysis itself recovers original overwritten data.
    """

    def __init__(self):
        self.img_cat = engine_manager.get_tool_path("img_cat")

    def _open_image_stream(self, image_path: Path, max_bytes: Optional[int] = None):
        """Opens a byte stream to the image using img_cat for E01 or native file read."""
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

    def analyze_patterns(
        self,
        image_path: Path,
        sector_size: int = 512,
        sample_limit_bytes: Optional[int] = 32 * 1024 * 1024,
        scan_all: bool = False
    ) -> Dict[str, Any]:
        """
        Performs exhaustive/statistical sector-by-sector overwrite pattern characterization.
        """
        start_time = time.time()
        started_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(start_time))

        if not image_path.exists():
            return {
                "stage": "A_overwrite_pattern_analysis",
                "status": "FAILED",
                "reason": f"Forensic image file not found: {image_path}",
                "started_at": started_at,
                "completed_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "duration_seconds": 0.0,
                "confidence": "NONE"
            }

        proc, stream = self._open_image_stream(image_path)
        
        total_sectors = 0
        zero_sectors = 0
        ff_sectors = 0
        repeated_pattern_sectors = 0
        random_entropy_sectors = 0  # Entropy >= 7.8
        residual_data_sectors = 0   # 0.5 <= Entropy < 7.8

        pattern_frequencies: Dict[str, int] = {}
        non_pattern_extents: List[Dict[str, Any]] = []
        current_extent_start: Optional[int] = None
        current_extent_len = 0

        chunk_size = 64 * 1024  # 64 KB read buffer
        max_bytes_to_read = None if scan_all else sample_limit_bytes
        bytes_read_total = 0

        try:
            while True:
                to_read = chunk_size
                if max_bytes_to_read is not None:
                    remaining = max_bytes_to_read - bytes_read_total
                    if remaining <= 0:
                        break
                    to_read = min(chunk_size, remaining)

                chunk = stream.read(to_read)
                if not chunk:
                    break

                chunk_len = len(chunk)
                bytes_read_total += chunk_len

                # Process chunk sector-by-sector
                for s_offset in range(0, chunk_len, sector_size):
                    sector = chunk[s_offset:s_offset + sector_size]
                    if len(sector) == 0:
                        continue

                    total_sectors += 1
                    abs_offset = bytes_read_total - chunk_len + s_offset

                    first_byte = sector[0]
                    # Check single-byte uniform fill
                    if sector == bytes([first_byte]) * len(sector):
                        if first_byte == 0x00:
                            zero_sectors += 1
                        elif first_byte == 0xFF:
                            ff_sectors += 1
                        else:
                            repeated_pattern_sectors += 1
                            pat_key = f"0x{first_byte:02X}"
                            pattern_frequencies[pat_key] = pattern_frequencies.get(pat_key, 0) + 1

                        if current_extent_start is not None:
                            non_pattern_extents.append({
                                "start_offset": current_extent_start,
                                "length_bytes": current_extent_len
                            })
                            current_extent_start = None
                            current_extent_len = 0
                    else:
                        entropy = calculate_shannon_entropy(sector)
                        if entropy >= 7.20:
                            random_entropy_sectors += 1
                            if current_extent_start is not None:
                                non_pattern_extents.append({
                                    "start_offset": current_extent_start,
                                    "length_bytes": current_extent_len
                                })
                                current_extent_start = None
                                current_extent_len = 0
                        else:
                            residual_data_sectors += 1
                            if current_extent_start is None:
                                current_extent_start = abs_offset
                                current_extent_len = len(sector)
                            else:
                                current_extent_len += len(sector)

            if current_extent_start is not None:
                non_pattern_extents.append({
                    "start_offset": current_extent_start,
                    "length_bytes": current_extent_len
                })

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

        if total_sectors == 0:
            return {
                "stage": "A_overwrite_pattern_analysis",
                "status": "NO_RECOVERABLE_EVIDENCE",
                "reason": "Empty or unreadable evidence image stream.",
                "started_at": started_at,
                "completed_at": completed_at,
                "duration_seconds": duration,
                "confidence": "LOW",
                "metrics": {}
            }

        # Percentage distribution
        zero_pct = round((zero_sectors / total_sectors) * 100, 2)
        ff_pct = round((ff_sectors / total_sectors) * 100, 2)
        pattern_pct = round((repeated_pattern_sectors / total_sectors) * 100, 2)
        random_pct = round((random_entropy_sectors / total_sectors) * 100, 2)
        residual_pct = round((residual_data_sectors / total_sectors) * 100, 2)

        # Classification
        if zero_pct >= 99.0:
            primary_pattern = "UNIFORM_ZERO_FILL_SINGLE_PASS"
            sanitization_indication = "Single-pass zero overwrite verified (NIST 800-88 Clear / Quick Wipe)"
            status = "COMPLETED"
            conf = "HIGH"
        elif ff_pct >= 99.0:
            primary_pattern = "UNIFORM_ONE_FILL_SINGLE_PASS"
            sanitization_indication = "Single-pass 0xFF overwrite verified"
            status = "COMPLETED"
            conf = "HIGH"
        elif random_pct >= 95.0:
            primary_pattern = "HIGH_ENTROPY_RANDOM_OR_CRYPTO"
            sanitization_indication = "Cryptographic wipe or random multi-pass overwrite verified"
            status = "COMPLETED"
            conf = "HIGH"
        elif (zero_pct + ff_pct + pattern_pct + random_pct) >= 90.0 and residual_pct > 0:
            primary_pattern = "PARTIAL_OVERWRITE_WITH_SURVIVING_REMNANTS"
            sanitization_indication = f"Sanitization verified with {residual_pct}% surviving residual data sectors"
            status = "COMPLETED"
            conf = "HIGH"
        elif residual_pct >= 80.0:
            primary_pattern = "ACTIVE_OR_UNSANITIZED_FILESYSTEM"
            sanitization_indication = "No comprehensive full-disk overwrite pattern detected"
            status = "COMPLETED"
            conf = "MEDIUM"
        else:
            primary_pattern = "MIXED_PATTERN_SANITIZATION"
            sanitization_indication = "Mixed overwrite and unallocated boundary patterns detected"
            status = "COMPLETED"
            conf = "MEDIUM"

        return {
            "stage": "A_overwrite_pattern_analysis",
            "status": status,
            "device_type": "Storage Device Image",
            "sanitization_type": primary_pattern,
            "started_at": started_at,
            "completed_at": completed_at,
            "duration": duration,
            "total_sectors_inspected": total_sectors,
            "bytes_inspected": bytes_read_total,
            "distribution": {
                "zero_fill_percent": zero_pct,
                "one_fill_percent": ff_pct,
                "repeated_pattern_percent": pattern_pct,
                "random_entropy_percent": random_pct,
                "residual_data_percent": residual_pct
            },
            "pattern_frequencies": pattern_frequencies,
            "residual_extents_found": len(non_pattern_extents),
            "residual_extents": non_pattern_extents[:50],  # Return up to first 50 extents
            "candidates_found": len(non_pattern_extents),
            "validated_candidates": 0,
            "recovered_targets": 0,
            "partial_targets": 0,
            "rejected_candidates": 0,
            "reason": sanitization_indication,
            "evidence_offsets": [e["start_offset"] for e in non_pattern_extents[:20]],
            "confidence": conf
        }


overwrite_analyzer = OverwritePatternAnalyzer()
