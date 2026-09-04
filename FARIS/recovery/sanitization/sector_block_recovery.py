import os
import time
import math
import hashlib
import subprocess
from pathlib import Path
from typing import Dict, List, Any, Optional
from collections import Counter

try:
    from core.paths import FARIS_ROOT, resolve_case_dir, get_relative_str
    from core.engine_manager import engine_manager
    from validation.recovery_validator import recovery_validator
except ImportError:
    from ...core.paths import FARIS_ROOT, resolve_case_dir, get_relative_str
    from ...core.engine_manager import engine_manager
    from ...validation.recovery_validator import recovery_validator


def _sector_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    cnt = Counter(data)
    l = len(data)
    return -sum((c / l) * math.log2(c / l) for c in cnt.values())


class SectorBlockRecoveryEngine:
    """
    Stage C: Sector / Block-Level Recovery
    =====================================
    Performs physical sector and cluster block-level examination.
    Analyzes:
      - Raw physical sectors (512-byte / 4096-byte alignment)
      - Partially overwritten transition sectors
      - Boundary blocks between wiped and unwiped extents
      - Surviving cluster slack sectors
    
    Integrity:
      Recovers ONLY bytes that physically exist in the acquired image.
    """

    def __init__(self):
        self.img_cat = engine_manager.get_tool_path("img_cat")

    def _open_stream(self, image_path: Path):
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

    def recover_sector_blocks(
        self,
        case_id: str,
        image_path: Path,
        sector_size: int = 512,
        block_size: int = 4096,
        max_scan_bytes: Optional[int] = 16 * 1024 * 1024,
        output_dir: Optional[Path] = None
    ) -> Dict[str, Any]:
        """
        Executes granular sector/block-level recovery on unallocated and boundary extents.
        """
        start_time = time.time()
        started_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(start_time))

        case_dir = resolve_case_dir(case_id)
        out_dir = output_dir or (case_dir / "recovery" / "sanitization" / "sectors")
        out_dir.mkdir(parents=True, exist_ok=True)

        if not image_path.exists():
            return {
                "stage": "C_sector_block_recovery",
                "status": "FAILED",
                "reason": f"Evidence image not found: {image_path}",
                "started_at": started_at,
                "completed_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "duration": 0.0,
                "confidence": "NONE"
            }

        proc, stream = self._open_stream(image_path)
        recovered_blocks: List[Dict[str, Any]] = []
        evidence_offsets: List[int] = []

        total_sectors_read = 0
        partially_overwritten_count = 0
        intact_blocks_count = 0

        chunk_size = 64 * 1024
        bytes_read = 0
        limit = max_scan_bytes or (16 * 1024 * 1024)

        try:
            while bytes_read < limit:
                chunk = stream.read(chunk_size)
                if not chunk:
                    break
                
                c_len = len(chunk)
                current_base = bytes_read
                bytes_read += c_len

                for s_off in range(0, c_len, sector_size):
                    sector = chunk[s_off:s_off + sector_size]
                    if len(sector) < sector_size:
                        continue
                    
                    total_sectors_read += 1
                    abs_offset = current_base + s_off

                    # Check for partial overwrite: non-uniform with trailing or leading zeros/patterns
                    is_all_zero = (sector == b"\x00" * sector_size)
                    is_all_ff = (sector == b"\xFF" * sector_size)

                    if is_all_zero or is_all_ff:
                        continue

                    ent = _sector_entropy(sector)
                    
                    # Detect partially overwritten sector (e.g. 128 bytes data + 384 bytes 0x00/0xFF)
                    leading_zeros = len(sector) - len(sector.lstrip(b"\x00"))
                    trailing_zeros = len(sector) - len(sector.rstrip(b"\x00"))
                    leading_ff = len(sector) - len(sector.lstrip(b"\xFF"))
                    trailing_ff = len(sector) - len(sector.rstrip(b"\xFF"))

                    is_partial = (trailing_zeros >= 64 or trailing_ff >= 64 or leading_zeros >= 64 or leading_ff >= 64) and (ent > 1.0)

                    if is_partial or (ent >= 2.5 and ent <= 7.5):
                        # Candidate surviving sector/block
                        if is_partial:
                            partially_overwritten_count += 1
                            ctype = "Partially Overwritten Sector Remnant"
                            indication = f"Partial overwrite boundary detected (Trailing padding: {max(trailing_zeros, trailing_ff)} B)"
                            conf = "MEDIUM"
                        else:
                            intact_blocks_count += 1
                            ctype = "Structured Data Sector Remnant"
                            indication = f"Surviving sector with entropy {ent:.2f} bits/byte"
                            conf = "HIGH"

                        evidence_offsets.append(abs_offset)

                        if len(recovered_blocks) < 50:  # Save up to 50 representative blocks
                            block_id = f"BLOCK_{len(recovered_blocks) + 1:04d}"
                            out_fname = f"{block_id}_off{abs_offset}.bin"
                            out_file = out_dir / out_fname

                            with open(out_file, "wb") as f_blk:
                                f_blk.write(sector)

                            val_res = recovery_validator.validate_file(out_file)
                            v_status = val_res.get("validation_status", "PARTIALLY_VALID" if is_partial else "VALID")

                            recovered_blocks.append({
                                "block_id": block_id,
                                "filename": out_fname,
                                "relative_path": get_relative_str(out_file),
                                "offset": abs_offset,
                                "length": len(sector),
                                "content_type": ctype,
                                "evidence_source": f"Sector #{abs_offset // sector_size} (0x{abs_offset:X})",
                                "sanitization_indication": indication,
                                "validation_status": v_status,
                                "confidence": conf,
                                "sha256": hashlib.sha256(sector).hexdigest()
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

        total_surviving = partially_overwritten_count + intact_blocks_count
        if total_surviving > 0:
            status = "RESIDUAL_EVIDENCE_FOUND"
            reason = f"Extracted {total_surviving} surviving sector/block remnants ({partially_overwritten_count} partial overwrite boundaries, {intact_blocks_count} structured blocks)."
            conf = "HIGH"
        else:
            status = "NO_RECOVERABLE_EVIDENCE"
            reason = "No surviving sector or block-level remnants identified (all inspected sectors uniformly sanitized)."
            conf = "HIGH"

        return {
            "stage": "C_sector_block_recovery",
            "status": status,
            "device_type": "Storage Device Image",
            "sanitization_type": "Physical Sector & Block Level Recovery",
            "started_at": started_at,
            "completed_at": completed_at,
            "duration": duration,
            "total_sectors_analyzed": total_sectors_read,
            "partially_overwritten_sectors": partially_overwritten_count,
            "intact_blocks_identified": intact_blocks_count,
            "candidates_found": len(recovered_blocks),
            "validated_candidates": sum(1 for b in recovered_blocks if b["validation_status"] in ("VALID", "PARTIALLY_VALID")),
            "recovered_targets": intact_blocks_count,
            "partial_targets": partially_overwritten_count,
            "rejected_candidates": 0,
            "reason": reason,
            "evidence_offsets": evidence_offsets[:25],
            "confidence": conf,
            "recovered_blocks": recovered_blocks[:20]
        }


sector_block_engine = SectorBlockRecoveryEngine()
