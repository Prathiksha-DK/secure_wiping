import os
import re
import json
import hashlib
from pathlib import Path
from typing import Dict, List, Any, Optional

class AntiForensicRecoveryEngine:
    """
    Deep / Anti-Forensic Recovery Engine.
    Recovers data from damaged filesystem areas, wiped metadata, orphan structures,
    and residual/fringe slack space.
    """

    def __init__(self, cluster_size: int = 4096):
        self.cluster_size = cluster_size

    def scan_fringe_residual_data(
        self,
        stream_reader,
        output_dir: Path,
        max_bytes: Optional[int] = None,
        chunk_size: int = 1024 * 1024
    ) -> List[Dict[str, Any]]:
        """
        Scans residual slack and fringe data blocks for embedded UTF-8 / ASCII text strings and structured records.
        Uses compiled C-speed regular expression matching with boundary overlap and periodic progress reporting.
        """
        output_dir.mkdir(parents=True, exist_ok=True)
        residual_artifacts = []
        global_offset = 0
        overlap_size = 64
        prev_tail = b""
        last_progress_mb = 0

        # High-density printable ASCII/UTF-8 runs (length >= 64)
        pattern = re.compile(rb'[\x20-\x7E\t\r\n]{64,}')

        while True:
            if max_bytes is not None and global_offset >= max_bytes:
                break

            to_read = chunk_size
            if max_bytes is not None:
                to_read = min(chunk_size, max_bytes - global_offset)

            raw_chunk = stream_reader.read(to_read)
            if not raw_chunk:
                break

            combined = prev_tail + raw_chunk
            base_offset = global_offset - len(prev_tail)

            for m in pattern.finditer(combined):
                r_bytes = m.group()
                # Filter out pure repeating characters (e.g. spaces or periods)
                if len(set(r_bytes)) > 8:
                    r_start = m.start()
                    # Skip matches wholly within the previous overlap to avoid duplication
                    if r_start < len(prev_tail) and (r_start + len(r_bytes)) <= len(prev_tail):
                        continue

                    sha256 = hashlib.sha256(r_bytes).hexdigest()
                    art_id = f"RESIDUAL_{len(residual_artifacts)+1:05d}"
                    out_file = output_dir / f"{art_id}.txt"
                    with open(out_file, "wb") as f_out:
                        f_out.write(r_bytes)

                    residual_artifacts.append({
                        "artifact_id": art_id,
                        "filename": out_file.name,
                        "type": "Residual / Slack Text Record",
                        "source_offset": base_offset + r_start,
                        "size_bytes": len(r_bytes),
                        "sha256": sha256,
                        "confidence": "MEDIUM",
                        "recovery_method": "Deep Anti-Forensic Residual Carving"
                    })

            global_offset += len(raw_chunk)
            if len(raw_chunk) >= overlap_size:
                prev_tail = raw_chunk[-overlap_size:]
            else:
                prev_tail = b""

            curr_mb = global_offset // (256 * 1024 * 1024)
            if curr_mb > last_progress_mb:
                last_progress_mb = curr_mb
                print(f"  [*] Anti-forensic scan progress: {global_offset / (1024*1024):.0f} MB scanned ({len(residual_artifacts)} residual artifacts found)...")

        # Write manifest
        manifest_file = output_dir / "anti_forensics_manifest.json"
        with open(manifest_file, "w", encoding="utf-8") as f_man:
            json.dump({
                "total_residual_artifacts": len(residual_artifacts),
                "artifacts": residual_artifacts
            }, f_man, indent=2)

        return residual_artifacts

# Singleton instance
anti_forensic_recovery = AntiForensicRecoveryEngine()
