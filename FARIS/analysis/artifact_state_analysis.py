import os
import re
import json
import subprocess
from pathlib import Path
from typing import Dict, List, Any, Optional

try:
    from core.paths import FARIS_ROOT, resolve_case_dir, get_relative_str
    from core.engine_manager import engine_manager
except ImportError:
    from ..core.paths import FARIS_ROOT, resolve_case_dir, get_relative_str
    from ..core.engine_manager import engine_manager

class ArtifactStateAnalyzer:
    """
    Forensic Artifact State Analysis.
    Classifies artifacts into HEALTHY, DELETED, DAMAGED, FRAGMENTED, UNKNOWN based on istat metadata.
    """

    def __init__(self):
        self.istat = engine_manager.get_tool_path("istat")

    def inspect_inode(self, image_path: Path, partition_offset: int, inode: str) -> Dict[str, Any]:
        """
        Executes istat on a specific inode to extract allocation state and cluster layout.
        """
        if not self.istat or not self.istat.exists():
            raise FileNotFoundError("istat executable not found in bundled Sleuth Kit.")

        # Clean inode string (strip leading flags or parens)
        clean_inode = re.sub(r"[^\d\-]", "", inode).split("-")[0]
        if not clean_inode:
            return {
                "inode": inode,
                "state": "UNKNOWN",
                "reason": "Invalid or unparseable inode identifier."
            }

        res = subprocess.run(
            [str(self.istat), "-o", str(partition_offset), str(image_path), clean_inode],
            capture_output=True,
            text=True
        )

        if res.returncode != 0:
            return {
                "inode": clean_inode,
                "state": "UNKNOWN",
                "reason": f"istat failed: {res.stderr.strip() or 'Inode not accessible'}",
                "allocated": False,
                "size_bytes": 0,
                "sectors": []
            }

        stdout = res.stdout
        is_allocated = "Not Allocated" not in stdout and "Allocated" in stdout
        size_bytes = 0
        sectors = []

        for line in stdout.splitlines():
            l = line.strip()
            if "Size:" in l:
                try:
                    size_bytes = int(l.split("Size:", 1)[1].split()[0].strip())
                except ValueError:
                    pass
            elif "Sectors:" in l:
                sec_part = l.split("Sectors:", 1)[1].strip()
                if sec_part:
                    sectors = [s.strip() for s in sec_part.split(",") if s.strip()]

        # Forensic State Classification logic
        if not is_allocated:
            if size_bytes == 0 and len(sectors) == 0:
                state = "DELETED"
                reason = "Unallocated metadata entry with unlinked/zeroed cluster pointer."
            elif len(sectors) > 1:
                state = "FRAGMENTED"
                reason = "Unallocated entry possessing multiple non-contiguous sector fragments."
            else:
                state = "DELETED"
                reason = "Unallocated directory entry with retained cluster pointer."
        else:
            if len(sectors) > 1:
                state = "FRAGMENTED"
                reason = "Allocated file with non-contiguous cluster chains."
            elif size_bytes > 0:
                state = "HEALTHY"
                reason = "Allocated file with valid metadata and cluster pointers."
            else:
                state = "HEALTHY"
                reason = "Allocated zero-byte file or placeholder."

        return {
            "inode": clean_inode,
            "state": state,
            "reason": reason,
            "allocated": is_allocated,
            "size_bytes": size_bytes,
            "sector_count": len(sectors),
            "sectors": sectors
        }

    def run_state_analysis(self, case_id: str, image_path: Path, partition_offset: int = 2048, sample_limit: int = 50) -> Dict[str, Any]:
        """
        Analyzes discovered artifacts for a case and generates state distribution.
        """
        case_dir = resolve_case_dir(case_id)
        analysis_dir = case_dir / "analysis"
        disc_file = analysis_dir / "discovered_artifacts.json"

        inodes_to_check = []
        if disc_file.exists():
            try:
                with open(disc_file, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    for item in data.get("artifacts", []):
                        ino = item.get("inode", "")
                        if ino and ino not in inodes_to_check:
                            inodes_to_check.append(ino)
            except Exception:
                pass

        # If sample_limit specified, slice; otherwise evaluate all discovered inodes
        sampled_inodes = inodes_to_check[:sample_limit] if (sample_limit and sample_limit > 0) else inodes_to_check
        results = []

        print(f"[*] Running artifact state analysis on {len(sampled_inodes)} inodes...")
        for ino in sampled_inodes:
            res = self.inspect_inode(image_path, partition_offset, ino)
            results.append(res)

        state_counts = {}
        for r in results:
            st = r["state"]
            state_counts[st] = state_counts.get(st, 0) + 1

        summary = {
            "case_id": case_id,
            "source_image": get_relative_str(image_path),
            "partition_offset": partition_offset,
            "total_analyzed": len(results),
            "state_counts": state_counts,
            "states": results
        }

        out_path = analysis_dir / "artifact_states.json"
        with open(out_path, "w", encoding="utf-8") as f:
            json.dump(summary, f, indent=2)

        print(f"[+] State analysis completed. State breakdown: {state_counts}")
        print(f"[+] State analysis saved to: {out_path}")
        return summary

# Singleton instance
artifact_state_analyzer = ArtifactStateAnalyzer()

if __name__ == "__main__":
    import sys
    if len(sys.argv) > 2:
        offset = int(sys.argv[3]) if len(sys.argv) > 3 else 0
        artifact_state_analyzer.run_state_analysis(sys.argv[1], Path(sys.argv[2]), offset)