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

class ImageAnalyzer:
    """
    Analyzes disk partition layouts, filesystems, allocated/unallocated regions,
    and inspects memory signatures.
    """

    def __init__(self):
        self.mmls = engine_manager.get_tool_path("mmls")
        self.fsstat = engine_manager.get_tool_path("fsstat")
        self.tsk_imageinfo = engine_manager.get_tool_path("tsk_imageinfo")
        self.ewfinfo = engine_manager.get_tool_path("ewfinfo")

    def parse_partitions(self, image_path: Path) -> List[Dict[str, Any]]:
        """
        Runs mmls on image to extract structured partition layout.
        """
        if not self.mmls or not self.mmls.exists():
            raise FileNotFoundError("mmls executable not found in bundled Sleuth Kit.")

        res = subprocess.run(
            [str(self.mmls), str(image_path)],
            capture_output=True,
            text=True
        )

        partitions = []
        if res.returncode != 0:
            return partitions

        # Regex for mmls standard table rows: Slot  Start  End  Length  Description
        pattern = re.compile(r"^\s*(\d{2,3}:\s+\S+|\d{2,3}:|\S+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(.+)$")
        for line in res.stdout.splitlines():
            line_str = line.strip()
            match = pattern.match(line_str)
            if match:
                slot, start, end, length, desc = match.groups()
                partitions.append({
                    "slot": slot.strip(),
                    "start_sector": int(start),
                    "end_sector": int(end),
                    "length_sectors": int(length),
                    "size_bytes": int(length) * 512,
                    "description": desc.strip(),
                    "is_allocated": "Unallocated" not in desc and "Table" not in desc
                })

        return partitions

    def parse_filesystem(self, image_path: Path, partition_offset: int) -> Dict[str, Any]:
        """
        Runs fsstat on a partition offset to extract filesystem geometry, cluster sizes, and metadata.
        """
        if not self.fsstat or not self.fsstat.exists():
            raise FileNotFoundError("fsstat executable not found in bundled Sleuth Kit.")

        res = subprocess.run(
            [str(self.fsstat), "-o", str(partition_offset), str(image_path)],
            capture_output=True,
            text=True
        )

        fs_info = {
            "partition_offset": partition_offset,
            "raw_output": res.stdout,
            "filesystem_type": "Unknown",
            "volume_name": "",
            "sector_size": 512,
            "cluster_size": 4096,
            "total_clusters": 0,
            "free_clusters": 0,
            "data_area_offset": 0,
            "fat_tables": 2
        }

        if res.returncode == 0:
            stdout = res.stdout
            for line in stdout.splitlines():
                l = line.strip()
                if "File System Type:" in l:
                    fs_info["filesystem_type"] = l.split(":", 1)[1].strip()
                elif "OEM Name:" in l or "Volume Name:" in l:
                    fs_info["volume_name"] = l.split(":", 1)[1].strip()
                elif "Sector Size:" in l:
                    try:
                        fs_info["sector_size"] = int(l.split(":", 1)[1].split()[0].strip())
                    except ValueError:
                        pass
                elif "Cluster Size:" in l:
                    try:
                        fs_info["cluster_size"] = int(l.split(":", 1)[1].split()[0].strip())
                    except ValueError:
                        pass
                elif "Total Cluster Range:" in l:
                    try:
                        parts = l.split(":", 1)[1].split("-")
                        fs_info["total_clusters"] = int(parts[1].strip()) - int(parts[0].strip()) + 1
                    except Exception:
                        pass
                elif "Data Area:" in l:
                    try:
                        fs_info["data_area_offset"] = int(l.split(":", 1)[1].split("-")[0].strip())
                    except Exception:
                        pass

        return fs_info

    def analyze_memory_evidence(self, image_path: Path) -> Dict[str, Any]:
        """
        Checks if the image represents memory (RAM dump/VMEM). If disk image, reports N/A honestly.
        """
        ext = image_path.suffix.lower()
        if ext in [".raw", ".dmp", ".vmem", ".lime", ".mem"]:
            return {
                "is_memory": True,
                "status": "MEMORY_EVIDENCE_DETECTED",
                "evidence_type": "Physical / Virtual Memory",
                "notes": "Evidence requires Volatility / memory inspection pipeline."
            }
        else:
            return {
                "is_memory": False,
                "status": "N/A",
                "evidence_type": "Disk Image",
                "notes": "N/A — evidence is a disk image, not memory evidence. Memory recovery bypassed."
            }

    def get_all_partition_offsets(self, analysis_report: Dict[str, Any]) -> List[int]:
        """
        Returns a list of all valid detected filesystem start sector offsets.
        """
        offsets = []
        # First check detected filesystems
        for fs in analysis_report.get("filesystems", []):
            off = fs.get("partition_offset")
            if off is not None and off not in offsets:
                offsets.append(off)

        # If none from filesystems, check allocated partitions
        if not offsets:
            for part in analysis_report.get("partitions", []):
                if part.get("is_allocated"):
                    off = part.get("start_sector")
                    if off is not None and off not in offsets:
                        offsets.append(off)

        return offsets if offsets else [0]

    def get_primary_partition_offset(self, analysis_report: Dict[str, Any]) -> int:
        """
        Determines the primary filesystem start sector offset from the analysis report.
        Returns the offset of the first/largest detected filesystem partition, or 0 if unpartitioned.
        """
        offsets = self.get_all_partition_offsets(analysis_report)
        return offsets[0] if offsets else 0

    def run_full_analysis(self, case_id: str, image_path: Path) -> Dict[str, Any]:
        """
        Executes complete image, partition, filesystem, and memory checks.
        Saves structured report into case analysis directory.
        """
        case_dir = resolve_case_dir(case_id)
        analysis_dir = case_dir / "analysis"
        analysis_dir.mkdir(parents=True, exist_ok=True)

        partitions = self.parse_partitions(image_path)
        filesystems = []

        for part in partitions:
            desc = part.get("description", "").lower()
            is_alloc = part.get("is_allocated", False)
            is_meta = any(k in desc for k in ["table", "unallocated", "meta", "primary table", "extended"])
            if is_alloc and not is_meta:
                offset = part["start_sector"]
                fs_data = self.parse_filesystem(image_path, offset)
                if fs_data.get("filesystem_type") != "Unknown" or fs_data.get("raw_output"):
                    filesystems.append(fs_data)

        # If no partition table recognized (e.g. raw filesystem on whole image), try offset 0
        if not filesystems and not partitions:
            fs_data_0 = self.parse_filesystem(image_path, 0)
            if fs_data_0.get("filesystem_type") != "Unknown" or fs_data_0.get("raw_output"):
                filesystems.append(fs_data_0)

        mem_check = self.analyze_memory_evidence(image_path)

        analysis_report = {
            "case_id": case_id,
            "image": get_relative_str(image_path),
            "partition_count": len(partitions),
            "partitions": partitions,
            "filesystems": filesystems,
            "primary_partition_offset": self.get_primary_partition_offset({"partitions": partitions, "filesystems": filesystems}),
            "all_partition_offsets": self.get_all_partition_offsets({"partitions": partitions, "filesystems": filesystems}),
            "memory_analysis": mem_check
        }

        output_path = analysis_dir / "image_analysis.json"
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(analysis_report, f, indent=2)

        print(f"[+] Image analysis completed. Partitions detected: {len(partitions)}")
        print(f"[+] Primary partition offset detected: {analysis_report['primary_partition_offset']}")
        print(f"[+] Analysis report saved to {output_path}")
        return analysis_report

# Singleton instance
image_analyzer = ImageAnalyzer()

if __name__ == "__main__":
    import sys
    if len(sys.argv) > 2:
        image_analyzer.run_full_analysis(sys.argv[1], Path(sys.argv[2]))
