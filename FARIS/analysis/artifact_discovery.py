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

# Extension categorization rules
CATEGORIES = {
    "database": [".sqlite", ".sqlite3", ".db", ".db3", ".mdb", ".accdb", ".sql"],
    "document": [".pdf", ".docx", ".doc", ".xlsx", ".xls", ".pptx", ".txt", ".rtf", ".odt", ".csv", ".json", ".xml"],
    "image": [".jpg", ".jpeg", ".png", ".gif", ".bmp", ".webp", ".tiff", ".ico"],
    "archive": [".zip", ".rar", ".7z", ".tar", ".gz", ".bz2"],
    "media": [".mp4", ".mov", ".avi", ".mkv", ".mp3", ".wav", ".flac"],
    "system": [".exe", ".dll", ".sys", ".evtx", ".reg", ".dat", ".wmi", ".inf", ".ini"]
}

class ArtifactDiscoveryEngine:
    """
    Forensic Artifact Discovery Layer.
    Discovers active, deleted, and orphaned files, categorizing them by forensic type.
    """

    def __init__(self):
        self.fls = engine_manager.get_tool_path("fls")

    def categorize_filename(self, filename: str) -> str:
        ext = Path(filename).suffix.lower()
        for cat, ext_list in CATEGORIES.items():
            if ext in ext_list:
                return cat
        return "other"

    def discover_artifacts(
        self,
        image_path: Path,
        partition_offset: int = 2048,
        include_active: bool = True,
        include_deleted: bool = True
    ) -> List[Dict[str, Any]]:
        """
        Executes fls against partition to discover all filesystem entries.
        """
        if not self.fls or not self.fls.exists():
            raise FileNotFoundError("fls executable not found in bundled Sleuth Kit.")

        cmd = [str(self.fls), "-o", str(partition_offset), "-r", "-p"]
        if include_deleted and not include_active:
            cmd.append("-d")
        elif include_active and not include_deleted:
            cmd.append("-u")
        # else default captures all

        cmd.append(str(image_path))

        print(f"[*] Running fls artifact discovery on {image_path.name} (offset {partition_offset})...")
        res = subprocess.run(cmd, capture_output=True, text=True)

        discovered = []
        if res.returncode != 0:
            print(f"[!] fls returned non-zero code: {res.stderr}")
            return discovered

        # Regex for fls lines:
        # Format: d/d * 4-144-1: dirname  OR  r/r 7: filename.ext  OR  r/- * 8: _deleted.ext
        line_pattern = re.compile(r"^\s*([a-z\-\*\+]+/[a-z\-\*\+]+)\s+(\*?\s*)([\d\-\(\)]+):\s*(.+)$")

        for line in res.stdout.splitlines():
            l = line.strip()
            match = line_pattern.match(l)
            if match:
                entry_type, del_marker, inode, filepath = match.groups()
                is_deleted = "*" in del_marker or "-" in entry_type or entry_type.startswith("r/-")
                is_dir = entry_type.startswith("d")
                clean_name = filepath.strip()
                inode_clean = inode.strip()

                category = "directory" if is_dir else self.categorize_filename(clean_name)

                artifact = {
                    "inode": inode_clean,
                    "filepath": clean_name,
                    "filename": Path(clean_name).name,
                    "is_directory": is_dir,
                    "is_deleted": is_deleted,
                    "entry_type": entry_type,
                    "category": category,
                    "partition_offset": partition_offset,
                    "source_image": image_path.name
                }
                discovered.append(artifact)

        print(f"[+] Artifact discovery completed. Found {len(discovered)} filesystem entries.")
        return discovered

    def run_case_discovery(self, case_id: str, image_path: Path, partition_offset: int = 2048) -> Dict[str, Any]:
        """
        Runs discovery and saves structured JSON catalog in case analysis folder.
        """
        case_dir = resolve_case_dir(case_id)
        analysis_dir = case_dir / "analysis"
        analysis_dir.mkdir(parents=True, exist_ok=True)

        artifacts = self.discover_artifacts(image_path, partition_offset=partition_offset)

        deleted_count = sum(1 for a in artifacts if a["is_deleted"])
        active_count = len(artifacts) - deleted_count
        categories_count = {}
        for a in artifacts:
            cat = a["category"]
            categories_count[cat] = categories_count.get(cat, 0) + 1

        summary = {
            "case_id": case_id,
            "source_image": get_relative_str(image_path),
            "partition_offset": partition_offset,
            "total_artifacts": len(artifacts),
            "active_artifacts": active_count,
            "deleted_artifacts": deleted_count,
            "categories": categories_count,
            "artifacts": artifacts
        }

        out_path = analysis_dir / "discovered_artifacts.json"
        with open(out_path, "w", encoding="utf-8") as f:
            json.dump(summary, f, indent=2)

        print(f"[+] Discovery catalog saved to: {out_path}")
        return summary

# Singleton instance
artifact_discovery_engine = ArtifactDiscoveryEngine()

if __name__ == "__main__":
    test_img = FARIS_ROOT / "case001" / "pendrive_image.E01"
    if test_img.exists():
        artifact_discovery_engine.run_case_discovery("case001", test_img, 2048)