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

class MetadataRecoveryEngine:
    """
    Dynamic Inode / Metadata Extraction Engine using bundled TSK icat.
    Extracts raw metadata and file data streams for any dynamically discovered artifact/inode ID.
    Operates without hard-coded case IDs, image paths, partition offsets, or inode IDs.
    """

    def __init__(self):
        self.icat = engine_manager.get_tool_path("icat")

    def recover_artifact_metadata(
        self,
        case_id: str,
        image_path: Path,
        artifact_id: str,
        partition_offset: int,
        output_dir: Optional[Path] = None,
        artifact_name: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Recovers metadata and content stream for a specific dynamically discovered artifact ID.
        """
        if not self.icat or not self.icat.exists():
            raise FileNotFoundError("icat executable not found in bundled Sleuth Kit engines.")

        case_dir = resolve_case_dir(case_id)
        if output_dir is None:
            output_dir = case_dir / "recovery" / "metadata"
        output_dir.mkdir(parents=True, exist_ok=True)

        # Sanitize artifact identifier and filename
        clean_id = re.sub(r"[^\w\-]", "_", str(artifact_id)).strip("_")
        if not clean_id:
            clean_id = "unknown"

        safe_name = ""
        if artifact_name:
            safe_name = re.sub(r"[^\w\-.]", "_", Path(artifact_name).name).strip("_")

        if safe_name:
            out_filename = f"metadata_{safe_name}_inode_{clean_id}.bin"
        else:
            out_filename = f"metadata_inode_{clean_id}.bin"

        output_file = output_dir / out_filename

        cmd = [
            str(self.icat),
            "-o", str(partition_offset),
            str(image_path),
            str(artifact_id)
        ]

        stdout_bytes = b""
        stderr_text = ""
        returncode = -1

        try:
            res = subprocess.run(cmd, capture_output=True, timeout=60)
            stdout_bytes = res.stdout
            stderr_text = res.stderr.decode(errors="replace")
            returncode = res.returncode
        except Exception as e:
            stderr_text = str(e)

        recovered_size = len(stdout_bytes)
        status = "FAILED"
        if returncode == 0 and recovered_size > 0:
            status = "RECOVERED"
            with open(output_file, "wb") as f_out:
                f_out.write(stdout_bytes)
        elif returncode == 0 and recovered_size == 0:
            status = "ZERO_BYTE_RECORD"
            with open(output_file, "wb") as f_out:
                f_out.write(b"")
        else:
            status = "EXTRACTION_ERROR"

        import datetime
        return {
            "case_id": case_id,
            "artifact_id": str(artifact_id),
            "artifact_name": artifact_name or "",
            "expected_size": None,
            "partition_offset": partition_offset,
            "source_image": get_relative_str(image_path),
            "output_file": get_relative_str(output_file) if output_file.exists() else "",
            "size_bytes": recovered_size,
            "recovery_method": "metadata/icat",
            "status": status,
            "error": stderr_text if status == "EXTRACTION_ERROR" else "",
            "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat()
        }

    def recover_all_discovered_artifacts(
        self,
        case_id: str,
        image_path: Path,
        discovered_artifacts: List[Dict[str, Any]],
        partition_offset: int,
        output_dir: Optional[Path] = None,
        max_artifacts: Optional[int] = None
    ) -> List[Dict[str, Any]]:
        """
        Dynamically extracts metadata/content for all discovered artifacts using parallel workers.
        """
        targets = [art for art in discovered_artifacts if art.get("inode")]
        if max_artifacts is not None and max_artifacts > 0:
            targets = targets[:max_artifacts]

        if not targets:
            return []

        def _extract(art):
            inode = art.get("inode")
            name = art.get("filename") or art.get("filepath")
            p_offset = art.get("partition_offset", partition_offset)
            expected_sz = art.get("size") or art.get("size_bytes")
            res = self.recover_artifact_metadata(
                case_id=case_id,
                image_path=image_path,
                artifact_id=str(inode),
                partition_offset=p_offset,
                output_dir=output_dir,
                artifact_name=name
            )
            res["expected_size"] = expected_sz
            return res

        from concurrent.futures import ThreadPoolExecutor
        workers = min(8, len(targets))
        with ThreadPoolExecutor(max_workers=workers) as executor:
            results = list(executor.map(_extract, targets))
        return results

# Singleton instance
metadata_recovery_engine = MetadataRecoveryEngine()