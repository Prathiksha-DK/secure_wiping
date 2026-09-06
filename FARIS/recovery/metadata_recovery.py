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
        self.tsk_recover = engine_manager.get_tool_path("tsk_recover")

    def extract_filesystem_tree(
        self,
        case_id: str,
        image_path: Path,
        partition_offset: int,
        output_dir: Optional[Path] = None
    ) -> Dict[str, Any]:
        """
        Extracts full filesystem directory structure and file hierarchies using bundled TSK tsk_recover.
        Recovers both allocated and unallocated/deleted files while preserving folders.
        """
        case_dir = resolve_case_dir(case_id)
        if output_dir is None:
            output_dir = case_dir / "recovery" / "filesystem_tree"
        output_dir.mkdir(parents=True, exist_ok=True)

        if not self.tsk_recover or not self.tsk_recover.exists():
            print("[!] tsk_recover executable not found in bundled Sleuth Kit.")
            return {"status": "NOT_AVAILABLE", "recovered_count": 0, "artifacts": []}

        # First attempt: -e (recover all files: allocated and unallocated)
        cmd = [
            str(self.tsk_recover),
            "-e",
            "-o", str(partition_offset),
            str(image_path),
            str(output_dir)
        ]

        print(f"[*] Running tsk_recover on {image_path.name} (offset {partition_offset}) to {output_dir.name}...")
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=180)
        
        # Fallback to -a (allocated only) if -e encountered an unsupported option or error
        if res.returncode != 0 and len(list(output_dir.rglob("*"))) == 0:
            print(f"[!] tsk_recover -e returned {res.returncode}. Retrying with -a (allocated files)...")
            cmd_a = [
                str(self.tsk_recover),
                "-a",
                "-o", str(partition_offset),
                str(image_path),
                str(output_dir)
            ]
            res = subprocess.run(cmd_a, capture_output=True, text=True, timeout=180)

        recovered_artifacts = []
        for root, dirs, files in os.walk(output_dir):
            for fname in files:
                fpath = Path(root) / fname
                try:
                    rel_p = fpath.relative_to(output_dir)
                    sz = fpath.stat().st_size
                    recovered_artifacts.append({
                        "filename": fname,
                        "relative_path": str(rel_p).replace("\\", "/"),
                        "output_file": get_relative_str(fpath),
                        "size_bytes": sz,
                        "is_directory": False,
                        "recovery_method": "filesystem_tree/tsk_recover",
                        "status": "RECOVERED" if sz > 0 else "ZERO_BYTE_RECORD"
                    })
                except Exception:
                    pass

        print(f"[+] tsk_recover extracted {len(recovered_artifacts)} filesystem artifacts into intact directory structure.")
        return {
            "status": "COMPLETED",
            "output_dir": get_relative_str(output_dir),
            "recovered_count": len(recovered_artifacts),
            "artifacts": recovered_artifacts
        }

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
        Preserves original filename, extension, and relative path.
        """
        if not self.icat or not self.icat.exists():
            raise FileNotFoundError("icat executable not found in bundled Sleuth Kit engines.")

        case_dir = resolve_case_dir(case_id)
        if output_dir is None:
            output_dir = case_dir / "recovery" / "metadata"
        output_dir.mkdir(parents=True, exist_ok=True)

        # Sanitize artifact identifier and filename
        clean_id = re.sub(r"[^\w\-]", "_", str(artifact_id)).strip("_") or "unknown"

        safe_rel_path = ""
        orig_filename = ""
        if artifact_name:
            norm_name = str(artifact_name).replace("\\", "/").strip("/")
            path_parts = [re.sub(r"[^\w\-.]", "_", p) for p in norm_name.split("/") if p]
            if path_parts:
                safe_rel_path = "/".join(path_parts)
                orig_filename = path_parts[-1]

        if orig_filename:
            # Preserve original filename and extension
            ext = Path(orig_filename).suffix
            stem = Path(orig_filename).stem
            out_filename = f"{stem}_inode_{clean_id}{ext}" if ext else f"{orig_filename}_inode_{clean_id}"
        else:
            out_filename = f"artifact_inode_{clean_id}.bin"

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
            "artifact_name": artifact_name or orig_filename or out_filename,
            "relative_path": safe_rel_path or orig_filename or out_filename,
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
        # Exclude pure directory entries from icat (directories are handled by tsk_recover / tree builder)
        targets = [art for art in discovered_artifacts if art.get("inode") and not art.get("is_directory")]
        if max_artifacts is not None and max_artifacts > 0:
            targets = targets[:max_artifacts]

        if not targets:
            return []

        def _extract(art):
            inode = art.get("inode")
            name = art.get("filepath") or art.get("filename")
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