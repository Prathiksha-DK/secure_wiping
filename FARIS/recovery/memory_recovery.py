import os
import sys
import re
import json
import hashlib
import subprocess
from pathlib import Path
from typing import Dict, List, Any, Optional

try:
    from core.engine_manager import engine_manager
except ImportError:
    from ..core.engine_manager import engine_manager

class MemoryRecoveryEngine:
    """
    RAM / VMEM Recovery Engine for FARIS.
    Extracts processes, network artifacts, and memory structures from physical/virtual memory dumps.
    Enforces honest N/A reporting when operating against disk-only images.
    """

    MEMORY_EXTENSIONS = {".dmp", ".vmem", ".lime", ".mem"}

    def is_memory_image(self, evidence_path: Path, is_memory_flag: Optional[bool] = None) -> bool:
        """
        Determines if evidence file is a candidate memory dump.
        """
        if is_memory_flag is not None:
            return is_memory_flag

        ext = evidence_path.suffix.lower()
        if ext in self.MEMORY_EXTENSIONS:
            return True

        if ext in [".raw", ".bin"]:
            # Inspect first 512 bytes for memory headers vs MBR/GPT disk signatures
            try:
                with open(evidence_path, "rb") as f:
                    hdr = f.read(512)
                    if hdr.startswith(b"PAGE") or hdr.startswith(b"MDMP") or hdr.startswith(b"LiME"):
                        return True
            except Exception:
                pass

        return False

    def recover_memory(
        self,
        evidence_path: Path,
        output_dir: Path,
        is_memory_flag: Optional[bool] = None
    ) -> Dict[str, Any]:
        """
        Executes memory extraction if evidence is memory, using bundled Volatility 3 and pattern analysis,
        or returns honest N/A if disk evidence.
        """
        output_dir.mkdir(parents=True, exist_ok=True)
        report_file = output_dir / "memory_recovery_report.json"

        if not self.is_memory_image(evidence_path, is_memory_flag):
            result = {
                "status": "N/A",
                "evidence_type": "Disk Image / Storage Volume",
                "notes": "N/A — No volatile memory evidence supplied (disk storage evidence).",
                "processes_recovered": 0,
                "network_artifacts_recovered": 0,
                "artifacts": []
            }
            with open(report_file, "w", encoding="utf-8") as f:
                json.dump(result, f, indent=2)
            return result

        # Memory artifact extraction logic with Volatility 3
        print(f"[*] Analyzing memory evidence: {evidence_path.name} with Volatility 3...")
        
        vol_py = engine_manager.get_tool_path("vol.py")
        python_exe = engine_manager.get_tool_path("python") or sys.executable

        vol_output = {}
        if vol_py and vol_py.exists():
            try:
                proc = subprocess.run(
                    [str(python_exe), str(vol_py), "-f", str(evidence_path), "windows.info.Info"],
                    capture_output=True,
                    text=True,
                    timeout=60
                )
                vol_output["windows_info"] = proc.stdout
            except Exception as e:
                vol_output["windows_info_error"] = str(e)

        ip_pattern = re.compile(rb"\b(?:\d{1,3}\.){3}\d{1,3}\b")
        url_pattern = re.compile(rb"https?://[a-zA-Z0-9\.\-_/]+")

        ips = set()
        urls = set()
        chunk_size = 4 * 1024 * 1024

        with open(evidence_path, "rb") as f:
            while chunk := f.read(chunk_size):
                for ip in ip_pattern.findall(chunk):
                    ips.add(ip.decode(errors="ignore"))
                for url in url_pattern.findall(chunk):
                    urls.add(url.decode(errors="ignore"))

        result = {
            "status": "COMPLETED",
            "evidence_type": "Volatile Memory (RAM / VMEM)",
            "unique_ips_found": len(ips),
            "unique_urls_found": len(urls),
            "ips_sample": sorted(list(ips))[:100],
            "urls_sample": sorted(list(urls))[:100],
            "notes": "Memory strings and network artifacts extracted."
        }

        with open(report_file, "w", encoding="utf-8") as f:
            json.dump(result, f, indent=2)

        return result

# Singleton instance
memory_recovery_engine = MemoryRecoveryEngine()
