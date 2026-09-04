import os
import sys
import datetime
import subprocess
from pathlib import Path
from typing import Dict, Any, Optional

try:
    from core.paths import FARIS_ROOT, resolve_case_dir, get_relative_str
    from core.engine_manager import engine_manager
except ImportError:
    from ..core.paths import FARIS_ROOT, resolve_case_dir, get_relative_str
    from ..core.engine_manager import engine_manager

def acquire_physical_device(
    case_id: str,
    source_device: str,
    examiner: str = "Examiner",
    evidence_id: str = "EVID_001",
    description: str = "Physical Device Acquisition",
    notes: str = "",
    media_type: str = "removable",
    compression: str = "fast",
    timeout_seconds: Optional[int] = 3600
) -> Dict[str, Any]:
    """
    Forensic bit-stream physical acquisition using bundled ewfacquire (libewf).
    Creates Expert Witness Format (EnCase 7 / E01) multi-segment image with SHA-256 integrity hash.
    Executes in strict unattended non-interactive mode (-u) with complete programmatic metadata flags.
    
    FORENSIC NOTICE:
    Software-level read-only handling does NOT provide hardware write-blocker guarantees.
    For forensic acquisition of seized physical evidence, hardware write blocking is recommended.
    """
    ewfacquire = engine_manager.get_tool_path("ewfacquire")
    if not ewfacquire or not ewfacquire.exists():
        raise FileNotFoundError("Bundled ewfacquire executable not found under engines/libewf.")

    case_dir = resolve_case_dir(case_id)
    acquired_dir = case_dir / "acquired"
    acquired_dir.mkdir(parents=True, exist_ok=True)
    logs_dir = case_dir / "logs"
    logs_dir.mkdir(parents=True, exist_ok=True)

    output_base = acquired_dir / f"{case_id}_evidence"

    # Sanitize metadata inputs to ensure valid argument values
    c_num = str(case_id).strip() if str(case_id).strip() else "CASE_001"
    e_num = str(evidence_id).strip() if str(evidence_id).strip() else "EVID_001"
    ex_name = str(examiner).strip() if str(examiner).strip() else "Examiner"
    desc = str(description).strip() if str(description).strip() else "Physical Device Acquisition"
    nts = str(notes).strip() if str(notes).strip() else "FARIS Automated Acquisition"

    # Determine initial media flags based on device path
    clean_src = source_device.strip().rstrip('\\')
    media_flag = "physical"
    if len(clean_src) == 2 and clean_src[1] == ":":
        clean_src = f"\\\\.\\{clean_src}"
        media_flag = "logical"
    elif clean_src.lower().startswith("\\\\.\\") and len(clean_src) == 6 and clean_src[5] == ":":
        media_flag = "logical"

    def build_command(target_src: str, m_flag: str):
        return [
            str(ewfacquire),
            "-u",                      # Unattended mode (disables interactive user prompts)
            "-C", c_num,               # Case number / identifier
            "-E", e_num,               # Evidence item ID / number
            "-e", ex_name,             # Examiner / operator name
            "-D", desc,                # Evidence description
            "-N", nts,                 # Forensic case notes
            "-m", media_type,          # Media type (removable / fixed)
            "-M", m_flag,              # Media flags (physical or logical)
            "-c", compression,         # Compression (fast)
            "-d", "sha256",            # Calculate SHA-256 digest
            "-f", "encase7",           # EnCase 7 EWF format
            "-t", str(output_base),    # Target output base name (without extension)
            target_src                 # Source device or volume handle
        ]

    command = build_command(clean_src, media_flag)

    log_path = logs_dir / "acquisition.log"
    with open(log_path, "w", encoding="utf-8") as f_log:
        f_log.write(f"FARIS Acquisition Log - {datetime.datetime.now(datetime.timezone.utc).isoformat()}\n")
        f_log.write(f"Source Device: {clean_src} (Flags: {media_flag})\n")
        f_log.write(f"Output Target: {output_base}.E01\n")
        f_log.write(f"Examiner:      {ex_name}\n")
        f_log.write(f"Evidence ID:   {e_num}\n")
        f_log.write(f"Command:       {' '.join(command)}\n\n")

    print("==================================================")
    print(" FARIS FORENSIC BIT-STREAM ACQUISITION")
    print("==================================================")
    print(f" Case ID:       {case_id}")
    print(f" Evidence ID:   {e_num}")
    print(f" Source Device: {clean_src} (Mode: {media_flag})")
    print(f" Output Target: {output_base}.E01")
    print(f" Examiner:      {ex_name}")
    print(" Mode:          Unattended / Non-Interactive (-u)")
    print(" Notice:        Hardware write-blocker recommended for live evidence.")
    print("==================================================")

    stdout_data = ""
    stderr_data = ""
    returncode = -1

    try:
        proc = subprocess.Popen(
            command,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        stdout_data, stderr_data = proc.communicate(timeout=timeout_seconds)
        returncode = proc.returncode

        # If physical drive handle failed with access denied on Windows, retry with accessible volume handle
        if returncode != 0 and ("access denied" in (stderr_data + stdout_data).lower() or "unable to open" in (stderr_data + stdout_data).lower()):
            from acquisition.device_discovery import device_discovery_manager
            fallback_vol = None
            for d in device_discovery_manager.scan_devices():
                if d.get("device_id") == source_device or d.get("physical_path") == source_device:
                    letters = d.get("drive_letters", "").split(",")
                    for l in letters:
                        clean_l = l.strip().rstrip("\\")
                        if clean_l and len(clean_l) <= 3:
                            fallback_vol = f"\\\\.\\{clean_l}"
                            break
                    if fallback_vol:
                        break

            if fallback_vol and fallback_vol != clean_src:
                print(f"[*] Physical handle restricted. Retrying acquisition via accessible volume handle {fallback_vol}...")
                command = build_command(fallback_vol, "logical")
                with open(log_path, "a", encoding="utf-8") as f_log:
                    f_log.write(f"\n[*] Physical access restricted. Retrying via volume handle: {fallback_vol}\n")
                    f_log.write(f"Command: {' '.join(command)}\n\n")

                proc = subprocess.Popen(
                    command,
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True
                )
                stdout_data, stderr_data = proc.communicate(timeout=timeout_seconds)
                returncode = proc.returncode

    except subprocess.TimeoutExpired:
        proc.kill()
        stdout_data, stderr_data = proc.communicate()
        stderr_data += f"\n[!] ERROR: Acquisition timed out after {timeout_seconds} seconds."
        returncode = -999
    except Exception as e:
        stderr_data += f"\n[!] ERROR: Subprocess execution exception: {e}"
        returncode = -1

    with open(log_path, "a", encoding="utf-8") as f_log:
        f_log.write("--- STDOUT ---\n" + (stdout_data or "") + "\n")
        f_log.write("--- STDERR ---\n" + (stderr_data or "") + "\n")
        f_log.write(f"Return Code: {returncode}\n")

    primary_e01 = acquired_dir / f"{case_id}_evidence.E01"
    success = (returncode == 0) and primary_e01.exists() and (primary_e01.stat().st_size > 0)

    return {
        "status": "SUCCESS" if success else "FAILED",
        "case_id": case_id,
        "evidence_id": e_num,
        "source_device": source_device,
        "primary_image": get_relative_str(primary_e01) if primary_e01.exists() else "",
        "acquired_dir": get_relative_str(acquired_dir),
        "return_code": returncode,
        "log_file": get_relative_str(log_path),
        "stdout": stdout_data,
        "stderr": stderr_data,
        "command": command,
        "write_protection_notice": "Software-level read-only handling applied. Hardware write-blocker recommended for legal acquisition."
    }

if __name__ == "__main__":
    src = input("Enter physical device (e.g. \\\\.\\PhysicalDrive1): ").strip()
    if src:
        acquire_physical_device("case001", src)