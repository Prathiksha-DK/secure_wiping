"""
SecureWipe — Storage Safety & Anti-Misdirection Engine
Enforces strict pre-wipe safety validation, system disk protection,
anti-misdirection hardware fingerprinting, and device concurrency locking.
"""

import os
import sys
import re
import json
import time
import psutil
import hashlib
import threading
import subprocess
from typing import Dict, Any, Tuple, Optional, List, Set

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
CRITICAL_POSIX_MOUNTS = {"/", "/boot", "/boot/efi", "/etc", "/usr", "/var", "/home", "/opt", "/root", "/bin", "/sbin", "/lib"}
CRITICAL_WIN_DRIVES = {"C:", "C:\\"}

# Global Device Concurrency Locks
_device_locks: Dict[str, threading.Lock] = {}
_locks_meta_lock = threading.Lock()
_active_wipe_jobs: Dict[str, Dict[str, Any]] = {}

# ---------------------------------------------------------------------------
# Device Concurrency Lock Manager
# ---------------------------------------------------------------------------
def acquire_device_lock(canonical_id: str, job_id: str, operator: str) -> Tuple[bool, str]:
    """
    Acquire exclusive lock for a physical storage target to prevent race conditions
    and concurrent sanitization jobs targeting the same storage medium.
    """
    with _locks_meta_lock:
        if canonical_id in _active_wipe_jobs:
            active = _active_wipe_jobs[canonical_id]
            return False, f"Device is currently locked by active job {active.get('job_id')} (Operator: {active.get('operator')})"
            
        if canonical_id not in _device_locks:
            _device_locks[canonical_id] = threading.Lock()
            
        _active_wipe_jobs[canonical_id] = {
            "job_id": job_id,
            "operator": operator,
            "acquired_at": time.time(),
        }
        return True, "Lock acquired successfully."

def release_device_lock(canonical_id: str, job_id: str) -> None:
    """Release exclusive device lock."""
    with _locks_meta_lock:
        if canonical_id in _active_wipe_jobs:
            if _active_wipe_jobs[canonical_id].get("job_id") == job_id:
                del _active_wipe_jobs[canonical_id]

# ---------------------------------------------------------------------------
# Target Hardware Identification & Fingerprint
# ---------------------------------------------------------------------------
def compute_device_fingerprint(meta: Dict[str, Any]) -> str:
    """
    Compute a stable SHA-256 hardware identity fingerprint.
    Used for anti-misdirection validation (re-validated immediately prior to destructive I/O).
    """
    elements = [
        str(meta.get("serial", "")).strip().upper(),
        str(meta.get("model", "")).strip().upper(),
        str(int(meta.get("size_bytes", 0))),
        str(meta.get("bus_type", "")).strip().upper(),
        str(meta.get("target_type", "")).strip().upper(),
    ]
    raw = "|".join(elements)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()

# ---------------------------------------------------------------------------
# System Disk & Critical Mount Detectors
# ---------------------------------------------------------------------------
def get_current_workspace_mounts() -> Set[str]:
    """Get all mountpoints containing the running application or current working directory."""
    mounts = set()
    try:
        app_path = os.path.abspath(os.path.dirname(__file__))
        cwd_path = os.path.abspath(os.getcwd())
        for path in (app_path, cwd_path, sys.executable):
            part = _find_mountpoint_for_path(path)
            if part:
                mounts.add(part)
    except Exception:
        pass
    return mounts

def _find_mountpoint_for_path(path: str) -> Optional[str]:
    """Resolve the mountpoint for an arbitrary file or folder path."""
    try:
        path = os.path.abspath(path)
        while path != os.path.dirname(path):
            if os.path.ismount(path):
                return path
            path = os.path.dirname(path)
        return path
    except Exception:
        return None

def is_system_path_posix(dev_path: str) -> Tuple[bool, str]:
    """Check if Linux device path hosts any critical OS mounts or root filesystems."""
    try:
        # Run lsblk to inspect block tree and all children mountpoints
        cmd = ["lsblk", "-J", "-b", "-o", "NAME,MOUNTPOINT,PKNAME,TYPE", dev_path]
        cp = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
        if cp.returncode == 0 and cp.stdout.strip():
            data = json.loads(cp.stdout)
            for d in data.get("blockdevices", []):
                mp = d.get("mountpoint")
                if mp in CRITICAL_POSIX_MOUNTS:
                    return True, f"Device contains critical system mount: '{mp}'"
                for child in d.get("children", []):
                    cmp = child.get("mountpoint")
                    if cmp in CRITICAL_POSIX_MOUNTS:
                        return True, f"Partition '{child.get('name')}' contains critical system mount: '{cmp}'"
        
        # Check psutil disk partitions as secondary verification
        for p in psutil.disk_partitions(all=True):
            if p.mountpoint in CRITICAL_POSIX_MOUNTS:
                if p.device == dev_path or p.device.startswith(dev_path):
                    return True, f"Device hosts root/system mountpoint '{p.mountpoint}' ({p.device})"
                    
        # Check workspace mount
        ws_mounts = get_current_workspace_mounts()
        for p in psutil.disk_partitions(all=True):
            if p.mountpoint in ws_mounts:
                if p.device == dev_path or p.device.startswith(dev_path):
                    return True, f"Device hosts the active SecureWipe application runtime directory on '{p.mountpoint}'"
                    
        return False, "Target is not a system/root disk."
    except Exception as e:
        # Fail closed on query error
        return True, f"Safety check failed closed: Unable to inspect Linux mountpoints ({e})"

def is_system_path_windows(dev_identifier: str) -> Tuple[bool, str]:
    """Check if Windows target represents system drive (C:) or OS physical drive."""
    try:
        # 1. Drive letter check
        ident_clean = dev_identifier.strip().upper().rstrip("\\/")
        system_drive = os.environ.get("SystemDrive", "C:").upper().rstrip("\\/")
        if ident_clean in (system_drive, f"{system_drive}\\"):
            return True, f"Target '{dev_identifier}' is the Windows System/Boot volume ({system_drive})."
            
        # 2. PowerShell query for boot/system partition
        ps = r"""
$ErrorActionPreference = 'Stop'
$sysPart = Get-Partition | Where-Object { $_.IsBoot -or $_.IsSystem -or $_.DriveLetter -eq 'C' } | Select-Object -First 1 DiskNumber, DriveLetter
if ($sysPart) { $sysPart | ConvertTo-Json -Compress }
"""
        cp = subprocess.run(["powershell", "-NoProfile", "-Command", ps], capture_output=True, text=True, timeout=8)
        if cp.returncode == 0 and cp.stdout.strip():
            sys_disk = json.loads(cp.stdout)
            sys_disk_num = sys_disk.get("DiskNumber")
            
            # Check if dev_identifier refers to this disk number
            if f"PhysicalDrive{sys_disk_num}" in dev_identifier or f"Disk {sys_disk_num}" in dev_identifier:
                return True, f"Target is PhysicalDrive{sys_disk_num} which hosts the Windows Boot/System Partition."
                
        return False, "Target is not a Windows system disk."
    except Exception as e:
        return True, f"Safety check failed closed: Windows system disk check error ({e})"

# ---------------------------------------------------------------------------
# Comprehensive Safety Validator (Fail-Closed Architecture)
# ---------------------------------------------------------------------------
def validate_storage_safety(target: str, expected_fingerprint: Optional[str] = None) -> Dict[str, Any]:
    """
    Execute exhaustive multi-layer safety validation before allowing destructive sanitization.
    Returns: {
        'safe': bool,
        'canonical_id': str,
        'target_type': str,
        'metadata': dict,
        'fingerprint': str,
        'reasons': list[str],
        'warnings': list[str],
    }
    """
    res = {
        "safe": False,
        "target": target,
        "canonical_id": "",
        "target_type": "unknown",
        "metadata": {},
        "fingerprint": "",
        "reasons": [],
        "warnings": [],
    }
    
    if not target or not isinstance(target, str) or not target.strip():
        res["reasons"].append("Target parameter is empty or invalid.")
        return res

    target = target.strip()
    
    # 1. Check if Target is a Regular File
    if os.path.isfile(target):
        res["target_type"] = "file"
        abs_path = os.path.abspath(target)
        res["canonical_id"] = f"FILE:{abs_path}"
        
        # Check if file is critical OS file or in system directory
        if sys.platform.startswith("win"):
            windir = os.environ.get("SystemRoot", "C:\\Windows").lower()
            if abs_path.lower().startswith(windir):
                res["reasons"].append(f"SAFETY ABORT: Target file resides in Windows system directory: {abs_path}")
                return res
        else:
            for sys_dir in ("/bin", "/sbin", "/usr", "/lib", "/etc", "/boot", "/dev", "/proc", "/sys"):
                if abs_path == sys_dir or abs_path.startswith(sys_dir + "/"):
                    res["reasons"].append(f"SAFETY ABORT: Target file resides in critical Linux system directory: {abs_path}")
                    return res

        # Check if target is part of SecureWipe application codebase
        app_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
        if abs_path.startswith(app_root):
            res["reasons"].append("SAFETY ABORT: Target file is part of the SecureWipe runtime or application database.")
            return res

        sz = os.path.getsize(target)
        res["metadata"] = {"size_bytes": sz, "path": abs_path, "target_type": "file"}
        res["fingerprint"] = hashlib.sha256(f"{abs_path}|{sz}".encode()).hexdigest()
        res["safe"] = True
        return res

    # 2. Check if Target is a Directory
    if os.path.isdir(target):
        res["target_type"] = "folder"
        abs_path = os.path.abspath(target)
        res["canonical_id"] = f"DIR:{abs_path}"

        # Prevent wiping root or critical system directories
        if sys.platform.startswith("win"):
            windir = os.environ.get("SystemRoot", "C:\\Windows").lower()
            sysdrive = os.environ.get("SystemDrive", "C:").lower()
            if abs_path.lower() in (sysdrive, f"{sysdrive}\\", windir) or abs_path.lower().startswith(windir + "\\"):
                res["reasons"].append(f"SAFETY ABORT: Target directory is or resides in Windows system root: {abs_path}")
                return res
        else:
            if abs_path in CRITICAL_POSIX_MOUNTS or abs_path == "/":
                res["reasons"].append(f"SAFETY ABORT: Target directory is a critical Linux system root or mountpoint: {abs_path}")
                return res
            for sys_dir in ("/bin", "/sbin", "/usr", "/lib", "/etc", "/boot", "/dev", "/proc", "/sys"):
                if abs_path == sys_dir or abs_path.startswith(sys_dir + "/"):
                    res["reasons"].append(f"SAFETY ABORT: Target directory resides in Linux system path: {abs_path}")
                    return res

        # Prevent wiping SecureWipe workspace directory
        app_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
        if abs_path.startswith(app_root) or app_root.startswith(abs_path):
            res["reasons"].append("SAFETY ABORT: Target directory contains or is contained in SecureWipe application directory.")
            return res

        res["metadata"] = {"path": abs_path, "target_type": "folder"}
        res["fingerprint"] = hashlib.sha256(abs_path.encode()).hexdigest()
        res["safe"] = True
        return res

    # 3. Check if Target is a Linux Block Device (/dev/...)
    if target.startswith("/dev/"):
        res["target_type"] = "disk"
        res["canonical_id"] = target
        
        if not os.path.exists(target):
            res["reasons"].append(f"Device node '{target}' does not exist.")
            return res
            
        # System Disk Check
        is_sys, sys_reason = is_system_path_posix(target)
        if is_sys:
            res["reasons"].append(f"SAFETY ABORT: {sys_reason}")
            return res
            
        # Inspect Hardware Identity via lsblk
        try:
            cmd = ["lsblk", "-J", "-b", "-o", "NAME,SIZE,MODEL,SERIAL,TRAN,ROTA,TYPE", target]
            cp = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
            if cp.returncode == 0 and cp.stdout.strip():
                data = json.loads(cp.stdout)
                devs = data.get("blockdevices", [])
                if devs:
                    d = devs[0]
                    res["metadata"] = {
                        "name": target,
                        "model": (d.get("model") or "").strip(),
                        "serial": (d.get("serial") or "").strip(),
                        "size_bytes": int(d.get("size") or 0),
                        "bus_type": (d.get("tran") or "").strip(),
                        "target_type": "disk",
                    }
                    res["fingerprint"] = compute_device_fingerprint(res["metadata"])
                    res["canonical_id"] = f"DISK:{res['metadata'].get('serial') or target}"
                    
                    # Validate against expected fingerprint if supplied (Anti-Misdirection)
                    if expected_fingerprint and res["fingerprint"] != expected_fingerprint:
                        res["reasons"].append(
                            f"ANTI-MISDIRECTION ABORT: Device hardware fingerprint has changed! "
                            f"(Expected: {expected_fingerprint[:16]}..., Current: {res['fingerprint'][:16]}...). "
                            f"Device may have been re-enumerated or replaced."
                        )
                        return res
                        
                    res["safe"] = True
                    return res
        except Exception as e:
            res["reasons"].append(f"Failed to inspect device details via lsblk: {e}")
            return res

    # 4. Check if Target is a Windows Device Identifier
    if sys.platform.startswith("win"):
        res["target_type"] = "disk"
        is_sys, sys_reason = is_system_path_windows(target)
        if is_sys:
            res["reasons"].append(f"SAFETY ABORT: {sys_reason}")
            return res
            
        res["canonical_id"] = f"WIN_DISK:{target}"
        res["safe"] = True
        return res

    # Fail Closed if unresolved
    res["reasons"].append(f"Target '{target}' could not be safely resolved to a verified non-system storage object. Failing closed.")
    return res
