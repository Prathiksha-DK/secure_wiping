import json
import subprocess
import sys
from typing import List, Dict, Any


def human_readable_size(num_bytes: Any) -> str:
    if num_bytes is None:
        return "Unknown"
    try:
        size = float(num_bytes)
    except Exception:
        return "Unknown"
    step = 1024.0
    for unit in ["B", "KB", "MB", "GB", "TB", "PB"]:
        if size < step:
            return f"{size:.1f} {unit}"
        size /= step
    return f"{size * step:.1f} PB"


def _windows_list_devices() -> List[Dict[str, Any]]:
    """Enumerate physical disks on Windows using PowerShell.
    Maps results to the required schema.
    """
    try:
        ps_script = r"""
$ErrorActionPreference = 'Stop'
$disks = Get-PhysicalDisk | Select-Object FriendlyName, MediaType, Size, HealthStatus, BusType, SerialNumber
$disks | ConvertTo-Json -Depth 3
"""
        completed = subprocess.run(
            ["powershell", "-NoProfile", "-Command", ps_script],
            capture_output=True,
            text=True,
            check=False,
        )
        if completed.returncode != 0:
            return []
        raw = completed.stdout.strip()
        if not raw:
            return []
        data = json.loads(raw)
        if isinstance(data, dict):
            data = [data]

        devices = []
        for d in data:
            name = d.get("FriendlyName") or "Unknown Device"
            media_type = d.get("MediaType") or "Unspecified"
            bus = d.get("BusType") or ""
            size = d.get("Size")
            health_status = d.get("HealthStatus") or "Unknown"

            # Derive type
            dtype = "USB" if str(bus).upper() == "USB" else str(media_type)

            # Map health to a numeric score
            hs_lower = str(health_status).lower()
            if hs_lower == "healthy":
                health_num = 100
            elif hs_lower == "warning":
                health_num = 50
            elif hs_lower == "unhealthy":
                health_num = 10
            else:
                health_num = 0

            devices.append(
                {
                    "name": str(name),
                    "type": str(dtype),
                    "size": human_readable_size(size) if isinstance(size, (int, float)) else human_readable_size(size),
                    "health": health_num,
                    "healthStatus": str(health_status),
                }
            )
        return devices
    except Exception:
        # On any unexpected error, return an empty list to avoid 500s
        return []


def list_devices() -> List[Dict[str, Any]]:
    if sys.platform.startswith("win"):
        return _windows_list_devices()
    # Non-Windows fallback: return an empty list (or add Linux/macOS implementations later)
    return []

