import json
import subprocess
import sys
import os
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
    """Enumerate physical disks on Windows using PowerShell."""
    try:
        ps_script = r"""
$ErrorActionPreference = 'Stop'
$disks = Get-PhysicalDisk | Select-Object FriendlyName, MediaType, Size, HealthStatus, BusType, SerialNumber, DeviceId
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
            health_status = d.get("HealthStatus") or "Healthy"
            serial = d.get("SerialNumber") or ""

            # Derive type
            dtype = "USB" if str(bus).upper() == "USB" else str(media_type)

            hs_lower = str(health_status).lower()
            if hs_lower == "healthy":
                health_num = 100
            elif hs_lower == "warning":
                health_num = 50
            elif hs_lower == "unhealthy":
                health_num = 10
            else:
                health_num = 100

            devices.append(
                {
                    "name": str(name),
                    "type": str(dtype),
                    "size": human_readable_size(size) if isinstance(size, (int, float)) else human_readable_size(size),
                    "sizeBytes": int(size) if isinstance(size, (int, float)) else 0,
                    "health": health_num,
                    "healthStatus": str(health_status),
                    "serial": str(serial).strip(),
                    "bus": str(bus),
                    "isSystem": False,
                }
            )
        return devices
    except Exception:
        return []


def _has_system_mount(dev_dict: Dict[str, Any]) -> bool:
    """Check if device or any child partition contains root/boot system mountpoints."""
    mp = dev_dict.get("mountpoint")
    if mp in ("/", "/boot", "/boot/efi", "/etc", "/usr", "/var"):
        return True
    for child in dev_dict.get("children", []):
        if _has_system_mount(child):
            return True
    return False


def _linux_list_devices() -> List[Dict[str, Any]]:
    """Enumerate block devices on Linux using lsblk."""
    try:
        cmd = ["lsblk", "-J", "-b", "-o", "NAME,SIZE,MODEL,SERIAL,TYPE,ROTA,TRAN,MOUNTPOINT,RM"]
        completed = subprocess.run(cmd, capture_output=True, text=True, check=False)
        if completed.returncode != 0:
            return []
        data = json.loads(completed.stdout or "{}")
        blockdevices = data.get("blockdevices", [])

        devices = []
        for d in blockdevices:
            name = d.get("name", "")
            if not name or name.startswith("loop") or name.startswith("zram"):
                continue

            model = (d.get("model") or "").strip()
            serial = (d.get("serial") or "").strip()
            size = d.get("size")
            rota = d.get("rota")  # True = HDD, False = SSD
            tran = (d.get("tran") or "").lower()  # nvme, usb, sata
            rm = d.get("rm")  # removable

            # Determine type
            if tran == "usb" or rm:
                dtype = "USB"
            elif tran == "nvme" or (tran == "sata" and rota is False):
                dtype = "SSD"
            elif rota is True:
                dtype = "HDD"
            else:
                dtype = "Storage"

            dev_name = f"/dev/{name}"
            display_name = f"{model} ({dev_name})" if model else dev_name
            is_system = _has_system_mount(d)

            devices.append(
                {
                    "name": dev_name,
                    "friendlyName": display_name,
                    "type": dtype,
                    "size": human_readable_size(size),
                    "sizeBytes": int(size) if isinstance(size, (int, float)) else 0,
                    "health": 100,
                    "healthStatus": "Healthy",
                    "serial": serial,
                    "model": model,
                    "isSystem": is_system,
                }
            )
        return devices
    except Exception:
        return []


_dev_cache = {"data": None, "expires_at": 0}


def list_devices() -> List[Dict[str, Any]]:
    import time
    now = time.time()
    if _dev_cache["data"] is not None and now < _dev_cache["expires_at"]:
        return _dev_cache["data"]

    if sys.platform.startswith("win"):
        devs = _windows_list_devices()
    else:
        devs = _linux_list_devices()

    _dev_cache["data"] = devs
    _dev_cache["expires_at"] = now + 3
    return devs
