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
    """Enumerate physical disks on Windows using PowerShell with full path resolution."""
    try:
        import base64
        ps_script = (
            "ConvertTo-Json -InputObject @{ "
            "Disks = @(Get-Disk -ErrorAction SilentlyContinue | Select-Object Number, FriendlyName, SerialNumber, BusType, PartitionStyle, Size, LogicalSectorSize, PhysicalSectorSize, IsBoot, IsSystem); "
            "PhysicalDisks = @(Get-PhysicalDisk -ErrorAction SilentlyContinue | Select-Object FriendlyName, MediaType, Size, HealthStatus, BusType, SerialNumber, DeviceId); "
            "Partitions = @(Get-Partition -ErrorAction SilentlyContinue | Select-Object DiskNumber, PartitionNumber, DriveLetter, Size, Offset, Type, IsBoot, IsSystem) "
            "} -Depth 4"
        )
        enc = base64.b64encode(ps_script.encode("utf-16le")).decode("ascii")
        completed = subprocess.run(
            ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-EncodedCommand", enc],
            capture_output=True,
            text=True,
            check=False,
            timeout=10,
        )
        if completed.returncode != 0 or not completed.stdout.strip():
            return []
        data = json.loads(completed.stdout)
        disks_data = data.get("Disks") or []
        pdisks_data = data.get("PhysicalDisks") or []
        parts_data = data.get("Partitions") or []

        if isinstance(disks_data, dict):
            disks_data = [disks_data]
        if isinstance(pdisks_data, dict):
            pdisks_data = [pdisks_data]
        if isinstance(parts_data, dict):
            parts_data = [parts_data]

        # Map physical disk details by device id / serial
        pdisk_map: Dict[str, Dict[str, Any]] = {}
        for pd in pdisks_data:
            dev_id = str(pd.get("DeviceId", "")).strip()
            if dev_id:
                pdisk_map[dev_id] = pd
            sn = str(pd.get("SerialNumber", "")).strip()
            if sn:
                pdisk_map[sn] = pd

        # Map partitions by disk number
        parts_by_disk: Dict[int, List[Dict[str, Any]]] = {}
        for p in parts_data:
            dn = p.get("DiskNumber")
            if dn is not None:
                parts_by_disk.setdefault(int(dn), []).append(p)

        devices = []
        for d in disks_data:
            dnum = d.get("Number")
            name = d.get("FriendlyName") or "Unknown Device"
            bus = d.get("BusType") or ""
            size = d.get("Size")
            serial = d.get("SerialNumber") or ""
            is_boot = bool(d.get("IsBoot"))
            is_system = bool(d.get("IsSystem")) or is_boot

            # Physical disk overlay
            pd_match = pdisk_map.get(str(dnum)) or pdisk_map.get(str(serial).strip()) or {}
            media_type = pd_match.get("MediaType") or d.get("PartitionStyle") or "Unspecified"
            health_status = pd_match.get("HealthStatus") or "Healthy"

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

            # Find drive letters
            disk_parts = parts_by_disk.get(int(dnum) if dnum is not None else -1, [])
            drive_letters = [
                f"{p['DriveLetter']}:"
                for p in disk_parts
                if p.get("DriveLetter") and str(p.get("DriveLetter")).strip()
            ]

            dev_path = f"\\\\.\\PhysicalDrive{dnum}" if dnum is not None else ""
            display_name = f"{name} ({dev_path})" if dev_path else str(name)
            if drive_letters:
                display_name += f" [{', '.join(drive_letters)}]"

            devices.append(
                {
                    "name": str(name),
                    "friendlyName": display_name,
                    "devicePath": dev_path,
                    "deviceId": str(dnum) if dnum is not None else "",
                    "driveLetters": drive_letters,
                    "type": str(dtype),
                    "size": human_readable_size(size) if isinstance(size, (int, float)) else human_readable_size(size),
                    "sizeBytes": int(size) if isinstance(size, (int, float)) else 0,
                    "health": health_num,
                    "healthStatus": str(health_status),
                    "serial": str(serial).strip(),
                    "bus": str(bus),
<<<<<<< HEAD
                    "isSystem": is_sys,
=======
                    "isSystem": is_system,
>>>>>>> backup/storage-inspector-fat32
                }
            )
        return devices
    except Exception:
        return []


def _has_system_mount(dev_dict: Dict[str, Any]) -> bool:
    """Check if device or any child partition contains root/boot/critical system mountpoints."""
    critical_mounts = {"/", "/boot", "/boot/efi", "/etc", "/usr", "/var", "/home", "/opt", "/root"}
    mp = dev_dict.get("mountpoint")
    if mp in critical_mounts:
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
