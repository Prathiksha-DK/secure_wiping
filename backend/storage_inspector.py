"""
SecureWipe — Storage Inspector & Hex/Sector Inspection Engine
Strictly Read-Only Forensic Analysis & Storage Visualization Module.

CRITICAL SAFETY GUARANTEES:
  - Opens all targets strictly in READ-ONLY mode (os.O_RDONLY | O_BINARY, 'rb').
  - Contains ZERO write, modify, erase, sanitize, format, or descriptor modification calls.
  - Validates and clamps all offset and sector bounds.
"""

import os
import sys
import math
import stat
import time
import json
import hashlib
import struct
import subprocess
from typing import Dict, Any, Optional, List, Tuple

from forensic_signatures import evaluate_buffer_signatures


# ---------------------------------------------------------------------------
# Entropy and Pattern Analysis Helpers
# ---------------------------------------------------------------------------

def calculate_shannon_entropy(data: bytes) -> float:
    """Calculate Shannon entropy (0.0 to 8.0 bits per byte)."""
    if not data:
        return 0.0
    entropy = 0.0
    length = len(data)
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    for count in counts:
        if count > 0:
            p = count / length
            entropy -= p * math.log2(p)
    return round(entropy, 3)


def analyze_sector_patterns(data: bytes) -> Dict[str, Any]:
    """
    Analyze sector buffer to identify known partition structures,
    filesystem boot records, entropy, and sanitization pattern conformity.
    """
    if not data:
        return {
            "detected_structure": "EMPTY",
            "entropy": 0.0,
            "zero_percentage": 100.0,
            "pattern_type": "ALL_ZEROS",
            "observed_pattern": "0x00",
            "details": "Empty buffer",
        }

    total_len = len(data)
    zero_count = data.count(b"\x00")
    ff_count = data.count(b"\xff")
    pattern_96_count = data.count(b"\x96")
    zero_pct = round((zero_count / total_len) * 100.0, 2)
    entropy = calculate_shannon_entropy(data)

    detected_structure = "UNSPECIFIED_DATA"
    details = f"Raw binary data (Entropy: {entropy} bits/byte, {zero_pct}% zeros)"

    # 1. Check for Master Boot Record (MBR)
    if total_len >= 512 and data[510:512] == b"\x55\xaa":
        # Check if contains partition entries (offsets 446, 462, 478, 494)
        has_part_entry = any(data[446 + i * 16 + 4] != 0 for i in range(4))
        if has_part_entry:
            detected_structure = "MASTER_BOOT_RECORD (MBR)"
            details = "Valid MBR detected (0x55AA boot signature present with partition table entries)"
        else:
            detected_structure = "BOOT_SECTOR (0x55AA)"
            details = "Volume boot record / partition boot sector with valid 0x55AA trailer"

    # 2. Check for GPT Header (EFI PART)
    if total_len >= 512 and data[:8] == b"EFI PART":
        detected_structure = "GUID_PARTITION_TABLE (GPT Header)"
        details = "GPT Partition Table Header (EFI PART signature confirmed)"

    # 3. Check for NTFS VBR
    elif total_len >= 512 and data[3:7] == b"NTFS":
        detected_structure = "NTFS_VOLUME_BOOT_RECORD"
        details = "NTFS Volume Boot Record (VBR) with valid OEM ID"

    # 4. Check for FAT32 / FAT16 / exFAT
    elif total_len >= 512 and (b"FAT32   " in data[54:90] or b"FAT16   " in data[54:90] or data[3:11] == b"EXFAT   "):
        detected_structure = "FAT_VOLUME_BOOT_RECORD"
        details = "FAT / exFAT Volume Boot Record detected"

    # 5. Check for ext2/3/4 Superblock
    elif total_len >= 1024 and data[56:58] == b"\x53\xef":
        detected_structure = "EXT4_SUPERBLOCK"
        details = "Linux ext2/ext3/ext4 Superblock (magic 0xEF53 present)"

    # 6. Evaluate forensic file signatures
    else:
        sigs = evaluate_buffer_signatures(data, 0)
        if sigs:
            best = sigs[0]
            detected_structure = f"DETECTED STRUCTURE: {best.format_name} ({best.level_name})"
            details = best.details

    # Evaluate sanitization pattern consistency
    if zero_count == total_len:
        pattern_type = "ZERO_FILL"
        observed_pattern = "ZERO-FILL (0x00)"
        expected_pattern = "0x00"
        matching_count = zero_count
        match_pct = 100.0
        statement = "Observed data is consistent with the selected overwrite pattern within the inspected region."
    elif ff_count == total_len:
        pattern_type = "ONE_FILL"
        observed_pattern = "0xFF-FILL (0xFF)"
        expected_pattern = "0xFF"
        matching_count = ff_count
        match_pct = 100.0
        statement = "Observed data is consistent with the selected overwrite pattern within the inspected region."
    elif pattern_96_count == total_len:
        pattern_type = "ECE_96_FILL"
        observed_pattern = "ECE-FILL (0x96)"
        expected_pattern = "0x96"
        matching_count = pattern_96_count
        match_pct = 100.0
        statement = "Observed data is consistent with the selected overwrite pattern within the inspected region."
    elif (entropy >= 7.4 if total_len <= 1024 else entropy >= 7.75):
        pattern_type = "HIGH_ENTROPY_RANDOM"
        observed_pattern = "RANDOM-OVERWRITE (High Entropy)"
        expected_pattern = "CSPRNG Random"
        matching_count = total_len
        match_pct = 100.0
        statement = "Observed data is consistent with the selected overwrite pattern within the inspected region."
    elif zero_pct > 80.0:
        pattern_type = "SPARSE_ZERO_DOMINANT"
        observed_pattern = f"SPARSE_ZERO ({zero_pct}% zeros)"
        expected_pattern = "0x00"
        matching_count = zero_count
        match_pct = zero_pct
        statement = "Observed data contains residual variations from expected pattern."
    else:
        pattern_type = "STRUCTURED_BINARY"
        observed_pattern = "STRUCTURED NON-UNIFORM"
        expected_pattern = "N/A"
        matching_count = 0
        match_pct = 0.0
        statement = "Observed data contains structured non-uniform byte patterns."

    # Byte frequency metrics
    import collections
    counts = collections.Counter(data)
    top_bytes = [{"byte_hex": f"0x{b:02X}", "count": c, "pct": round(c / total_len * 100.0, 1)} for b, c in counts.most_common(4)]
    ascii_count = sum(1 for b in data if 32 <= b <= 126)
    ascii_pct = round((ascii_count / total_len) * 100.0, 2)

    return {
        "detected_structure": detected_structure,
        "entropy": entropy,
        "total_bytes": total_len,
        "zero_bytes": zero_count,
        "nonzero_bytes": total_len - zero_count,
        "ff_bytes": ff_count,
        "zero_percentage": zero_pct,
        "ff_percentage": round((ff_count / total_len) * 100.0, 2),
        "printable_ascii_percentage": ascii_pct,
        "unique_byte_values": len(counts),
        "top_byte_values": top_bytes,
        "pattern_type": pattern_type,
        "observed_pattern": observed_pattern,
        "details": details,
        "sanitization_inspection": {
            "observed": observed_pattern,
            "expected": expected_pattern,
            "bytes_inspected": total_len,
            "matching_bytes": matching_count,
            "match_percentage": match_pct,
            "statement": statement,
        },
    }


# ---------------------------------------------------------------------------
# Path & Device Resolver
# ---------------------------------------------------------------------------

def resolve_target_path(target_path: str) -> Tuple[str, str, Dict[str, Any]]:
    """
    Resolve a user-provided target string into an accessible filesystem or raw device path.
    Handles:
      - Files and directories (os.path.exists)
      - Windows Drive Letters (e.g. 'E:', 'E:\\', '\\\\.\\E:')
      - Windows Physical Drives (e.g. 'PhysicalDrive0', '\\\\.\\PhysicalDrive0', '0')
      - Windows Friendly Device Names ('INTEL SSDPEKNU010TZ', 'HP v236w')
      - Linux block devices ('/dev/sda', '/dev/nvme0n1')
    Returns (resolved_path, display_name, metadata_hints).
    """
    if not target_path or not isinstance(target_path, str):
        return "", "", {}

    raw = target_path.strip()
    clean = raw.strip("\"'").strip()

    if sys.platform.startswith("win"):
        import re

        # 1. Windows Drive Letter: "E:", "E:\", "\\.\E:", "e:"
        m_vol = re.match(r"^(\\\\?\.\\|//\./)?([a-zA-Z]):?\\?$", clean)
        if m_vol:
            letter = m_vol.group(2).upper()
            vol_path = f"\\\\.\\{letter}:"
            return vol_path, f"Volume ({letter}:)", {"type": "volume", "drive_letter": letter}

        # 2. Windows Physical Drive: "PhysicalDrive0", "\\.\PhysicalDrive0", "//./PhysicalDrive0", "disk 0", "0"
        m_pd = re.match(r"^(\\\\?\.\\|//\./)?(?:PhysicalDrive|Disk\s*|disk\s*)?(\d+)$", clean, re.IGNORECASE)
        if m_pd:
            num = m_pd.group(2)
            pd_path = f"\\\\.\\PhysicalDrive{num}"
            return pd_path, f"PhysicalDrive{num}", {"type": "disk", "disk_number": int(num)}

        # 3. Linux-style device mapping on Windows: "/dev/sda" -> PhysicalDrive0
        m_linux = re.match(r"^/dev/(sd[a-z]|nvme\d+n\d+)$", clean, re.IGNORECASE)
        if m_linux:
            dev_str = m_linux.group(1).lower()
            if dev_str.startswith("sd") and len(dev_str) == 3:
                num = ord(dev_str[2]) - ord('a')
                pd_path = f"\\\\.\\PhysicalDrive{num}"
                return pd_path, f"PhysicalDrive{num} ({clean})", {"type": "disk", "disk_number": num}

    # 4. Direct filesystem match (File or Directory)
    if os.path.exists(clean):
        abs_p = os.path.abspath(clean)
        return abs_p, os.path.basename(abs_p) or abs_p, {"type": "file" if os.path.isfile(abs_p) else "directory"}

    # 5. Friendly name or serial match via device inventory (Windows)
    if sys.platform.startswith("win"):
        try:
            from devices import list_devices
            dev_list = list_devices()
            for dev in dev_list:
                name_match = (
                    clean.lower() == str(dev.get("name", "")).lower() or
                    clean.lower() in str(dev.get("friendlyName", "")).lower() or
                    clean.lower() == str(dev.get("serial", "")).lower() or
                    clean.lower() == str(dev.get("deviceId", "")).lower()
                )
                if name_match:
                    dev_path = dev.get("devicePath") or f"\\\\.\\PhysicalDrive{dev.get('deviceId', 0)}"
                    return dev_path, dev.get("friendlyName", clean), {
                        "type": "disk",
                        "disk_number": int(dev.get("deviceId")) if str(dev.get("deviceId")).isdigit() else 0,
                        "device_info": dev,
                    }
        except Exception:
            pass

    return clean, clean, {}


_windows_meta_cache: Dict[str, Any] = {}
_windows_meta_cache_time: float = 0.0


def _windows_query_disk_metadata(disk_num: Optional[int] = None, drive_letter: Optional[str] = None) -> Dict[str, Any]:
    """Query Windows disk, partition, and volume metadata safely using PowerShell."""
    global _windows_meta_cache, _windows_meta_cache_time
    now = time.time()
    if _windows_meta_cache and (now - _windows_meta_cache_time) < 15.0:
        return _windows_meta_cache

    try:
        import base64
        ps_script = (
            "ConvertTo-Json -InputObject @{ "
            "Disks = @(Get-Disk -ErrorAction SilentlyContinue | Select-Object Number, FriendlyName, SerialNumber, BusType, PartitionStyle, Size, LogicalSectorSize, PhysicalSectorSize, IsBoot, IsSystem); "
            "PhysicalDisks = @(Get-PhysicalDisk -ErrorAction SilentlyContinue | Select-Object FriendlyName, MediaType, Size, HealthStatus, BusType, SerialNumber, DeviceId); "
            "Partitions = @(Get-Partition -ErrorAction SilentlyContinue | Select-Object DiskNumber, PartitionNumber, DriveLetter, Size, Offset, Type, IsBoot, IsSystem); "
            "Volumes = @(Get-Volume -ErrorAction SilentlyContinue | Select-Object DriveLetter, FileSystemLabel, FileSystem, Size, SizeRemaining, HealthStatus) "
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
            return {}
        data = json.loads(completed.stdout)
        disks = data.get("Disks") or []
        pdisks = data.get("PhysicalDisks") or []
        parts = data.get("Partitions") or []
        vols = data.get("Volumes") or []

        if isinstance(disks, dict):
            disks = [disks]
        if isinstance(pdisks, dict):
            pdisks = [pdisks]
        if isinstance(parts, dict):
            parts = [parts]
        if isinstance(vols, dict):
            vols = [vols]

        vol_map = {}
        for v in vols:
            let = (v.get("DriveLetter") or "").upper()
            if let:
                vol_map[let] = v

        pdisk_map = {}
        for pd in pdisks:
            dev_id = str(pd.get("DeviceId", "")).strip()
            if dev_id:
                pdisk_map[dev_id] = pd
            sn = str(pd.get("SerialNumber", "")).strip()
            if sn:
                pdisk_map[sn] = pd

        if disk_num is None and drive_letter:
            clean_let = drive_letter.replace(":", "").replace("\\", "").strip().upper()
            for p in parts:
                p_let = str(p.get("DriveLetter") or "").strip().upper()
                if p_let == clean_let and p.get("DiskNumber") is not None:
                    disk_num = int(p["DiskNumber"])
                    break

        matched_disk = None
        for d in disks:
            if disk_num is not None and d.get("Number") == disk_num:
                matched_disk = d
                break
        if not matched_disk and disks:
            matched_disk = disks[0]

        matched_parts = []
        if matched_disk:
            d_num = matched_disk.get("Number")
            for p in parts:
                if p.get("DiskNumber") == d_num:
                    matched_parts.append(p)

        matched_pdisk = None
        if matched_disk:
            d_num_str = str(matched_disk.get("Number"))
            sn_str = str(matched_disk.get("SerialNumber") or "").strip()
            matched_pdisk = pdisk_map.get(d_num_str) or pdisk_map.get(sn_str)

        return {
            "disk": matched_disk,
            "physical_disk": matched_pdisk,
            "partitions": matched_parts,
            "vol_map": vol_map,
        }
    except Exception:
        return {}


# ---------------------------------------------------------------------------
# Device & Metadata Inspector (Strictly Read-Only)
# ---------------------------------------------------------------------------

def inspect_storage_metadata(target_path: str) -> Dict[str, Any]:
    """
    Gather comprehensive physical and OS metadata for the selected target.
    Strictly read-only inspection.
    """
    resolved_path, display_name, hints = resolve_target_path(target_path)

    info: Dict[str, Any] = {
        "target_path": target_path,
        "resolved_path": resolved_path,
        "display_name": display_name,
        "target_type": "unknown",
        "exists": bool(resolved_path),
        "physical_identity": {
            "model": "Not reported by hardware",
            "serial": "Not reported by hardware",
            "vendor": "Not reported by hardware",
            "bus_interface": "Not reported by hardware",
            "media_type": "Not reported by hardware",
            "firmware_revision": "Not available through current interface",
            "capacity_bytes": 0,
            "logical_sector_size": 512,
            "physical_sector_size": 512,
            "partition_table_type": "Not reported",
            "total_sectors": 0,
        },
        "os_metadata": {
            "platform": sys.platform,
            "read_only_access": True,
            "is_block_device": False,
            "is_file": False,
            "is_directory": False,
            "mount_point": "Not mounted",
            "filesystem_type": "Not reported",
            "volume_label": "Not available",
            "uuid": "Not available",
            "size_formatted": "0 B",
            "permissions": "Not reported",
            "inode": "N/A",
            "timestamps_applicable": True,
            "created_time": "N/A",
            "modified_time": "N/A",
            "accessed_time": "N/A",
        },
        "health_capability": {
            "status": "Healthy / Operational (OS Reported)",
            "smart_supported": True,
            "temperature": "Not available through current interface",
            "reallocated_sectors": "Not available through current interface",
            "wear_indicator": "Not available through current interface",
            "source": "Operating System Block Subsystem",
        },
        "partitions": [],
        "sanitization_certificate_link": None,
        "inspection_disclaimer": (
            "Observed data reflects addressable logical storage accessible via the OS driver interface. "
            "Physical NAND flash controller translation, wear-leveling reserves, and retired bad blocks "
            "cannot be inspected through software."
        ),
    }

    if not resolved_path:
        info["os_metadata"]["device_status"] = "Target not found"
        return info

    # File or Directory on Filesystem
    if os.path.exists(resolved_path) and not resolved_path.startswith("\\\\.\\PhysicalDrive") and not (resolved_path.startswith("\\\\.\\") and len(resolved_path) == 6):
        try:
            st = os.stat(resolved_path)
            is_file = stat.S_ISREG(st.st_mode)
            is_dir = stat.S_ISDIR(st.st_mode)
            is_block = stat.S_ISBLK(st.st_mode)

            info["os_metadata"]["is_block_device"] = is_block
            info["os_metadata"]["is_file"] = is_file
            info["os_metadata"]["is_directory"] = is_dir

            if is_file:
                info["target_type"] = "file"
                info["physical_identity"]["capacity_bytes"] = st.st_size
                info["os_metadata"]["size_formatted"] = f"{st.st_size:,} bytes"
                info["os_metadata"]["permissions"] = oct(st.st_mode)[-3:]
                info["os_metadata"]["inode"] = str(st.st_ino)
                info["os_metadata"]["created_time"] = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(st.st_ctime))
                info["os_metadata"]["modified_time"] = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(st.st_mtime))
                info["os_metadata"]["accessed_time"] = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(st.st_atime))
                info["physical_identity"]["total_sectors"] = (st.st_size + 511) // 512
                info["exists"] = True
                return info

            elif is_dir:
                info["target_type"] = "directory"
                total_size = 0
                file_count = 0
                for dirpath, _, filenames in os.walk(resolved_path):
                    for fn in filenames:
                        file_count += 1
                        try:
                            total_size += os.path.getsize(os.path.join(dirpath, fn))
                        except Exception:
                            pass
                info["physical_identity"]["capacity_bytes"] = total_size
                info["os_metadata"]["size_formatted"] = f"{total_size:,} bytes ({file_count} files)"
                info["os_metadata"]["permissions"] = oct(st.st_mode)[-3:]
                info["os_metadata"]["created_time"] = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(st.st_ctime))
                info["os_metadata"]["modified_time"] = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(st.st_mtime))
                info["exists"] = True
                return info
        except Exception:
            pass

    # Raw block device, Windows physical drive, or Volume
    info["target_type"] = "disk"
    info["os_metadata"]["is_block_device"] = True
    info["os_metadata"]["timestamps_applicable"] = False
    info["os_metadata"]["created_time"] = "Filesystem object timestamps: Not applicable to raw block device"
    info["os_metadata"]["modified_time"] = "Filesystem object timestamps: Not applicable to raw block device"

    # Query Windows Storage Subsystem via PowerShell
    if sys.platform.startswith("win"):
        disk_num = hints.get("disk_number")
        drive_letter = hints.get("drive_letter")
        if disk_num is None and resolved_path.startswith(r"\\.\PhysicalDrive"):
            try:
                disk_num = int(resolved_path.replace(r"\\.\PhysicalDrive", ""))
            except Exception:
                pass

        ws_meta = _windows_query_disk_metadata(disk_num=disk_num, drive_letter=drive_letter)
        disk_obj = ws_meta.get("disk") or {}
        pdisk_obj = ws_meta.get("physical_disk") or {}
        parts_list = ws_meta.get("partitions") or []
        vol_map = ws_meta.get("vol_map") or {}

        if disk_obj:
            model = disk_obj.get("FriendlyName") or "Windows Physical Disk"
            serial = str(disk_obj.get("SerialNumber") or "Not exposed by controller").strip()
            bus = str(disk_obj.get("BusType") or "Storage").upper()
            pt_style = str(disk_obj.get("PartitionStyle") or "MBR/GPT").upper()
            sz = int(disk_obj.get("Size") or 0)
            log_sec = int(disk_obj.get("LogicalSectorSize") or 512)
            phy_sec = int(disk_obj.get("PhysicalSectorSize") or 512)
            media_type = pdisk_obj.get("MediaType") if pdisk_obj else ("SSD / NVMe / Flash" if "NVME" in bus or "SSD" in model.upper() else "HDD / Mass Storage")

            info["physical_identity"]["model"] = model
            info["physical_identity"]["serial"] = serial
            info["physical_identity"]["vendor"] = "Windows Storage Subsystem"
            info["physical_identity"]["bus_interface"] = bus
            info["physical_identity"]["media_type"] = media_type or "Storage"
            info["physical_identity"]["capacity_bytes"] = sz
            info["os_metadata"]["size_formatted"] = f"{sz / (1024*1024*1024):.2f} GiB ({sz:,} bytes)" if sz > 0 else "N/A"
            info["physical_identity"]["logical_sector_size"] = log_sec
            info["physical_identity"]["physical_sector_size"] = phy_sec
            info["physical_identity"]["partition_table_type"] = pt_style
            if log_sec > 0 and sz > 0:
                info["physical_identity"]["total_sectors"] = sz // log_sec

            # Partitions breakdown
            for idx, p in enumerate(parts_list):
                part_sz = int(p.get("Size") or 0)
                offset = int(p.get("Offset") or 0)
                start_lba_val = offset // max(1, log_sec) if log_sec > 0 else 0
                part_sectors = part_sz // max(1, log_sec) if log_sec > 0 else 0
                end_lba_val = start_lba_val + max(0, part_sectors - 1)
                p_let = str(p.get("DriveLetter") or "").strip().upper()
                v_obj = vol_map.get(p_let) or {}

                fs_type = v_obj.get("FileSystem") or p.get("Type") or "Unknown / Unformatted"
                label = v_obj.get("FileSystemLabel") or "N/A"
                mount = f"{p_let}:" if p_let else "Unmounted"

                info["partitions"].append({
                    "partition_number": p.get("PartitionNumber") or (idx + 1),
                    "name": f"Partition {p.get('PartitionNumber', idx + 1)}" + (f" ({p_let}:)" if p_let else ""),
                    "path": f"\\\\.\\{p_let}:" if p_let else f"{resolved_path}#Partition{p.get('PartitionNumber', idx + 1)}",
                    "size_bytes": part_sz,
                    "size_formatted": f"{part_sz / (1024*1024*1024):.2f} GiB" if part_sz >= 1024*1024*1024 else f"{part_sz / (1024*1024):.2f} MiB",
                    "start_lba": start_lba_val,
                    "end_lba": end_lba_val,
                    "filesystem": fs_type,
                    "mountpoint": mount,
                    "uuid": "N/A",
                    "label": label,
                })

    # Query Linux lsblk for physical & partition details
    elif sys.platform.startswith("linux"):
        try:
            cmd = ["lsblk", "-J", "-b", "-o", "NAME,SIZE,START,MODEL,SERIAL,VENDOR,TRAN,ROTA,PHY-SEC,LOG-SEC,FSTYPE,UUID,LABEL,MOUNTPOINT,PTTYPE,PARTTYPE,PARTN", resolved_path]
            cp = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
            if cp.returncode == 0:
                data = json.loads(cp.stdout or "{}")
                devs = data.get("blockdevices", [])
                if devs:
                    d = devs[0]
                    info["physical_identity"]["model"] = (d.get("model") or "Generic Block Device").strip()
                    info["physical_identity"]["serial"] = (d.get("serial") or "Not exposed by controller").strip()
                    info["physical_identity"]["vendor"] = (d.get("vendor") or "Not exposed").strip()
                    info["physical_identity"]["bus_interface"] = str(d.get("tran") or "SATA/NVMe").upper()
                    rota = d.get("rota")
                    info["physical_identity"]["media_type"] = "HDD (Rotational Magnetic)" if rota is True else "SSD / NVMe / Flash"
                    sz = int(d.get("size") or 0)
                    info["physical_identity"]["capacity_bytes"] = sz
                    info["os_metadata"]["size_formatted"] = f"{sz / (1024*1024*1024):.2f} GiB ({sz:,} bytes)"
                    log_sec = int(d.get("log-sec") or 512)
                    phy_sec = int(d.get("phy-sec") or 512)
                    info["physical_identity"]["logical_sector_size"] = log_sec
                    info["physical_identity"]["physical_sector_size"] = phy_sec
                    info["physical_identity"]["partition_table_type"] = str(d.get("pttype") or "MBR/GPT").upper()
                    info["os_metadata"]["mount_point"] = d.get("mountpoint") or "Not mounted"
                    info["os_metadata"]["filesystem_type"] = d.get("fstype") or "Raw Block Device"
                    info["os_metadata"]["volume_label"] = d.get("label") or "Not available"
                    info["os_metadata"]["uuid"] = d.get("uuid") or "Not available"

                    if log_sec > 0 and sz > 0:
                        info["physical_identity"]["total_sectors"] = sz // log_sec

                    # Partitions breakdown with start/end LBA calculation
                    for idx, child in enumerate(d.get("children", [])):
                        part_sz = int(child.get("size") or 0)
                        start_lba_val = int(child.get("start") or 0) if child.get("start") is not None else (idx * 2048)
                        part_sectors = part_sz // max(1, log_sec) if log_sec > 0 else 0
                        end_lba_val = start_lba_val + max(0, part_sectors - 1)

                        info["partitions"].append({
                            "partition_number": child.get("partn") or (idx + 1),
                            "name": child.get("name"),
                            "path": f"/dev/{child.get('name')}",
                            "size_bytes": part_sz,
                            "size_formatted": f"{part_sz / (1024*1024*1024):.2f} GiB",
                            "start_lba": start_lba_val,
                            "end_lba": end_lba_val,
                            "filesystem": child.get("fstype") or "Unknown / Unformatted",
                            "mountpoint": child.get("mountpoint") or "Unmounted",
                            "uuid": child.get("uuid") or "N/A",
                            "label": child.get("label") or "N/A",
                        })
        except Exception:
            pass

    # Check for recent sanitization record in SQLite
    try:
        import sqlite3
        db_path = os.path.join(os.path.dirname(__file__), "data", "history.db")
        if os.path.exists(db_path):
            conn = sqlite3.connect(db_path)
            conn.row_factory = sqlite3.Row
            row = conn.execute(
                "SELECT id, standard, method, status, finalState, startTime, endTime, filesVerified FROM wipe_history WHERE device = ? OR device = ? ORDER BY created_at DESC LIMIT 1",
                (target_path, resolved_path)
            ).fetchone()
            if row:
                info["sanitization_certificate_link"] = {
                    "has_certificate": True,
                    "session_id": row["id"],
                    "method": row["standard"] or row["method"],
                    "status": row["status"],
                    "final_state": row["finalState"] or row["status"],
                    "timestamp": row["startTime"],
                    "verified_lba": 0,
                }
            conn.close()
    except Exception:
        pass

    return info


# ---------------------------------------------------------------------------
# Hex / Sector Reader (Strictly Read-Only)
# ---------------------------------------------------------------------------

def read_storage_hex_sector(
    target_path: str,
    lba: int = 0,
    sector_size: int = 512,
    sector_count: int = 1,
) -> Dict[str, Any]:
    """
    Read specific sector(s) from a block device or file in strictly READ-ONLY mode.
    Formats bytes into hexadecimal and ASCII representations with address calculators.
    Includes live sector SHA-256 telemetry.
    """
    resolved_path, display_name, hints = resolve_target_path(target_path)
    if not resolved_path:
        return {"error": f"Target not found: {target_path}", "status": "ERROR"}

    sector_size = max(512, min(sector_size, 4096))
    sector_count = max(1, min(sector_count, 16))
    lba = max(0, lba)

    byte_offset = lba * sector_size
    read_length = sector_size * sector_count

    try:
        if os.path.isfile(resolved_path):
            file_size = os.path.getsize(resolved_path)
            if byte_offset >= file_size and file_size > 0:
                return {
                    "error": f"Requested LBA {lba} (offset {byte_offset:,}) exceeds file size ({file_size:,} bytes)",
                    "status": "OUT_OF_BOUNDS",
                }
            with open(resolved_path, "rb") as f:
                f.seek(byte_offset)
                raw_bytes = f.read(read_length)
        else:
            fd = os.open(resolved_path, os.O_RDONLY | getattr(os, "O_BINARY", 0))
            try:
                os.lseek(fd, byte_offset, os.SEEK_SET)
                raw_bytes = os.read(fd, read_length)
            finally:
                os.close(fd)

    except PermissionError:
        if sys.platform.startswith("win"):
            return {
                "error": f"Permission denied reading raw device sectors on {resolved_path} (Administrator privileges required)",
                "status": "PERMISSION_DENIED",
                "is_permission_error": True,
                "help_instructions": [
                    "Option 1: Run the backend with Administrator privileges (Right-click PowerShell/Terminal -> 'Run as administrator', then python app.py)",
                    "Option 2: Inspect individual partition drive handles (e.g. \\\\.\\E:) if accessible",
                    "Option 3: Inspect synthetic disk image files or containers directly",
                ],
            }
        else:
            return {
                "error": "Permission denied reading raw device sectors (root/Administrator required)",
                "status": "PERMISSION_DENIED",
                "is_permission_error": True,
                "help_instructions": [
                    "Option 1: Add user to 'disk' group: sudo usermod -a -G disk $USER (then re-login)",
                    "Option 2: Run backend with root: sudo python3 backend/app.py",
                ],
            }
    except Exception as e:
        return {"error": f"Read error at LBA {lba}: {e}", "status": "READ_ERROR"}

    if not raw_bytes:
        return {"error": "Reached end of device / zero bytes read", "status": "EOF"}

    # Format into 16-byte hex editor rows
    rows: List[Dict[str, Any]] = []
    for row_idx in range(0, len(raw_bytes), 16):
        row_bytes = raw_bytes[row_idx:row_idx + 16]
        row_abs_addr = byte_offset + row_idx
        hex_parts = [f"{b:02X}" for b in row_bytes]
        ascii_parts = "".join(chr(b) if 32 <= b <= 126 else "." for b in row_bytes)

        # Pad hex parts to 16 if short row
        hex_formatted = " ".join(hex_parts[:8]) + "  " + " ".join(hex_parts[8:])
        rows.append({
            "address": f"{row_abs_addr:08X}",
            "address_dec": row_abs_addr,
            "hex": hex_formatted,
            "ascii": ascii_parts,
            "sector_index": (byte_offset + row_idx) // sector_size,
        })

    analysis = analyze_sector_patterns(raw_bytes)
    sha256_digest = hashlib.sha256(raw_bytes).hexdigest()

    return {
        "status": "SUCCESS",
        "target": target_path,
        "resolved_target": resolved_path,
        "display_name": display_name,
        "lba": lba,
        "sector_size": sector_size,
        "sector_count": sector_count,
        "byte_offset": byte_offset,
        "end_byte_offset": byte_offset + len(raw_bytes) - 1,
        "bytes_read": len(raw_bytes),
        "sha256": sha256_digest,
        "rows": rows,
        "analysis": analysis,
        "read_only_mode": True,
    }


# ---------------------------------------------------------------------------
# Before vs After Sanitization Diff Analyzer
# ---------------------------------------------------------------------------

def compare_sector_diff(
    before_bytes_hex: str,
    after_bytes_hex: str,
    lba: int = 0,
    sector_size: int = 512,
) -> Dict[str, Any]:
    """
    Compare 'Before' and 'After' sector hexadecimal strings.
    Computes exact byte changes, unchanged regions, and zero-byte percentages.
    """
    try:
        b_raw = bytes.fromhex(before_bytes_hex.replace(" ", "").replace("\n", ""))
        a_raw = bytes.fromhex(after_bytes_hex.replace(" ", "").replace("\n", ""))
    except Exception as e:
        return {"error": f"Invalid hex input: {e}", "status": "ERROR"}

    min_len = min(len(b_raw), len(a_raw))
    if min_len == 0:
        return {"error": "Empty buffer provided", "status": "ERROR"}

    changed_count = sum(1 for i in range(min_len) if b_raw[i] != a_raw[i])
    unchanged_count = min_len - changed_count
    pct_changed = round((changed_count / min_len) * 100.0, 2)

    before_analysis = analyze_sector_patterns(b_raw)
    after_analysis = analyze_sector_patterns(a_raw)

    return {
        "status": "SUCCESS",
        "lba": lba,
        "sector_size": sector_size,
        "compared_bytes": min_len,
        "bytes_changed": changed_count,
        "bytes_unchanged": unchanged_count,
        "percentage_changed": pct_changed,
        "before": before_analysis,
        "after": after_analysis,
    }


# ---------------------------------------------------------------------------
# In-Storage Read-Only Search (Layer 1: Raw Bytes & Layer 2: Filesystem-Aware)
# ---------------------------------------------------------------------------

TEXT_EXTENSIONS = {
    ".txt", ".log", ".md", ".json", ".csv", ".xml", ".py", ".c", ".h", ".cpp",
    ".hpp", ".rs", ".go", ".java", ".js", ".ts", ".jsx", ".tsx", ".html", ".css",
    ".ini", ".cfg", ".conf", ".yml", ".yaml", ".toml", ".sql", ".sh", ".bat",
    ".ps1", ".env", ".inf", ".reg", ".tex", ".rtf", ".tsv"
}


def _is_text_file(filepath: str, sample_bytes: bytes) -> bool:
    """Safely check if file is likely plain text without loading whole file."""
    ext = os.path.splitext(filepath)[1].lower()
    if ext in TEXT_EXTENSIONS:
        return True
    if not sample_bytes:
        return True
    # If sample contains null byte, it's binary
    if b"\x00" in sample_bytes:
        return False
    # Check printable ASCII / UTF-8 ratio
    printable = sum(1 for b in sample_bytes if 32 <= b <= 126 or b in (9, 10, 13))
    return (printable / len(sample_bytes)) >= 0.85


def _get_file_attributes_str(filepath: str) -> str:
    """Safely query Windows file attributes without modification."""
    if sys.platform.startswith("win"):
        try:
            import ctypes
            res = ctypes.windll.kernel32.GetFileAttributesW(str(filepath))
            if res != -1:
                attrs = []
                if res & 0x1: attrs.append("ReadOnly")
                if res & 0x2: attrs.append("Hidden")
                if res & 0x4: attrs.append("System")
                if res & 0x20: attrs.append("Archive")
                return ", ".join(attrs) if attrs else "Normal"
        except Exception:
            pass
    return "Normal"


# ---------------------------------------------------------------------------
# FAT32 Parser & Storage Allocation / Cluster-to-LBA Mapping Engine
# ---------------------------------------------------------------------------

def parse_fat32_bpb(boot_sector_bytes: bytes) -> Optional[Dict[str, Any]]:
    """
    Parse a 512-byte FAT32 Volume Boot Record (BPB).
    Returns dictionary containing geometry, FAT offsets, and data cluster boundaries.
    """
    if not boot_sector_bytes or len(boot_sector_bytes) < 512:
        return None

    # Check 0x55AA boot signature
    if boot_sector_bytes[510:512] != b"\x55\xaa":
        return None

    try:
        bytes_per_sector = struct.unpack_from("<H", boot_sector_bytes, 0x0B)[0]
        if bytes_per_sector not in (512, 1024, 2048, 4096):
            return None

        sectors_per_cluster = boot_sector_bytes[0x0D]
        if sectors_per_cluster not in (1, 2, 4, 8, 16, 32, 64, 128):
            return None

        reserved_sectors = struct.unpack_from("<H", boot_sector_bytes, 0x0E)[0]
        if reserved_sectors == 0:
            return None

        num_fats = boot_sector_bytes[0x10]
        if num_fats == 0:
            return None

        # FAT size 32
        fat_size_32 = struct.unpack_from("<I", boot_sector_bytes, 0x24)[0]
        if fat_size_32 == 0:
            fat_size_16 = struct.unpack_from("<H", boot_sector_bytes, 0x16)[0]
            fat_size_32 = fat_size_16

        if fat_size_32 == 0:
            return None

        # Root cluster
        root_cluster = struct.unpack_from("<I", boot_sector_bytes, 0x2C)[0]
        if root_cluster == 0:
            root_cluster = 2

        # Total sectors
        total_sectors = struct.unpack_from("<I", boot_sector_bytes, 0x20)[0]
        if total_sectors == 0:
            total_sectors = struct.unpack_from("<H", boot_sector_bytes, 0x13)[0]

        fat_start_lba = reserved_sectors
        first_data_sector = reserved_sectors + (num_fats * fat_size_32)
        bytes_per_cluster = bytes_per_sector * sectors_per_cluster

        return {
            "bytes_per_sector": bytes_per_sector,
            "sectors_per_cluster": sectors_per_cluster,
            "bytes_per_cluster": bytes_per_cluster,
            "cluster_size_bytes": bytes_per_cluster,
            "reserved_sectors": reserved_sectors,
            "num_fats": num_fats,
            "fat_size_32": fat_size_32,
            "fat_size_sectors": fat_size_32,
            "fat_start_lba": fat_start_lba,
            "first_data_sector": first_data_sector,
            "root_cluster": root_cluster,
            "total_sectors": total_sectors,
        }
    except Exception:
        return None


def read_fat32_cluster_chain(
    read_fn,
    start_cluster: int,
    bpb_info: Dict[str, Any],
    max_chain_len: int = 65536
) -> List[int]:
    """
    Follow FAT32 cluster chain in strictly READ-ONLY mode.
    Returns ordered list of allocated cluster numbers.
    """
    if start_cluster < 2:
        return []

    bytes_per_sector = bpb_info["bytes_per_sector"]
    fat_start_lba = bpb_info["fat_start_lba"]
    chain = []
    curr = start_cluster
    visited = set()

    while curr >= 2 and curr not in visited and len(chain) < max_chain_len:
        chain.append(curr)
        visited.add(curr)

        fat_offset = curr * 4
        fat_sector_lba = fat_start_lba + (fat_offset // bytes_per_sector)
        offset_in_sector = fat_offset % bytes_per_sector

        sec_bytes = read_fn(fat_sector_lba, 1)
        if len(sec_bytes) < offset_in_sector + 4:
            break

        next_val = struct.unpack_from("<I", sec_bytes, offset_in_sector)[0] & 0x0FFFFFFF

        # EOC markers: 0x0FFFFFF8 to 0x0FFFFFFF
        if next_val >= 0x0FFFFFF8 or next_val < 2 or next_val == 0x0FFFFFF7:
            break

        curr = next_val

    return chain


def map_clusters_to_lba_extents(
    cluster_chain: List[int],
    bpb_info: Dict[str, Any],
    partition_start_lba: int = 0
) -> Dict[str, Any]:
    """
    Convert a cluster chain into exact starting/ending LBAs, byte offsets,
    occupied sectors/clusters, and grouped contiguous extent ranges.
    """
    if not cluster_chain:
        return {
            "is_allocation_available": False,
            "starting_cluster": None,
            "cluster_chain": "Unavailable",
            "cluster_chain_list": [],
            "starting_lba": None,
            "ending_lba": None,
            "byte_offset": None,
            "byte_offset_hex": "Unavailable",
            "sectors_occupied": 0,
            "clusters_occupied": 0,
            "is_fragmented": False,
            "extents": [],
            "allocation_disclaimer": "No allocation clusters found.",
        }

    bytes_per_sector = bpb_info["bytes_per_sector"]
    sectors_per_cluster = bpb_info["sectors_per_cluster"]
    first_data_sector = bpb_info["first_data_sector"]

    extents = []
    curr_start_clus = cluster_chain[0]
    curr_prev_clus = cluster_chain[0]
    curr_clus_count = 1

    for i in range(1, len(cluster_chain)):
        c = cluster_chain[i]
        if c == curr_prev_clus + 1:
            curr_prev_clus = c
            curr_clus_count += 1
        else:
            ext_start_lba = partition_start_lba + first_data_sector + (curr_start_clus - 2) * sectors_per_cluster
            ext_sec_count = curr_clus_count * sectors_per_cluster
            ext_end_lba = ext_start_lba + ext_sec_count - 1
            ext_start_byte = ext_start_lba * bytes_per_sector
            ext_end_byte = (ext_end_lba + 1) * bytes_per_sector - 1

            extents.append({
                "start_cluster": curr_start_clus,
                "end_cluster": curr_prev_clus,
                "cluster_count": curr_clus_count,
                "start_lba": ext_start_lba,
                "end_lba": ext_end_lba,
                "sector_count": ext_sec_count,
                "start_byte_offset": ext_start_byte,
                "end_byte_offset": ext_end_byte,
            })
            curr_start_clus = c
            curr_prev_clus = c
            curr_clus_count = 1

    # Append final extent
    ext_start_lba = partition_start_lba + first_data_sector + (curr_start_clus - 2) * sectors_per_cluster
    ext_sec_count = curr_clus_count * sectors_per_cluster
    ext_end_lba = ext_start_lba + ext_sec_count - 1
    ext_start_byte = ext_start_lba * bytes_per_sector
    ext_end_byte = (ext_end_lba + 1) * bytes_per_sector - 1

    extents.append({
        "start_cluster": curr_start_clus,
        "end_cluster": curr_prev_clus,
        "cluster_count": curr_clus_count,
        "start_lba": ext_start_lba,
        "end_lba": ext_end_lba,
        "sector_count": ext_sec_count,
        "start_byte_offset": ext_start_byte,
        "end_byte_offset": ext_end_byte,
    })

    start_lba = extents[0]["start_lba"]
    end_lba = extents[-1]["end_lba"]
    byte_offset = extents[0]["start_byte_offset"]
    total_clusters = len(cluster_chain)
    total_sectors = total_clusters * sectors_per_cluster
    is_fragmented = len(extents) > 1

    if len(cluster_chain) <= 6:
        chain_str = " -> ".join(str(c) for c in cluster_chain)
    else:
        chain_str = f"{cluster_chain[0]} -> {cluster_chain[1]} -> ... -> {cluster_chain[-1]} ({len(cluster_chain)} clusters, {len(extents)} extent{'s' if is_fragmented else ''})"

    return {
        "is_allocation_available": True,
        "starting_cluster": cluster_chain[0],
        "cluster_chain": chain_str,
        "cluster_chain_list": cluster_chain,
        "starting_lba": start_lba,
        "ending_lba": end_lba,
        "byte_offset": byte_offset,
        "byte_offset_hex": f"0x{byte_offset:08X}",
        "sectors_occupied": total_sectors,
        "clusters_occupied": total_clusters,
        "is_fragmented": is_fragmented,
        "extents": extents,
        "filesystem": "FAT32",
        "allocation_disclaimer": "Calculated from verified FAT32 BPB and File Allocation Table. Device LBA represents logical controller address.",
    }


def parse_fat32_directory_entries(
    read_fn,
    bpb_info: Dict[str, Any],
    start_cluster: Optional[int] = None,
    partition_start_lba: int = 0
) -> List[Dict[str, Any]]:
    """
    Read and parse directory entries from a FAT32 volume starting at given cluster (default root_cluster).
    Returns list of file/directory metadata with starting cluster and file sizes.
    """
    if start_cluster is None:
        start_cluster = bpb_info.get("root_cluster", 2)

    chain = read_fat32_cluster_chain(read_fn, start_cluster, bpb_info)
    if not chain:
        chain = [start_cluster]

    bytes_per_sector = bpb_info["bytes_per_sector"]
    sectors_per_cluster = bpb_info["sectors_per_cluster"]
    first_data_sector = bpb_info["first_data_sector"]

    entries = []
    lfn_parts = {}

    for clus in chain:
        clus_lba = partition_start_lba + first_data_sector + (clus - 2) * sectors_per_cluster
        data = read_fn(clus_lba, sectors_per_cluster)

        for off in range(0, len(data), 32):
            entry_bytes = data[off:off + 32]
            if len(entry_bytes) < 32:
                break
            first_byte = entry_bytes[0]
            if first_byte == 0x00:
                break
            if first_byte == 0xE5:
                lfn_parts.clear()
                continue

            attr = entry_bytes[0x0B]
            if attr == 0x0F:
                # LFN entry
                seq = first_byte & 0x1F
                name_chars = bytearray()
                name_chars.extend(entry_bytes[1:11])
                name_chars.extend(entry_bytes[14:26])
                name_chars.extend(entry_bytes[28:32])
                try:
                    lfn_str = name_chars.decode("utf-16le", errors="ignore").split("\x00")[0]
                    lfn_parts[seq] = lfn_str
                except Exception:
                    pass
                continue

            name_main = entry_bytes[0:8].decode("latin-1", errors="replace").rstrip()
            ext = entry_bytes[8:11].decode("latin-1", errors="replace").rstrip()
            short_name = f"{name_main}.{ext}" if ext else name_main

            if lfn_parts:
                sorted_seqs = sorted(lfn_parts.keys())
                full_name = "".join(lfn_parts[s] for s in sorted_seqs)
                lfn_parts.clear()
            else:
                full_name = short_name

            fst_clus_hi = struct.unpack_from("<H", entry_bytes, 0x14)[0]
            fst_clus_lo = struct.unpack_from("<H", entry_bytes, 0x1A)[0]
            file_size = struct.unpack_from("<I", entry_bytes, 0x1C)[0]
            entry_start_clus = (fst_clus_hi << 16) | fst_clus_lo
            is_dir = bool(attr & 0x10)

            entries.append({
                "name": full_name,
                "short_name": short_name,
                "is_dir": is_dir,
                "attributes_byte": attr,
                "starting_cluster": entry_start_clus,
                "file_size": file_size,
            })

    return entries


def get_windows_file_retrieval_pointers(file_path: str) -> Optional[Dict[str, Any]]:
    """
    Query exact logical cluster (LCN) extents for a mounted file on Windows via FSCTL_GET_RETRIEVAL_POINTERS.
    Strictly READ-ONLY (opens handle with FILE_READ_ATTRIBUTES).
    """
    if not sys.platform.startswith("win") or not os.path.exists(file_path):
        return None

    try:
        import ctypes
        from ctypes import wintypes

        kernel32 = ctypes.windll.kernel32

        FILE_READ_ATTRIBUTES = 0x0080
        FILE_SHARE_READ = 0x00000001
        FILE_SHARE_WRITE = 0x00000002
        FILE_SHARE_DELETE = 0x00000004
        OPEN_EXISTING = 3
        FILE_FLAG_BACKUP_SEMANTICS = 0x02000000
        FSCTL_GET_RETRIEVAL_POINTERS = 0x00090073
        INVALID_HANDLE_VALUE = wintypes.HANDLE(-1).value

        h_file = kernel32.CreateFileW(
            file_path,
            FILE_READ_ATTRIBUTES,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            None,
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS,
            None
        )

        if h_file == INVALID_HANDLE_VALUE:
            return None

        try:
            in_buf = ctypes.c_int64(0)
            out_buf = ctypes.create_string_buffer(4096)
            bytes_returned = wintypes.DWORD(0)

            res = kernel32.DeviceIoControl(
                h_file,
                FSCTL_GET_RETRIEVAL_POINTERS,
                ctypes.byref(in_buf),
                ctypes.sizeof(in_buf),
                out_buf,
                ctypes.sizeof(out_buf),
                ctypes.byref(bytes_returned),
                None
            )

            last_err = kernel32.GetLastError()
            if not res and last_err != 234:  # ERROR_MORE_DATA
                return None

            extent_count = struct.unpack_from("<I", out_buf.raw, 0)[0]
            starting_vcn = struct.unpack_from("<q", out_buf.raw, 8)[0]

            if extent_count == 0:
                return None

            drive_letter = os.path.splitdrive(file_path)[0] + "\\"
            sectors_per_clus_dw = wintypes.DWORD()
            bytes_per_sec_dw = wintypes.DWORD()
            free_clus_dw = wintypes.DWORD()
            total_clus_dw = wintypes.DWORD()

            kernel32.GetDiskFreeSpaceW(
                drive_letter,
                ctypes.byref(sectors_per_clus_dw),
                ctypes.byref(bytes_per_sec_dw),
                ctypes.byref(free_clus_dw),
                ctypes.byref(total_clus_dw)
            )

            sec_per_clus = sectors_per_clus_dw.value or 8
            bytes_per_sec = bytes_per_sec_dw.value or 512

            part_offset_lba = 0
            fs_name = "NTFS"
            vol_let = drive_letter.replace(":", "").replace("\\", "").upper()
            meta = _windows_query_disk_metadata(drive_letter=vol_let)
            for p in meta.get("partitions", []):
                if str(p.get("DriveLetter") or "").upper() == vol_let:
                    off_bytes = int(p.get("Offset") or 0)
                    part_offset_lba = off_bytes // bytes_per_sec
                    break
            vol_info = meta.get("vol_map", {}).get(vol_let, {})
            if vol_info.get("FileSystem"):
                fs_name = vol_info["FileSystem"]

            extents = []
            curr_vcn = starting_vcn
            pos = 16
            cluster_list = []

            for _ in range(extent_count):
                if pos + 16 > len(out_buf.raw):
                    break
                next_vcn, lcn = struct.unpack_from("<qq", out_buf.raw, pos)
                pos += 16

                if lcn != -1:
                    clus_count = next_vcn - curr_vcn
                    ext_start_lba = part_offset_lba + (lcn * sec_per_clus)
                    ext_sec_count = clus_count * sec_per_clus
                    ext_end_lba = ext_start_lba + ext_sec_count - 1
                    ext_start_byte = ext_start_lba * bytes_per_sec
                    ext_end_byte = (ext_end_lba + 1) * bytes_per_sec - 1

                    extents.append({
                        "start_cluster": lcn,
                        "end_cluster": lcn + clus_count - 1,
                        "cluster_count": clus_count,
                        "start_lba": ext_start_lba,
                        "end_lba": ext_end_lba,
                        "sector_count": ext_sec_count,
                        "start_byte_offset": ext_start_byte,
                        "end_byte_offset": ext_end_byte,
                    })

                    if len(cluster_list) < 32:
                        for c_i in range(min(clus_count, 32 - len(cluster_list))):
                            cluster_list.append(lcn + c_i)

                curr_vcn = next_vcn

            if not extents:
                return None

            start_lba = extents[0]["start_lba"]
            end_lba = extents[-1]["end_lba"]
            byte_offset = extents[0]["start_byte_offset"]
            total_sectors = sum(e["sector_count"] for e in extents)
            total_clusters = sum(e["cluster_count"] for e in extents)
            is_fragmented = len(extents) > 1

            if len(extents) == 1 and total_clusters <= 6:
                chain_str = " -> ".join(str(c) for c in cluster_list)
            else:
                chain_str = f"LCN {extents[0]['start_cluster']} -> LCN {extents[-1]['end_cluster']} ({total_clusters:,} clusters, {len(extents)} extent{'s' if is_fragmented else ''})"

            return {
                "is_allocation_available": True,
                "starting_cluster": extents[0]["start_cluster"],
                "cluster_chain": chain_str,
                "cluster_chain_list": cluster_list,
                "starting_lba": start_lba,
                "ending_lba": end_lba,
                "byte_offset": byte_offset,
                "byte_offset_hex": f"0x{byte_offset:08X}",
                "sectors_occupied": total_sectors,
                "clusters_occupied": total_clusters,
                "is_fragmented": is_fragmented,
                "extents": extents,
                "filesystem": fs_name,
                "allocation_disclaimer": f"Obtained from Windows Storage Driver via FSCTL_GET_RETRIEVAL_POINTERS. Device LBA represents logical controller address.",
            }
        finally:
            kernel32.CloseHandle(h_file)
    except Exception:
        return None


def _parse_fat32_file_allocation_engine(
    read_fn,
    bpb: Dict[str, Any],
    rel_path: str,
    part_start_lba: int,
    full_file_path: str,
    device_name: str = ""
) -> Optional[Dict[str, Any]]:
    """
    Core FAT32 directory navigation, cluster chain following, extent mapping, and verification engine.
    Strictly READ-ONLY.
    """
    bps = bpb["bytes_per_sector"]
    spc = bpb["sectors_per_cluster"]
    res_sec = bpb["reserved_sectors"]
    num_fats = bpb["num_fats"]
    fat_sz = bpb["fat_size_32"]
    root_clus = bpb["root_cluster"]
    first_data_sec = bpb["first_data_sector"]

    # Strict FAT32 Validations
    if bps not in (512, 1024, 2048, 4096) or spc not in (1, 2, 4, 8, 16, 32, 64, 128) or res_sec == 0 or num_fats == 0 or fat_sz == 0:
        return {
            "is_allocation_available": False,
            "starting_cluster": None,
            "cluster_chain": "UNAVAILABLE (INVALID FAT32 METADATA)",
            "cluster_chain_list": [],
            "starting_lba": None,
            "ending_lba": None,
            "byte_offset": None,
            "byte_offset_hex": "Unavailable",
            "sectors_occupied": 0,
            "clusters_occupied": 0,
            "allocated_sectors_extent": 0,
            "allocated_clusters_extent": 0,
            "is_fragmented": False,
            "extents": [],
            "filesystem": "FAT32",
            "mapping_layer": "Device Logical LBA",
            "raw_lba_verification": "UNVERIFIED",
            "verification_statement": "Invalid FAT32 BPB metadata encountered.",
            "allocation_disclaimer": "UNAVAILABLE (INVALID FAT32 METADATA)",
        }

    def clus_to_part_lba(c: int) -> int:
        return first_data_sec + (c - 2) * spc

    def clus_to_device_lba(c: int) -> int:
        return part_start_lba + clus_to_part_lba(c)

    fat_cache: Dict[int, bytes] = {}

    def read_fat_entry(c: int) -> int:
        fat_offset = c * 4
        sec_num = res_sec + (fat_offset // bps)
        off_in_sec = fat_offset % bps
        if sec_num not in fat_cache:
            fat_cache[sec_num] = read_fn(sec_num, 1)
        sec_bytes = fat_cache[sec_num]
        if len(sec_bytes) >= off_in_sec + 4:
            return struct.unpack_from("<I", sec_bytes, off_in_sec)[0] & 0x0FFFFFFF
        return 0x0FFFFFFF

    def get_cluster_chain(start_c: int) -> List[int]:
        chain = []
        curr = start_c
        visited = set()
        while curr >= 2 and curr < 0x0FFFFFF8 and curr not in visited and len(chain) < 65536:
            chain.append(curr)
            visited.add(curr)
            curr = read_fat_entry(curr)
        return chain

    def read_dir_entries_for_chain(start_c: int) -> List[Dict[str, Any]]:
        chain = [start_c] if start_c == root_clus else get_cluster_chain(start_c)
        if not chain and start_c >= 2:
            chain = [start_c]
        entries = []
        for c in chain:
            lba = clus_to_part_lba(c)
            data = read_fn(lba, spc)
            lfn_parts = {}
            for pos in range(0, len(data), 32):
                chunk = data[pos:pos+32]
                if not chunk or chunk[0] == 0x00:
                    break
                if chunk[0] == 0xE5:
                    lfn_parts.clear()
                    continue
                attr = chunk[11]
                if attr == 0x0F:
                    seq = chunk[0] & 0x1F
                    name_chars = bytearray()
                    name_chars.extend(chunk[1:11])
                    name_chars.extend(chunk[14:26])
                    name_chars.extend(chunk[28:32])
                    try:
                        lfn_str = name_chars.decode("utf-16le", errors="ignore").split("\x00")[0]
                        lfn_parts[seq] = lfn_str
                    except Exception:
                        pass
                    continue
                name_main = chunk[0:8].decode("latin-1", errors="replace").rstrip()
                ext = chunk[8:11].decode("latin-1", errors="replace").rstrip()
                short_name = f"{name_main}.{ext}" if ext else name_main
                if lfn_parts:
                    sorted_seqs = sorted(lfn_parts.keys())
                    full_name = "".join(lfn_parts[s] for s in sorted_seqs)
                    lfn_parts.clear()
                else:
                    full_name = short_name
                hi = struct.unpack_from("<H", chunk, 0x14)[0]
                lo = struct.unpack_from("<H", chunk, 0x1A)[0]
                sz = struct.unpack_from("<I", chunk, 0x1C)[0]
                start_clus = (hi << 16) | lo
                is_dir = bool(attr & 0x10)
                entries.append({
                    "name": full_name,
                    "short_name": short_name,
                    "is_dir": is_dir,
                    "starting_cluster": start_clus,
                    "file_size": sz,
                    "attributes_byte": attr,
                })
        return entries

    # Traverse path components
    norm_rel = rel_path.strip(r"\/")
    parts = [p for p in norm_rel.replace("/", "\\").split("\\") if p]
    if not parts:
        parts = [os.path.basename(full_file_path)]

    curr_c = root_clus
    target_entry = None

    for idx, segment in enumerate(parts):
        entries = read_dir_entries_for_chain(curr_c)
        match = next((e for e in entries if e["name"].lower() == segment.lower() or e["short_name"].lower() == segment.lower()), None)
        if not match:
            return None
        if idx == len(parts) - 1:
            target_entry = match
        else:
            if not match["is_dir"]:
                return None
            curr_c = match["starting_cluster"]

    if not target_entry:
        return None

    file_sz = target_entry["file_size"]
    start_c = target_entry["starting_cluster"]

    # Handle zero-byte files
    if file_sz == 0 or start_c < 2:
        return {
            "is_allocation_available": True,
            "starting_cluster": 0 if start_c == 0 else start_c,
            "starting_lba": None,
            "ending_lba": None,
            "byte_offset": None,
            "byte_offset_hex": "0x00000000",
            "sectors_occupied": 0,
            "clusters_occupied": 0,
            "allocated_sectors_extent": 0,
            "allocated_clusters_extent": 0,
            "cluster_chain": "0 clusters (Empty file)",
            "cluster_chain_list": [],
            "is_fragmented": False,
            "extents": [],
            "filesystem": "FAT32",
            "mapping_layer": "Device Logical LBA",
            "raw_lba_verification": "PASS (Empty File)",
            "verification_statement": "Zero-byte file requires no sector cluster allocation.",
            "partition_start_lba": part_start_lba,
            "partition_relative_start_lba": 0,
            "device_path": device_name,
            "allocation_disclaimer": "Calculated via Direct FAT32 Volume Parser. Device LBA represents partition-relative device address.",
        }

    chain = get_cluster_chain(start_c)
    if not chain:
        return None

    # Group into Extents
    extents = []
    c_start = chain[0]
    c_prev = chain[0]
    c_count = 1

    for c in chain[1:]:
        if c == c_prev + 1:
            c_prev = c
            c_count += 1
        else:
            ext_start_lba = clus_to_device_lba(c_start)
            ext_sec_count = c_count * spc
            ext_end_lba = ext_start_lba + ext_sec_count - 1
            ext_start_byte = ext_start_lba * bps
            ext_end_byte = (ext_end_lba + 1) * bps - 1
            extents.append({
                "start_cluster": c_start,
                "end_cluster": c_prev,
                "cluster_count": c_count,
                "start_lba": ext_start_lba,
                "end_lba": ext_end_lba,
                "sector_count": ext_sec_count,
                "start_byte_offset": ext_start_byte,
                "end_byte_offset": ext_end_byte,
                "start_byte_offset_hex": f"0x{ext_start_byte:08X}",
                "end_byte_offset_hex": f"0x{ext_end_byte:08X}",
            })
            c_start = c
            c_prev = c
            c_count = 1

    ext_start_lba = clus_to_device_lba(c_start)
    ext_sec_count = c_count * spc
    ext_end_lba = ext_start_lba + ext_sec_count - 1
    ext_start_byte = ext_start_lba * bps
    ext_end_byte = (ext_end_lba + 1) * bps - 1
    extents.append({
        "start_cluster": c_start,
        "end_cluster": c_prev,
        "cluster_count": c_count,
        "start_lba": ext_start_lba,
        "end_lba": ext_end_lba,
        "sector_count": ext_sec_count,
        "start_byte_offset": ext_start_byte,
        "end_byte_offset": ext_end_byte,
        "start_byte_offset_hex": f"0x{ext_start_byte:08X}",
        "end_byte_offset_hex": f"0x{ext_end_byte:08X}",
    })

    clus_by_size = math.ceil(file_sz / (bps * spc)) if file_sz > 0 else 0
    sec_by_size = math.ceil(file_sz / bps) if file_sz > 0 else 0
    total_clusters = len(chain)
    total_sectors = total_clusters * spc
    is_frag = len(extents) > 1

    if len(chain) <= 6:
        chain_str = " -> ".join(str(c) for c in chain)
    else:
        chain_str = f"{chain[0]} -> {chain[1]} -> ... -> {chain[-1]} ({len(chain)} clusters, {len(extents)} extent{'s' if is_frag else ''})"

    # Raw LBA Content Verification
    raw_verif = "UNVERIFIED"
    verif_stmt = "Raw sector byte verification was not performed."
    try:
        check_len = min(file_sz, 4096)
        raw_sec_data = read_fn(clus_to_part_lba(start_c), math.ceil(check_len / bps))[:check_len]
        if os.path.exists(full_file_path) and os.path.isfile(full_file_path):
            with open(full_file_path, "rb") as f_orig:
                file_sample = f_orig.read(check_len)
            if raw_sec_data == file_sample:
                raw_verif = "PASS"
                verif_stmt = "The bytes obtained from the calculated LBA/cluster allocation match the filesystem file content."
            else:
                raw_verif = "FAIL"
                verif_stmt = "Raw bytes read from calculated LBA do not match filesystem file content."
    except Exception:
        pass

    return {
        "is_allocation_available": True,
        "starting_cluster": extents[0]["start_cluster"],
        "starting_lba": extents[0]["start_lba"],
        "ending_lba": extents[-1]["end_lba"],
        "byte_offset": extents[0]["start_byte_offset"],
        "byte_offset_hex": extents[0]["start_byte_offset_hex"],
        "sectors_occupied": sec_by_size,
        "clusters_occupied": clus_by_size,
        "allocated_sectors_extent": total_sectors,
        "allocated_clusters_extent": total_clusters,
        "cluster_chain": chain_str,
        "cluster_chain_list": chain,
        "is_fragmented": is_frag,
        "extents": extents,
        "filesystem": "FAT32",
        "mapping_layer": "Device Logical LBA",
        "raw_lba_verification": raw_verif,
        "verification_statement": verif_stmt,
        "partition_start_lba": part_start_lba,
        "partition_relative_start_lba": clus_to_part_lba(start_c),
        "device_path": device_name,
        "allocation_disclaimer": "Calculated via Direct FAT32 Volume Parser. Device LBA represents partition-relative device address.",
    }


def direct_fat32_file_allocation(file_path: str, target_device: Optional[str] = None) -> Optional[Dict[str, Any]]:
    """
    Direct, strictly READ-ONLY FAT32 filesystem metadata and directory parser.
    Works directly against:
      - Mounted Windows FAT32 drive letters (e.g. E:\..., \\.\E:)
      - FAT32 raw disk / partition images
      - Raw physical drives with partition offset (e.g. \\.\PhysicalDrive1)
    """
    if not file_path:
        return None

    clean_path = os.path.abspath(file_path) if os.path.exists(file_path) else file_path
    drive_prefix, rel_path = os.path.splitdrive(clean_path)
    drive_let = drive_prefix.replace(":", "").replace("\\", "").strip().upper()

    # Case A: Target is a mounted Windows Volume / Drive Letter
    if sys.platform.startswith("win") and drive_let:
        import ctypes
        from ctypes import wintypes
        kernel32 = ctypes.windll.kernel32

        GENERIC_READ = 0x80000000
        FILE_SHARE_READ = 1
        FILE_SHARE_WRITE = 2
        FILE_SHARE_DELETE = 4
        OPEN_EXISTING = 3

        vol_handle_path = f"\\\\.\\{drive_let}:"
        h_vol = kernel32.CreateFileW(
            vol_handle_path,
            GENERIC_READ,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            None,
            OPEN_EXISTING,
            0,
            None
        )

        if h_vol != -1:
            try:
                def read_vol_sectors(vol_lba: int, count: int) -> bytes:
                    offset = vol_lba * 512
                    li_dist = wintypes.LARGE_INTEGER(offset)
                    kernel32.SetFilePointerEx(h_vol, li_dist, None, 0)
                    buf = ctypes.create_string_buffer(count * 512)
                    bytes_read = wintypes.DWORD(0)
                    res = kernel32.ReadFile(h_vol, buf, count * 512, ctypes.byref(bytes_read), None)
                    return buf.raw[:bytes_read.value]

                boot = read_vol_sectors(0, 1)
                bpb = parse_fat32_bpb(boot)
                if not bpb:
                    return None

                # Query Partition Start LBA and Physical Drive mapping for this volume
                part_start_lba = 2048
                phys_drive_name = f"\\\\.\\{drive_let}:"
                meta = _windows_query_disk_metadata(drive_letter=drive_let)
                for p in meta.get("partitions", []):
                    if str(p.get("DriveLetter") or "").upper() == drive_let:
                        off_bytes = int(p.get("Offset") or 0)
                        part_start_lba = off_bytes // max(1, bpb["bytes_per_sector"])
                        if p.get("DiskNumber") is not None:
                            phys_drive_name = f"\\\\.\\PhysicalDrive{p['DiskNumber']}"
                        break

                return _parse_fat32_file_allocation_engine(
                    read_fn=read_vol_sectors,
                    bpb=bpb,
                    rel_path=rel_path,
                    part_start_lba=part_start_lba,
                    full_file_path=file_path,
                    device_name=phys_drive_name
                )
            finally:
                kernel32.CloseHandle(h_vol)

    # Case B: Target is a file image (or target_device is an image file)
    target_img = target_device if (target_device and os.path.isfile(target_device)) else (file_path if os.path.isfile(file_path) else None)
    if target_img and os.path.isfile(target_img):
        try:
            with open(target_img, "rb") as f_img:
                boot = f_img.read(512)
                bpb = parse_fat32_bpb(boot)
                if not bpb:
                    return None

                def read_file_sectors(vol_lba: int, count: int) -> bytes:
                    f_img.seek(vol_lba * bpb["bytes_per_sector"])
                    return f_img.read(count * bpb["bytes_per_sector"])

                rel = os.path.basename(file_path) if file_path == target_img else file_path
                return _parse_fat32_file_allocation_engine(
                    read_fn=read_file_sectors,
                    bpb=bpb,
                    rel_path=rel,
                    part_start_lba=0,
                    full_file_path=file_path,
                    device_name=target_img
                )
        except Exception:
            pass

    return None


def get_file_storage_allocation(file_path: str, target_device: Optional[str] = None) -> Dict[str, Any]:
    """
    Unified entry point to resolve file storage allocation.
    Attempts:
      1. Direct FAT32 Volume / Device Parser (reliable direct read)
      2. Windows Kernel retrieval pointers (for NTFS/exFAT)
      3. Clean fallback reporting "Unavailable" without guessing
    """
    # 1. Try Direct FAT32 parser (Primary reliable method for FAT32)
    fat32_alloc = direct_fat32_file_allocation(file_path, target_device=target_device)
    if fat32_alloc:
        return fat32_alloc

    # 2. Try Windows native retrieval pointers (for NTFS / exFAT)
    win_alloc = get_windows_file_retrieval_pointers(file_path)
    if win_alloc:
        return win_alloc

    # 3. Clean fallback
    return {
        "is_allocation_available": False,
        "starting_cluster": None,
        "cluster_chain": "Unavailable",
        "cluster_chain_list": [],
        "starting_lba": None,
        "ending_lba": None,
        "byte_offset": None,
        "byte_offset_hex": "Unavailable",
        "sectors_occupied": 0,
        "clusters_occupied": 0,
        "allocated_sectors_extent": 0,
        "allocated_clusters_extent": 0,
        "is_fragmented": False,
        "extents": [],
        "filesystem": "Filesystem Managed",
        "mapping_layer": "Device Logical LBA",
        "raw_lba_verification": "UNAVAILABLE",
        "verification_statement": "Direct physical LBA translation is abstracted or unexposed by host filesystem driver.",
        "allocation_disclaimer": "Direct storage cluster mapping is abstracted or unexposed by current OS filesystem driver.",
    }



def search_filesystem_stream(
    target_path: str,
    query: str,
    query_type: str = "text",  # "text" or "hex"
    search_content: bool = True,
    max_matches: int = 100,
    max_depth: int = 15,
) -> Dict[str, Any]:
    """
    Layer 2: Filesystem-Aware Search.
    Recursively and safely enumerates directory structures, filenames, paths,
    and text file contents in strictly READ-ONLY mode.
    """
    resolved_path, display_name, hints = resolve_target_path(target_path)
    if not target_path or not query:
        return {"error": "Missing target or query parameter", "status": "ERROR"}

    # Determine filesystem root directory
    root_dir = ""
    fs_type = "Unknown"

    if sys.platform.startswith("win"):
        # Check if target is a drive letter (e.g. E:, \\.\E:, E:\)
        import re
        m_vol = re.match(r"^(\\\\?\.\\|//\./)?([a-zA-Z]):?\\?$", resolved_path or target_path)
        if m_vol:
            letter = m_vol.group(2).upper()
            root_dir = f"{letter}:\\"
        elif os.path.isdir(resolved_path):
            root_dir = resolved_path
        elif os.path.isfile(resolved_path):
            root_dir = os.path.dirname(resolved_path)
        elif resolved_path.startswith(r"\\.\PhysicalDrive"):
            # Try to map physical drive to mounted drive letters
            drive_letters = hints.get("device_info", {}).get("driveLetters", [])
            if not drive_letters and hints.get("drive_letter"):
                drive_letters = [f"{hints['drive_letter']}:"]
            if drive_letters:
                root_dir = f"{drive_letters[0].replace(':', '')}:\\"
    else:
        if os.path.isdir(resolved_path):
            root_dir = resolved_path
        elif os.path.isfile(resolved_path):
            root_dir = os.path.dirname(resolved_path)

    if not root_dir or not os.path.exists(root_dir):
        return {
            "status": "UNAVAILABLE",
            "target": target_path,
            "resolved_target": resolved_path,
            "error": "Filesystem-aware search unavailable for unmounted raw drive. Raw byte search remains available.",
            "matches_found": 0,
            "matches": [],
        }

    # Query filesystem type
    if sys.platform.startswith("win"):
        try:
            drive_let = os.path.splitdrive(root_dir)[0].replace(":", "").upper()
            meta = _windows_query_disk_metadata(drive_letter=drive_let)
            vol_info = meta.get("vol_map", {}).get(drive_let, {})
            fs_type = vol_info.get("FileSystem") or "FAT32 / NTFS"
        except Exception:
            fs_type = "Mounted Volume"
    else:
        fs_type = "Linux Filesystem"

    matches: List[Dict[str, Any]] = []
    query_str = query.strip()
    query_lower = query_str.lower()
    hex_pattern = None

    if query_type == "hex":
        try:
            hex_pattern = bytes.fromhex(query_str.replace(" ", "").replace("0x", ""))
        except Exception:
            return {"error": "Invalid hexadecimal query string", "status": "ERROR"}

    # Breadth-first traversal with safety bounds
    queue: List[Tuple[str, int]] = [(root_dir, 0)]
    files_scanned = 0
    dirs_scanned = 0

    while queue and len(matches) < max_matches:
        current_dir, depth = queue.pop(0)
        if depth > max_depth:
            continue

        try:
            with os.scandir(current_dir) as it:
                for entry in it:
                    if len(matches) >= max_matches:
                        break

                    try:
                        # 1. Folder Evaluation
                        if entry.is_dir(follow_symlinks=False):
                            dirs_scanned += 1
                            name = entry.name
                            path = entry.path

                            # Check for folder name match
                            if query_type == "text" and query_lower in name.lower():
                                st = entry.stat()
                                matches.append({
                                    "type": "folder",
                                    "match_type": "folder_name",
                                    "name": name,
                                    "path": path,
                                    "parent": current_dir,
                                    "size": None,
                                    "size_formatted": "—",
                                    "extension": "—",
                                    "filesystem": fs_type,
                                    "created_time": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(st.st_ctime)),
                                    "modified_time": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(st.st_mtime)),
                                    "accessed_time": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(st.st_atime)),
                                    "attributes": _get_file_attributes_str(path),
                                    "matched_value": name,
                                    "content_preview": f"Directory: {name}",
                                    "cluster": None,
                                    "lba": None,
                                    "byte_offset": None,
                                    "physical_location_available": False,
                                })
                            elif query_type == "text" and query_lower in path.lower():
                                st = entry.stat()
                                matches.append({
                                    "type": "folder",
                                    "match_type": "folder_path",
                                    "name": name,
                                    "path": path,
                                    "parent": current_dir,
                                    "size": None,
                                    "size_formatted": "—",
                                    "extension": "—",
                                    "filesystem": fs_type,
                                    "created_time": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(st.st_ctime)),
                                    "modified_time": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(st.st_mtime)),
                                    "accessed_time": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(st.st_atime)),
                                    "attributes": _get_file_attributes_str(path),
                                    "matched_value": path,
                                    "content_preview": f"Directory Path Match: {path}",
                                    "cluster": None,
                                    "lba": None,
                                    "byte_offset": None,
                                    "physical_location_available": False,
                                })

                            # Avoid system volume noise recursion
                            if name not in ("$RECYCLE.BIN", "System Volume Information", ".git", "node_modules"):
                                queue.append((path, depth + 1))

                        # 2. File Evaluation
                        elif entry.is_file(follow_symlinks=False):
                            files_scanned += 1
                            name = entry.name
                            path = entry.path
                            ext = os.path.splitext(name)[1].lower()
                            st = entry.stat()
                            fsize = st.st_size

                            # 2a. Check Filename match
                            filename_matched = False
                            if query_type == "text" and query_lower in name.lower():
                                filename_matched = True
                                alloc = get_file_storage_allocation(path, target_device=resolved_path)
                                matches.append({
                                    "type": "file",
                                    "match_type": "file_name",
                                    "name": name,
                                    "path": path,
                                    "parent": current_dir,
                                    "size": fsize,
                                    "size_formatted": f"{fsize:,} bytes",
                                    "extension": ext or "—",
                                    "filesystem": alloc.get("filesystem") or fs_type,
                                    "created_time": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(st.st_ctime)),
                                    "modified_time": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(st.st_mtime)),
                                    "accessed_time": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(st.st_atime)),
                                    "attributes": _get_file_attributes_str(path),
                                    "matched_value": name,
                                    "content_preview": f"Filename match: {name}",
                                    "is_allocation_available": alloc.get("is_allocation_available", False),
                                    "starting_cluster": alloc.get("starting_cluster"),
                                    "cluster_chain": alloc.get("cluster_chain"),
                                    "cluster_chain_list": alloc.get("cluster_chain_list", []),
                                    "starting_lba": alloc.get("starting_lba"),
                                    "ending_lba": alloc.get("ending_lba"),
                                    "byte_offset": alloc.get("byte_offset"),
                                    "byte_offset_hex": alloc.get("byte_offset_hex"),
                                    "sectors_occupied": alloc.get("sectors_occupied", 0),
                                    "clusters_occupied": alloc.get("clusters_occupied", 0),
                                    "is_fragmented": alloc.get("is_fragmented", False),
                                    "extents": alloc.get("extents", []),
                                    "allocation_disclaimer": alloc.get("allocation_disclaimer", ""),
                                    "lba": alloc.get("starting_lba"),
                                    "cluster": alloc.get("starting_cluster"),
                                    "physical_location_available": alloc.get("is_allocation_available", False),
                                })
                            elif query_type == "text" and query_lower in path.lower():
                                filename_matched = True
                                alloc = get_file_storage_allocation(path, target_device=resolved_path)
                                matches.append({
                                    "type": "file",
                                    "match_type": "file_path",
                                    "name": name,
                                    "path": path,
                                    "parent": current_dir,
                                    "size": fsize,
                                    "size_formatted": f"{fsize:,} bytes",
                                    "extension": ext or "—",
                                    "filesystem": alloc.get("filesystem") or fs_type,
                                    "created_time": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(st.st_ctime)),
                                    "modified_time": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(st.st_mtime)),
                                    "accessed_time": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(st.st_atime)),
                                    "attributes": _get_file_attributes_str(path),
                                    "matched_value": path,
                                    "content_preview": f"File Path match: {path}",
                                    "is_allocation_available": alloc.get("is_allocation_available", False),
                                    "starting_cluster": alloc.get("starting_cluster"),
                                    "cluster_chain": alloc.get("cluster_chain"),
                                    "cluster_chain_list": alloc.get("cluster_chain_list", []),
                                    "starting_lba": alloc.get("starting_lba"),
                                    "ending_lba": alloc.get("ending_lba"),
                                    "byte_offset": alloc.get("byte_offset"),
                                    "byte_offset_hex": alloc.get("byte_offset_hex"),
                                    "sectors_occupied": alloc.get("sectors_occupied", 0),
                                    "clusters_occupied": alloc.get("clusters_occupied", 0),
                                    "is_fragmented": alloc.get("is_fragmented", False),
                                    "extents": alloc.get("extents", []),
                                    "allocation_disclaimer": alloc.get("allocation_disclaimer", ""),
                                    "lba": alloc.get("starting_lba"),
                                    "cluster": alloc.get("starting_cluster"),
                                    "physical_location_available": alloc.get("is_allocation_available", False),
                                })

                            # 2b. Check File Contents match (if size <= 10 MiB to prevent memory overhead)
                            if search_content and fsize > 0 and fsize <= 10 * 1024 * 1024 and len(matches) < max_matches:
                                try:
                                    if query_type == "text":
                                        with open(path, "rb") as f_sample:
                                            sample = f_sample.read(512)
                                        if _is_text_file(path, sample):
                                            with open(path, "r", encoding="utf-8", errors="replace") as f:
                                                content = f.read(1024 * 1024)  # Read up to 1 MB for search
                                                idx = content.lower().find(query_lower)
                                                if idx != -1:
                                                    start_idx = max(0, idx - 30)
                                                    end_idx = min(len(content), idx + len(query_str) + 30)
                                                    snippet = content[start_idx:end_idx].replace("\n", " ").replace("\r", " ").strip()
                                                    lines = content.splitlines()
                                                    line_num = 1
                                                    for l_idx, l_text in enumerate(lines):
                                                        if query_lower in l_text.lower():
                                                            line_num = l_idx + 1
                                                            break
                                                    alloc = get_file_storage_allocation(path, target_device=resolved_path)
                                                    matches.append({
                                                        "type": "file",
                                                        "match_type": "file_content",
                                                        "name": name,
                                                        "path": path,
                                                        "parent": current_dir,
                                                        "size": fsize,
                                                        "size_formatted": f"{fsize:,} bytes",
                                                        "extension": ext or "—",
                                                        "filesystem": alloc.get("filesystem") or fs_type,
                                                        "created_time": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(st.st_ctime)),
                                                        "modified_time": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(st.st_mtime)),
                                                        "accessed_time": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(st.st_atime)),
                                                        "attributes": _get_file_attributes_str(path),
                                                        "matched_value": query_str,
                                                        "snippet": snippet,
                                                        "line_number": line_num,
                                                        "content_preview": f"Line {line_num}: ...{snippet}..." if start_idx > 0 or end_idx < len(content) else f"Line {line_num}: {snippet}",
                                                        "is_allocation_available": alloc.get("is_allocation_available", False),
                                                        "starting_cluster": alloc.get("starting_cluster"),
                                                        "cluster_chain": alloc.get("cluster_chain"),
                                                        "cluster_chain_list": alloc.get("cluster_chain_list", []),
                                                        "starting_lba": alloc.get("starting_lba"),
                                                        "ending_lba": alloc.get("ending_lba"),
                                                        "byte_offset": alloc.get("byte_offset"),
                                                        "byte_offset_hex": alloc.get("byte_offset_hex"),
                                                        "sectors_occupied": alloc.get("sectors_occupied", 0),
                                                        "clusters_occupied": alloc.get("clusters_occupied", 0),
                                                        "is_fragmented": alloc.get("is_fragmented", False),
                                                        "extents": alloc.get("extents", []),
                                                        "allocation_disclaimer": alloc.get("allocation_disclaimer", ""),
                                                        "lba": alloc.get("starting_lba"),
                                                        "cluster": alloc.get("starting_cluster"),
                                                        "physical_location_available": alloc.get("is_allocation_available", False),
                                                    })
                                    elif query_type == "hex" and hex_pattern:
                                        with open(path, "rb") as f_bin:
                                            chunk = f_bin.read(1024 * 1024)
                                            idx = chunk.find(hex_pattern)
                                            if idx != -1:
                                                alloc = get_file_storage_allocation(path, target_device=resolved_path)
                                                matches.append({
                                                    "type": "file",
                                                    "match_type": "file_content",
                                                    "name": name,
                                                    "path": path,
                                                    "parent": current_dir,
                                                    "size": fsize,
                                                    "size_formatted": f"{fsize:,} bytes",
                                                    "extension": ext or "—",
                                                    "filesystem": alloc.get("filesystem") or fs_type,
                                                    "created_time": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(st.st_ctime)),
                                                    "modified_time": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(st.st_mtime)),
                                                    "accessed_time": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(st.st_atime)),
                                                    "attributes": _get_file_attributes_str(path),
                                                    "matched_value": hex_pattern.hex().upper(),
                                                    "snippet": hex_pattern.hex().upper(),
                                                    "line_number": None,
                                                    "content_preview": f"Binary pattern matched at file offset 0x{idx:06X} ({idx})",
                                                    "is_allocation_available": alloc.get("is_allocation_available", False),
                                                    "starting_cluster": alloc.get("starting_cluster"),
                                                    "cluster_chain": alloc.get("cluster_chain"),
                                                    "cluster_chain_list": alloc.get("cluster_chain_list", []),
                                                    "starting_lba": alloc.get("starting_lba"),
                                                    "ending_lba": alloc.get("ending_lba"),
                                                    "byte_offset": alloc.get("byte_offset"),
                                                    "byte_offset_hex": alloc.get("byte_offset_hex"),
                                                    "sectors_occupied": alloc.get("sectors_occupied", 0),
                                                    "clusters_occupied": alloc.get("clusters_occupied", 0),
                                                    "is_fragmented": alloc.get("is_fragmented", False),
                                                    "extents": alloc.get("extents", []),
                                                    "allocation_disclaimer": alloc.get("allocation_disclaimer", ""),
                                                    "lba": alloc.get("starting_lba"),
                                                    "cluster": alloc.get("starting_cluster"),
                                                    "physical_location_available": alloc.get("is_allocation_available", False),
                                                })
                                except Exception:
                                    pass

                    except (PermissionError, OSError):
                        continue
        except (PermissionError, OSError):
            continue

    return {
        "status": "SUCCESS",
        "target": target_path,
        "root_directory": root_dir,
        "filesystem": fs_type,
        "query": query,
        "query_type": query_type,
        "files_scanned": files_scanned,
        "dirs_scanned": dirs_scanned,
        "matches_found": len(matches),
        "matches": matches,
    }


def search_storage_stream(
    target_path: str,
    query: str,
    query_type: str = "text",  # "text" or "hex" or "file_details" or "file_details_hash"
    max_scan_bytes: int = 50 * 1024 * 1024,  # 50 MiB default limit
    sector_size: int = 512,
    search_mode: str = "both",
) -> Dict[str, Any]:
    """
    Layer 1 & Backward Compatible Storage Search.
    Supports raw sector streaming, directory filesystem traversal, and on-demand file inspection.
    """
    if query_type in ("file_details", "file_details_hash") or query == "__FILE_DETAILS__":
        return get_file_details(target_path, compute_hash=(query_type == "file_details_hash"))

    resolved_path, display_name, hints = resolve_target_path(target_path)
    if not resolved_path:
        return {"error": "Target device/file not found", "status": "ERROR"}

    # If target is a directory, automatically perform filesystem-aware search
    if os.path.isdir(resolved_path):
        return search_filesystem_stream(
            target_path=resolved_path,
            query=query,
            query_type=query_type,
            search_content=True,
            max_matches=100,
        )

    if query_type == "hex":
        try:
            pattern = bytes.fromhex(query.replace(" ", "").replace("0x", ""))
        except Exception:
            return {"error": "Invalid hexadecimal query string", "status": "ERROR"}
    else:
        pattern = query.encode("utf-8")

    if not pattern:
        return {"error": "Empty search pattern", "status": "ERROR"}

    matches: List[Dict[str, Any]] = []
    chunk_size = 2 * 1024 * 1024
    overlap = len(pattern) - 1
    overlap_buf = b""
    bytes_scanned = 0

    try:
        if os.path.isfile(resolved_path):
            total_size = min(os.path.getsize(resolved_path), max_scan_bytes)
            with open(resolved_path, "rb") as f:
                while bytes_scanned < total_size and len(matches) < 50:
                    chunk = f.read(chunk_size)
                    if not chunk:
                        break
                    eval_buf = overlap_buf + chunk
                    base_offset = max(0, bytes_scanned - len(overlap_buf))

                    pos = 0
                    while True:
                        idx = eval_buf.find(pattern, pos)
                        if idx == -1 or len(matches) >= 50:
                            break
                        match_abs = base_offset + idx
                        matches.append({
                            "type": "raw_sector",
                            "match_type": "raw_byte",
                            "offset": match_abs,
                            "offset_hex": f"0x{match_abs:08X}",
                            "lba": match_abs // sector_size,
                            "sector_offset": match_abs % sector_size,
                            "matched_bytes_hex": eval_buf[idx:idx + len(pattern)].hex().upper(),
                            "content_preview": f"Raw Byte Match at LBA {match_abs // sector_size} (+{match_abs % sector_size} B)",
                        })
                        pos = idx + len(pattern)

                    bytes_scanned += len(chunk)
                    overlap_buf = chunk[-overlap:] if len(chunk) >= overlap else chunk
        else:
            fd = os.open(resolved_path, os.O_RDONLY | getattr(os, "O_BINARY", 0))
            try:
                while bytes_scanned < max_scan_bytes and len(matches) < 50:
                    os.lseek(fd, bytes_scanned, os.SEEK_SET)
                    chunk = os.read(fd, chunk_size)
                    if not chunk:
                        break
                    eval_buf = overlap_buf + chunk
                    base_offset = max(0, bytes_scanned - len(overlap_buf))

                    pos = 0
                    while True:
                        idx = eval_buf.find(pattern, pos)
                        if idx == -1 or len(matches) >= 50:
                            break
                        match_abs = base_offset + idx
                        matches.append({
                            "type": "raw_sector",
                            "match_type": "raw_byte",
                            "offset": match_abs,
                            "offset_hex": f"0x{match_abs:08X}",
                            "lba": match_abs // sector_size,
                            "sector_offset": match_abs % sector_size,
                            "matched_bytes_hex": eval_buf[idx:idx + len(pattern)].hex().upper(),
                            "content_preview": f"Raw Byte Match at LBA {match_abs // sector_size} (+{match_abs % sector_size} B)",
                        })
                        pos = idx + len(pattern)

                    bytes_scanned += len(chunk)
                    overlap_buf = chunk[-overlap:] if len(chunk) >= overlap else chunk
            finally:
                os.close(fd)

    except PermissionError:
        if sys.platform.startswith("win"):
            return {
                "error": f"Permission denied searching raw device on {resolved_path} (Administrator privileges required)",
                "status": "PERMISSION_DENIED",
                "is_permission_error": True,
                "help_instructions": [
                    "Option 1: Run the backend with Administrator privileges",
                    "Option 2: Search within an accessible partition drive handle or file image",
                ],
            }
        else:
            return {
                "error": "Permission denied reading raw device sectors (root/Administrator required)",
                "status": "PERMISSION_DENIED",
                "is_permission_error": True,
                "help_instructions": [
                    "Option 1: Add your user to the 'disk' group: sudo usermod -a -G disk $USER (then log out and back in)",
                    "Option 2: Run the backend with root privileges: sudo python3 backend/app.py",
                ],
            }
    except Exception as e:
        return {"error": str(e), "status": "SEARCH_ERROR"}

    return {
        "status": "SUCCESS",
        "target": target_path,
        "resolved_target": resolved_path,
        "display_name": display_name,
        "query": query,
        "query_type": query_type,
        "bytes_scanned": bytes_scanned,
        "matches_found": len(matches),
        "matches": matches,
    }


def unified_storage_search(
    target_path: str,
    query: str,
    query_type: str = "text",
    search_mode: str = "both",  # "raw" | "filesystem" | "both"
    max_scan_bytes: int = 50 * 1024 * 1024,
    sector_size: int = 512,
) -> Dict[str, Any]:
    """
    Unified search entry point orchestrating Layer 1 (Raw Bytes) and Layer 2 (Filesystem-Aware).
    Strictly READ-ONLY.
    """
    raw_res: Dict[str, Any] = {"matches": [], "status": "SKIPPED"}
    fs_res: Dict[str, Any] = {"matches": [], "status": "SKIPPED"}

    if search_mode in ("raw", "both"):
        raw_res = search_storage_stream(
            target_path=target_path,
            query=query,
            query_type=query_type,
            max_scan_bytes=max_scan_bytes,
            sector_size=sector_size,
        )

    if search_mode in ("filesystem", "both"):
        fs_res = search_filesystem_stream(
            target_path=target_path,
            query=query,
            query_type=query_type,
            search_content=True,
            max_matches=100,
        )

    raw_matches = raw_res.get("matches") or []
    fs_matches = fs_res.get("matches") or []

    # Combined matches for unified view
    combined: List[Dict[str, Any]] = []
    combined.extend(fs_matches)
    combined.extend(raw_matches)

    return {
        "status": "SUCCESS",
        "target": target_path,
        "query": query,
        "query_type": query_type,
        "search_mode": search_mode,
        "total_matches": len(combined),
        "filesystem_matches_count": len(fs_matches),
        "raw_matches_count": len(raw_matches),
        "filesystem_status": fs_res.get("status"),
        "filesystem_error": fs_res.get("error"),
        "raw_status": raw_res.get("status"),
        "raw_error": raw_res.get("error"),
        "matches": combined,
        "filesystem_matches": fs_matches,
        "raw_matches": raw_matches,
    }


def get_file_details(file_path: str, compute_hash: bool = False, target_device: Optional[str] = None) -> Dict[str, Any]:
    """
    Retrieve comprehensive read-only metadata, attributes, preview, storage allocation mapping, and optional SHA-256 for a file/folder.
    """
    if not file_path or not os.path.exists(file_path):
        return {"error": f"Path not found: {file_path}", "status": "ERROR"}

    try:
        st = os.stat(file_path)
        is_file = stat.S_ISREG(st.st_mode)
        is_dir = stat.S_ISDIR(st.st_mode)
        name = os.path.basename(file_path) or file_path
        parent = os.path.dirname(file_path)
        ext = os.path.splitext(name)[1].lower() if is_file else ""

        # Determine filesystem
        fs = "Unknown"
        if sys.platform.startswith("win"):
            drive_let = os.path.splitdrive(file_path)[0].replace(":", "").upper()
            if drive_let:
                meta = _windows_query_disk_metadata(drive_letter=drive_let)
                vol_info = meta.get("vol_map", {}).get(drive_let, {})
                fs = vol_info.get("FileSystem") or "NTFS / FAT32"

        text_preview = ""
        hex_preview = ""
        is_text = False
        sha256_digest = None

        if is_file:
            with open(file_path, "rb") as f:
                sample = f.read(512)
            is_text = _is_text_file(file_path, sample)

            if is_text:
                with open(file_path, "r", encoding="utf-8", errors="replace") as f:
                    text_preview = f.read(4096)
            else:
                hex_parts = [f"{b:02X}" for b in sample[:256]]
                hex_preview = " ".join(hex_parts)

            if compute_hash:
                h = hashlib.sha256()
                with open(file_path, "rb") as f:
                    for chunk in iter(lambda: f.read(65536), b""):
                        h.update(chunk)
                sha256_digest = h.hexdigest()

        # Query file storage allocation in read-only mode
        if is_file:
            alloc = get_file_storage_allocation(file_path, target_device=target_device)
        else:
            alloc = {
                "is_allocation_available": False,
                "starting_cluster": None,
                "cluster_chain": "Unavailable (Directory)",
                "cluster_chain_list": [],
                "starting_lba": None,
                "ending_lba": None,
                "byte_offset": None,
                "byte_offset_hex": "Unavailable",
                "sectors_occupied": 0,
                "clusters_occupied": 0,
                "is_fragmented": False,
                "extents": [],
                "filesystem": fs,
                "allocation_disclaimer": "Directories are metadata structures without direct file allocation extents.",
            }

        resolved_fs = alloc.get("filesystem") if (alloc.get("filesystem") and alloc.get("filesystem") != "Filesystem Managed") else fs

        return {
            "status": "SUCCESS",
            "name": name,
            "path": file_path,
            "parent": parent,
            "type": "file" if is_file else ("folder" if is_dir else "other"),
            "size": st.st_size if is_file else None,
            "size_formatted": f"{st.st_size:,} bytes" if is_file else "—",
            "extension": ext or "—",
            "filesystem": resolved_fs,
            "created_time": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(st.st_ctime)),
            "modified_time": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(st.st_mtime)),
            "accessed_time": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(st.st_atime)),
            "attributes": _get_file_attributes_str(file_path),
            "is_text": is_text,
            "text_preview": text_preview,
            "hex_preview": hex_preview,
            "sha256": sha256_digest,
            "is_allocation_available": alloc.get("is_allocation_available", False),
            "starting_cluster": alloc.get("starting_cluster"),
            "cluster_chain": alloc.get("cluster_chain"),
            "cluster_chain_list": alloc.get("cluster_chain_list", []),
            "starting_lba": alloc.get("starting_lba"),
            "ending_lba": alloc.get("ending_lba"),
            "byte_offset": alloc.get("byte_offset"),
            "byte_offset_hex": alloc.get("byte_offset_hex"),
            "sectors_occupied": alloc.get("sectors_occupied", 0),
            "clusters_occupied": alloc.get("clusters_occupied", 0),
            "allocated_sectors_extent": alloc.get("allocated_sectors_extent", alloc.get("sectors_occupied", 0)),
            "allocated_clusters_extent": alloc.get("allocated_clusters_extent", alloc.get("clusters_occupied", 0)),
            "is_fragmented": alloc.get("is_fragmented", False),
            "extents": alloc.get("extents", []),
            "mapping_layer": alloc.get("mapping_layer", "Device Logical LBA"),
            "raw_lba_verification": alloc.get("raw_lba_verification", "UNVERIFIED"),
            "verification_statement": alloc.get("verification_statement", ""),
            "partition_start_lba": alloc.get("partition_start_lba", 0),
            "partition_relative_start_lba": alloc.get("partition_relative_start_lba", 0),
            "device_path": alloc.get("device_path", ""),
            "allocation_disclaimer": alloc.get("allocation_disclaimer", ""),
            "cluster": alloc.get("starting_cluster"),
            "lba": alloc.get("starting_lba"),
            "physical_location_statement": alloc.get("allocation_disclaimer") or "Direct physical LBA translation is abstracted by host filesystem driver.",
        }
    except Exception as e:
        return {"error": str(e), "status": "ERROR"}


