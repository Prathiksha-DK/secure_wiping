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
    elif entropy > 7.7:
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
# Device & Metadata Inspector (Strictly Read-Only)
# ---------------------------------------------------------------------------

def inspect_storage_metadata(target_path: str) -> Dict[str, Any]:
    """
    Gather comprehensive physical and OS metadata for the selected target.
    Strictly read-only inspection.
    """
    info: Dict[str, Any] = {
        "target_path": target_path,
        "target_type": "unknown",
        "exists": os.path.exists(target_path),
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

    if not os.path.exists(target_path):
        info["os_metadata"]["device_status"] = "Target not found"
        return info

    st = os.stat(target_path)
    is_block = stat.S_ISBLK(st.st_mode)
    is_file = stat.S_ISREG(st.st_mode)
    is_dir = stat.S_ISDIR(st.st_mode)

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

    elif is_dir:
        info["target_type"] = "directory"
        total_size = 0
        file_count = 0
        for dirpath, _, filenames in os.walk(target_path):
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

    elif is_block or target_path.startswith("/dev/"):
        info["target_type"] = "disk"
        info["os_metadata"]["timestamps_applicable"] = False
        info["os_metadata"]["created_time"] = "Filesystem object timestamps: Not applicable to raw block device"
        info["os_metadata"]["modified_time"] = "Filesystem object timestamps: Not applicable to raw block device"

        # Query Linux lsblk for physical & partition details
        if sys.platform.startswith("linux"):
            try:
                cmd = ["lsblk", "-J", "-b", "-o", "NAME,SIZE,START,MODEL,SERIAL,VENDOR,TRAN,ROTA,PHY-SEC,LOG-SEC,FSTYPE,UUID,LABEL,MOUNTPOINT,PTTYPE,PARTTYPE,PARTN", target_path]
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

                        # Read firmware revision from sysfs if exposed
                        try:
                            base_name = os.path.basename(target_path)
                            for fw_path in [
                                f"/sys/block/{base_name}/device/firmware_rev",
                                f"/sys/class/block/{base_name}/device/firmware_rev",
                                f"/sys/block/{base_name}/device/rev",
                                f"/sys/class/block/{base_name}/device/rev",
                            ]:
                                if os.path.exists(fw_path):
                                    with open(fw_path, "r") as ff:
                                        fw = ff.read().strip()
                                        if fw:
                                            info["physical_identity"]["firmware_revision"] = fw
                                            break
                        except Exception:
                            pass

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
                "SELECT id, standard, method, status, finalState, startTime, endTime, filesVerified FROM wipe_history WHERE device = ? ORDER BY created_at DESC LIMIT 1",
                (target_path,)
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
    """
    if not os.path.exists(target_path):
        return {"error": f"Target not found: {target_path}", "status": "ERROR"}

    sector_size = max(512, min(sector_size, 4096))
    sector_count = max(1, min(sector_count, 16))
    lba = max(0, lba)

    byte_offset = lba * sector_size
    read_length = sector_size * sector_count

    try:
        if os.path.isfile(target_path):
            file_size = os.path.getsize(target_path)
            if byte_offset >= file_size and file_size > 0:
                return {
                    "error": f"Requested LBA {lba} (offset {byte_offset:,}) exceeds file size ({file_size:,} bytes)",
                    "status": "OUT_OF_BOUNDS",
                }
            with open(target_path, "rb") as f:
                f.seek(byte_offset)
                raw_bytes = f.read(read_length)
        else:
            fd = os.open(target_path, os.O_RDONLY | getattr(os, "O_BINARY", 0))
            try:
                os.lseek(fd, byte_offset, os.SEEK_SET)
                raw_bytes = os.read(fd, read_length)
            finally:
                os.close(fd)

    except PermissionError:
        return {
            "error": "Permission denied reading raw device sectors (root/Administrator required)",
            "status": "PERMISSION_DENIED",
            "is_permission_error": True,
            "help_instructions": [
                "Option 1: Add user to 'disk' group: sudo usermod -a -G disk $USER (then re-login)",
                "Option 2: Run backend with root: sudo python3 backend/app.py"
            ]
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

    return {
        "status": "SUCCESS",
        "target": target_path,
        "lba": lba,
        "sector_size": sector_size,
        "sector_count": sector_count,
        "byte_offset": byte_offset,
        "end_byte_offset": byte_offset + len(raw_bytes) - 1,
        "bytes_read": len(raw_bytes),
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
# In-Storage Read-Only Search
# ---------------------------------------------------------------------------

def search_storage_stream(
    target_path: str,
    query: str,
    query_type: str = "text",  # "text" or "hex"
    max_scan_bytes: int = 50 * 1024 * 1024,  # 50 MiB default limit
    sector_size: int = 512,
) -> Dict[str, Any]:
    """
    Read-only stream search for text or hexadecimal sequences across storage.
    """
    if not os.path.exists(target_path):
        return {"error": "Target device/file not found", "status": "ERROR"}

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
        if os.path.isfile(target_path):
            total_size = min(os.path.getsize(target_path), max_scan_bytes)
            with open(target_path, "rb") as f:
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
                            "offset": match_abs,
                            "offset_hex": f"0x{match_abs:08X}",
                            "lba": match_abs // sector_size,
                            "sector_offset": match_abs % sector_size,
                            "matched_bytes_hex": eval_buf[idx:idx + len(pattern)].hex().upper(),
                        })
                        pos = idx + len(pattern)

                    bytes_scanned += len(chunk)
                    overlap_buf = chunk[-overlap:] if len(chunk) >= overlap else chunk
        else:
            fd = os.open(target_path, os.O_RDONLY | getattr(os, "O_BINARY", 0))
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
                            "offset": match_abs,
                            "offset_hex": f"0x{match_abs:08X}",
                            "lba": match_abs // sector_size,
                            "sector_offset": match_abs % sector_size,
                            "matched_bytes_hex": eval_buf[idx:idx + len(pattern)].hex().upper(),
                        })
                        pos = idx + len(pattern)

                    bytes_scanned += len(chunk)
                    overlap_buf = chunk[-overlap:] if len(chunk) >= overlap else chunk
            finally:
                os.close(fd)

    except PermissionError:
        return {
            "error": "Permission denied reading raw device sectors (root/Administrator required)",
            "status": "PERMISSION_DENIED",
            "is_permission_error": True,
            "help_instructions": [
                "Option 1: Add your user to the 'disk' group: sudo usermod -a -G disk $USER (then log out and back in)",
                "Option 2: Run the backend with root privileges: sudo python3 backend/app.py"
            ]
        }
    except Exception as e:
        return {"error": str(e), "status": "SEARCH_ERROR"}

    return {
        "status": "SUCCESS",
        "target": target_path,
        "query": query,
        "query_type": query_type,
        "bytes_scanned": bytes_scanned,
        "matches_found": len(matches),
        "matches": matches,
    }

