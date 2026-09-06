#!/usr/bin/env python3
"""
FARIS — FAT32 Deleted File & Directory Entry Forensic Recovery Module
====================================================================
Provides strictly READ-ONLY raw inspection of FAT32 filesystem structures:
- Parses BPB, FAT tables, and directory cluster chains.
- Detects and reconstructs deleted directory entries (0xE5 markers & LFN chains).
- Recovers deleted file data clusters via defensible FAT-chain or contiguous allocation.
- Computes SHA-256 digests and validates structural integrity.
"""

import os
import sys
import math
import struct
import hashlib
import datetime
from typing import Dict, List, Any, Optional, Tuple, Callable


def parse_fat32_bpb_from_boot(boot_sector: bytes) -> Optional[Dict[str, Any]]:
    """
    Parses standard FAT32 BIOS Parameter Block (BPB) from sector 0 bytes.
    """
    if not boot_sector or len(boot_sector) < 512:
        return None

    # Check boot signature 0x55AA
    if boot_sector[510:512] != b"\x55\xaa":
        return None

    try:
        bps = struct.unpack_from("<H", boot_sector, 11)[0]
        spc = boot_sector[13]
        res_sec = struct.unpack_from("<H", boot_sector, 14)[0]
        num_fats = boot_sector[16]
        tot_sec16 = struct.unpack_from("<H", boot_sector, 19)[0]
        tot_sec32 = struct.unpack_from("<I", boot_sector, 32)[0]
        tot_sec = tot_sec32 if tot_sec32 != 0 else tot_sec16
        spf = struct.unpack_from("<I", boot_sector, 36)[0]
        root_clus = struct.unpack_from("<I", boot_sector, 44)[0]

        if bps not in (512, 1024, 2048, 4096) or spc == 0 or num_fats == 0 or spf == 0:
            return None

        first_data_sec = res_sec + (num_fats * spf)
        bytes_per_cluster = bps * spc

        return {
            "bytes_per_sector": bps,
            "sectors_per_cluster": spc,
            "bytes_per_cluster": bytes_per_cluster,
            "reserved_sectors": res_sec,
            "num_fats": num_fats,
            "sectors_per_fat": spf,
            "root_cluster": root_clus,
            "first_data_sector": first_data_sec,
            "total_sectors": tot_sec,
        }
    except Exception:
        return None


def parse_fat_datetime(date_val: int, time_val: int) -> str:
    """Parses standard DOS date and time words into ISO timestamp string."""
    try:
        if date_val == 0:
            return ""
        year = ((date_val >> 9) & 0x7F) + 1980
        month = (date_val >> 5) & 0x0F
        day = date_val & 0x1F
        hour = (time_val >> 11) & 0x1F
        minute = (time_val >> 5) & 0x3F
        second = (time_val & 0x1F) * 2
        month = max(1, min(12, month))
        day = max(1, min(31, day))
        hour = max(0, min(23, hour))
        minute = max(0, min(59, minute))
        second = max(0, min(59, second))
        dt = datetime.datetime(year, month, day, hour, minute, second, tzinfo=datetime.timezone.utc)
        return dt.isoformat()
    except Exception:
        return ""


class FAT32RawScanner:
    """
    Strictly READ-ONLY FAT32 raw disk/volume scanner.
    """

    def __init__(
        self,
        read_fn: Callable[[int, int], bytes],
        bpb: Dict[str, Any],
        part_start_lba: int = 0,
        device_path: str = ""
    ):
        self.read_fn = read_fn
        self.bpb = bpb
        self.part_start_lba = part_start_lba
        self.device_path = device_path
        self.bps = bpb["bytes_per_sector"]
        self.spc = bpb["sectors_per_cluster"]
        self.bpc = bpb["bytes_per_cluster"]
        self.first_data_sec = bpb["first_data_sector"]
        self.res_sec = bpb["reserved_sectors"]
        self.root_clus = bpb["root_cluster"]
        self._fat_cache: Dict[int, bytes] = {}

    def clus_to_part_lba(self, cluster: int) -> int:
        """Translates cluster number to partition relative LBA."""
        return self.first_data_sec + (cluster - 2) * self.spc

    def clus_to_device_lba(self, cluster: int) -> int:
        """Translates cluster number to device logical LBA."""
        return self.part_start_lba + self.clus_to_part_lba(cluster)

    def read_fat_entry(self, cluster: int) -> int:
        """Reads FAT32 table entry for cluster (strictly 28-bit mask)."""
        fat_offset = cluster * 4
        sec_num = self.res_sec + (fat_offset // self.bps)
        off_in_sec = fat_offset % self.bps
        if sec_num not in self._fat_cache:
            self._fat_cache[sec_num] = self.read_fn(sec_num, 1)
        sec_bytes = self._fat_cache[sec_num]
        if len(sec_bytes) >= off_in_sec + 4:
            return struct.unpack_from("<I", sec_bytes, off_in_sec)[0] & 0x0FFFFFFF
        return 0x0FFFFFFF

    def get_cluster_chain(self, start_clus: int) -> List[int]:
        """Retrieves cluster chain from FAT table."""
        chain = []
        curr = start_clus
        visited = set()
        while 2 <= curr < 0x0FFFFFF8 and curr not in visited and len(chain) < 65536:
            chain.append(curr)
            visited.add(curr)
            curr = self.read_fat_entry(curr)
        return chain

    def scan_directory_cluster(
        self,
        dir_cluster: int,
        parent_folder_path: str = ""
    ) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
        """
        Scans a directory cluster chain for both ACTIVE and DELETED directory entries.
        Returns: (active_entries, deleted_entries)
        """
        chain = [dir_cluster] if dir_cluster == self.root_clus else self.get_cluster_chain(dir_cluster)
        if not chain and dir_cluster >= 2:
            chain = [dir_cluster]

        active_entries: List[Dict[str, Any]] = []
        deleted_entries: List[Dict[str, Any]] = []

        lfn_parts: Dict[int, str] = {}
        deleted_lfn_parts: List[str] = []

        for c in chain:
            part_lba = self.clus_to_part_lba(c)
            dev_lba = self.clus_to_device_lba(c)
            clus_bytes = self.read_fn(part_lba, self.spc)

            for pos in range(0, len(clus_bytes), 32):
                chunk = clus_bytes[pos:pos + 32]
                if len(chunk) < 32:
                    break

                first_byte = chunk[0]
                if first_byte == 0x00:
                    break

                sec_in_clus = pos // self.bps
                entry_dev_lba = dev_lba + sec_in_clus
                entry_byte_offset = (entry_dev_lba * self.bps) + (pos % self.bps)
                attr = chunk[11]

                # Check for Long File Name (LFN) entry
                if attr == 0x0F:
                    seq = first_byte & 0x1F
                    name_chars = bytearray()
                    name_chars.extend(chunk[1:11])
                    name_chars.extend(chunk[14:26])
                    name_chars.extend(chunk[28:32])
                    try:
                        lfn_str = name_chars.decode("utf-16le", errors="ignore").split("\x00")[0]
                        if first_byte == 0xE5:
                            # Deleted LFN fragment
                            deleted_lfn_parts.append(lfn_str)
                        else:
                            lfn_parts[seq] = lfn_str
                    except Exception:
                        pass
                    continue

                # Skip Volume Label entries
                if attr & 0x08:
                    lfn_parts.clear()
                    deleted_lfn_parts.clear()
                    continue

                # Regular 8.3 Directory Entry (Active or Deleted)
                is_deleted = (first_byte == 0xE5)

                # Reconstruct short name
                if is_deleted:
                    raw_body = chunk[1:8]
                    raw_ext = chunk[8:11]
                    # Check for valid printable characters
                    if not any(32 <= b <= 126 for b in raw_body) and not any(32 <= b <= 126 for b in raw_ext):
                        # Noise/garbage entry
                        lfn_parts.clear()
                        deleted_lfn_parts.clear()
                        continue
                    body_str = "_" + raw_body.decode("latin-1", errors="replace").rstrip()
                    ext_str = raw_ext.decode("latin-1", errors="replace").rstrip()
                    short_name = f"{body_str}.{ext_str}" if ext_str else body_str
                else:
                    body_str = chunk[0:8].decode("latin-1", errors="replace").rstrip()
                    ext_str = chunk[8:11].decode("latin-1", errors="replace").rstrip()
                    short_name = f"{body_str}.{ext_str}" if ext_str else body_str

                # Reconstruct full filename
                if is_deleted and deleted_lfn_parts:
                    full_name = "".join(reversed(deleted_lfn_parts))
                elif not is_deleted and lfn_parts:
                    full_name = "".join(lfn_parts[k] for k in sorted(lfn_parts.keys()))
                else:
                    full_name = short_name

                # Clean up LFN buffers
                lfn_parts.clear()
                deleted_lfn_parts.clear()

                # Extract cluster pointer and size
                hi_clus = struct.unpack_from("<H", chunk, 0x14)[0]
                lo_clus = struct.unpack_from("<H", chunk, 0x1A)[0]
                start_clus = (hi_clus << 16) | lo_clus
                file_size = struct.unpack_from("<I", chunk, 0x1C)[0]
                is_dir = bool(attr & 0x10)

                # Parse Timestamps
                create_time = struct.unpack_from("<H", chunk, 14)[0]
                create_date = struct.unpack_from("<H", chunk, 16)[0]
                access_date = struct.unpack_from("<H", chunk, 18)[0]
                write_time = struct.unpack_from("<H", chunk, 22)[0]
                write_date = struct.unpack_from("<H", chunk, 24)[0]

                ts_created = parse_fat_datetime(create_date, create_time)
                ts_accessed = parse_fat_datetime(access_date, 0)
                ts_modified = parse_fat_datetime(write_date, write_time)

                # Calculate device LBA range for data
                if start_clus >= 2:
                    data_start_lba = self.clus_to_device_lba(start_clus)
                    data_sec_count = math.ceil(file_size / self.bps) if file_size > 0 else (self.spc if is_dir else 0)
                    data_end_lba = data_start_lba + max(1, data_sec_count) - 1
                else:
                    data_start_lba = None
                    data_end_lba = None
                    data_sec_count = 0

                entry_meta = {
                    "name": full_name,
                    "short_name": short_name,
                    "is_dir": is_dir,
                    "is_deleted": is_deleted,
                    "state": "DELETED" if is_deleted else "ACTIVE",
                    "starting_cluster": start_clus if start_clus >= 2 else None,
                    "size": file_size,
                    "attributes_byte": attr,
                    "attributes_hex": f"0x{attr:02X}",
                    "directory_cluster": dir_cluster,
                    "directory_entry_lba": entry_dev_lba,
                    "directory_entry_byte_offset": entry_byte_offset,
                    "directory_entry_byte_offset_hex": f"0x{entry_byte_offset:08X}",
                    "starting_lba": data_start_lba,
                    "ending_lba": data_end_lba,
                    "allocated_sectors": data_sec_count,
                    "parent_folder": parent_folder_path,
                    "timestamps": {
                        "created": ts_created,
                        "accessed": ts_accessed,
                        "modified": ts_modified,
                    },
                    "metadata_confidence": "HIGH" if start_clus >= 2 else "METADATA_ONLY",
                }

                if is_deleted:
                    deleted_entries.append(entry_meta)
                else:
                    active_entries.append(entry_meta)

        return active_entries, deleted_entries

    def recover_deleted_file_data(
        self,
        deleted_entry: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Recovers raw file content bytes from storage based on starting cluster & size.
        Applies defensible FAT-chain checking or contiguous cluster recovery.
        """
        start_clus = deleted_entry.get("starting_cluster")
        size_bytes = deleted_entry.get("size", 0)
        name = deleted_entry.get("name", "recovered_deleted_file")

        if not start_clus or start_clus < 2:
            return {
                "status": "METADATA_ONLY",
                "recovery_method": "DELETED_ENTRY_ONLY",
                "bytes": b"",
                "size_recovered": 0,
                "sha256": "",
                "confidence": "METADATA_ONLY",
                "validation": "UNVERIFIED (0 Bytes / No Cluster Allocated)",
                "error": "No valid starting cluster in directory entry",
            }

        if size_bytes == 0:
            return {
                "status": "RECOVERED",
                "recovery_method": "DELETED_ENTRY_ONLY (Zero-Byte File)",
                "bytes": b"",
                "size_recovered": 0,
                "sha256": hashlib.sha256(b"").hexdigest(),
                "confidence": "HIGH",
                "validation": "VALID (0-byte file entry)",
                "extents": [],
            }

        expected_clus_count = math.ceil(size_bytes / self.bpc)
        fat_chain = self.get_cluster_chain(start_clus)

        # Check if FAT chain is still intact
        if len(fat_chain) == expected_clus_count and fat_chain[0] == start_clus:
            rec_method = "DELETED_ENTRY + FAT_CHAIN"
            clusters_to_read = fat_chain
        else:
            # FAT entry was zeroed on deletion; apply contiguous cluster allocation
            rec_method = "DELETED_ENTRY + CONTIGUOUS_CLUSTER_RECOVERY"
            clusters_to_read = [start_clus + i for i in range(expected_clus_count)]

        # Read clusters
        accum = bytearray()
        extents = []
        for c in clusters_to_read:
            part_lba = self.clus_to_part_lba(c)
            dev_lba = self.clus_to_device_lba(c)
            c_data = self.read_fn(part_lba, self.spc)
            accum.extend(c_data)
            extents.append({
                "cluster": c,
                "start_lba": dev_lba,
                "end_lba": dev_lba + self.spc - 1,
                "sector_count": self.spc,
                "start_byte_offset": dev_lba * self.bps,
                "end_byte_offset": (dev_lba + self.spc) * self.bps - 1,
            })

        # Trim to exact file size
        file_bytes = bytes(accum[:size_bytes])
        sha256_hash = hashlib.sha256(file_bytes).hexdigest()

        # Perform Structural / Content Validation
        val_result, val_confidence = validate_recovered_bytes(file_bytes, name)

        return {
            "status": "RECOVERED" if file_bytes else "FAILED",
            "recovery_method": rec_method,
            "bytes": file_bytes,
            "size_recovered": len(file_bytes),
            "sha256": sha256_hash,
            "confidence": val_confidence,
            "validation": val_result,
            "extents": extents,
            "starting_lba": extents[0]["start_lba"] if extents else None,
            "ending_lba": extents[-1]["end_lba"] if extents else None,
        }


def validate_recovered_bytes(file_bytes: bytes, filename: str) -> Tuple[str, str]:
    """
    Validates recovered data bytes based on file format heuristics.
    Returns: (validation_status_str, confidence_level: 'HIGH' | 'MEDIUM' | 'LOW')
    """
    if not file_bytes:
        return "EMPTY (0 Bytes)", "METADATA_ONLY"

    ext = filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
    length = len(file_bytes)

    # 1. Text formats (.txt, .log, .json, .csv, .xml, .py, .md, .ini, .bat)
    if ext in ("txt", "log", "json", "csv", "xml", "py", "md", "ini", "bat", "cfg", "conf"):
        printable_count = sum(1 for b in file_bytes if 32 <= b <= 126 or b in (9, 10, 13))
        printable_ratio = printable_count / length
        null_count = file_bytes.count(b"\x00")
        null_ratio = null_count / length

        if null_ratio == 1.0:
            return "FAILED (All Zero Bytes / Overwritten Cluster)", "LOW"

        if printable_ratio >= 0.85:
            try:
                file_bytes.decode("utf-8")
                return "VALID (UTF-8 Plaintext Structure Intact)", "HIGH"
            except UnicodeDecodeError:
                return "VALID (ASCII/Printable Plaintext Content)", "HIGH"
        elif printable_ratio >= 0.50:
            return "PARTIAL (Mixed Binary / Plaintext Remnant)", "MEDIUM"
        else:
            return "UNVERIFIED (High Non-Printable Byte Ratio)", "LOW"

    # 2. PNG image
    elif ext == "png":
        if length >= 8 and file_bytes[:8] == b"\x89PNG\r\n\x1a\n":
            if file_bytes.endswith(b"IEND\xaeB`\x82"):
                return "VALID (Complete PNG Structure with IEND trailer)", "HIGH"
            return "VALID (PNG Header Signature Confirmed)", "HIGH"
        return "FAILED (Invalid PNG Signature)", "LOW"

    # 3. JPEG image
    elif ext in ("jpg", "jpeg"):
        if length >= 2 and file_bytes[:2] == b"\xff\xd8":
            if file_bytes.endswith(b"\xff\xd9"):
                return "VALID (Complete JPEG with SOI & EOI markers)", "HIGH"
            return "VALID (JPEG SOI Signature Confirmed)", "HIGH"
        return "FAILED (Invalid JPEG Signature)", "LOW"

    # 4. ZIP / Office formats
    elif ext in ("zip", "docx", "xlsx", "pptx", "jar"):
        if length >= 4 and file_bytes[:4] in (b"PK\x03\x04", b"PK\x05\x06"):
            return f"VALID ({ext.upper()} Archive Magic Bytes Confirmed)", "HIGH"
        return f"FAILED (Invalid {ext.upper()} Signature)", "LOW"

    # 5. MP3 audio
    elif ext == "mp3":
        if (length >= 3 and file_bytes[:3] == b"ID3") or (length >= 2 and file_bytes[:2] == b"\xff\xfb"):
            return "VALID (MP3 Audio Header / ID3 Tag Confirmed)", "HIGH"
        return "UNVERIFIED (MP3 Signature Not Detected)", "MEDIUM"

    # 6. PDF document
    elif ext == "pdf":
        if length >= 4 and file_bytes[:4] == b"%PDF":
            return "VALID (PDF Document Header Confirmed)", "HIGH"
        return "FAILED (Invalid PDF Signature)", "LOW"

    # 7. Generic Binary
    null_ratio = file_bytes.count(b"\x00") / length
    if null_ratio == 1.0:
        return "EMPTY (All Zero Bytes / Overwritten)", "LOW"

    return f"RECOVERED ({length} Bytes Extracted)", "MEDIUM"
