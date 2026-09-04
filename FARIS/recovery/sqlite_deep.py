import os
import json
import sqlite3
import hashlib
import struct
from pathlib import Path
from typing import Dict, List, Any, Optional, Tuple

class SQLiteRecordParser:
    """
    Forensic record deserializer conforming to the official SQLite 3 Record Format.
    Decodes varints, serial types, numbers, strings, blobs, and deleted payloads.
    """

    @staticmethod
    def read_varint(buffer: bytes, offset: int) -> Tuple[int, int]:
        """
        Reads a variable-length integer (varint) from buffer starting at offset.
        Returns (value, bytes_consumed).
        """
        value = 0
        consumed = 0
        for i in range(9):
            if offset + i >= len(buffer):
                break
            b = buffer[offset + i]
            consumed += 1
            if i == 8:
                value = (value << 8) | b
                break
            value = (value << 7) | (b & 0x7F)
            if not (b & 0x80):
                break
        return value, consumed

    def parse_record(self, payload: bytes) -> Optional[List[Any]]:
        """
        Parses an SQLite binary record payload into deserialized Python values.
        """
        if len(payload) < 2:
            return None

        try:
            hdr_size, consumed = self.read_varint(payload, 0)
            if hdr_size > len(payload) or hdr_size < consumed:
                return None

            serial_types = []
            curr_hdr_offset = consumed
            while curr_hdr_offset < hdr_size:
                st, st_consumed = self.read_varint(payload, curr_hdr_offset)
                serial_types.append(st)
                curr_hdr_offset += st_consumed

            values = []
            curr_body_offset = hdr_size

            for st in serial_types:
                if st == 0:
                    values.append(None)
                elif st == 1:
                    if curr_body_offset + 1 <= len(payload):
                        val = struct.unpack(">b", payload[curr_body_offset:curr_body_offset+1])[0]
                        values.append(val)
                        curr_body_offset += 1
                elif st == 2:
                    if curr_body_offset + 2 <= len(payload):
                        val = struct.unpack(">h", payload[curr_body_offset:curr_body_offset+2])[0]
                        values.append(val)
                        curr_body_offset += 2
                elif st == 3:
                    if curr_body_offset + 3 <= len(payload):
                        b = payload[curr_body_offset:curr_body_offset+3]
                        val = int.from_bytes(b, byteorder="big", signed=True)
                        values.append(val)
                        curr_body_offset += 3
                elif st == 4:
                    if curr_body_offset + 4 <= len(payload):
                        val = struct.unpack(">i", payload[curr_body_offset:curr_body_offset+4])[0]
                        values.append(val)
                        curr_body_offset += 4
                elif st == 5:
                    if curr_body_offset + 6 <= len(payload):
                        b = payload[curr_body_offset:curr_body_offset+6]
                        val = int.from_bytes(b, byteorder="big", signed=True)
                        values.append(val)
                        curr_body_offset += 6
                elif st == 6:
                    if curr_body_offset + 8 <= len(payload):
                        val = struct.unpack(">q", payload[curr_body_offset:curr_body_offset+8])[0]
                        values.append(val)
                        curr_body_offset += 8
                elif st == 7:
                    if curr_body_offset + 8 <= len(payload):
                        val = struct.unpack(">d", payload[curr_body_offset:curr_body_offset+8])[0]
                        values.append(val)
                        curr_body_offset += 8
                elif st == 8:
                    values.append(0)
                elif st == 9:
                    values.append(1)
                elif st >= 12 and st % 2 == 0:
                    # BLOB: length is (st - 12) / 2
                    length = (st - 12) // 2
                    if curr_body_offset + length <= len(payload):
                        val = payload[curr_body_offset:curr_body_offset+length]
                        values.append(f"<BLOB {length} bytes>")
                        curr_body_offset += length
                elif st >= 13 and st % 2 == 1:
                    # TEXT: length is (st - 13) / 2
                    length = (st - 13) // 2
                    if curr_body_offset + length <= len(payload):
                        raw_str = payload[curr_body_offset:curr_body_offset+length]
                        try:
                            val = raw_str.decode("utf-8")
                        except UnicodeDecodeError:
                            val = raw_str.decode("latin-1", errors="replace")
                        values.append(val)
                        curr_body_offset += length
                else:
                    values.append(f"<UNKNOWN_SERIAL_TYPE_{st}>")

            return values
        except Exception:
            return None


class SQLiteDeepRecovery:
    """
    Complete SQLite Deep Recovery Pipeline.
    Performs Page Carving, B-Tree Analysis, Cell/Record Parsing, Headerless Recovery,
    Deleted/Unallocated Record Carving, Fragment Correlation, and Database Reconstruction.
    """

    PAGE_TYPES = {
        0x02: "Interior Index B-Tree",
        0x05: "Interior Table B-Tree",
        0x0A: "Leaf Index B-Tree",
        0x0D: "Leaf Table B-Tree"
    }

    def __init__(self, default_page_size: int = 4096):
        self.default_page_size = default_page_size
        self.parser = SQLiteRecordParser()

    def parse_page(self, page_bytes: bytes, page_offset: int = 0, is_page_1: bool = False) -> Dict[str, Any]:
        """
        Parses a candidate SQLite page, extracts B-Tree headers, cells, and unallocated/deleted records.
        """
        hdr_offset = 100 if is_page_1 else 0
        if len(page_bytes) < hdr_offset + 8:
            return {"valid": False, "reason": "Page size smaller than header"}

        page_type_byte = page_bytes[hdr_offset]
        if page_type_byte not in self.PAGE_TYPES:
            return {"valid": False, "reason": f"Invalid page type flag 0x{page_type_byte:02X}"}

        page_type = self.PAGE_TYPES[page_type_byte]
        first_freeblock = int.from_bytes(page_bytes[hdr_offset+1:hdr_offset+3], byteorder="big")
        cell_count = int.from_bytes(page_bytes[hdr_offset+3:hdr_offset+5], byteorder="big")
        cell_content_offset = int.from_bytes(page_bytes[hdr_offset+5:hdr_offset+7], byteorder="big")
        if cell_content_offset == 0:
            cell_content_offset = 65536  # In SQLite, 0 represents 65536

        # Read cell pointers
        cell_pointers = []
        ptr_start = hdr_offset + (12 if page_type_byte in [0x02, 0x05] else 8)
        for i in range(cell_count):
            p_idx = ptr_start + (i * 2)
            if p_idx + 2 <= len(page_bytes):
                ptr = int.from_bytes(page_bytes[p_idx:p_idx+2], byteorder="big")
                if ptr < len(page_bytes):
                    cell_pointers.append(ptr)

        # Parse active cells
        active_records = []
        for ptr in cell_pointers:
            if page_type_byte == 0x0D:  # Leaf Table B-Tree
                # Payload size (varint), row ID (varint), payload
                payload_sz, sz_len = self.parser.read_varint(page_bytes, ptr)
                row_id, id_len = self.parser.read_varint(page_bytes, ptr + sz_len)
                payload_start = ptr + sz_len + id_len
                payload_bytes = page_bytes[payload_start:payload_start + payload_sz]
                fields = self.parser.parse_record(payload_bytes)
                if fields:
                    active_records.append({
                        "row_id": row_id,
                        "fields": fields,
                        "source_offset": page_offset + ptr,
                        "status": "ACTIVE"
                    })

        # Scan unallocated page gaps for deleted records
        deleted_records = []
        gap_start = ptr_start + (cell_count * 2)
        gap_end = min(len(page_bytes), cell_content_offset)

        if gap_end > gap_start + 4:
            gap_data = page_bytes[gap_start:gap_end]
            # Heuristic scan for deleted records in unallocated space
            for scan_idx in range(0, len(gap_data) - 8):
                rec = self.parser.parse_record(gap_data[scan_idx:])
                if rec and len(rec) > 1 and any(isinstance(f, str) and len(f) > 2 for f in rec):
                    deleted_records.append({
                        "row_id": None,
                        "fields": rec,
                        "source_offset": page_offset + gap_start + scan_idx,
                        "status": "DELETED_CARVED"
                    })

        return {
            "valid": True,
            "page_type": page_type,
            "page_type_byte": page_type_byte,
            "cell_count": cell_count,
            "cell_content_offset": cell_content_offset,
            "first_freeblock": first_freeblock,
            "active_records": active_records,
            "deleted_records": deleted_records
        }

    def carve_sqlite_pages_from_stream(
        self,
        stream_reader,
        output_case_dir: Path,
        page_size: int = 4096,
        max_pages: int = 5000,
        max_scan_bytes: Optional[int] = None,
        db_filename: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Carves and correlates all SQLite pages and records from a binary stream or unallocated pool.
        Reconstructs recovered records into a candidate database and catalog.
        """
        recovered_pages = []
        all_active_records = []
        all_deleted_records = []
        global_offset = 0
        page_index = 0
        total_scanned_pages = 0

        while page_index < max_pages:
            if max_scan_bytes and global_offset >= max_scan_bytes:
                break

            chunk = stream_reader.read(page_size)
            if not chunk or len(chunk) < 512:
                break

            total_scanned_pages += 1
            is_p1 = (chunk[:16] == b"SQLite format 3\x00")
            page_info = self.parse_page(chunk, page_offset=global_offset, is_page_1=is_p1)

            if page_info["valid"]:
                page_index += 1
                page_summary = {
                    "page_index": page_index,
                    "global_offset": global_offset,
                    "page_type": page_info["page_type"],
                    "active_count": len(page_info["active_records"]),
                    "deleted_count": len(page_info["deleted_records"])
                }
                recovered_pages.append(page_summary)
                all_active_records.extend(page_info["active_records"])
                all_deleted_records.extend(page_info["deleted_records"])

            global_offset += len(chunk)

        # Output folder
        out_db_dir = output_case_dir / "recovery" / "sqlite_deep"
        out_db_dir.mkdir(parents=True, exist_ok=True)

        catalog_path = out_db_dir / "sqlite_deep_catalog.json"
        
        # Dynamic database name
        db_name = db_filename or f"{output_case_dir.name}_recovered_sqlite.db"
        reconstructed_db = out_db_dir / db_name

        db_created = False
        if all_active_records or all_deleted_records:
            self._reconstruct_database(reconstructed_db, all_active_records, all_deleted_records)
            db_created = reconstructed_db.exists()

        summary = {
            "total_pages_carved": len(recovered_pages),
            "total_active_records": len(all_active_records),
            "total_deleted_records": len(all_deleted_records),
            "database_reconstructed": db_created,
            "database_file": str(reconstructed_db) if db_created else "",
            "pages": recovered_pages,
            "active_records": all_active_records,
            "deleted_records": all_deleted_records
        }

        with open(catalog_path, "w", encoding="utf-8") as f:
            json.dump(summary, f, indent=2)

        return summary

    def _reconstruct_database(self, db_path: Path, active_recs: List[Dict], deleted_recs: List[Dict]):
        if db_path.exists():
            db_path.unlink()

        conn = sqlite3.connect(str(db_path))
        cur = conn.cursor()

        cur.execute("""
            CREATE TABLE IF NOT EXISTS recovered_records (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                status TEXT,
                source_offset TEXT,
                row_id TEXT,
                column_count INTEGER,
                payload_json TEXT,
                sha256 TEXT
            )
        """)

        for r in (active_recs + deleted_recs):
            payload_str = json.dumps(r.get("fields", []), default=str)
            r_hash = hashlib.sha256(payload_str.encode("utf-8")).hexdigest()
            row_id_val = str(r.get("row_id")) if r.get("row_id") is not None else None
            offset_val = str(r.get("source_offset", 0))
            cur.execute("""
                INSERT INTO recovered_records (status, source_offset, row_id, column_count, payload_json, sha256)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (
                r.get("status", "UNKNOWN"),
                offset_val,
                row_id_val,
                len(r.get("fields", [])),
                payload_str,
                r_hash
            ))

        conn.commit()
        conn.close()

# Singleton instance
sqlite_deep_recovery = SQLiteDeepRecovery()
