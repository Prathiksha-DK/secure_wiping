import os
import time
import uuid
import json
import struct
from .config import SUPPORTED_PAGE_SIZES
from .db import get_db_connection
from .sqlite_parser import (
    parse_page_header,
    parse_cell_pointers,
    parse_table_leaf_cell,
    decode_record,
    PAGE_TYPE_TABLE_LEAF
)
from .confidence import calculate_page_confidence, calculate_record_confidence
from .provenance import build_provenance_record
from .correlation import correlate_fragments
from .timeline import extract_timeline_events
from .chain_of_custody import add_chain_event

def detect_page_size_and_mode(file_path: str) -> tuple:
    """Detect page size and SQLite recovery mode (Normal vs Header-Damaged)."""
    file_size = os.path.getsize(file_path)
    if file_size < 100:
        return 4096, "Header-Independent"

    with open(file_path, "rb") as f:
        header = f.read(100)

    if len(header) >= 16 and header[:15] == b"SQLite format 3":
        page_size_val = struct.unpack_from(">H", header, 16)[0]
        if page_size_val == 1:
            page_size = 65536
        elif page_size_val in SUPPORTED_PAGE_SIZES:
            page_size = page_size_val
        else:
            page_size = 4096
        return page_size, "Normal"

    # Header is missing or damaged — probe candidate page sizes
    best_ps = 4096
    max_valid_pages = 0

    with open(file_path, "rb") as f:
        # Check first 512KB for candidate page sizes
        probe_limit = min(file_size, 512 * 1024)
        sample_bytes = f.read(probe_limit)

    for ps in [4096, 1024, 2048, 8192, 512, 16384]:
        valid_count = 0
        for off in range(0, len(sample_bytes), ps):
            page_chunk = sample_bytes[off:off + ps]
            h = parse_page_header(page_chunk, is_page1=False)
            if h:
                valid_count += 1
        if valid_count > max_valid_pages:
            max_valid_pages = valid_count
            best_ps = ps

    return best_ps, "Header-Damaged"

def execute_carve_scan(job_id: str, file_path: str, evidence_id: str, case_id: str, original_filename: str):
    """Background worker that executes byte-level carving of SQLite artifacts."""
    start_time = time.time()
    conn = get_db_connection()

    try:
        page_size, mode = detect_page_size_and_mode(file_path)
        file_size = os.path.getsize(file_path)
        total_pages = max(1, file_size // page_size)

        # Update initial job status
        with conn:
            conn.execute("""
                UPDATE faris_scan_jobs
                SET mode = ?, detected_page_size = ?, status = 'Running', progress = 5
                WHERE job_id = ?
            """, (mode, page_size, job_id))

        add_chain_event(
            case_id=case_id,
            action="SCAN_STARTED",
            details=f"Initiated {mode} recovery scan on '{original_filename}' (Page size: {page_size}B, Total expected pages: {total_pages})",
            evidence_id=evidence_id
        )

        detected_page_records = []
        page_candidates_found = 0
        validated_pages_count = 0
        records_recovered_count = 0

        with open(file_path, "rb") as f:
            for page_idx in range(total_pages):
                offset = page_idx * page_size
                f.seek(offset)
                page_bytes = f.read(page_size)

                if len(page_bytes) < 8:
                    break

                is_first = (page_idx == 0 and mode == "Normal")
                header_info = parse_page_header(page_bytes, is_page1=is_first)

                if not header_info:
                    # Not a valid page header, continue scanning
                    continue

                page_candidates_found += 1
                pointers = parse_cell_pointers(page_bytes, header_info)
                page_conf, page_reasons = calculate_page_confidence(header_info, pointers, page_size)

                if page_conf >= 50.0:
                    validated_pages_count += 1

                candidate_id = f"PAGE-{uuid.uuid4().hex[:8].upper()}"
                status_str = "Validated" if page_conf >= 70.0 else ("Candidate" if page_conf >= 40.0 else "Rejected")

                with conn:
                    conn.execute("""
                        INSERT INTO faris_page_candidates
                        (candidate_id, job_id, offset, page_size, page_type, confidence_score, cell_count, reasons_json, validation_status, created_at)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """, (
                        candidate_id,
                        job_id,
                        offset,
                        page_size,
                        header_info["page_type"],
                        page_conf,
                        header_info["cell_count"],
                        json.dumps(page_reasons),
                        status_str,
                        int(time.time())
                    ))

                # Track for correlation
                page_meta = {
                    "candidate_id": candidate_id,
                    "offset": offset,
                    "page_size": page_size,
                    "page_type_id": header_info["page_type_id"],
                    "max_row_id": 0,
                    "min_row_id": 999999999,
                    "schema_signature": []
                }

                # If Table Leaf page, carve individual records!
                if header_info["page_type_id"] == PAGE_TYPE_TABLE_LEAF:
                    for cell_idx, ptr in enumerate(pointers):
                        cell_info = parse_table_leaf_cell(page_bytes, ptr)
                        if not cell_info:
                            continue

                        row_id = cell_info["row_id"]
                        page_meta["max_row_id"] = max(page_meta["max_row_id"], row_id)
                        page_meta["min_row_id"] = min(page_meta["min_row_id"], row_id)

                        record_info = decode_record(cell_info["payload_bytes"])
                        if not record_info or record_info.get("column_count", 0) == 0:
                            continue

                        if not page_meta["schema_signature"]:
                            page_meta["schema_signature"] = record_info["column_types"]

                        rec_conf, rec_level, rec_reasons = calculate_record_confidence(cell_info, record_info)

                        prov = build_provenance_record(
                            evidence_id=evidence_id,
                            original_filename=original_filename,
                            byte_offset=offset + ptr,
                            page_offset=offset,
                            page_size=page_size,
                            page_num=page_idx + 1,
                            cell_idx=cell_idx,
                            cell_offset=ptr,
                            raw_bytes=cell_info["payload_bytes"]
                        )

                        record_id = f"REC-{uuid.uuid4().hex[:10].upper()}"
                        with conn:
                            conn.execute("""
                                INSERT INTO faris_recovered_records
                                (record_id, job_id, evidence_id, case_id, byte_offset, page_offset, page_num, cell_idx, row_id,
                                 column_types, column_values, inferred_schema, confidence_score, confidence_level, reasons_json, provenance_json, created_at)
                                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                            """, (
                                record_id,
                                job_id,
                                evidence_id,
                                case_id,
                                offset + ptr,
                                offset,
                                page_idx + 1,
                                cell_idx,
                                row_id,
                                json.dumps(record_info["column_types"]),
                                json.dumps(record_info["column_values"]),
                                json.dumps({}),
                                rec_conf,
                                rec_level,
                                json.dumps(rec_reasons),
                                json.dumps(prov),
                                int(time.time())
                            ))
                        records_recovered_count += 1

                detected_page_records.append(page_meta)

                # Update progress periodically
                if page_idx % max(1, total_pages // 20) == 0 or page_idx == total_pages - 1:
                    prog = min(85, int((page_idx + 1) / total_pages * 80) + 5)
                    with conn:
                        conn.execute("""
                            UPDATE faris_scan_jobs
                            SET progress = ?, pages_scanned = ?, candidates_found = ?, validated_pages = ?, records_recovered = ?
                            WHERE job_id = ?
                        """, (prog, page_idx + 1, page_candidates_found, validated_pages_count, records_recovered_count, job_id))

        # Perform fragment correlation across detected pages
        with conn:
            conn.execute("UPDATE faris_scan_jobs SET progress = 90 WHERE job_id = ?", (job_id,))

        for i in range(len(detected_page_records)):
            for j in range(i + 1, min(i + 10, len(detected_page_records))):
                p_a = detected_page_records[i]
                p_b = detected_page_records[j]
                corr_score, corr_reasons = correlate_fragments(p_a, p_b)
                if corr_score >= 50.0:
                    rel_id = f"REL-{uuid.uuid4().hex[:8].upper()}"
                    with conn:
                        conn.execute("""
                            INSERT INTO faris_fragment_relationships
                            (rel_id, job_id, frag_a_offset, frag_b_offset, correlation_score, reasons_json, created_at)
                            VALUES (?, ?, ?, ?, ?, ?, ?)
                        """, (rel_id, job_id, p_a["offset"], p_b["offset"], corr_score, json.dumps(corr_reasons), int(time.time())))

        # Extract timeline events from recovered records
        extract_timeline_events(case_id, job_id)

        duration = round(time.time() - start_time, 2)
        with conn:
            conn.execute("""
                UPDATE faris_scan_jobs
                SET status = 'Completed', progress = 100, pages_scanned = ?, candidates_found = ?,
                    validated_pages = ?, records_recovered = ?, duration_sec = ?, completed_at = ?
                WHERE job_id = ?
            """, (total_pages, page_candidates_found, validated_pages_count, records_recovered_count, duration, int(time.time()), job_id))

        add_chain_event(
            case_id=case_id,
            action="SCAN_COMPLETED",
            details=f"Completed {mode} recovery scan: {validated_pages_count} valid SQLite pages, {records_recovered_count} records recovered in {duration}s",
            evidence_id=evidence_id
        )

    except Exception as e:
        duration = round(time.time() - start_time, 2)
        with conn:
            conn.execute("""
                UPDATE faris_scan_jobs
                SET status = 'Failed', error_message = ?, duration_sec = ?, completed_at = ?
                WHERE job_id = ?
            """, (str(e), duration, int(time.time()), job_id))
        add_chain_event(
            case_id=case_id,
            action="SCAN_FAILED",
            details=f"Scan failed on evidence '{original_filename}': {str(e)}",
            evidence_id=evidence_id
        )
    finally:
        conn.close()
