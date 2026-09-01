import hashlib
import time

def build_provenance_record(
    evidence_id: str,
    original_filename: str,
    byte_offset: int,
    page_offset: int,
    page_size: int,
    page_num: int,
    cell_idx: int,
    cell_offset: int,
    raw_bytes: bytes,
    extraction_method: str = "Header-Independent B-Tree Carving"
) -> dict:
    """Construct an immutable provenance metadata block for an extracted artifact."""
    byte_hash = hashlib.sha256(raw_bytes).hexdigest().upper() if raw_bytes else ""
    return {
        "evidence_id": evidence_id,
        "original_filename": original_filename,
        "byte_offset": byte_offset,
        "page_offset": page_offset,
        "page_size": page_size,
        "page_num": page_num,
        "cell_idx": cell_idx,
        "cell_offset": cell_offset,
        "byte_length": len(raw_bytes) if raw_bytes else 0,
        "sha256_slice": byte_hash,
        "extraction_method": extraction_method,
        "timestamp_extracted": time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime())
    }
