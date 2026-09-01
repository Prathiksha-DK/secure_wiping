from .config import (
    WEIGHT_PAGE_HEADER,
    WEIGHT_CELL_POINTERS,
    WEIGHT_RECORD_STRUCTURE,
    WEIGHT_DATA_TYPE_VALIDITY,
    WEIGHT_FRAGMENT_CORRELATION
)

def calculate_page_confidence(header_info: dict, pointers: list, page_size: int) -> tuple:
    """Calculate an explainable recovery confidence score for a candidate SQLite page."""
    if not header_info:
        return 0.0, ["Invalid or missing SQLite page header structure"]

    score = 0.0
    reasons = []

    # 1. Page Header Validity (25%)
    page_type = header_info.get("page_type_id")
    if page_type in (0x02, 0x05, 0x0A, 0x0D):
        score += WEIGHT_PAGE_HEADER * 100
        reasons.append(f"✓ Valid SQLite B-tree header ({header_info['page_type']} - 0x{page_type:02X})")
    else:
        reasons.append("✗ Unrecognized page type byte")

    # 2. Cell Pointers Validity (20%)
    cell_count = header_info.get("cell_count", 0)
    valid_pointers = len(pointers)
    if cell_count > 0 and valid_pointers == cell_count:
        score += WEIGHT_CELL_POINTERS * 100
        reasons.append(f"✓ All {cell_count} cell pointers reside strictly within page memory bounds (0..{page_size})")
    elif cell_count > 0 and valid_pointers > 0:
        ratio = valid_pointers / cell_count
        score += (WEIGHT_CELL_POINTERS * 100) * ratio
        reasons.append(f"⚠ {valid_pointers}/{cell_count} cell pointers valid within page bounds ({ratio*100:.0f}%)")
    elif cell_count == 0:
        score += (WEIGHT_CELL_POINTERS * 100) * 0.5
        reasons.append("ℹ Empty page with 0 cells (valid empty leaf/interior)")

    # 3. Cell Content Area Alignment (25%)
    content_offset = header_info.get("cell_content_offset", 0)
    if 0 < content_offset <= page_size:
        score += WEIGHT_RECORD_STRUCTURE * 100
        reasons.append(f"✓ Cell content area offset ({content_offset}) correctly bounded")
    else:
        reasons.append(f"✗ Cell content area offset ({content_offset}) out of bounds")

    # 4. Freeblock Integrity (15%)
    first_free = header_info.get("first_freeblock", 0)
    if first_free == 0 or (0 < first_free < page_size):
        score += WEIGHT_DATA_TYPE_VALIDITY * 100
        reasons.append("✓ Freeblock pointer sequence structurally consistent")

    # Final normalized score (0..100)
    final_score = min(100.0, max(0.0, round(score, 1)))
    return final_score, reasons

def calculate_record_confidence(cell_info: dict, record_info: dict, correlated: bool = False) -> tuple:
    """Calculate explainable confidence score for an extracted record."""
    if not record_info:
        return 0.0, "Rejected", ["Malformed or unparseable record structure"]

    score = 0.0
    reasons = []

    # 1. Payload & Cell Header (25%)
    if cell_info and not cell_info.get("is_truncated"):
        score += 25.0
        reasons.append(f"✓ Complete non-truncated payload ({cell_info.get('payload_len')} bytes)")
    elif cell_info:
        score += 12.0
        reasons.append(f"⚠ Partial payload ({len(cell_info.get('payload_bytes', b''))}/{cell_info.get('payload_len')} bytes carved)")

    # 2. Record Header & Serial Types (30%)
    col_count = record_info.get("column_count", 0)
    if col_count > 0:
        score += 30.0
        types_summary = ", ".join(record_info.get("column_types", [])[:4])
        reasons.append(f"✓ Valid SQLite record header ({col_count} columns: {types_summary})")
    else:
        reasons.append("✗ Record header contains 0 recognized columns")

    # 3. Data Values Decodability (25%)
    values = record_info.get("column_values", [])
    valid_values = sum(1 for v in values if v is not None and v != "<TRUNCATED TEXT>" and v != "<TRUNCATED BLOB>")
    if col_count > 0:
        val_ratio = valid_values / col_count
        score += 25.0 * val_ratio
        if val_ratio == 1.0:
            reasons.append("✓ 100% of column values decoded without corruption")
        else:
            reasons.append(f"⚠ {valid_values}/{col_count} column values successfully decoded")

    # 4. Correlation & RowID Validity (20%)
    row_id = cell_info.get("row_id", 0) if cell_info else 0
    if row_id >= 0:
        score += 10.0
        reasons.append(f"✓ Valid positive RowID ({row_id})")

    if correlated:
        score += 10.0
        reasons.append("✓ Correlated with neighboring B-tree fragment")

    final_score = min(100.0, max(0.0, round(score, 1)))

    if final_score >= 85.0:
        level = "High"
    elif final_score >= 60.0:
        level = "Medium"
    elif final_score >= 40.0:
        level = "Low"
    else:
        level = "Candidate"

    return final_score, level, reasons
