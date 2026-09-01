import struct

# SQLite B-Tree Page Types
PAGE_TYPE_INDEX_INTERIOR = 0x02
PAGE_TYPE_TABLE_INTERIOR = 0x05
PAGE_TYPE_INDEX_LEAF = 0x0A
PAGE_TYPE_TABLE_LEAF = 0x0D

PAGE_TYPE_NAMES = {
    0x02: "Index Interior",
    0x05: "Table Interior",
    0x0A: "Index Leaf",
    0x0D: "Table Leaf"
}

def read_varint(buf: bytes, offset: int = 0) -> tuple:
    """Read a variable-length integer from buf at offset. Returns (value, bytes_read)."""
    if offset >= len(buf):
        return 0, 0

    val = 0
    bytes_read = 0
    for i in range(8):
        if offset + i >= len(buf):
            return val, bytes_read
        byte = buf[offset + i]
        bytes_read += 1
        val = (val << 7) | (byte & 0x7F)
        if (byte & 0x80) == 0:
            return val, bytes_read

    # 9th byte uses all 8 bits
    if offset + 8 < len(buf):
        byte = buf[offset + 8]
        bytes_read += 1
        val = (val << 8) | byte

    return val, bytes_read

def parse_page_header(page_bytes: bytes, is_page1: bool = False) -> dict:
    """Parse SQLite B-tree page header at offset 100 for page 1 (if standard), or offset 0 for others."""
    header_offset = 100 if is_page1 else 0
    if len(page_bytes) < header_offset + 8:
        return None

    page_type = page_bytes[header_offset]
    if page_type not in (PAGE_TYPE_INDEX_INTERIOR, PAGE_TYPE_TABLE_INTERIOR, PAGE_TYPE_INDEX_LEAF, PAGE_TYPE_TABLE_LEAF):
        return None

    first_freeblock = struct.unpack_from(">H", page_bytes, header_offset + 1)[0]
    cell_count = struct.unpack_from(">H", page_bytes, header_offset + 3)[0]
    cell_content_offset = struct.unpack_from(">H", page_bytes, header_offset + 5)[0]
    if cell_content_offset == 0:
        cell_content_offset = 65536
    fragmented_free_bytes = page_bytes[header_offset + 7]

    is_interior = page_type in (PAGE_TYPE_INDEX_INTERIOR, PAGE_TYPE_TABLE_INTERIOR)
    right_child = None
    header_size = 8
    if is_interior:
        if len(page_bytes) < header_offset + 12:
            return None
        right_child = struct.unpack_from(">I", page_bytes, header_offset + 8)[0]
        header_size = 12

    # Structural sanity checks
    page_size = len(page_bytes)
    if cell_count * 2 + header_size + header_offset > page_size:
        return None  # Cell pointer array exceeds page size

    if cell_content_offset > page_size and cell_content_offset != 65536:
        return None

    return {
        "page_type_id": page_type,
        "page_type": PAGE_TYPE_NAMES.get(page_type, f"Unknown (0x{page_type:02X})"),
        "header_offset": header_offset,
        "header_size": header_size,
        "first_freeblock": first_freeblock,
        "cell_count": cell_count,
        "cell_content_offset": cell_content_offset,
        "fragmented_free_bytes": fragmented_free_bytes,
        "right_child": right_child
    }

def parse_cell_pointers(page_bytes: bytes, header_info: dict) -> list:
    """Extract cell pointers array from page."""
    if not header_info:
        return []

    ptr_start = header_info["header_offset"] + header_info["header_size"]
    cell_count = header_info["cell_count"]
    page_size = len(page_bytes)

    pointers = []
    for i in range(cell_count):
        idx = ptr_start + (i * 2)
        if idx + 2 > page_size:
            break
        cell_offset = struct.unpack_from(">H", page_bytes, idx)[0]
        # Validate cell pointer is inside page bounds
        if 0 < cell_offset < page_size:
            pointers.append(cell_offset)

    return pointers

def parse_table_leaf_cell(page_bytes: bytes, cell_offset: int) -> dict:
    """Parse SQLite table leaf cell: payload_len (varint), rowid (varint), payload."""
    page_size = len(page_bytes)
    if cell_offset >= page_size:
        return None

    payload_len, len_bytes = read_varint(page_bytes, cell_offset)
    if len_bytes == 0:
        return None

    rowid_offset = cell_offset + len_bytes
    if rowid_offset >= page_size:
        return None

    row_id, rowid_bytes = read_varint(page_bytes, rowid_offset)
    if rowid_bytes == 0:
        return None

    payload_start = rowid_offset + rowid_bytes
    # Handle local payload vs overflow
    # For forensic carving, read up to min(payload_len, remaining page bytes)
    max_local = min(payload_len, page_size - payload_start)
    if max_local <= 0:
        return None

    payload_data = page_bytes[payload_start:payload_start + max_local]

    return {
        "cell_offset": cell_offset,
        "payload_len": payload_len,
        "row_id": row_id,
        "payload_start": payload_start,
        "payload_bytes": payload_data,
        "is_truncated": (len(payload_data) < payload_len)
    }

def decode_record(payload_bytes: bytes) -> dict:
    """Decode SQLite Record format into column types and column values."""
    if not payload_bytes or len(payload_bytes) < 1:
        return None

    # Record Header starts with total header size (varint)
    header_size, varint_len = read_varint(payload_bytes, 0)
    if varint_len == 0 or header_size <= 0 or header_size > len(payload_bytes):
        return None

    # Read serial type codes
    serial_types = []
    curr_offset = varint_len
    while curr_offset < header_size:
        st, st_bytes = read_varint(payload_bytes, curr_offset)
        if st_bytes == 0:
            break
        serial_types.append(st)
        curr_offset += st_bytes

    # Now decode column data starting at header_size
    col_values = []
    col_types = []
    data_offset = header_size

    for st in serial_types:
        if st == 0:
            col_types.append("NULL")
            col_values.append(None)
        elif st == 1:
            col_types.append("INTEGER")
            if data_offset + 1 <= len(payload_bytes):
                val = struct.unpack_from(">b", payload_bytes, data_offset)[0]
                col_values.append(val)
                data_offset += 1
            else:
                col_values.append(None)
        elif st == 2:
            col_types.append("INTEGER")
            if data_offset + 2 <= len(payload_bytes):
                val = struct.unpack_from(">h", payload_bytes, data_offset)[0]
                col_values.append(val)
                data_offset += 2
            else:
                col_values.append(None)
        elif st == 3:
            col_types.append("INTEGER")
            if data_offset + 3 <= len(payload_bytes):
                raw = payload_bytes[data_offset:data_offset + 3]
                # 24-bit signed int
                val = int.from_bytes(raw, byteorder="big", signed=True)
                col_values.append(val)
                data_offset += 3
            else:
                col_values.append(None)
        elif st == 4:
            col_types.append("INTEGER")
            if data_offset + 4 <= len(payload_bytes):
                val = struct.unpack_from(">i", payload_bytes, data_offset)[0]
                col_values.append(val)
                data_offset += 4
            else:
                col_values.append(None)
        elif st == 5:
            col_types.append("INTEGER")
            if data_offset + 6 <= len(payload_bytes):
                raw = payload_bytes[data_offset:data_offset + 6]
                val = int.from_bytes(raw, byteorder="big", signed=True)
                col_values.append(val)
                data_offset += 6
            else:
                col_values.append(None)
        elif st == 6:
            col_types.append("INTEGER")
            if data_offset + 8 <= len(payload_bytes):
                val = struct.unpack_from(">q", payload_bytes, data_offset)[0]
                col_values.append(val)
                data_offset += 8
            else:
                col_values.append(None)
        elif st == 7:
            col_types.append("REAL")
            if data_offset + 8 <= len(payload_bytes):
                val = struct.unpack_from(">d", payload_bytes, data_offset)[0]
                col_values.append(val)
                data_offset += 8
            else:
                col_values.append(None)
        elif st == 8:
            col_types.append("INTEGER")
            col_values.append(0)
        elif st == 9:
            col_types.append("INTEGER")
            col_values.append(1)
        elif st >= 12 and (st % 2 == 0):
            # BLOB
            blob_len = (st - 12) // 2
            col_types.append(f"BLOB({blob_len})")
            if data_offset + blob_len <= len(payload_bytes):
                raw_blob = payload_bytes[data_offset:data_offset + blob_len]
                col_values.append(f"0x{raw_blob.hex().upper()}")
                data_offset += blob_len
            else:
                col_values.append("<TRUNCATED BLOB>")
        elif st >= 13 and (st % 2 == 1):
            # TEXT (UTF-8)
            text_len = (st - 13) // 2
            col_types.append("TEXT")
            if data_offset + text_len <= len(payload_bytes):
                raw_text = payload_bytes[data_offset:data_offset + text_len]
                try:
                    text_val = raw_text.decode("utf-8", errors="replace")
                except Exception:
                    text_val = raw_text.decode("latin-1", errors="replace")
                col_values.append(text_val)
                data_offset += text_len
            else:
                col_values.append("<TRUNCATED TEXT>")
        else:
            col_types.append("RESERVED")
            col_values.append(None)

    return {
        "header_size": header_size,
        "serial_types": serial_types,
        "column_types": col_types,
        "column_values": col_values,
        "column_count": len(col_types)
    }
