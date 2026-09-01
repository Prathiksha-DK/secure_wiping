import os

def extract_hex_view(file_path: str, offset: int = 0, length: int = 512, highlight_offset: int = None, highlight_length: int = None) -> dict:
    """Read a slice of evidence bytes and format into forensic hex view."""
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"Evidence file not found: {file_path}")

    file_size = os.path.getsize(file_path)
    offset = max(0, min(offset, file_size))
    length = max(16, min(length, 4096))  # Clamp to reasonable display size

    with open(file_path, "rb") as f:
        f.seek(offset)
        raw_bytes = f.read(length)

    rows = []
    for row_idx in range(0, len(raw_bytes), 16):
        row_offset = offset + row_idx
        chunk = raw_bytes[row_idx:row_idx + 16]

        hex_parts = [f"{b:02X}" for b in chunk]
        # Pad if less than 16 bytes
        while len(hex_parts) < 16:
            hex_parts.append("  ")

        ascii_chars = []
        for b in chunk:
            if 32 <= b <= 126:
                ascii_chars.append(chr(b))
            else:
                ascii_chars.append(".")
        ascii_str = "".join(ascii_chars)

        rows.append({
            "offset": f"{row_offset:08X}",
            "offset_dec": row_offset,
            "hex_left": " ".join(hex_parts[:8]),
            "hex_right": " ".join(hex_parts[8:]),
            "hex_full": " ".join(hex_parts),
            "ascii": ascii_str,
            "bytes_count": len(chunk)
        })

    return {
        "file_size": file_size,
        "offset": offset,
        "length": len(raw_bytes),
        "highlight_offset": highlight_offset,
        "highlight_length": highlight_length,
        "rows": rows
    }
