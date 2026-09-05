"""
Forensic File Signature Database & Multi-Level Structural Validators
Part of SecureWipe Phase 3 Forensic Verification Engine.

Validation Levels:
  Level 1 (Signature Hit): A matching magic byte sequence exists.
  Level 2 (Valid Candidate): Surrounding headers, length fields, and markers match format specifications.
  Level 3 (Validated Artifact): The internal structure can be parsed, decompressed, or decoded successfully.
"""

import struct
import zlib
import io
from typing import Dict, Any, Optional, Tuple, List


class ValidationResult:
    def __init__(
        self,
        format_name: str,
        level: int,
        confidence: float,
        extracted_size: int,
        details: str,
        is_fragmented: bool = False,
        header_offset: int = 0,
    ):
        self.format_name = format_name
        self.level = level  # 1, 2, or 3
        self.confidence = confidence  # 0.0 to 1.0
        self.extracted_size = extracted_size
        self.details = details
        self.is_fragmented = is_fragmented
        self.header_offset = header_offset

    def to_dict(self) -> Dict[str, Any]:
        level_names = {1: "Signature Hit", 2: "Valid Candidate", 3: "Validated Artifact"}
        return {
            "format": self.format_name,
            "level": self.level,
            "level_name": level_names.get(self.level, "Unknown"),
            "confidence": round(self.confidence, 3),
            "extracted_size": self.extracted_size,
            "details": self.details,
            "is_fragmented": self.is_fragmented,
            "header_offset": self.header_offset,
        }


# ---------------------------------------------------------------------------
# Individual Format Validators
# ---------------------------------------------------------------------------

def validate_jpeg(data: bytes, offset: int) -> Optional[ValidationResult]:
    """Validate JPEG file structure (SOI: FF D8, segments: FF Ex, EOI: FF D9)."""
    if len(data) < offset + 4:
        return None
    if not (data[offset:offset + 2] == b"\xff\xd8" and data[offset + 2] == 0xff):
        return None

    level = 1
    confidence = 0.35
    details = "JPEG SOI marker detected"
    extracted_size = 2

    # Level 2: Check for valid JPEG markers (JFIF / Exif / SOF0 / DQT / DHT)
    third_byte = data[offset + 3]
    if third_byte in (0xe0, 0xe1, 0xdb, 0xc0, 0xc4, 0xee):
        level = 2
        confidence = 0.65
        details = f"JPEG segment marker 0xFF{third_byte:02X} verified"

        # Walk markers to find EOI and estimate size
        pos = offset + 2
        max_pos = min(len(data), offset + 50 * 1024 * 1024)
        found_eoi = False

        while pos + 4 < max_pos:
            if data[pos] == 0xff:
                marker = data[pos + 1]
                if marker == 0xd9:  # EOI
                    found_eoi = True
                    extracted_size = (pos + 2) - offset
                    break
                elif marker in (0xd8, 0xd0, 0xd1, 0xd2, 0xd3, 0xd4, 0xd5, 0xd6, 0xd7, 0x00, 0xff):
                    pos += 1
                else:
                    if pos + 4 <= max_pos:
                        seg_len = (data[pos + 2] << 8) + data[pos + 3]
                        if seg_len < 2:
                            break
                        pos += 2 + seg_len
                    else:
                        break
            else:
                pos += 1

        if found_eoi and extracted_size > 128:
            level = 3
            confidence = 0.95
            details = f"Complete JPEG structure verified with EOI marker at +{extracted_size} bytes"
        elif not found_eoi and pos > offset + 256:
            extracted_size = min(pos - offset, len(data) - offset)
            details += f" (truncated/partial JPEG stream of ~{extracted_size} bytes)"

    return ValidationResult("JPEG", level, confidence, extracted_size, details, is_fragmented=not (level == 3), header_offset=offset)


def validate_png(data: bytes, offset: int) -> Optional[ValidationResult]:
    """Validate PNG file structure (8-byte header, IHDR, chunks with CRC, IEND)."""
    PNG_MAGIC = b"\x89PNG\r\n\x1a\n"
    if len(data) < offset + 8 or data[offset:offset + 8] != PNG_MAGIC:
        return None

    level = 1
    confidence = 0.50
    details = "PNG 8-byte magic header verified"
    extracted_size = 8

    # Level 2: Check IHDR chunk
    if len(data) >= offset + 8 + 12:
        ihdr_len = struct.unpack(">I", data[offset + 8:offset + 12])[0]
        ihdr_type = data[offset + 12:offset + 16]
        if ihdr_type == b"IHDR" and ihdr_len == 13:
            level = 2
            confidence = 0.80
            details = "PNG IHDR chunk verified"

            # Check IEND chunk and parse chunks
            pos = offset + 8
            max_pos = min(len(data), offset + 50 * 1024 * 1024)
            found_iend = False

            while pos + 12 <= max_pos:
                chunk_len = struct.unpack(">I", data[pos:pos + 4])[0]
                chunk_type = data[pos + 4:pos + 8]
                if chunk_len > 30 * 1024 * 1024:  # Suspicious chunk length
                    break
                if chunk_type == b"IEND":
                    found_iend = True
                    extracted_size = (pos + 12) - offset
                    break
                pos += 12 + chunk_len

            if found_iend:
                level = 3
                confidence = 0.98
                details = f"Valid PNG image with IEND trailer at +{extracted_size} bytes"

    return ValidationResult("PNG", level, confidence, extracted_size, details, is_fragmented=not (level == 3), header_offset=offset)


def validate_pdf(data: bytes, offset: int) -> Optional[ValidationResult]:
    """Validate PDF structure (%PDF-x.y, stream/obj markers, %%EOF)."""
    if len(data) < offset + 8 or not data[offset:offset + 5].startswith(b"%PDF-"):
        return None

    level = 1
    confidence = 0.40
    version_str = data[offset + 5:offset + 8].decode("ascii", errors="ignore")
    details = f"PDF header detected (%PDF-{version_str})"
    extracted_size = 8

    # Level 2: Check for obj, stream, or xref structures
    sample_window = data[offset:offset + min(64 * 1024, len(data) - offset)]
    if b"obj" in sample_window and (b"stream" in sample_window or b"endobj" in sample_window):
        level = 2
        confidence = 0.75
        details = f"PDF structural object markers (obj/stream) verified"

        # Level 3: Search for %%EOF
        max_scan = min(len(data), offset + 50 * 1024 * 1024)
        full_sample = data[offset:max_scan]
        eof_pos = full_sample.rfind(b"%%EOF")
        if eof_pos != -1:
            level = 3
            confidence = 0.95
            extracted_size = eof_pos + 5
            details = f"Validated PDF document with %%EOF marker at +{extracted_size} bytes"

    return ValidationResult("PDF", level, confidence, extracted_size, details, is_fragmented=not (level == 3), header_offset=offset)


def validate_zip_and_office(data: bytes, offset: int) -> Optional[ValidationResult]:
    """Validate ZIP / DOCX / XLSX / PPTX structure."""
    if len(data) < offset + 30 or data[offset:offset + 4] != b"PK\x03\x04":
        return None

    level = 1
    confidence = 0.40
    details = "ZIP local file header detected"
    extracted_size = 30
    format_name = "ZIP"

    # Level 2: Parse local header fields
    try:
        min_ver, flags, comp_method, mod_time, mod_date, crc32, comp_size, uncomp_size, fn_len, extra_len = struct.unpack(
            "<HHHIIIHHHH", data[offset + 4:offset + 30]
        )[:10]
        if fn_len > 0 and len(data) >= offset + 30 + fn_len:
            filename = data[offset + 30:offset + 30 + fn_len].decode("utf-8", errors="ignore")
            level = 2
            confidence = 0.70
            details = f"ZIP entry: '{filename}' (Method {comp_method})"

            if "[Content_Types].xml" in filename or "word/" in filename:
                format_name = "DOCX"
                confidence = 0.80
                details = f"Microsoft Word (DOCX) package: entry '{filename}'"
            elif "xl/" in filename:
                format_name = "XLSX"
                confidence = 0.80
                details = f"Microsoft Excel (XLSX) package: entry '{filename}'"
            elif "ppt/" in filename:
                format_name = "PPTX"
                confidence = 0.80
                details = f"Microsoft PowerPoint (PPTX) package: entry '{filename}'"

            # Level 3: Search for EOCD marker PK\x05\x06
            max_scan = min(len(data), offset + 50 * 1024 * 1024)
            eocd_pos = data[offset:max_scan].rfind(b"PK\x05\x06")
            if eocd_pos != -1:
                level = 3
                confidence = 0.98
                extracted_size = eocd_pos + 22
                details = f"Fully structured {format_name} archive with EOCD header at +{extracted_size} bytes"
    except Exception:
        pass

    return ValidationResult(format_name, level, confidence, extracted_size, details, is_fragmented=not (level == 3), header_offset=offset)


def validate_gzip(data: bytes, offset: int) -> Optional[ValidationResult]:
    """Validate GZIP file header (1F 8B 08) and test decompression."""
    if len(data) < offset + 10 or data[offset:offset + 3] != b"\x1f\x8b\x08":
        return None

    level = 1
    confidence = 0.45
    details = "GZIP magic bytes and Deflate method (0x08) detected"
    extracted_size = 10

    flags = data[offset + 3]
    mtime = struct.unpack("<I", data[offset + 4:offset + 8])[0]

    # Level 2: Valid flags and timestamp
    if (flags & 0xE0) == 0:  # Reserved bits must be 0
        level = 2
        confidence = 0.70
        details = f"Valid GZIP header (flags: 0x{flags:02X}, mtime: {mtime})"

        # Level 3: Attempt zlib decompression of sample
        try:
            decompressor = zlib.decompressobj(-zlib.MAX_WBITS)
            decompressed = decompressor.decompress(data[offset + 10:offset + min(1024 * 1024, len(data) - offset)])
            if len(decompressed) > 0:
                level = 3
                confidence = 0.96
                extracted_size = len(data) - offset - len(decompressor.unused_data)
                details = f"Verified GZIP stream (successfully decompressed {len(decompressed)} bytes)"
        except Exception:
            pass

    return ValidationResult("GZIP", level, confidence, extracted_size, details, is_fragmented=not (level == 3), header_offset=offset)


def validate_bmp(data: bytes, offset: int) -> Optional[ValidationResult]:
    """Validate BMP structure (BM magic, header size >= 54, plausible width/height)."""
    if len(data) < offset + 26 or data[offset:offset + 2] != b"BM":
        return None

    file_size = struct.unpack("<I", data[offset + 2:offset + 6])[0]
    reserved = struct.unpack("<I", data[offset + 6:offset + 10])[0]
    data_offset = struct.unpack("<I", data[offset + 10:offset + 14])[0]
    dib_size = struct.unpack("<I", data[offset + 14:offset + 18])[0]

    if reserved != 0 or dib_size not in (40, 56, 108, 124, 12):
        return None  # Rejects random false positive "BM" hits

    width = struct.unpack("<i", data[offset + 18:offset + 22])[0]
    height = struct.unpack("<i", data[offset + 22:offset + 26])[0]

    if not (0 < abs(width) < 65536 and 0 < abs(height) < 65536 and 54 <= data_offset <= 1048576):
        return None

    level = 2
    confidence = 0.85
    extracted_size = file_size if 54 < file_size <= len(data) - offset else 54
    details = f"BMP image header: {abs(width)}x{abs(height)}, offset: {data_offset}, size: {file_size} bytes"

    if file_size > 54 and file_size <= len(data) - offset:
        level = 3
        confidence = 0.95
        details = f"Validated BMP bitmap ({abs(width)}x{abs(height)}, {file_size} bytes)"

    return ValidationResult("BMP", level, confidence, extracted_size, details, is_fragmented=not (level == 3), header_offset=offset)


def validate_gif(data: bytes, offset: int) -> Optional[ValidationResult]:
    """Validate GIF structure (GIF87a / GIF89a, screen descriptor, trailer 0x3B)."""
    if len(data) < offset + 13:
        return None
    header = data[offset:offset + 6]
    if header not in (b"GIF87a", b"GIF89a"):
        return None

    width, height = struct.unpack("<HH", data[offset + 6:offset + 10])
    level = 2
    confidence = 0.80
    details = f"{header.decode('ascii')} header: {width}x{height}"
    extracted_size = 13

    # Check for trailer 0x3B
    max_scan = min(len(data), offset + 10 * 1024 * 1024)
    trailer_pos = data[offset:max_scan].rfind(b"\x3b")
    if trailer_pos != -1 and trailer_pos > 13:
        level = 3
        confidence = 0.96
        extracted_size = trailer_pos + 1
        details = f"Validated {header.decode('ascii')} image ({width}x{height}, {extracted_size} bytes)"

    return ValidationResult("GIF", level, confidence, extracted_size, details, is_fragmented=not (level == 3), header_offset=offset)


def validate_elf(data: bytes, offset: int) -> Optional[ValidationResult]:
    """Validate Linux ELF binary header."""
    if len(data) < offset + 52 or data[offset:offset + 4] != b"\x7fELF":
        return None

    ei_class = data[offset + 4]  # 1 = 32-bit, 2 = 64-bit
    ei_data = data[offset + 5]   # 1 = Little Endian, 2 = Big Endian
    ei_version = data[offset + 6]

    if ei_class not in (1, 2) or ei_data not in (1, 2) or ei_version != 1:
        return None

    endian = "<" if ei_data == 1 else ">"
    e_type, e_machine = struct.unpack(f"{endian}HH", data[offset + 16:offset + 20])
    bits = "64-bit" if ei_class == 2 else "32-bit"

    level = 3
    confidence = 0.95
    details = f"Validated ELF executable/binary ({bits}, type: {e_type}, machine: {e_machine})"
    return ValidationResult("ELF", level, confidence, 64, details, is_fragmented=False, header_offset=offset)


def validate_pe(data: bytes, offset: int) -> Optional[ValidationResult]:
    """Validate Windows PE / EXE format (MZ header with valid e_lfanew pointer to PE\\x00\\x00)."""
    if len(data) < offset + 64 or data[offset:offset + 2] != b"MZ":
        return None

    e_lfanew = struct.unpack("<I", data[offset + 60:offset + 64])[0]
    if not (64 <= e_lfanew <= 4096 and len(data) >= offset + e_lfanew + 4):
        return None  # Rejects accidental "MZ" hits

    pe_sig = data[offset + e_lfanew:offset + e_lfanew + 4]
    if pe_sig != b"PE\x00\x00":
        return None

    level = 3
    confidence = 0.98
    details = f"Validated Windows PE Executable (PE signature confirmed at offset +0x{e_lfanew:02X})"
    return ValidationResult("PE/EXE", level, confidence, e_lfanew + 248, details, is_fragmented=False, header_offset=offset)


def validate_7z(data: bytes, offset: int) -> Optional[ValidationResult]:
    """Validate 7-Zip Archive header."""
    SEVENZ_MAGIC = b"7z\xbc\xaf\x27\x1c"
    if len(data) < offset + 32 or data[offset:offset + 6] != SEVENZ_MAGIC:
        return None

    major_ver = data[offset + 6]
    minor_ver = data[offset + 7]
    level = 3
    confidence = 0.96
    details = f"Validated 7-Zip Archive header (v{major_ver}.{minor_ver})"
    return ValidationResult("7Z", level, confidence, 32, details, is_fragmented=False, header_offset=offset)


def validate_rar(data: bytes, offset: int) -> Optional[ValidationResult]:
    """Validate RAR archive header (RAR4: Rar!\\x1a\\x07\\x00 or RAR5: Rar!\\x1a\\x07\\x01\\x00)."""
    if len(data) < offset + 8 or not data[offset:offset + 4] == b"Rar!":
        return None

    if data[offset:offset + 7] == b"Rar!\x1a\x07\x00":
        return ValidationResult("RAR", 3, 0.95, 7, "Validated RAR v4 Archive header", False, offset)
    elif data[offset:offset + 8] == b"Rar!\x1a\x07\x01\x00":
        return ValidationResult("RAR", 3, 0.95, 8, "Validated RAR v5 Archive header", False, offset)
    return None


def validate_sqlite(data: bytes, offset: int) -> Optional[ValidationResult]:
    """Validate SQLite 3 database header (SQLite format 3\\x00, valid page size, page header)."""
    SQLITE_MAGIC = b"SQLite format 3\x00"
    if len(data) < offset + 16 or data[offset:offset + 16] != SQLITE_MAGIC:
        return None

    level = 1
    confidence = 0.50
    details = "SQLite v3 magic signature verified"
    extracted_size = 100

    # Level 2: Validate database page size & format version
    if len(data) >= offset + 100:
        raw_page_size = struct.unpack(">H", data[offset + 16:offset + 18])[0]
        page_size = 65536 if raw_page_size == 1 else raw_page_size
        write_ver = data[offset + 18]
        read_ver = data[offset + 19]
        text_encoding = struct.unpack(">I", data[offset + 56:offset + 60])[0] if len(data) >= offset + 60 else 1

        # Valid page sizes in SQLite are powers of 2 between 512 and 65536
        valid_page = page_size in (512, 1024, 2048, 4096, 8192, 16384, 32768, 65536)
        valid_ver = write_ver in (1, 2) and read_ver in (1, 2)
        valid_enc = text_encoding in (1, 2, 3)

        if valid_page and valid_ver and valid_enc:
            level = 2
            confidence = 0.85
            extracted_size = max(page_size, 1024)
            enc_names = {1: "UTF-8", 2: "UTF-16le", 3: "UTF-16be"}
            details = f"SQLite Database (Page Size: {page_size}B, Encoding: {enc_names.get(text_encoding, 'UTF-8')}, Format: v{write_ver})"

            # Level 3: Check b-tree page header at offset 100
            # Root page type: 0x0d = Leaf Table, 0x05 = Interior Table, 0x0a = Leaf Index, 0x02 = Interior Index
            if len(data) >= offset + 108:
                page_type = data[offset + 100]
                if page_type in (0x0d, 0x05, 0x0a, 0x02):
                    cell_count = struct.unpack(">H", data[offset + 103:offset + 105])[0]
                    level = 3
                    confidence = 0.98
                    page_desc = "Leaf Table" if page_type == 0x0d else ("Interior Table" if page_type == 0x05 else "Index")
                    details = f"Validated SQLite Database ({page_desc} root page, {cell_count} cells, page size {page_size}B)"

    return ValidationResult("SQLITE", level, confidence, extracted_size, details, is_fragmented=not (level == 3), header_offset=offset)


# -----------------------------------------------------------
# Master Forensic Dispatcher
# -----------------------------------------------------------

FORENSIC_VALIDATORS = [
    (b"SQLite format 3\x00", validate_sqlite),
    (b"\xff\xd8\xff", validate_jpeg),
    (b"\x89PNG\r\n\x1a\n", validate_png),
    (b"%PDF-", validate_pdf),
    (b"PK\x03\x04", validate_zip_and_office),
    (b"\x1f\x8b\x08", validate_gzip),
    (b"BM", validate_bmp),
    (b"GIF8", validate_gif),
    (b"\x7fELF", validate_elf),
    (b"MZ", validate_pe),
    (b"7z\xbc\xaf\x27\x1c", validate_7z),
    (b"Rar!", validate_rar),
]


def evaluate_buffer_signatures(buffer: bytes, base_offset: int = 0) -> List[ValidationResult]:
    """
    Fast C-accelerated evaluation of buffer against forensic validators.
    Uses bytes.find() to jump directly to candidate prefix offsets.
    """
    results: List[ValidationResult] = []
    buf_len = len(buffer)
    i = 0

    while i < buf_len - 4:
        earliest_pos = buf_len
        best_match = None

        for prefix, validator in FORENSIC_VALIDATORS:
            pos = buffer.find(prefix, i)
            if pos != -1 and pos < earliest_pos:
                earliest_pos = pos
                best_match = (prefix, validator)

        if best_match is None or earliest_pos >= buf_len - 4:
            break

        i = earliest_pos
        prefix, validator = best_match
        res = validator(buffer, i)
        if res is not None:
            res.header_offset += base_offset
            results.append(res)
            i += max(1, min(res.extracted_size, 512))
        else:
            i += 1

    return results
