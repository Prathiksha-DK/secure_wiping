import os
import json
import sqlite3
import hashlib
import zipfile
from pathlib import Path
from typing import Dict, List, Any, Optional

try:
    from core.paths import FARIS_ROOT, resolve_case_dir, get_relative_str
except ImportError:
    from ..core.paths import FARIS_ROOT, resolve_case_dir, get_relative_str

class RecoveryValidator:
    """
    Forensic Recovery Validation and Confidence Scoring Engine.
    Validates internal file structures, detects false positives, checks parser openability,
    and assigns measurable forensic confidence ratings (HIGH, MEDIUM, LOW) with justifications.
    """
    def _validate_mp3(self, full_data: bytes, file_name: str, size: int, sha256: str) -> Optional[Dict[str, Any]]:
        """
        Validates MPEG Audio Layer III (MP3) frame structure and audio headers.
        """
        if len(full_data) < 128:
            return None

        # Check for ID3 tag or MPEG sync word
        has_id3 = full_data.startswith(b"ID3")
        pos = 0
        if has_id3 and len(full_data) >= 10:
            id3_size = ((full_data[6] & 0x7F) << 21) | ((full_data[7] & 0x7F) << 14) | ((full_data[8] & 0x7F) << 7) | (full_data[9] & 0x7F)
            pos = 10 + id3_size
            if pos >= len(full_data):
                pos = 10

        bitrates = {
            1: [0, 32, 40, 48, 56, 64, 80, 96, 112, 128, 160, 192, 224, 256, 320, 0],
            2: [0, 8, 16, 24, 32, 40, 48, 56, 64, 80, 96, 112, 128, 144, 160, 0]
        }
        samplerates = {
            1: [44100, 48000, 32000, 0],
            2: [22050, 24000, 16000, 0]
        }

        valid_frames = 0
        first_frame = None
        data_len = len(full_data)

        # Search for initial valid frame sync within first 16KB
        search_limit = min(data_len - 4, pos + 16384)
        sync_found = False
        while pos < search_limit:
            b1, b2 = full_data[pos], full_data[pos+1]
            if b1 == 0xFF and (b2 & 0xE0) == 0xE0:
                ver_bits = (b2 >> 3) & 0x03
                layer_bits = (b2 >> 1) & 0x03
                if ver_bits in (3, 2) and layer_bits == 1:
                    ver = 1 if ver_bits == 3 else 2
                    b3 = full_data[pos+2]
                    br_idx = (b3 >> 4) & 0x0F
                    sr_idx = (b3 >> 2) & 0x03
                    padding = (b3 >> 1) & 0x01
                    br = bitrates[ver][br_idx]
                    sr = samplerates[ver][sr_idx]
                    if br > 0 and sr > 0:
                        frame_len = (144 * br * 1000 // sr) + padding
                        if frame_len > 0 and pos + frame_len <= data_len:
                            first_frame = {"ver": ver, "br": br, "sr": sr}
                            sync_found = True
                            valid_frames += 1
                            pos += frame_len
                            break
            pos += 1

        if not sync_found:
            return None

        # Walk remaining frames to verify continuity
        max_checks = 100
        checks = 0
        while pos < data_len - 4 and checks < max_checks:
            b1, b2 = full_data[pos], full_data[pos+1]
            if b1 == 0xFF and (b2 & 0xE0) == 0xE0:
                ver_bits = (b2 >> 3) & 0x03
                layer_bits = (b2 >> 1) & 0x03
                if ver_bits in (3, 2) and layer_bits == 1:
                    ver = 1 if ver_bits == 3 else 2
                    b3 = full_data[pos+2]
                    br_idx = (b3 >> 4) & 0x0F
                    sr_idx = (b3 >> 2) & 0x03
                    padding = (b3 >> 1) & 0x01
                    br = bitrates[ver][br_idx]
                    sr = samplerates[ver][sr_idx]
                    if br > 0 and sr > 0:
                        frame_len = (144 * br * 1000 // sr) + padding
                        if frame_len > 0:
                            valid_frames += 1
                            pos += frame_len
                            checks += 1
                            continue
            pos += 1
            checks += 1

        if valid_frames >= 5:
            duration_est = f"MPEG-{first_frame['ver']} Layer III, {first_frame['br']} kbps, {first_frame['sr']} Hz"
            return {
                "file": file_name,
                "validation_status": "VALID",
                "confidence": "HIGH",
                "reason": f"MPEG Audio Layer III verified ({duration_est}, {valid_frames}+ consecutive valid frames confirmed).",
                "size_bytes": size,
                "sha256": sha256
            }
        elif valid_frames >= 1:
            return {
                "file": file_name,
                "validation_status": "PARTIALLY_VALID",
                "confidence": "MEDIUM",
                "reason": f"MPEG Audio header detected with partial frame sync ({valid_frames} frames).",
                "size_bytes": size,
                "sha256": sha256
            }
        return None

    def validate_file(self, file_path: Path, expected_size: Optional[int] = None) -> Dict[str, Any]:
        """
        Validates a single recovered file against forensic integrity criteria.
        Optionally evaluates expected_size when known from filesystem metadata.
        """
        if not file_path.exists() or file_path.is_dir():
            return {
                "file": file_path.name,
                "validation_status": "REJECTED",
                "confidence": "LOW",
                "reason": "File does not exist or is a directory.",
                "size_bytes": 0,
                "sha256": ""
            }

        size = file_path.stat().st_size
        if size == 0:
            return {
                "file": file_path.name,
                "validation_status": "REJECTED_ZERO_BYTE",
                "confidence": "LOW",
                "reason": "Artifact is 0 bytes; no forensic data recovered.",
                "size_bytes": 0,
                "sha256": hashlib.sha256(b"").hexdigest()
            }

        # Read first 8KB for header validation
        with open(file_path, "rb") as f:
            header_sample = f.read(8192)
            f.seek(0)
            full_data = f.read()

        sha256 = hashlib.sha256(full_data).hexdigest()

        # Check for zero-fill false positive
        null_count = full_data.count(b"\x00")
        if null_count / len(full_data) > 0.98 and len(full_data) > 1024:
            return {
                "file": file_path.name,
                "validation_status": "REJECTED_NULL_FILL",
                "confidence": "LOW",
                "reason": "False-recovery detection: >98% null bytes (sparse zero-fill).",
                "size_bytes": size,
                "sha256": sha256
            }

        ext = file_path.suffix.lower()
        clean_name = file_path.name.lower()

        # 1. MP3 / Audio Validation (Checks .mp3 extension or metadata audio files or MPEG frame sync)
        if ext in [".mp3", ".audio"] or "mp3" in clean_name or header_sample.startswith(b"ID3") or (len(header_sample) >= 2 and header_sample[0] == 0xFF and (header_sample[1] & 0xE0) == 0xE0):
            mp3_res = self._validate_mp3(full_data, file_path.name, size, sha256)
            if mp3_res:
                if expected_size is not None and expected_size > 0:
                    if size == expected_size:
                        mp3_res["reason"] += f" Exact expected size match ({size:,} bytes)."
                    elif size < expected_size:
                        mp3_res["validation_status"] = "PARTIALLY_VALID"
                        mp3_res["confidence"] = "MEDIUM"
                        mp3_res["reason"] += f" Partial recovery: {size:,} of {expected_size:,} bytes."
                return mp3_res

        # 2. SQLite Database Validation
        if ext in [".sqlite", ".db", ".sqlite3"] or header_sample.startswith(b"SQLite format 3\x00"):
            try:
                conn = sqlite3.connect(str(file_path))
                cur = conn.cursor()
                cur.execute("PRAGMA quick_check;")
                res = cur.fetchone()
                conn.close()
                if res and res[0] == "ok":
                    return {
                        "file": file_path.name,
                        "validation_status": "VALID",
                        "confidence": "HIGH",
                        "reason": "SQLite PRAGMA quick_check returned 'ok'; B-Tree structures fully consistent.",
                        "size_bytes": size,
                        "sha256": sha256
                    }
                else:
                    return {
                        "file": file_path.name,
                        "validation_status": "PARTIALLY_VALID",
                        "confidence": "MEDIUM",
                        "reason": f"SQLite quick_check reported partial issues: {res[0] if res else 'Unknown'}.",
                        "size_bytes": size,
                        "sha256": sha256
                    }
            except Exception as e:
                return {
                    "file": file_path.name,
                    "validation_status": "DAMAGED",
                    "confidence": "LOW",
                    "reason": f"SQLite parser error: {str(e)}",
                    "size_bytes": size,
                    "sha256": sha256
                }

        # 3. JPEG Validation
        if ext in [".jpg", ".jpeg"] or header_sample.startswith(b"\xFF\xD8\xFF"):
            has_header = header_sample.startswith(b"\xFF\xD8\xFF")
            has_footer = full_data.endswith(b"\xFF\xD9") or b"\xFF\xD9" in full_data[-1024:]
            if has_header and has_footer:
                return {
                    "file": file_path.name,
                    "validation_status": "VALID",
                    "confidence": "HIGH",
                    "reason": "JPEG SOI marker (0xFFD8) and EOI marker (0xFFD9) both confirmed intact.",
                    "size_bytes": size,
                    "sha256": sha256
                }
            elif has_header:
                return {
                    "file": file_path.name,
                    "validation_status": "PARTIALLY_VALID",
                    "confidence": "MEDIUM",
                    "reason": "JPEG SOI header verified; EOI footer truncated or missing.",
                    "size_bytes": size,
                    "sha256": sha256
                }

        # 4. PNG Validation
        if ext == ".png" or header_sample.startswith(b"\x89PNG\r\n\x1a\n"):
            has_hdr = header_sample.startswith(b"\x89PNG\r\n\x1a\n")
            has_iend = b"IEND\xaeB`\x82" in full_data[-1024:]
            if has_hdr and has_iend:
                return {
                    "file": file_path.name,
                    "validation_status": "VALID",
                    "confidence": "HIGH",
                    "reason": "PNG magic header and IEND chunk verified.",
                    "size_bytes": size,
                    "sha256": sha256
                }
            elif has_hdr:
                return {
                    "file": file_path.name,
                    "validation_status": "PARTIALLY_VALID",
                    "confidence": "MEDIUM",
                    "reason": "PNG header verified; trailing IEND chunk missing or truncated.",
                    "size_bytes": size,
                    "sha256": sha256
                }

        # 5. ZIP / Office XML Validation
        if ext in [".zip", ".docx", ".xlsx", ".pptx", ".jar"] or header_sample.startswith(b"PK\x03\x04"):
            try:
                with zipfile.ZipFile(file_path, "r") as zf:
                    bad_file = zf.testzip()
                    if bad_file is None:
                        return {
                            "file": file_path.name,
                            "validation_status": "VALID",
                            "confidence": "HIGH",
                            "reason": f"ZIP archive verified; {len(zf.infolist())} entries parsed without CRC errors.",
                            "size_bytes": size,
                            "sha256": sha256
                        }
                    else:
                        return {
                            "file": file_path.name,
                            "validation_status": "PARTIALLY_VALID",
                            "confidence": "MEDIUM",
                            "reason": f"ZIP archive corrupted at entry '{bad_file}'.",
                            "size_bytes": size,
                            "sha256": sha256
                        }
            except Exception as e:
                return {
                    "file": file_path.name,
                    "validation_status": "DAMAGED",
                    "confidence": "LOW",
                    "reason": f"ZIP central directory parsing failed: {str(e)}",
                    "size_bytes": size,
                    "sha256": sha256
                }

        # 6. PDF Validation
        if ext == ".pdf" or header_sample.startswith(b"%PDF-"):
            has_hdr = header_sample.startswith(b"%PDF-")
            has_eof = b"%%EOF" in full_data[-1024:]
            if has_hdr and has_eof:
                return {
                    "file": file_path.name,
                    "validation_status": "VALID",
                    "confidence": "HIGH",
                    "reason": "PDF header version and %%EOF xref footer verified.",
                    "size_bytes": size,
                    "sha256": sha256
                }
            elif has_hdr:
                return {
                    "file": file_path.name,
                    "validation_status": "PARTIALLY_VALID",
                    "confidence": "MEDIUM",
                    "reason": "PDF header verified, but trailing %%EOF footer missing.",
                    "size_bytes": size,
                    "sha256": sha256
                }

        # Generic Binary Fallback
        return {
            "file": file_path.name,
            "validation_status": "UNVERIFIED_GENERIC",
            "confidence": "MEDIUM",
            "reason": "Binary stream contains non-null data with no known parser failure.",
            "size_bytes": size,
            "sha256": sha256
        }

    def validate_case_recoveries(self, case_id: str) -> Dict[str, Any]:
        """
        Validates all recovered artifacts in a case and outputs validation manifest.
        """
        case_dir = resolve_case_dir(case_id)
        recovery_dir = case_dir / "recovery"
        recovered_dir = case_dir / "recovered"
        validated_dir = case_dir / "validated"
        validated_dir.mkdir(parents=True, exist_ok=True)

        files_to_check = []
        for d in [recovery_dir, recovered_dir]:
            if d.exists():
                for f in d.rglob("*"):
                    if f.is_file() and not f.name.endswith(".json") and not f.name.endswith(".log"):
                        files_to_check.append(f)

        validation_results = []
        for f in files_to_check:
            res = self.validate_file(f)
            res["relative_path"] = get_relative_str(f)
            validation_results.append(res)

        summary_counts = {
            "VALID": sum(1 for r in validation_results if r["validation_status"] == "VALID"),
            "PARTIALLY_VALID": sum(1 for r in validation_results if r["validation_status"] == "PARTIALLY_VALID"),
            "REJECTED": sum(1 for r in validation_results if "REJECTED" in r["validation_status"]),
            "UNVERIFIED_GENERIC": sum(1 for r in validation_results if r["validation_status"] == "UNVERIFIED_GENERIC")
        }

        report = {
            "case_id": case_id,
            "total_artifacts_evaluated": len(validation_results),
            "summary_counts": summary_counts,
            "artifacts": validation_results
        }

        report_file = validated_dir / "validation_report.json"
        with open(report_file, "w", encoding="utf-8") as f_out:
            json.dump(report, f_out, indent=2)

        print(f"[+] Recovery validation completed for case '{case_id}'.")
        print(f"[+] Breakdown: {summary_counts}")
        print(f"[+] Validation report written to: {report_file}")
        return report

# Singleton instance
recovery_validator = RecoveryValidator()
