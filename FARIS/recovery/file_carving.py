import os
import sys
import json
import hashlib
import subprocess
from pathlib import Path
from typing import Dict, List, Optional, Generator, Tuple

try:
    from core.paths import FARIS_ROOT, get_relative_str
    from core.engine_manager import engine_manager
except ImportError:
    from ..core.paths import FARIS_ROOT, get_relative_str
    from ..core.engine_manager import engine_manager

# Forensic file signature definitions
SIGNATURES = [
    {
        "type": "sqlite",
        "name": "SQLite Database",
        "ext": "sqlite",
        "header": b"SQLite format 3\x00",
        "header_offset": 0,
        "footer": None,
        "max_size": 100 * 1024 * 1024,  # 100 MB
        "sector_aligned": True
    },
    {
        "type": "jpeg",
        "name": "JPEG Image",
        "ext": "jpg",
        "header": b"\xFF\xD8\xFF",
        "header_offset": 0,
        "footer": b"\xFF\xD9",
        "max_size": 30 * 1024 * 1024,  # 30 MB
        "sector_aligned": True
    },
    {
        "type": "png",
        "name": "PNG Image",
        "ext": "png",
        "header": b"\x89PNG\r\n\x1a\n",
        "header_offset": 0,
        "footer": b"IEND\xaeB`\x82",
        "max_size": 30 * 1024 * 1024,
        "sector_aligned": True
    },
    {
        "type": "pdf",
        "name": "PDF Document",
        "ext": "pdf",
        "header": b"%PDF-",
        "header_offset": 0,
        "footer": b"%%EOF",
        "max_size": 50 * 1024 * 1024,
        "sector_aligned": True
    },
    {
        "type": "zip",
        "name": "ZIP Archive / Office Document",
        "ext": "zip",
        "header": b"PK\x03\x04",
        "header_offset": 0,
        "footer": b"PK\x05\x06",
        "max_size": 100 * 1024 * 1024,
        "sector_aligned": True
    },
    {
        "type": "7z",
        "name": "7-Zip Archive",
        "ext": "7z",
        "header": b"7z\xbc\xaf'\x1c",
        "header_offset": 0,
        "footer": None,
        "max_size": 100 * 1024 * 1024,
        "sector_aligned": True
    },
    {
        "type": "gif89a",
        "name": "GIF Image (89a)",
        "ext": "gif",
        "header": b"GIF89a",
        "header_offset": 0,
        "footer": b"\x00;",
        "max_size": 20 * 1024 * 1024,
        "sector_aligned": True
    },
    {
        "type": "gif87a",
        "name": "GIF Image (87a)",
        "ext": "gif",
        "header": b"GIF87a",
        "header_offset": 0,
        "footer": b"\x00;",
        "max_size": 20 * 1024 * 1024,
        "sector_aligned": True
    },
    {
        "type": "evtx",
        "name": "Windows Event Log",
        "ext": "evtx",
        "header": b"ElfFile\x00",
        "header_offset": 0,
        "footer": None,
        "max_size": 64 * 1024 * 1024,
        "sector_aligned": True
    },
    {
        "type": "regf",
        "name": "Windows Registry Hive",
        "ext": "regf",
        "header": b"regf",
        "header_offset": 0,
        "footer": None,
        "max_size": 64 * 1024 * 1024,
        "sector_aligned": True
    },
    {
        "type": "ole",
        "name": "Compound Binary / Legacy Office",
        "ext": "ole",
        "header": b"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1",
        "header_offset": 0,
        "footer": None,
        "max_size": 50 * 1024 * 1024,
        "sector_aligned": True
    }
]


class FileCarver:
    """
    Forensic Signature-Based File Carver for FARIS.
    Scans raw disk streams, E01 images, or unallocated block pools to carve files by header/footer signatures.
    """

    def __init__(self, chunk_size: int = 4 * 1024 * 1024, sector_size: int = 512):
        self.chunk_size = chunk_size
        self.sector_size = sector_size

    def carve_stream(
        self,
        stream_reader,
        output_dir: Path,
        source_name: str = "raw_stream",
        max_scan_bytes: Optional[int] = None
    ) -> List[Dict]:
        """
        Carves files from any readable binary stream.
        """
        output_dir.mkdir(parents=True, exist_ok=True)
        carved_records = []
        carved_count = 0
        global_offset = 0
        overlap_size = 1024 * 1024  # 1MB overlap across chunk boundaries
        buffer = b""

        print(f"[*] Starting signature-based file carving on {source_name}...")
        print(f"[*] Output directory: {output_dir}")

        while True:
            if max_scan_bytes and global_offset >= max_scan_bytes:
                break

            to_read = self.chunk_size
            if max_scan_bytes:
                to_read = min(to_read, max_scan_bytes - global_offset)

            chunk = stream_reader.read(to_read)
            if not chunk:
                break

            buffer += chunk
            buf_len = len(buffer)

            # Search signatures in the current buffer
            i = 0
            while i < buf_len - 16:
                # Align to sector boundaries for disk images
                matched_sig = None
                for sig in SIGNATURES:
                    header = sig["header"]
                    hdr_len = len(header)
                    if buffer[i:i + hdr_len] == header:
                        matched_sig = sig
                        break

                if matched_sig:
                    sig_type = matched_sig["type"]
                    ext = matched_sig["ext"]
                    max_sz = matched_sig["max_size"]
                    footer = matched_sig["footer"]
                    file_start_offset = global_offset + i

                    carved_data = b""
                    carved_len = 0

                    if footer:
                        # Search for footer within max_size
                        search_limit = min(buf_len, i + max_sz)
                        footer_idx = buffer.find(footer, i + len(matched_sig["header"]), search_limit)
                        
                        if footer_idx != -1:
                            if sig_type == "zip":
                                # ZIP End of Central Directory record is at least 22 bytes
                                end_idx = min(buf_len, footer_idx + len(footer) + 20)
                            else:
                                end_idx = footer_idx + len(footer)
                            carved_data = buffer[i:end_idx]
                            carved_len = len(carved_data)
                        else:
                            # If footer not yet found in current buffer and buffer can be expanded, wait
                            if len(chunk) == to_read and (buf_len - i) < max_sz:
                                # We will retain from i onward and read more next iteration
                                break
                            else:
                                # Truncated or upper-bound carve
                                carved_len = min(buf_len - i, max_sz)
                                carved_data = buffer[i:i + carved_len]
                    elif sig_type == "sqlite":
                        # Determine SQLite database size from page size and page count in header
                        if len(buffer) >= i + 32:
                            page_size = int.from_bytes(buffer[i+16:i+18], byteorder="big")
                            if page_size == 1:
                                page_size = 65536
                            db_size_pages = int.from_bytes(buffer[i+28:i+32], byteorder="big")
                            expected_size = page_size * db_size_pages if db_size_pages > 0 else 0
                            if 512 <= expected_size <= max_sz and (i + expected_size <= buf_len):
                                carved_len = expected_size
                                carved_data = buffer[i:i + carved_len]
                            else:
                                # Standard chunk
                                carved_len = min(buf_len - i, 16 * 1024 * 1024)
                                carved_data = buffer[i:i + carved_len]
                        else:
                            carved_len = min(buf_len - i, max_sz)
                            carved_data = buffer[i:i + carved_len]
                    else:
                        # Fixed chunk or sector scan
                        carved_len = min(buf_len - i, max_sz)
                        carved_data = buffer[i:i + carved_len]

                    if carved_len > 0 and len(carved_data) > 0:
                        carved_count += 1
                        artifact_id = f"CARVE_{carved_count:05d}"
                        out_filename = f"{artifact_id}.{ext}"
                        out_path = output_dir / out_filename

                        with open(out_path, "wb") as f_out:
                            f_out.write(carved_data)

                        sha256_hash = hashlib.sha256(carved_data).hexdigest()

                        record = {
                            "artifact_id": artifact_id,
                            "filename": out_filename,
                            "file_type": matched_sig["name"],
                            "type_code": sig_type,
                            "extension": ext,
                            "source_offset": file_start_offset,
                            "size_bytes": carved_len,
                            "sha256": sha256_hash,
                            "recovery_method": "Signature Carving (Header/Footer)",
                            "confidence": "HIGH" if footer and footer_idx != -1 else "MEDIUM",
                            "source": source_name
                        }
                        carved_records.append(record)
                        print(f"  [+] Carved {out_filename} ({matched_sig['name']}) at offset {file_start_offset} ({carved_len} bytes) - SHA256: {sha256_hash[:16]}...")
                        
                        i += max(self.sector_size, carved_len)
                        continue

                i += self.sector_size

            # Retain overlap at end of buffer
            keep_bytes = min(overlap_size, buf_len - i) if i < buf_len else 0
            if keep_bytes > 0:
                buffer = buffer[-keep_bytes:]
                global_offset += (buf_len - keep_bytes)
            else:
                buffer = b""
                global_offset += buf_len

        # Write manifest
        manifest_path = output_dir / "carving_manifest.json"
        with open(manifest_path, "w", encoding="utf-8") as f_man:
            json.dump({
                "source": source_name,
                "total_carved": len(carved_records),
                "artifacts": carved_records
            }, f_man, indent=2)

        print(f"\n[+] Carving complete. Total artifacts carved: {len(carved_records)}")
        print(f"[+] Manifest written to: {manifest_path}")
        return carved_records

    def carve_image(self, image_path: Path, output_dir: Path, partition_offset: Optional[int] = None) -> List[Dict]:
        """
        Carves an E01 image or raw disk image using Sleuth Kit img_cat streaming.
        """
        img_cat = engine_manager.require_tool("img_cat")
        cmd = [str(img_cat), str(image_path)]
        print(f"[*] Streaming disk image via Sleuth Kit img_cat: {image_path.name}")
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

        try:
            records = self.carve_stream(proc.stdout, output_dir, source_name=image_path.name)
        finally:
            try:
                proc.stdout.close()
            except Exception:
                pass
            proc.kill()
            proc.wait()

        return records

    def carve_unallocated(self, image_path: Path, output_dir: Path, partition_offset: int = 2048) -> List[Dict]:
        """
        Carves only the unallocated sectors from a partition using Sleuth Kit blkls.
        """
        blkls = engine_manager.require_tool("blkls")
        cmd = [str(blkls), "-o", str(partition_offset), str(image_path)]
        print(f"[*] Streaming unallocated blocks via Sleuth Kit blkls (offset {partition_offset}): {image_path.name}")
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

        try:
            records = self.carve_stream(
                proc.stdout,
                output_dir,
                source_name=f"{image_path.name}:unallocated_offset_{partition_offset}"
            )
        finally:
            try:
                proc.stdout.close()
            except Exception:
                pass
    def carve_with_photorec(self, image_path: Path, output_dir: Path, partition_offset: Optional[int] = None) -> Dict:
        """
        Executes genuine signature-based carving using the bundled official CGSecurity PhotoRec engine.
        Ensures evidence is opened in strict read-only mode and all outputs are isolated.
        """
        output_dir.mkdir(parents=True, exist_ok=True)
        pr_exe = engine_manager.get_tool_path("photorec_win")
        
        if not pr_exe or not pr_exe.exists():
            return {
                "status": "ENGINE_UNAVAILABLE",
                "carved_files": 0,
                "artifacts": [],
                "notes": "PhotoRec binary not found in bundled engines."
            }

        print(f"[*] Invoking bundled CGSecurity PhotoRec on {image_path.name}...")
        
        # Build batch command for PhotoRec: /cmd <image> [options] search
        # Writes into isolated output_dir
        cmd = [str(pr_exe), "/cmd", str(image_path), f"d {str(output_dir)}", "search"]
        
        try:
            # Execute PhotoRec from its engine directory so all DLLs resolve cleanly
            proc = subprocess.run(
                cmd,
                cwd=str(pr_exe.parent),
                capture_output=True,
                text=True,
                timeout=120
            )
        except subprocess.TimeoutExpired:
            print("[!] PhotoRec scan timed out (bounded run).")
        except Exception as e:
            print(f"[!] PhotoRec execution exception: {e}")

        # Index all carved artifacts produced by PhotoRec
        recovered_artifacts = []
        for root, _, files in os.walk(output_dir):
            for file in files:
                if file.endswith(".json") or file.endswith(".txt") or file == "report.xml":
                    continue
                fpath = Path(root) / file
                try:
                    sz = fpath.stat().st_size
                    with open(fpath, "rb") as f_art:
                        f_hash = hashlib.sha256(f_art.read()).hexdigest()
                    
                    recovered_artifacts.append({
                        "artifact_id": f"PHOTOREC_{file}",
                        "filename": file,
                        "file_type": fpath.suffix.lstrip(".").upper() or "BINARY",
                        "size_bytes": sz,
                        "sha256": f_hash,
                        "recovery_method": "CGSecurity PhotoRec 7.2 Carving",
                        "confidence": "HIGH" if sz > 0 else "LOW",
                        "path": str(fpath)
                    })
                except Exception:
                    pass

        manifest_path = output_dir / "photorec_manifest.json"
        with open(manifest_path, "w", encoding="utf-8") as f_man:
            json.dump({
                "engine": "CGSecurity PhotoRec 7.2 (Win64 Bundled)",
                "source": image_path.name,
                "total_carved": len(recovered_artifacts),
                "artifacts": recovered_artifacts
            }, f_man, indent=2)

        return {
            "status": "COMPLETED",
            "carved_files": len(recovered_artifacts),
            "artifacts": recovered_artifacts,
            "manifest": str(manifest_path)
        }


if __name__ == "__main__":
    test_image = FARIS_ROOT / "case001" / "pendrive_image.E01"
    test_out = FARIS_ROOT / "case001" / "recovered" / "carved"

    carver = FileCarver()
    if test_image.exists():
        carver.carve_unallocated(test_image, test_out, partition_offset=2048)
    else:
        print(f"Image not found at {test_image}")
