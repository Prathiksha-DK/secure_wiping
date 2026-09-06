#!/usr/bin/env python3
"""
Test Suite for FARIS Folder-Level Forensic Recovery
===================================================
Tests scope resolution, relative hierarchy preservation, two-pass recovery,
scoped carving isolation, SHA-256 manifest integrity, safety checks, and REST API.
"""

import os
import sys
import json
import time
import struct
import shutil
import hashlib
import unittest
import tempfile
from pathlib import Path

# Add FARIS root and application directories to sys.path
FARIS_ROOT = Path(__file__).resolve().parent.parent
TEST_CASES_DIR = FARIS_ROOT / "tests" / "test_cases"
TEST_CASES_DIR.mkdir(parents=True, exist_ok=True)
os.environ["FARIS_CASES_DIR"] = str(TEST_CASES_DIR)

if str(FARIS_ROOT) not in sys.path:
    sys.path.insert(0, str(FARIS_ROOT))
if str(FARIS_ROOT / "application") not in sys.path:
    sys.path.insert(0, str(FARIS_ROOT / "application"))

from application.faris_service import app
from application.faris_api import faris_api
from recovery.folder_recovery import folder_recovery_engine, FolderRecoveryEngine


class TestFARISFolderRecovery(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        os.environ["FARIS_CASES_DIR"] = str(TEST_CASES_DIR)
        TEST_CASES_DIR.mkdir(parents=True, exist_ok=True)

    def setUp(self):
        self.app = app
        self.client = self.app.test_client()
        self.test_case_id = f"test_fld_{int(time.time() * 1000)}"

    def test_01_resolve_folder_scope_valid(self):
        """Test scope resolution on a structured test directory."""
        with tempfile.TemporaryDirectory() as tmpdir:
            test_folder = Path(tmpdir) / "Evidence_Folder"
            test_folder.mkdir()
            (test_folder / "file1.txt").write_text("Hello Forensic Evidence 1", encoding="utf-8")
            (test_folder / "sub").mkdir()
            (test_folder / "sub" / "file2.txt").write_text("Nested Subfolder Evidence 2", encoding="utf-8")

            res = folder_recovery_engine.resolve_folder_scope(str(test_folder))
            self.assertEqual(res["status"], "SUCCESS")
            self.assertTrue(res["is_allocation_available"])
            self.assertEqual(res["folder_name"], "Evidence_Folder")
            self.assertEqual(res["child_files_count"], 2)
            rel_paths = [f["relative_path"] for f in res["child_files"]]
            self.assertTrue(any("file1.txt" in p for p in rel_paths))
            self.assertTrue(any("sub/file2.txt" in p.replace("\\", "/") for p in rel_paths))

    def test_02_resolve_folder_scope_invalid(self):
        """Test scope resolution error handling for empty or non-existent path."""
        res_empty = folder_recovery_engine.resolve_folder_scope("")
        self.assertEqual(res_empty["status"], "ERROR")
        self.assertFalse(res_empty["is_allocation_available"])

    def test_03_folder_hierarchy_preservation_recovery(self):
        """Test relative directory hierarchy is preserved upon recovery (never flattened)."""
        with tempfile.TemporaryDirectory() as src_dir, tempfile.TemporaryDirectory() as dest_dir:
            src_folder = Path(src_dir) / "TestTree"
            src_folder.mkdir()
            (src_folder / "root_file.txt").write_bytes(b"Root content 12345")
            (src_folder / "alpha").mkdir()
            (src_folder / "alpha" / "alpha_doc.txt").write_bytes(b"Alpha document 67890")
            (src_folder / "alpha" / "beta").mkdir()
            (src_folder / "alpha" / "beta" / "deep_file.dat").write_bytes(b"Deep nested binary 99999")

            setup = {
                "case_id": self.test_case_id,
                "folder_path": str(src_folder),
                "export_destination": str(dest_dir),
                "examiner": "Forensic Tester",
                "selected_methods": ["fs_hierarchy", "sha256_validation"],
            }

            rec_res = folder_recovery_engine.execute_folder_recovery(setup)
            self.assertEqual(rec_res["status"], "SUCCESS")
            self.assertEqual(rec_res["recovered_files_count"], 3)

            out_root = Path(dest_dir) / self.test_case_id / "recovery" / "folder" / "TestTree"
            self.assertTrue((out_root / "root_file.txt").exists())
            self.assertTrue((out_root / "alpha" / "alpha_doc.txt").exists())
            self.assertTrue((out_root / "alpha" / "beta" / "deep_file.dat").exists())

            # Verify contents
            self.assertEqual((out_root / "root_file.txt").read_bytes(), b"Root content 12345")
            self.assertEqual((out_root / "alpha" / "alpha_doc.txt").read_bytes(), b"Alpha document 67890")
            self.assertEqual((out_root / "alpha" / "beta" / "deep_file.dat").read_bytes(), b"Deep nested binary 99999")

    def test_04_sha256_cryptographic_verification(self):
        """Test SHA-256 verification of recovered files."""
        with tempfile.TemporaryDirectory() as src_dir, tempfile.TemporaryDirectory() as dest_dir:
            src_folder = Path(src_dir) / "HashTest"
            src_folder.mkdir()
            content = b"Cryptographic validation content test 12345"
            expected_hash = hashlib.sha256(content).hexdigest()
            (src_folder / "sample.bin").write_bytes(content)

            setup = {
                "case_id": f"{self.test_case_id}_hash",
                "folder_path": str(src_folder),
                "export_destination": str(dest_dir),
                "examiner": "Hash Verifier",
                "selected_methods": ["fs_hierarchy", "sha256_validation"],
            }

            rec_res = folder_recovery_engine.execute_folder_recovery(setup)
            self.assertEqual(rec_res["status"], "SUCCESS")
            recovered_items = rec_res["recovered_items"]
            self.assertEqual(len(recovered_items), 1)
            self.assertEqual(recovered_items[0]["sha256"], expected_hash)
            self.assertTrue(recovered_items[0]["integrity_verified"])

    def test_05_destination_safety_check(self):
        """Test safety check: Output destination cannot reside on or inside source evidence."""
        with tempfile.TemporaryDirectory() as test_dir:
            src_folder = Path(test_dir) / "Evidence"
            src_folder.mkdir()
            (src_folder / "test.txt").write_text("evidence", encoding="utf-8")

            # Same folder or subfolder as destination
            invalid_dest = src_folder / "recovered"

            setup = {
                "case_id": f"{self.test_case_id}_unsafe",
                "folder_path": str(src_folder),
                "export_destination": str(invalid_dest),
                "examiner": "Safety Tester",
            }

            rec_res = folder_recovery_engine.execute_folder_recovery(setup)
            self.assertEqual(rec_res["status"], "FAILED")
            self.assertIn("Safety Violation", rec_res["error"])

    def test_06_multi_format_reports_generated(self):
        """Test that JSON, CSV, and HTML reports are generated for folder recovery."""
        with tempfile.TemporaryDirectory() as src_dir, tempfile.TemporaryDirectory() as dest_dir:
            src_folder = Path(src_dir) / "ReportTest"
            src_folder.mkdir()
            (src_folder / "data.csv").write_text("col1,col2\nval1,val2", encoding="utf-8")

            setup = {
                "case_id": f"{self.test_case_id}_rep",
                "folder_path": str(src_folder),
                "export_destination": str(dest_dir),
                "examiner": "Report Examiner",
                "selected_methods": ["fs_hierarchy", "sha256_validation"],
            }

            rec_res = folder_recovery_engine.execute_folder_recovery(setup)
            self.assertEqual(rec_res["status"], "SUCCESS")
            reports = rec_res["reports"]
            self.assertIn("json", reports)
            self.assertIn("csv", reports)
            self.assertIn("html", reports)

    def test_07_rest_api_folder_endpoints(self):
        """Test REST endpoints: /api/faris/folder/resolve-scope, /api/faris/folder/recover, /api/faris/folder/jobs/<id>."""
        with tempfile.TemporaryDirectory() as src_dir, tempfile.TemporaryDirectory() as dest_dir:
            src_folder = Path(src_dir) / "RestTest"
            src_folder.mkdir()
            (src_folder / "item.txt").write_text("REST Test Item", encoding="utf-8")

            # 1. Resolve Scope
            res_scope = self.client.post("/api/faris/folder/resolve-scope", json={
                "folder_path": str(src_folder)
            })
            self.assertEqual(res_scope.status_code, 200)
            data_scope = res_scope.get_json()
            self.assertEqual(data_scope["status"], "SUCCESS")
            self.assertEqual(data_scope["child_files_count"], 1)

            # 2. Start Recovery
            res_rec = self.client.post("/api/faris/folder/recover", json={
                "case_id": f"{self.test_case_id}_rest",
                "folder_path": str(src_folder),
                "recovery_output_path": str(dest_dir),
                "examiner": "REST Tester",
            })
            self.assertEqual(res_rec.status_code, 200)
            data_rec = res_rec.get_json()
            self.assertEqual(data_rec["status"], "SUCCESS")
            job_id = data_rec["job_id"]
            self.assertTrue(job_id.startswith("JOB-FLD-"))

            # 3. Poll Job Status
            time.sleep(0.5)
            res_job = self.client.get(f"/api/faris/folder/jobs/{job_id}")
            self.assertEqual(res_job.status_code, 200)
            data_job = res_job.get_json()
            self.assertIn(data_job["status"], ["RUNNING", "SUCCESS"])

    def test_08_immutable_audit_chain_recorded(self):
        """Test that immutable SHA-256 chained audit logs are recorded."""
        with tempfile.TemporaryDirectory() as src_dir, tempfile.TemporaryDirectory() as dest_dir:
            src_folder = Path(src_dir) / "AuditTest"
            src_folder.mkdir()
            (src_folder / "audit.log").write_text("Audit log sample", encoding="utf-8")

            case_id = f"{self.test_case_id}_audit"
            setup = {
                "case_id": case_id,
                "folder_path": str(src_folder),
                "export_destination": str(dest_dir),
                "examiner": "Auditor",
                "selected_methods": ["fs_hierarchy", "sha256_validation"],
            }

            rec_res = folder_recovery_engine.execute_folder_recovery(setup)
            self.assertEqual(rec_res["status"], "SUCCESS")

            # Check audit endpoint
            res_audit = self.client.get(f"/api/faris/audit/{case_id}")
            self.assertEqual(res_audit.status_code, 200)
            audit_data = res_audit.get_json()
            actions = [e.get("record", {}).get("action") for e in audit_data.get("entries", [])]
            self.assertIn("FOLDER_RECOVERY_STARTED", actions)
            self.assertIn("FOLDER_SCOPE_RESOLVED", actions)
            self.assertIn("FOLDER_RECOVERY_COMPLETED", actions)

    def test_09_fat32_bpb_parser_and_calculations(self):
        """Test FAT32 BPB parsing and sector offset calculations."""
        from recovery.fat32_deleted_recovery import parse_fat32_bpb_from_boot

        # Build valid 512-byte FAT32 boot sector
        boot = bytearray(512)
        boot[11:13] = struct.pack("<H", 512)      # BPS = 512
        boot[13] = 8                              # SPC = 8
        boot[14:16] = struct.pack("<H", 32)       # Reserved sectors = 32
        boot[16] = 2                              # Num FATs = 2
        boot[32:36] = struct.pack("<I", 65536)    # Total sectors = 65536
        boot[36:40] = struct.pack("<I", 512)      # SPF = 512
        boot[44:48] = struct.pack("<I", 2)        # Root clus = 2
        boot[510:512] = b"\x55\xaa"

        bpb = parse_fat32_bpb_from_boot(bytes(boot))
        self.assertIsNotNone(bpb)
        self.assertEqual(bpb["bytes_per_sector"], 512)
        self.assertEqual(bpb["sectors_per_cluster"], 8)
        self.assertEqual(bpb["bytes_per_cluster"], 4096)
        self.assertEqual(bpb["first_data_sector"], 32 + (2 * 512))  # 1056

    def test_10_fat32_deleted_directory_entry_scanning(self):
        """Test scanning and reconstructing deleted FAT32 directory records with 0xE5 markers."""
        from recovery.fat32_deleted_recovery import FAT32RawScanner, parse_fat32_bpb_from_boot

        # Build memory disk
        disk_sectors = {}

        def mock_read(sec_lba: int, sec_count: int) -> bytes:
            buf = bytearray()
            for s in range(sec_lba, sec_lba + sec_count):
                buf.extend(disk_sectors.get(s, b"\x00" * 512))
            return bytes(buf)

        bpb = {
            "bytes_per_sector": 512,
            "sectors_per_cluster": 8,
            "bytes_per_cluster": 4096,
            "reserved_sectors": 32,
            "num_fats": 2,
            "sectors_per_fat": 512,
            "root_cluster": 2,
            "first_data_sector": 1056,
            "total_sectors": 65536,
        }

        # Cluster 2 (Root directory) at LBA 1056
        dir_data = bytearray(4096)
        
        # Entry 0: Active file ACTIVE.TXT (cluster 3, 20 bytes)
        dir_data[0:11] = b"ACTIVE  TXT"
        dir_data[11] = 0x20
        dir_data[20:22] = struct.pack("<H", 0)  # High cluster
        dir_data[26:28] = struct.pack("<H", 3)  # Low cluster
        dir_data[28:32] = struct.pack("<I", 20) # Size

        # Entry 1: Deleted file _VIDENCETXT (0xE5, cluster 4, 28 bytes)
        dir_data[32:43] = b"\xe5VIDENCETXT"
        dir_data[43] = 0x20
        dir_data[52:54] = struct.pack("<H", 0)  # High cluster
        dir_data[58:60] = struct.pack("<H", 4)  # Low cluster
        dir_data[60:64] = struct.pack("<I", 28) # Size

        # Entry 2: Deleted 0-byte file _MPTY.DAT (0xE5, cluster 0, 0 bytes)
        dir_data[64:75] = b"\xe5MPTY   DAT"
        dir_data[75] = 0x20
        dir_data[84:86] = struct.pack("<H", 0)  # High cluster
        dir_data[90:92] = struct.pack("<H", 0)  # Low cluster
        dir_data[92:96] = struct.pack("<I", 0)  # Size

        # Populate disk sectors for cluster 2 (sectors 1056..1063)
        for i in range(8):
            disk_sectors[1056 + i] = dir_data[i * 512:(i + 1) * 512]

        scanner = FAT32RawScanner(mock_read, bpb, part_start_lba=2048, device_path="\\\\.\\PhysicalDriveMock")
        active, deleted = scanner.scan_directory_cluster(2)

        self.assertEqual(len(active), 1)
        self.assertEqual(active[0]["name"], "ACTIVE.TXT")
        self.assertEqual(active[0]["starting_cluster"], 3)
        self.assertEqual(active[0]["size"], 20)

        self.assertEqual(len(deleted), 2)
        del_names = [d["name"] for d in deleted]
        self.assertTrue(any("VIDENCE.TXT" in n or "VIDENCETXT" in n or "_VIDENCE" in n for n in del_names))
        self.assertTrue(any("MPTY.DAT" in n or "_MPTY" in n for n in del_names))

        # Check deleted file starting cluster and LBA
        del_evidence = next(d for d in deleted if "VIDENCE" in d["name"])
        self.assertEqual(del_evidence["starting_cluster"], 4)
        self.assertEqual(del_evidence["size"], 28)
        self.assertEqual(del_evidence["starting_lba"], 2048 + 1056 + (4 - 2) * 8)

    def test_11_fat32_deleted_file_data_recovery_and_validation(self):
        """Test recovering data clusters for deleted files and validating SHA-256."""
        from recovery.fat32_deleted_recovery import FAT32RawScanner, validate_recovered_bytes

        disk_sectors = {}
        target_payload = b"SECUREWIPE_FOLDER_TEST_12345"
        expected_sha = hashlib.sha256(target_payload).hexdigest()

        def mock_read(sec_lba: int, sec_count: int) -> bytes:
            buf = bytearray()
            for s in range(sec_lba, sec_lba + sec_count):
                buf.extend(disk_sectors.get(s, b"\x00" * 512))
            return bytes(buf)

        bpb = {
            "bytes_per_sector": 512,
            "sectors_per_cluster": 8,
            "bytes_per_cluster": 4096,
            "reserved_sectors": 32,
            "num_fats": 2,
            "sectors_per_fat": 512,
            "root_cluster": 2,
            "first_data_sector": 1056,
            "total_sectors": 65536,
        }

        # Cluster 4 starts at partition sector 1056 + (4-2)*8 = 1072
        clus4_data = bytearray(4096)
        clus4_data[:len(target_payload)] = target_payload
        for i in range(8):
            disk_sectors[1072 + i] = clus4_data[i * 512:(i + 1) * 512]

        scanner = FAT32RawScanner(mock_read, bpb, part_start_lba=0)
        deleted_entry = {
            "name": "evidence.txt",
            "starting_cluster": 4,
            "size": len(target_payload),
            "is_dir": False,
        }

        rec_result = scanner.recover_deleted_file_data(deleted_entry)
        self.assertEqual(rec_result["status"], "RECOVERED")
        self.assertEqual(rec_result["bytes"], target_payload)
        self.assertEqual(rec_result["sha256"], expected_sha)
        self.assertIn("DELETED_ENTRY", rec_result["recovery_method"])

        val_status, val_conf = validate_recovered_bytes(rec_result["bytes"], "evidence.txt")
        self.assertEqual(val_conf, "HIGH")
        self.assertIn("Plaintext", val_status)

    def test_12_fat32_zero_byte_deleted_file_handling(self):
        """Test zero-byte deleted file metadata handling without corrupting reads."""
        from recovery.fat32_deleted_recovery import FAT32RawScanner

        scanner = FAT32RawScanner(lambda lba, cnt: b"\x00" * (cnt * 512), {
            "bytes_per_sector": 512,
            "sectors_per_cluster": 8,
            "bytes_per_cluster": 4096,
            "reserved_sectors": 32,
            "num_fats": 2,
            "sectors_per_fat": 512,
            "root_cluster": 2,
            "first_data_sector": 1056,
            "total_sectors": 65536,
        })

        zero_entry = {
            "name": "empty.log",
            "starting_cluster": 0,
            "file_size": 0,
            "is_dir": False,
        }

        rec_result = scanner.recover_deleted_file_data(zero_entry)
        self.assertEqual(rec_result["status"], "METADATA_ONLY")
        self.assertEqual(rec_result["bytes"], b"")
        self.assertEqual(rec_result["size_recovered"], 0)

    def test_13_folder_recovery_with_deleted_entries_pass1b(self):
        """Test Pass 1B execution recovering deleted entries during execute_folder_recovery."""
        with tempfile.TemporaryDirectory() as src_dir, tempfile.TemporaryDirectory() as dest_dir:
            src_folder = Path(src_dir) / "LiveFolder"
            src_folder.mkdir()
            (src_folder / "active1.txt").write_bytes(b"Active File 1 Content")

            case_id = f"{self.test_case_id}_del1b"
            setup = {
                "case_id": case_id,
                "folder_path": str(src_folder),
                "export_destination": str(dest_dir),
                "examiner": "Pass1B Tester",
                "selected_methods": ["fs_hierarchy", "sha256_validation"],
            }

            rec_res = folder_recovery_engine.execute_folder_recovery(setup)
            self.assertEqual(rec_res["status"], "SUCCESS")
            self.assertGreaterEqual(rec_res["recovered_files_count"], 1)

            # Check recovered items include state attribute
            recovered_items = rec_res.get("recovered_items", [])
            self.assertTrue(len(recovered_items) >= 1)
            self.assertTrue(all("state" in item for item in recovered_items))
            self.assertIn("json", rec_res["reports"])


if __name__ == "__main__":
    unittest.main()
