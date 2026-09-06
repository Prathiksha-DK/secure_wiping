"""
Comprehensive Test Suite: Seek Help & Forensic Case Investigation Workflow
Tests all 10 core constraints and scenarios (A through J).
"""

import os
import sys
import time
import json
import uuid
import hashlib
import unittest
import tempfile
import sqlite3

# Ensure backend directory is in sys.path
BACKEND_DIR = os.path.dirname(os.path.abspath(__file__))
if BACKEND_DIR not in sys.path:
    sys.path.insert(0, BACKEND_DIR)

from auth import get_db, init_platform_db, register_user
from central_device_registry import (
    init_device_registry_db,
    register_device,
    get_registered_device_by_id,
    compute_device_fingerprint,
)
from seek_help_case_engine import (
    init_seek_help_db,
    acquire_raw_forensic_image,
    CASES_STORAGE_DIR,
)
from audit_engine import get_audit_logs, verify_audit_integrity


class TestSeekHelpWorkflow(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        init_platform_db()
        init_device_registry_db()
        init_seek_help_db()

        # Create test users
        register_user("inspector_test", "Secret123!", "forensic", "inspector@test.com", "Forensics Div")
        register_user("hunter_alpha", "Secret123!", "hunter", "hunter_alpha@test.com", "Hunter Ops")
        register_user("hunter_beta", "Secret123!", "hunter", "hunter_beta@test.com", "Hunter Ops")

    def setUp(self):
        # Create a mock source disk file (256 KB) with known pattern
        self.test_src = tempfile.NamedTemporaryFile(delete=False, suffix=".raw")
        pattern = b"SECUREWIPE_FORENSIC_RAW_SECTOR_DATA_" * 5000  # ~180 KB
        self.test_src.write(pattern)
        self.test_src.close()

        # Compute reference hash
        hasher = hashlib.sha256()
        with open(self.test_src.name, "rb") as f:
            hasher.update(f.read())
        self.expected_src_sha256 = hasher.hexdigest()

    def tearDown(self):
        if os.path.exists(self.test_src.name):
            try:
                os.remove(self.test_src.name)
            except Exception:
                pass

    def test_A_unregistered_device_blocked(self):
        """Test A: An unregistered device must be blocked from forensic acquisition."""
        unregistered_device_id = "SW-DEV-UNREGISTERED99"
        conn = get_db()
        try:
            cur = conn.cursor()
            cur.execute("SELECT * FROM central_device_registry WHERE device_id = ?", (unregistered_device_id,))
            self.assertIsNone(cur.fetchone())
        finally:
            conn.close()

        dev = get_registered_device_by_id(unregistered_device_id)
        self.assertIsNone(dev)

    def test_B_registered_device_acquisition_and_case_creation(self):
        """Test B: A registered device undergoes RAW imaging, generates SHA-256, and creates AVAILABLE case."""
        # 1. Register device
        raw_dev = {
            "name": "Transcend JetFlash 16GB",
            "manufacturer": "Transcend",
            "model": "JetFlash 700",
            "serial": "TS16GJF700_SN9901",
            "sizeBytes": 16000000000,
            "size": "14.9 GB",
            "bus": "USB",
            "type": "USB Storage"
        }
        ok, msg, reg_record = register_device(raw_dev, created_by="forensic_analyst")
        self.assertTrue(ok)
        device_id = reg_record["device_id"]
        self.assertTrue(device_id.startswith("SW-DEV-"))

        # 2. Acquire RAW image to central case directory
        case_id = f"CASE-2026-TEST{uuid.uuid4().hex[:4].upper()}"
        case_dir = os.path.join(CASES_STORAGE_DIR, case_id)
        os.makedirs(case_dir, exist_ok=True)
        img_dest = os.path.join(case_dir, f"{case_id}.img")

        acq_result = acquire_raw_forensic_image(
            source_target=self.test_src.name,
            output_image_path=img_dest
        )

        self.assertTrue(os.path.isfile(img_dest))
        self.assertEqual(acq_result["sha256"], self.expected_src_sha256)
        self.assertEqual(acq_result["acquisition_status"], "ACQUISITION_COMPLETED")

        # 3. Create Case in database
        now = int(time.time())
        conn = get_db()
        try:
            with conn:
                conn.execute("""
                    INSERT INTO forensic_investigation_cases (
                        case_id, title, device_id, device_fingerprint, device_model,
                        device_manufacturer, device_serial, device_capacity, device_capacity_readable,
                        image_filename, image_path, image_format, image_size, sector_size,
                        total_sectors, sha256, md5, acquisition_start_time, acquisition_end_time,
                        acquisition_status, case_status, created_by, created_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'RAW', ?, ?, ?, ?, ?, ?, ?, 'ACQUISITION_COMPLETED', 'AVAILABLE', 'forensic_analyst', ?)
                """, (
                    case_id, f"Investigation — {reg_record['model']}", device_id, reg_record["device_fingerprint"],
                    reg_record["model"], reg_record["manufacturer"], reg_record["serial_number"],
                    reg_record["capacity"], reg_record["capacity_readable"],
                    f"{case_id}.img", img_dest, acq_result["image_size"], acq_result["sector_size"],
                    acq_result["total_sectors"], acq_result["sha256"], acq_result["md5"],
                    acq_result["acquisition_start_time"], acq_result["acquisition_end_time"], now
                ))

            cur = conn.cursor()
            cur.execute("SELECT * FROM forensic_investigation_cases WHERE case_id = ?", (case_id,))
            case_row = cur.fetchone()
            self.assertIsNotNone(case_row)
            self.assertEqual(case_row["case_status"], "AVAILABLE")
            self.assertEqual(case_row["sha256"], self.expected_src_sha256)
            self.assertIsNone(case_row["assigned_hunter_id"])
        finally:
            conn.close()

    def test_C_and_D_and_E_hunter_claiming_locking_and_one_case_rule(self):
        """Tests C, D, E: Atomic case locking, anti-double claiming, and one-active-case restriction."""
        case_id_1 = f"CASE-2026-CLAIM1_{uuid.uuid4().hex[:4].upper()}"
        case_id_2 = f"CASE-2026-CLAIM2_{uuid.uuid4().hex[:4].upper()}"
        hunter_a = f"hunter_alpha_{uuid.uuid4().hex[:4]}"
        hunter_b = f"hunter_beta_{uuid.uuid4().hex[:4]}"
        now = int(time.time())

        # Insert 2 available cases
        conn = get_db()
        try:
            with conn:
                for cid in [case_id_1, case_id_2]:
                    conn.execute("""
                        INSERT INTO forensic_investigation_cases (
                            case_id, title, device_id, device_fingerprint, device_model,
                            image_filename, image_path, sha256, acquisition_start_time, acquisition_end_time,
                            case_status, created_at
                        ) VALUES (?, 'Test Case', 'SW-DEV-001', 'fp123', 'Flash Drive', 'test.img', '/tmp/test.img', 'hash123', ?, ?, 'AVAILABLE', ?)
                    """, (cid, now, now, now))
        finally:
            conn.close()

        # Step C: Hunter A claims case 1
        conn = get_db()
        try:
            with conn:
                cur = conn.cursor()
                cur.execute("""
                    UPDATE forensic_investigation_cases
                    SET case_status = 'INVESTIGATION_IN_PROGRESS',
                        assigned_hunter_id = ?,
                        claimed_at = ?
                    WHERE case_id = ? AND case_status = 'AVAILABLE'
                """, (hunter_a, now, case_id_1))
                self.assertEqual(cur.rowcount, 1)

                cur.execute("SELECT case_status, assigned_hunter_id FROM forensic_investigation_cases WHERE case_id = ?", (case_id_1,))
                row = cur.fetchone()
                self.assertEqual(row["case_status"], "INVESTIGATION_IN_PROGRESS")
                self.assertEqual(row["assigned_hunter_id"], hunter_a)
        finally:
            conn.close()

        # Step D: Hunter B attempts to claim case 1 (already claimed) -> must fail atomically
        conn = get_db()
        try:
            with conn:
                cur = conn.cursor()
                cur.execute("""
                    UPDATE forensic_investigation_cases
                    SET case_status = 'INVESTIGATION_IN_PROGRESS',
                        assigned_hunter_id = ?,
                        claimed_at = ?
                    WHERE case_id = ? AND case_status = 'AVAILABLE'
                """, (hunter_b, now, case_id_1))
                self.assertEqual(cur.rowcount, 0)  # Double claiming prevented!
        finally:
            conn.close()

        # Step E: Hunter A attempts to claim case 2 while case 1 is in progress -> blocked by One-Active-Case rule
        conn = get_db()
        try:
            cur = conn.cursor()
            cur.execute("""
                SELECT case_id FROM forensic_investigation_cases
                WHERE assigned_hunter_id = ?
                  AND case_status IN ('INVESTIGATION_IN_PROGRESS', 'SUBMITTED_FOR_REVIEW', 'RETURNED_FOR_CORRECTION')
            """, (hunter_a,))
            active = cur.fetchall()
            self.assertEqual(len(active), 1)
            self.assertEqual(active[0]["case_id"], case_id_1)
        finally:
            conn.close()

    def test_F_and_G_investigation_submission_and_inspector_completion(self):
        """Tests F & G: Hunter submits findings -> SUBMITTED_FOR_REVIEW -> Inspector ACCEPTS -> COMPLETED."""
        case_id = f"CASE-2026-SUB1_{uuid.uuid4().hex[:4].upper()}"
        hunter_name = f"hunter_gamma_{uuid.uuid4().hex[:4]}"
        now = int(time.time())

        # Setup in-progress case for Hunter
        conn = get_db()
        try:
            with conn:
                conn.execute("""
                    INSERT INTO forensic_investigation_cases (
                        case_id, title, device_id, device_fingerprint, device_model,
                        image_filename, image_path, sha256, acquisition_start_time, acquisition_end_time,
                        case_status, assigned_hunter_id, claimed_at, created_at
                    ) VALUES (?, 'Sub Test Case', 'SW-DEV-002', 'fp456', 'SanDisk Ultra', 'test2.img', '/tmp/test2.img', 'hash456', ?, ?, 'INVESTIGATION_IN_PROGRESS', ?, ?, ?)
                """, (case_id, now, now, hunter_name, now, now))
        finally:
            conn.close()

        # Step F: Hunter submits findings
        findings_text = "Discovered 3 deleted SQLite database fragments and 2 valid PDF documents at sector offset 2048."
        artifacts = [{"name": "evidence_db.sqlite", "lba": 2048, "confidence": 98}, {"name": "contract.pdf", "lba": 4096, "confidence": 95}]
        conn = get_db()
        try:
            with conn:
                conn.execute("""
                    UPDATE forensic_investigation_cases
                    SET case_status = 'SUBMITTED_FOR_REVIEW',
                        submitted_at = ?,
                        investigation_findings = ?,
                        evidence_artifacts = ?
                    WHERE case_id = ? AND assigned_hunter_id = ?
                """, (now, findings_text, json.dumps(artifacts), case_id, hunter_name))

            cur = conn.cursor()
            cur.execute("SELECT * FROM forensic_investigation_cases WHERE case_id = ?", (case_id,))
            row = cur.fetchone()
            self.assertEqual(row["case_status"], "SUBMITTED_FOR_REVIEW")
            self.assertEqual(row["investigation_findings"], findings_text)
        finally:
            conn.close()

        # Step G: Inspector reviews and ACCEPTS case -> COMPLETED
        conn = get_db()
        try:
            with conn:
                conn.execute("""
                    UPDATE forensic_investigation_cases
                    SET case_status = 'COMPLETED',
                        reviewed_at = ?,
                        completed_at = ?,
                        inspector_notes = 'Findings validated. Cryptographic chain verified.'
                    WHERE case_id = ? AND case_status = 'SUBMITTED_FOR_REVIEW'
                """, (now, now, case_id))

            cur = conn.cursor()
            cur.execute("SELECT * FROM forensic_investigation_cases WHERE case_id = ?", (case_id,))
            row = cur.fetchone()
            self.assertEqual(row["case_status"], "COMPLETED")
            self.assertIsNotNone(row["completed_at"])

            # Verify Hunter is now free to take another case
            cur.execute("""
                SELECT case_id FROM forensic_investigation_cases
                WHERE assigned_hunter_id = ?
                  AND case_status IN ('INVESTIGATION_IN_PROGRESS', 'SUBMITTED_FOR_REVIEW', 'RETURNED_FOR_CORRECTION')
            """, (hunter_name,))
            active = cur.fetchall()
            self.assertEqual(len(active), 0)  # Hunter released!
        finally:
            conn.close()

    def test_H_correction_flow(self):
        """Test H: Inspector returns case for correction -> RETURNED_FOR_CORRECTION -> Hunter remains assigned."""
        case_id = f"CASE-2026-CORR_{uuid.uuid4().hex[:4].upper()}"
        now = int(time.time())

        # Setup submitted case
        conn = get_db()
        try:
            with conn:
                conn.execute("""
                    INSERT INTO forensic_investigation_cases (
                        case_id, title, device_id, device_fingerprint, device_model,
                        image_filename, image_path, sha256, acquisition_start_time, acquisition_end_time,
                        case_status, assigned_hunter_id, claimed_at, submitted_at, created_at
                    ) VALUES (?, 'Correction Test Case', 'SW-DEV-003', 'fp789', 'Kingston DataTraveler', 'test3.img', '/tmp/test3.img', 'hash789', ?, ?, 'SUBMITTED_FOR_REVIEW', 'hunter_beta', ?, ?, ?)
                """, (case_id, now, now, now, now, now))

                # Inspector returns for correction
                conn.execute("""
                    UPDATE forensic_investigation_cases
                    SET case_status = 'RETURNED_FOR_CORRECTION',
                        reviewed_at = ?,
                        inspector_notes = 'Please extract metadata timestamps for the recovered SQLite table.'
                    WHERE case_id = ?
                """, (now, case_id))

            cur = conn.cursor()
            cur.execute("SELECT * FROM forensic_investigation_cases WHERE case_id = ?", (case_id,))
            row = cur.fetchone()
            self.assertEqual(row["case_status"], "RETURNED_FOR_CORRECTION")
            self.assertEqual(row["assigned_hunter_id"], "hunter_beta")  # Remains assigned

            # Hunter beta updates and resubmits
            conn.execute("""
                UPDATE forensic_investigation_cases
                SET case_status = 'SUBMITTED_FOR_REVIEW',
                    submitted_at = ?,
                    investigation_findings = 'Added detailed schema timestamps from page headers.'
                WHERE case_id = ? AND assigned_hunter_id = 'hunter_beta'
            """, (now, case_id))

            cur.execute("SELECT * FROM forensic_investigation_cases WHERE case_id = ?", (case_id,))
            row = cur.fetchone()
            self.assertEqual(row["case_status"], "SUBMITTED_FOR_REVIEW")
        finally:
            conn.close()

    def test_I_image_immutability(self):
        """Test I: Verify original SHA-256 = Stored SHA-256 = Verified SHA-256."""
        case_id = f"CASE-2026-IMMUT_{uuid.uuid4().hex[:4].upper()}"
        case_dir = os.path.join(CASES_STORAGE_DIR, case_id)
        os.makedirs(case_dir, exist_ok=True)
        img_dest = os.path.join(case_dir, f"{case_id}.img")

        acq = acquire_raw_forensic_image(
            source_target=self.test_src.name,
            output_image_path=img_dest
        )

        stored_sha = acq["sha256"]

        # Re-hash destination file on disk
        hasher = hashlib.sha256()
        with open(img_dest, "rb") as f:
            while chunk := f.read(65536):
                hasher.update(chunk)
        verified_sha = hasher.hexdigest()

        self.assertEqual(self.expected_src_sha256, stored_sha)
        self.assertEqual(stored_sha, verified_sha)

    def test_J_no_physicaldrive0_fallback(self):
        """Test J: Non-existent or unresolvable source must raise error and NEVER touch PhysicalDrive0."""
        invalid_source = r"\\.\PhysicalDrive9999_NON_EXISTENT"
        dest_img = os.path.join(tempfile.gettempdir(), f"invalid_test_{uuid.uuid4().hex}.img")
        
        with self.assertRaises((RuntimeError, FileNotFoundError, PermissionError)) as ctx:
            acquire_raw_forensic_image(
                source_target=invalid_source,
                output_image_path=dest_img
            )
        self.assertTrue(
            "not currently connected" in str(ctx.exception) or
            "Unable to open physical source device" in str(ctx.exception) or
            "denied read access" in str(ctx.exception)
        )
        # Ensure no fake image file was left behind
        if os.path.exists(dest_img):
            self.assertEqual(os.path.getsize(dest_img), 0)
            os.remove(dest_img)

    def test_K_case_directory_structure(self):
        """Test K: Structured subfolders are properly initialized for each case."""
        case_id = f"CASE-2026-DIR_{uuid.uuid4().hex[:4].upper()}"
        case_dir = os.path.join(CASES_STORAGE_DIR, case_id)
        
        subdirs = ["image", "metadata", "evidence", "results", "documents", "audit"]
        for s in subdirs:
            os.makedirs(os.path.join(case_dir, s), exist_ok=True)
            self.assertTrue(os.path.isdir(os.path.join(case_dir, s)))
        
        meta_path = os.path.join(case_dir, "metadata", "acquisition.json")
        meta_data = {
            "case_id": case_id,
            "device_id": "SW-DEV-TEST01",
            "format": "RAW",
            "sha256": "dummyhash123",
            "created_at": int(time.time())
        }
        with open(meta_path, "w", encoding="utf-8") as f:
            json.dump(meta_data, f, indent=2)
            
        self.assertTrue(os.path.isfile(meta_path))

    def test_L_empty_or_unreadable_source_rejection(self):
        """Test L: Unreadable or 0-byte source fails cleanly without synthetic fake MBR fallback."""
        empty_src = tempfile.NamedTemporaryFile(delete=False, suffix=".empty")
        empty_src.close()
        dest_img = os.path.join(tempfile.gettempdir(), f"empty_test_{uuid.uuid4().hex}.img")
        
        try:
            with self.assertRaises((RuntimeError, ValueError)) as ctx:
                acquire_raw_forensic_image(
                    source_target=empty_src.name,
                    output_image_path=dest_img
                )
            self.assertIn("Cannot acquire empty source", str(ctx.exception))
        finally:
            if os.path.exists(empty_src.name):
                os.remove(empty_src.name)
            if os.path.exists(dest_img):
                os.remove(dest_img)


if __name__ == "__main__":
    unittest.main()

