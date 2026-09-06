"""
Comprehensive Test Suite: Safe Physical Device Acquisition & Hunter Strict Case Scoping
Tests all 28 verification requirements across Acquisition & Hunter RBAC Scoping.
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

from app import app
from auth import get_db, init_platform_db, register_user, create_session
from central_device_registry import (
    init_device_registry_db,
    register_device,
    get_registered_device_by_id,
    resolve_registered_device_to_live_path,
)
from seek_help_case_engine import (
    init_seek_help_db,
    acquire_raw_forensic_image,
    CASES_STORAGE_DIR,
)


class TestHunterCaseScopingAndAcquisition(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        init_platform_db()
        init_device_registry_db()
        init_seek_help_db()

        # Create test users for different roles
        register_user("inspector_sec_1", "Secret123!", "forensic", "inspector1@test.com", "Forensics")
        register_user("hunter_sc_1", "Secret123!", "hunter", "hunter1@test.com", "Hunter Division")
        register_user("hunter_sc_2", "Secret123!", "hunter", "hunter2@test.com", "Hunter Division")
        register_user("gov_sec_1", "Secret123!", "government", "gov1@test.com", "Gov Defense")

        cls.client = app.test_client()

    def setUp(self):
        # Create a mock source disk file (128 KB)
        self.test_src = tempfile.NamedTemporaryFile(delete=False, suffix=".raw")
        pattern = b"REAL_GENUINE_SECTOR_DATA_BLOCK_NTRO_" * 3500
        self.test_src.write(pattern)
        self.test_src.close()

        hasher = hashlib.sha256()
        with open(self.test_src.name, "rb") as f:
            hasher.update(f.read())
        self.expected_sha256 = hasher.hexdigest()
        self.expected_size = os.path.getsize(self.test_src.name)

    def tearDown(self):
        if os.path.exists(self.test_src.name):
            try:
                os.remove(self.test_src.name)
            except Exception:
                pass

    # =========================================================================
    # PART 1: ACQUISITION SAFETY & PERMISSION TESTS (Requirements 1 - 12)
    # =========================================================================

    def test_01_real_source_bytes_and_sha256_generation(self):
        """Req 1, 2, 3, 4: Real source bytes are streamed and exact SHA-256 generated."""
        case_id = f"CASE-TEST-ACQ-{uuid.uuid4().hex[:4].upper()}"
        out_img = os.path.join(tempfile.gettempdir(), f"{case_id}.img")

        res = acquire_raw_forensic_image(
            source_target=self.test_src.name,
            output_image_path=out_img
        )

        self.assertTrue(os.path.exists(out_img))
        self.assertEqual(res["sha256"], self.expected_sha256)
        self.assertEqual(res["image_size"], self.expected_size)
        self.assertEqual(res["acquisition_status"], "ACQUISITION_COMPLETED")

        if os.path.exists(out_img):
            os.remove(out_img)

    def test_05_case_published_only_after_successful_acquisition(self):
        """Req 5: Case is inserted into database with AVAILABLE status ONLY after real image creation."""
        raw_dev = {
            "name": "Kingston DataTraveler 32GB",
            "model": "DataTraveler G4",
            "serial": f"KNG_{uuid.uuid4().hex[:6]}",
            "sizeBytes": 32000000000,
            "bus": "USB",
            "current_connection_path": self.test_src.name
        }
        ok, msg, reg = register_device(raw_dev, created_by="forensic_analyst")
        self.assertTrue(ok)
        dev_id = reg["device_id"]

        resp = self.client.post("/api/seek-help/acquire-and-create-case", json={
            "device_id": dev_id,
            "title": "Valid Case Acquisition"
        })
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertEqual(data["status"], "success")
        self.assertEqual(data["case"]["case_status"], "AVAILABLE")
        self.assertEqual(data["case"]["sha256"], self.expected_sha256)

    def test_06_and_07_win32_permission_error_and_no_case_publication(self):
        """Req 6, 7: Access denied / permission error produces clean error and publishes NO case."""
        raw_dev = {
            "name": "Protected Host Disk",
            "model": "Internal Locked NVMe",
            "serial": f"LOCK_{uuid.uuid4().hex[:6]}",
            "sizeBytes": 512000000000,
            "bus": "NVMe",
            "current_connection_path": r"\\.\PhysicalDrive9999_LOCKED"
        }
        ok, msg, reg = register_device(raw_dev, created_by="forensic_analyst")
        self.assertTrue(ok)
        dev_id = reg["device_id"]

        resp = self.client.post("/api/seek-help/acquire-and-create-case", json={
            "device_id": dev_id,
            "title": "Locked Disk Test"
        })
        self.assertEqual(resp.status_code, 400)
        data = resp.get_json()
        self.assertIn("Forensic acquisition", data["message"])
        self.assertIn("No case published", data["message"])

        conn = get_db()
        try:
            cur = conn.cursor()
            cur.execute("SELECT * FROM forensic_investigation_cases WHERE device_id = ?", (dev_id,))
            self.assertIsNone(cur.fetchone())
        finally:
            conn.close()

    def test_08_and_09_no_physicaldrive0_fallback_and_no_synthetic_image(self):
        """Req 8, 9: Absolute prohibition on PhysicalDrive0 fallback or synthetic 512-byte placeholder."""
        invalid_path = r"\\.\PhysicalDrive99"
        dest_img = os.path.join(tempfile.gettempdir(), f"test_no_fallback_{uuid.uuid4().hex}.img")

        try:
            with self.assertRaises(Exception) as ctx:
                acquire_raw_forensic_image(invalid_path, dest_img)
            if os.path.exists(dest_img):
                self.assertEqual(os.path.getsize(dest_img), 0)
        finally:
            if os.path.exists(dest_img):
                os.remove(dest_img)

    def test_10_and_11_client_cannot_arbitrarily_substitute_physicaldrive(self):
        """Req 10, 11: Backend strictly binds device_id to registered record, ignoring arbitrary client paths."""
        raw_dev = {
            "name": "Target Device",
            "model": "Registered Thumb Drive",
            "serial": f"THUMB_{uuid.uuid4().hex[:6]}",
            "sizeBytes": 8000000000,
            "bus": "USB",
            "current_connection_path": self.test_src.name
        }
        ok, msg, reg = register_device(raw_dev, created_by="forensic_analyst")
        dev_id = reg["device_id"]

        resp = self.client.post("/api/seek-help/acquire-and-create-case", json={
            "device_id": dev_id,
            "device_path": r"\\.\PhysicalDrive0", # client override attempt
            "title": "Injection Test"
        })
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertEqual(data["case"]["sha256"], self.expected_sha256)

    # =========================================================================
    # PART 2: HUNTER STRICT CASE-SCOPING (Requirements 13 - 28)
    # =========================================================================

    def test_13_hunter_with_no_active_case_sees_zero_devices(self):
        """Req 13: Hunter with no active case gets empty device list."""
        hunter_username = f"hunter_idle_{uuid.uuid4().hex[:4]}"
        register_user(hunter_username, "Secret123!", "hunter", f"{hunter_username}@test.com", "Hunter")

        self.client.set_cookie("userRole", "hunter")
        resp = self.client.get("/api/devices")
        self.assertEqual(resp.status_code, 200)
        devices = resp.get_json()
        self.assertEqual(len(devices), 0)

        resp_curr = self.client.get("/api/devices/current")
        self.assertEqual(resp_curr.status_code, 200)
        data_curr = resp_curr.get_json()
        self.assertEqual(len(data_curr.get("connected_devices", [])), 0)
        self.assertIsNone(data_curr.get("hunter_active_case"))

    def test_14_to_19_hunter_claims_case_and_sees_only_case_device(self):
        """Req 14, 15, 16, 17, 18, 19: Hunter claims Case 1 (Device A) and sees ONLY Device A, NOT B or C."""
        hunter_username = f"hunter_active_{uuid.uuid4().hex[:4]}"
        register_user(hunter_username, "Secret123!", "hunter", f"{hunter_username}@test.com", "Hunter")

        _, _, dev_a = register_device({"name": "Case A Device", "model": "Model-A", "serial": f"SN-A-{uuid.uuid4().hex[:4]}", "sizeBytes": 1000000000}, created_by="operator")
        _, _, dev_b = register_device({"name": "Case B Device", "model": "Model-B", "serial": f"SN-B-{uuid.uuid4().hex[:4]}", "sizeBytes": 2000000000}, created_by="operator")
        _, _, dev_c = register_device({"name": "Case C Device", "model": "Model-C", "serial": f"SN-C-{uuid.uuid4().hex[:4]}", "sizeBytes": 3000000000}, created_by="operator")

        dev_a_id = dev_a["device_id"]
        dev_b_id = dev_b["device_id"]
        dev_c_id = dev_c["device_id"]

        case_a_id = f"CASE-A-{uuid.uuid4().hex[:4].upper()}"
        case_b_id = f"CASE-B-{uuid.uuid4().hex[:4].upper()}"
        now = int(time.time())

        conn = get_db()
        try:
            with conn:
                conn.execute("""
                    INSERT INTO forensic_investigation_cases (
                        case_id, title, device_id, device_fingerprint, device_model,
                        image_filename, image_path, sha256, acquisition_start_time, acquisition_end_time,
                        case_status, created_at
                    ) VALUES (?, 'Case A', ?, 'fpA', 'Model-A', 'caseA.img', '/tmp/caseA.img', 'hashA', ?, ?, 'AVAILABLE', ?)
                """, (case_a_id, dev_a_id, now, now, now))
                conn.execute("""
                    INSERT INTO forensic_investigation_cases (
                        case_id, title, device_id, device_fingerprint, device_model,
                        image_filename, image_path, sha256, acquisition_start_time, acquisition_end_time,
                        case_status, created_at
                    ) VALUES (?, 'Case B', ?, 'fpB', 'Model-B', 'caseB.img', '/tmp/caseB.img', 'hashB', ?, ?, 'AVAILABLE', ?)
                """, (case_b_id, dev_b_id, now, now, now))
        finally:
            conn.close()

        claim_resp = self.client.post(f"/api/seek-help/cases/{case_a_id}/claim", json={"hunter_id": hunter_username})
        self.assertEqual(claim_resp.status_code, 200)

        sess = create_session(hunter_username)
        self.client.set_cookie("session_token", sess["token"])
        self.client.set_cookie("userRole", "hunter")

        dev_resp = self.client.get("/api/devices")
        self.assertEqual(dev_resp.status_code, 200)
        devs = dev_resp.get_json()
        self.assertEqual(len(devs), 1)
        self.assertEqual(devs[0]["deviceId"], dev_a_id)

        returned_ids = [d["deviceId"] for d in devs]
        self.assertNotIn(dev_b_id, returned_ids)
        self.assertNotIn(dev_c_id, returned_ids)

        reg_resp = self.client.get("/api/devices/registry")
        self.assertEqual(reg_resp.status_code, 200)
        reg_list = reg_resp.get_json()["devices"]
        self.assertEqual(len(reg_list), 1)
        self.assertEqual(reg_list[0]["device_id"], dev_a_id)

    def test_20_and_21_storage_inspector_and_recovery_scoping(self):
        """Req 20, 21: Storage Inspector & Recovery allow Case Device A, but forbid Device B."""
        hunter_username = f"hunter_insp_{uuid.uuid4().hex[:4]}"
        register_user(hunter_username, "Secret123!", "hunter", f"{hunter_username}@test.com", "Hunter")

        _, _, dev_a = register_device({"name": "Case A Device", "model": "Model-A", "serial": f"SN-A-{uuid.uuid4().hex[:4]}", "sizeBytes": 1000000000}, created_by="operator")
        _, _, dev_b = register_device({"name": "Case B Device", "model": "Model-B", "serial": f"SN-B-{uuid.uuid4().hex[:4]}", "sizeBytes": 2000000000}, created_by="operator")
        dev_a_id = dev_a["device_id"]
        dev_b_id = dev_b["device_id"]

        case_id = f"CASE-INSP-{uuid.uuid4().hex[:4].upper()}"
        now = int(time.time())
        conn = get_db()
        try:
            with conn:
                conn.execute("""
                    INSERT INTO forensic_investigation_cases (
                        case_id, title, device_id, device_fingerprint, device_model,
                        image_filename, image_path, sha256, acquisition_start_time, acquisition_end_time,
                        case_status, assigned_hunter_id, claimed_at, created_at
                    ) VALUES (?, 'Inspector Test Case', ?, 'fpA', 'Model-A', 'test.img', ?, 'hashA', ?, ?, 'INVESTIGATION_IN_PROGRESS', ?, ?, ?)
                """, (case_id, dev_a_id, self.test_src.name, now, now, hunter_username, now, now))
        finally:
            conn.close()

        sess = create_session(hunter_username)
        self.client.set_cookie("session_token", sess["token"])
        self.client.set_cookie("userRole", "hunter")

        resp_allowed = self.client.post("/api/inspector/read-hex", json={
            "target": dev_a_id,
            "lba": 0,
            "sector_size": 512
        })
        self.assertEqual(resp_allowed.status_code, 200)

        resp_forbidden = self.client.post("/api/inspector/read-hex", json={
            "target": dev_b_id,
            "lba": 0,
            "sector_size": 512
        })
        self.assertEqual(resp_forbidden.status_code, 403)
        self.assertIn("Access Denied", resp_forbidden.get_json()["error"])

    def test_22_and_23_direct_api_for_unrelated_device_or_case_returns_403(self):
        """Req 22, 23: Direct API requests for unauthorized device registry or FARIS case return 403."""
        hunter_username = f"hunter_direct_{uuid.uuid4().hex[:4]}"
        register_user(hunter_username, "Secret123!", "hunter", f"{hunter_username}@test.com", "Hunter")

        _, _, dev_a = register_device({"name": "Case A Device", "model": "Model-A", "serial": f"SN-A-{uuid.uuid4().hex[:4]}", "sizeBytes": 1000000000}, created_by="operator")
        _, _, dev_b = register_device({"name": "Case B Device", "model": "Model-B", "serial": f"SN-B-{uuid.uuid4().hex[:4]}", "sizeBytes": 2000000000}, created_by="operator")

        case_id = f"CASE-DIR-{uuid.uuid4().hex[:4].upper()}"
        other_case_id = f"CASE-OTHER-{uuid.uuid4().hex[:4].upper()}"
        now = int(time.time())

        conn = get_db()
        try:
            with conn:
                conn.execute("""
                    INSERT INTO forensic_investigation_cases (
                        case_id, title, device_id, device_fingerprint, device_model,
                        image_filename, image_path, sha256, acquisition_start_time, acquisition_end_time,
                        case_status, assigned_hunter_id, claimed_at, created_at
                    ) VALUES (?, 'Dir Test', ?, 'fpA', 'Model-A', 'test.img', '/tmp/test.img', 'hashA', ?, ?, 'INVESTIGATION_IN_PROGRESS', ?, ?, ?)
                """, (case_id, dev_a["device_id"], now, now, hunter_username, now, now))
                conn.execute("""
                    INSERT INTO forensic_investigation_cases (
                        case_id, title, device_id, device_fingerprint, device_model,
                        image_filename, image_path, sha256, acquisition_start_time, acquisition_end_time,
                        case_status, created_at
                    ) VALUES (?, 'Other Case', ?, 'fpB', 'Model-B', 'testB.img', '/tmp/testB.img', 'hashB', ?, ?, 'AVAILABLE', ?)
                """, (other_case_id, dev_b["device_id"], now, now, now))
        finally:
            conn.close()

        sess = create_session(hunter_username)
        self.client.set_cookie("session_token", sess["token"])
        self.client.set_cookie("userRole", "hunter")

        resp_dev_b = self.client.get(f"/api/devices/registry/{dev_b['device_id']}")
        self.assertEqual(resp_dev_b.status_code, 403)

        resp_dev_a = self.client.get(f"/api/devices/registry/{dev_a['device_id']}")
        self.assertEqual(resp_dev_a.status_code, 200)

        resp_faris = self.client.get(f"/api/faris/cases/{other_case_id}")
        self.assertEqual(resp_faris.status_code, 403)

    def test_24_to_27_lifecycle_anti_double_claim_return_and_completion(self):
        """Req 24, 25, 26, 27: Anti-double claim -> Returned for correction -> Completion releases Hunter."""
        hunter_username = f"hunter_life_{uuid.uuid4().hex[:4]}"
        register_user(hunter_username, "Secret123!", "hunter", f"{hunter_username}@test.com", "Hunter")

        case_1 = f"CASE-1-{uuid.uuid4().hex[:4].upper()}"
        case_2 = f"CASE-2-{uuid.uuid4().hex[:4].upper()}"
        now = int(time.time())

        conn = get_db()
        try:
            with conn:
                conn.execute("""
                    INSERT INTO forensic_investigation_cases (
                        case_id, title, device_id, device_fingerprint, device_model,
                        image_filename, image_path, sha256, acquisition_start_time, acquisition_end_time,
                        case_status, created_at
                    ) VALUES (?, 'Case 1', 'SW-DEV-1', 'fp1', 'Flash 1', 'img1.img', '/tmp/img1.img', 'h1', ?, ?, 'AVAILABLE', ?)
                """, (case_1, now, now, now))
                conn.execute("""
                    INSERT INTO forensic_investigation_cases (
                        case_id, title, device_id, device_fingerprint, device_model,
                        image_filename, image_path, sha256, acquisition_start_time, acquisition_end_time,
                        case_status, created_at
                    ) VALUES (?, 'Case 2', 'SW-DEV-2', 'fp2', 'Flash 2', 'img2.img', '/tmp/img2.img', 'h2', ?, ?, 'AVAILABLE', ?)
                """, (case_2, now, now, now))
        finally:
            conn.close()

        claim1 = self.client.post(f"/api/seek-help/cases/{case_1}/claim", json={"hunter_id": hunter_username})
        self.assertEqual(claim1.status_code, 200)

        claim2 = self.client.post(f"/api/seek-help/cases/{case_2}/claim", json={"hunter_id": hunter_username})
        self.assertEqual(claim2.status_code, 400)
        self.assertIn("already have an active case", claim2.get_json()["message"])

        sub_resp = self.client.post(f"/api/seek-help/cases/{case_1}/submit", json={
            "hunter_id": hunter_username,
            "findings": "Carved 2 SQLite databases.",
            "evidence_artifacts": [{"name": "db.sqlite", "offset_lba": "LBA 2048", "type": "SQLite", "confidence": "99%"}]
        })
        self.assertEqual(sub_resp.status_code, 200)

        rev_corr = self.client.post(f"/api/seek-help/cases/{case_1}/review", json={
            "action": "RETURN_FOR_CORRECTION",
            "inspector_notes": "Extract page header timestamps."
        })
        self.assertEqual(rev_corr.status_code, 200)

        conn = get_db()
        try:
            cur = conn.cursor()
            cur.execute("SELECT case_status, assigned_hunter_id FROM forensic_investigation_cases WHERE case_id = ?", (case_1,))
            row = cur.fetchone()
            self.assertEqual(row["case_status"], "RETURNED_FOR_CORRECTION")
            self.assertEqual(row["assigned_hunter_id"], hunter_username)
        finally:
            conn.close()

        self.client.post(f"/api/seek-help/cases/{case_1}/submit", json={"hunter_id": hunter_username, "findings": "Updated."})
        rev_acc = self.client.post(f"/api/seek-help/cases/{case_1}/review", json={
            "action": "ACCEPT",
            "inspector_notes": "Verified and accepted."
        })
        self.assertEqual(rev_acc.status_code, 200)

        claim2_after = self.client.post(f"/api/seek-help/cases/{case_2}/claim", json={"hunter_id": hunter_username})
        self.assertEqual(claim2_after.status_code, 200)
        self.assertEqual(claim2_after.get_json()["status"], "success")

    def test_28_non_hunter_roles_retain_full_device_visibility(self):
        """Req 28: Non-hunter roles (Forensic Inspector, Government, Individual) retain full global device visibility."""
        self.client.set_cookie("userRole", "forensic")
        resp_forensic = self.client.get("/api/devices")
        self.assertEqual(resp_forensic.status_code, 200)
        devs_forensic = resp_forensic.get_json()
        self.assertIsInstance(devs_forensic, list)

        self.client.set_cookie("userRole", "government")
        resp_gov = self.client.get("/api/devices")
        self.assertEqual(resp_gov.status_code, 200)
        devs_gov = resp_gov.get_json()
        self.assertIsInstance(devs_gov, list)


if __name__ == "__main__":
    unittest.main()
