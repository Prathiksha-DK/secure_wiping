#!/usr/bin/env python3
"""
Test Suite for FARIS REST Integration Service (faris_service.py)
Validates endpoints, case creation, dynamic pipeline telemetry, and artifact export via FARISAPI.
"""

import os
import sys
import json
import time
import unittest
import tempfile
from pathlib import Path

# Add FARIS root and application directories to sys.path
FARIS_ROOT = Path(__file__).resolve().parent.parent
TEST_CASES_DIR = FARIS_ROOT / "tests" / "test_cases"
TEST_CASES_DIR.mkdir(parents=True, exist_ok=True)
os.environ["FARIS_CASES_DIR"] = str(TEST_CASES_DIR)

sys.path.insert(0, str(FARIS_ROOT))
sys.path.insert(0, str(FARIS_ROOT / "application"))

from application.faris_service import app
from application.faris_api import faris_api


class TestFARISServiceIntegration(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        os.environ["FARIS_CASES_DIR"] = str(TEST_CASES_DIR)
        TEST_CASES_DIR.mkdir(parents=True, exist_ok=True)

    def setUp(self):
        self.app = app
        self.client = self.app.test_client()
        self.test_case_id = f"test_svc_{int(time.time())}"

    def test_01_health_and_engine_status(self):
        """Test health check and engine inventory endpoints."""
        res = self.client.get("/api/faris/health")
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertEqual(data["status"], "SUCCESS")
        self.assertEqual(data["port"], 8760)

        res_eng = self.client.get("/api/faris/engine-status")
        self.assertEqual(res_eng.status_code, 200)
        eng_data = res_eng.get_json()
        self.assertEqual(eng_data["status"], "SUCCESS")
        self.assertIn("engines", eng_data)
        self.assertIn("sleuthkit", eng_data["engines"])

    def test_02_device_discovery(self):
        """Test physical storage discovery endpoint."""
        res = self.client.get("/api/faris/devices")
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertEqual(data["status"], "SUCCESS")
        self.assertIn("physical_devices", data)

    def test_03_case_creation_and_listing(self):
        """Test creating a case and listing cases."""
        payload = {
            "case_id": self.test_case_id,
            "case_name": "Automated Unit Test Case",
            "operator": "Service Tester"
        }
        res = self.client.post("/api/faris/cases/create", json=payload)
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertEqual(data["status"], "SUCCESS")
        self.assertEqual(data["case_id"], self.test_case_id)

        # List cases
        res_list = self.client.get("/api/faris/cases")
        self.assertEqual(res_list.status_code, 200)
        list_data = res_list.get_json()
        self.assertTrue(any(c["case_id"] == self.test_case_id for c in list_data["cases"]))

        # Get case details
        res_detail = self.client.get(f"/api/faris/cases/{self.test_case_id}")
        self.assertEqual(res_detail.status_code, 200)
        detail_data = res_detail.get_json()
        self.assertEqual(detail_data["status"], "SUCCESS")
        self.assertEqual(detail_data["case"]["case_id"], self.test_case_id)

    def test_04_pipeline_execution_and_status(self):
        """Test launching the full FARIS pipeline on controlled test evidence."""
        with tempfile.TemporaryDirectory() as tmpdir:
            test_img = Path(tmpdir) / "test_svc_evidence.raw"
            # Create a 2MB raw test image containing recognizable magic signatures
            with open(test_img, "wb") as f:
                f.write(b"\x00" * 1024)
                # Embedded PNG signature and dummy chunk
                f.write(b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x10\x00\x00\x00\x10\x08\x06\x00\x00\x00")
                f.write(b"\x00" * 4096)
                f.write(b"\x00\x00\x00\x00IEND\xaeB`\x82")
                # Embedded JPEG signature
                f.write(b"\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01\x01\x00`\x00`\x00\x00")
                f.write(b"\x00" * 2048)
                f.write(b"\xff\xd9")
                # Pad to 1MB
                remaining = 1024 * 1024 - f.tell()
                if remaining > 0:
                    f.write(b"\x00" * remaining)

            pipe_case_id = f"test_pipe_{int(time.time())}"
            start_payload = {
                "case_id": pipe_case_id,
                "examiner": "Automated Tester",
                "source_path": str(test_img),
                "is_physical": False,
                "source_type": "Raw Disk Image",
                "description": "Integration Test Raw Image"
            }

            res = self.client.post("/api/faris/pipeline/start", json=start_payload)
            self.assertEqual(res.status_code, 200)
            data = res.get_json()
            self.assertEqual(data["status"], "SUCCESS")
            job_id = data["job_id"]

            # Poll status until done or timeout (max 40s)
            start_wait = time.time()
            done = False
            final_job = {}
            while time.time() - start_wait < 40:
                time.sleep(1)
                st_res = self.client.get(f"/api/faris/pipeline/status/{job_id}")
                self.assertEqual(st_res.status_code, 200)
                final_job = st_res.get_json()
                if final_job["status"] in ["SUCCESS", "FAILED"]:
                    done = True
                    break

            self.assertTrue(done, "Pipeline did not complete in time")
            self.assertEqual(final_job["status"], "SUCCESS")
            self.assertGreaterEqual(final_job["progress_pct"], 98.0)
            self.assertTrue(len(final_job["logs"]) > 5)

            # Test report endpoint
            rep_res = self.client.get(f"/api/faris/report/{pipe_case_id}/json")
            self.assertEqual(rep_res.status_code, 200)
            rep_data = rep_res.get_json()
            self.assertEqual(rep_data["case_metadata"]["case_id"], pipe_case_id)

            # Test audit trail endpoint
            audit_res = self.client.get(f"/api/faris/audit/{pipe_case_id}")
            self.assertEqual(audit_res.status_code, 200)
            audit_data = audit_res.get_json()
            self.assertTrue(len(audit_data["entries"]) > 0)


if __name__ == "__main__":
    unittest.main()
