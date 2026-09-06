"""
Automated Test Suite for Hunter Registration + Forensic Approval + ISO Inspection Workflow.
Tests:
1. Seed accounts validation (approved, pending, rejected).
2. Hunter registration creates status PENDING_FORENSIC_APPROVAL.
3. Pending hunter login blocked with specific notification message.
4. Forensic investigator notification shows pending count.
5. Forensic investigator reviews and APPROVES candidate.
6. Newly approved hunter logs in successfully and receives hunter session.
7. Rejected candidate login blocked with specific rejection reason.
8. Hunter ISO retrieval returns available ISO images with full authorized metadata.
9. Forensic Investigator publishes new ISO image and it becomes available to Hunters.
"""

import os
import sys
import json
import unittest

sys.path.insert(0, os.path.dirname(__file__))

from app import app
from auth import init_platform_db, authenticate_user, get_db

class TestHunterWorkflow(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        init_platform_db()
        cls.client = app.test_client()
        conn = get_db()
        try:
            with conn:
                conn.execute("DELETE FROM hunter_applications WHERE username IN ('cadet_hunter_99', 'unverified_candidate_77', 'rejected_applicant_88')")
                conn.execute("DELETE FROM users WHERE username IN ('cadet_hunter_99', 'unverified_candidate_77', 'rejected_applicant_88')")
                conn.execute("UPDATE users SET status = 'PENDING_FORENSIC_APPROVAL' WHERE username = 'pending_hunter'")
                conn.execute("UPDATE hunter_applications SET status = 'PENDING_FORENSIC_APPROVAL' WHERE username = 'pending_hunter'")
                conn.execute("UPDATE users SET status = 'REJECTED' WHERE username = 'rejected_hunter'")
                conn.execute("UPDATE hunter_applications SET status = 'REJECTED' WHERE username = 'rejected_hunter'")
        finally:
            conn.close()

    def test_01_seed_accounts_authentication_rules(self):
        """Test pre-seeded demo accounts for all 3 states."""
        # Approved hunter can log in
        ok, msg, sess = authenticate_user("hunter_agent", "Hunter@2026")
        self.assertTrue(ok)
        self.assertEqual(sess["role"], "hunter")

        # Pending hunter blocked with required message
        ok, msg, sess = authenticate_user("pending_hunter", "Hunter@2026")
        self.assertFalse(ok)
        self.assertIn("Your registration is awaiting approval from a Forensic Investigator.", msg)

        # Rejected hunter blocked with rejection reason
        ok, msg, sess = authenticate_user("rejected_hunter", "Hunter@2026")
        self.assertFalse(ok)
        self.assertIn("Registration rejected:", msg)
        self.assertIn("expired", msg.lower())

    def test_02_new_hunter_registration(self):
        """Register a brand new hunter via /api/hunter/register."""
        uname = "cadet_hunter_99"
        payload = {
            "name": "Arjun Sharma",
            "email": "arjun.sharma@cyberdefense.in",
            "mobile": "+91-9876501234",
            "aadhaar": "9988-7766-5544",
            "pan": "BKPPS1290Q",
            "cert_name": "Certified Ethical Hacker (CEH v12)",
            "cert_id": "ECC-CEH-88392",
            "issuing_org": "EC-Council",
            "cert_expiry": "2027-11-30",
            "professional_details": "Digital forensics triage specialist with memory analysis experience.",
            "username": uname,
            "password": "SecurePassword@2026",
            "confirm_password": "SecurePassword@2026"
        }

        res = self.client.post("/api/hunter/register", json=payload)
        self.assertEqual(res.status_code, 201)
        data = res.get_json()
        self.assertEqual(data["status"], "success")
        self.assertEqual(data["account_status"], "PENDING_FORENSIC_APPROVAL")
        self.assertTrue(data["application_id"].startswith("HUNT-REQ-"))

        # Verify login immediately blocked
        login_res = self.client.post("/api/auth/login", json={
            "username": uname,
            "password": "SecurePassword@2026"
        })
        self.assertEqual(login_res.status_code, 401)
        login_data = login_res.get_json()
        self.assertIn("Your registration is awaiting approval from a Forensic Investigator.", login_data["message"])

    def test_03_forensic_notifications_and_requests_list(self):
        """Forensic Investigator checks notifications and pending requests."""
        notif_res = self.client.get("/api/forensics/notifications")
        self.assertEqual(notif_res.status_code, 200)
        notif_data = notif_res.get_json()
        self.assertGreaterEqual(notif_data["pending_hunter_count"], 1)
        self.assertEqual(notif_data["notification"], "New Hunter registration requires approval.")

        # Query requests list
        req_res = self.client.get("/api/forensics/hunter-requests")
        self.assertEqual(req_res.status_code, 200)
        req_data = req_res.get_json()
        requests = req_data["requests"]
        self.assertTrue(any(r["username"] == "cadet_hunter_99" for r in requests))

        # Find request ID for cadet_hunter_99
        target_req = next(r for r in requests if r["username"] == "cadet_hunter_99")
        self.assertEqual(target_req["status"], "PENDING_FORENSIC_APPROVAL")
        self.assertTrue(target_req["aadhaar_masked"].startswith("XXXX-XXXX-"))

    def test_04_forensic_investigator_approval(self):
        """Forensic Investigator approves cadet_hunter_99."""
        req_res = self.client.get("/api/forensics/hunter-requests")
        requests = req_res.get_json()["requests"]
        target_req = next(r for r in requests if r["username"] == "cadet_hunter_99")

        rev_res = self.client.post(f"/api/forensics/hunter-requests/{target_req['id']}/review", json={
            "decision": "APPROVE",
            "investigator": "forensic_analyst"
        })
        self.assertEqual(rev_res.status_code, 200)
        rev_data = rev_res.get_json()
        self.assertEqual(rev_data["status_code"], "APPROVED")

        # Now login should succeed!
        login_res = self.client.post("/api/auth/login", json={
            "username": "cadet_hunter_99",
            "password": "SecurePassword@2026"
        })
        self.assertEqual(login_res.status_code, 200)
        login_data = login_res.get_json()
        self.assertEqual(login_data["session"]["role"], "hunter")

    def test_05_rejection_workflow_and_reason_display(self):
        """Register candidate, reject with specific reason, verify login error."""
        uname = "rejected_applicant_88"
        payload = {
            "name": "Devendra Joshi",
            "email": "devendra.j@unknown.net",
            "mobile": "+91-9111223344",
            "aadhaar": "1234-5678-9012",
            "pan": "ZZZPJ9988X",
            "cert_name": "Basic Computer Certificate",
            "cert_id": "CERT-UNKNOWN",
            "issuing_org": "Unaccredited Institution",
            "cert_expiry": "2020-01-01",
            "professional_details": "No prior forensic experience.",
            "username": uname,
            "password": "CandidatePass@2026",
            "confirm_password": "CandidatePass@2026"
        }
        reg_res = self.client.post("/api/hunter/register", json=payload)
        self.assertEqual(reg_res.status_code, 201)
        app_id = reg_res.get_json()["application_id"]

        # Reject with specific reason
        rej_reason = "Certification credential could not be verified against the National Cyber Security Accreditation Registry."
        rev_res = self.client.post(f"/api/forensics/hunter-requests/{app_id}/review", json={
            "decision": "REJECT",
            "rejection_reason": rej_reason,
            "investigator": "forensic_analyst"
        })
        self.assertEqual(rev_res.status_code, 200)

        # Login must fail and display reason
        login_res = self.client.post("/api/auth/login", json={
            "username": uname,
            "password": "CandidatePass@2026"
        })
        self.assertEqual(login_res.status_code, 401)
        msg = login_res.get_json()["message"]
        self.assertIn("Registration rejected:", msg)
        self.assertIn("National Cyber Security Accreditation Registry", msg)

    def test_06_iso_images_management_and_hunter_view(self):
        """Forensic Investigator publishes new ISO image and Hunter accesses it."""
        # 1. Forensic publish
        pub_res = self.client.post("/api/forensics/iso-images", json={
            "image_name": "EVIDENCE-SUSPECT-LAPTOP-M2-NVME.iso",
            "case_ref_id": "NTRO-CR-2026-7788",
            "description": "Physical disk clone of suspect workstation containing encrypted container remnants.",
            "file_size_human": "5.6 GB",
            "file_size_bytes": 6012954214
        })
        self.assertEqual(pub_res.status_code, 201)

        # 2. Hunter retrieves available ISOs
        hunter_iso_res = self.client.get("/api/hunter/iso-images")
        self.assertEqual(hunter_iso_res.status_code, 200)
        data = hunter_iso_res.get_json()
        self.assertGreaterEqual(data["count"], 1)
        isos = data["iso_images"]

        # Check required fields
        sample = next(i for i in isos if i["case_ref_id"] == "NTRO-CR-2026-7788")
        self.assertEqual(sample["image_name"], "EVIDENCE-SUSPECT-LAPTOP-M2-NVME.iso")
        self.assertEqual(sample["uploaded_by"], "forensic_analyst")
        self.assertTrue("GB" in sample["file_size_human"] or "MB" in sample["file_size_human"])
        self.assertEqual(sample["status"], "AVAILABLE")
        self.assertTrue(len(sample["sha256_hash"]) > 10)
        self.assertTrue(sample["integrity_verified"])

if __name__ == "__main__":
    unittest.main()
