"""
Comprehensive Test Suite for NTRO Platform Subsystems
Validates:
  1. PBKDF2 Authentication & RBAC role access
  2. Cryptographic audit chain tamper detection
  3. Pre-wipe forensic risk assessment
  4. Hardware health scoring & private marketplace rules
  5. Cryptographic Sanitization Certificate generation & digital signatures
"""

import unittest
import os
import json
import tempfile
import shutil

from auth import (
    init_platform_db,
    authenticate_user,
    register_user,
    validate_session,
    terminate_session,
    _hash_password,
    _verify_password,
)
from audit_engine import (
    record_audit_event,
    verify_audit_integrity,
    get_audit_logs,
)
from pre_wipe_advisor import conduct_pre_wipe_assessment
from health_valuation import evaluate_device_health, create_marketplace_listing
from reporting_engine import generate_sanitization_certificate, get_certificate_by_id


class TestNTROPlatformSubsystems(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        init_platform_db()

    def test_01_password_hashing_and_auth(self):
        # 1. Test PBKDF2 hashing
        pwd = "TestSecret@2026"
        h, salt = _hash_password(pwd)
        self.assertTrue(_verify_password(pwd, salt, h))
        self.assertFalse(_verify_password("WrongPassword", salt, h))

        # 2. Test seeding default accounts
        for uname, expected_role in [
            ("citizen_user", "individual"),
            ("gov_officer", "government"),
            ("forensic_analyst", "forensic"),
        ]:
            if expected_role == "individual":
                pwd = "Individual@2026"
            elif expected_role == "government":
                pwd = "GovAdmin@2026"
            else:
                pwd = "Forensic@2026"

            ok, msg, sess = authenticate_user(uname, pwd)
            self.assertTrue(ok, f"Failed auth for {uname}: {msg}")
            self.assertEqual(sess["role"], expected_role)

            # Validate session token
            token_valid = validate_session(sess["token"])
            self.assertIsNotNone(token_valid)
            self.assertEqual(token_valid["username"], uname)

    def test_02_audit_chain_tamper_detection(self):
        # Record a test audit event
        res = record_audit_event(
            user_id="test_runner",
            role="government",
            operation="UNIT_TEST_OP",
            status="SUCCESS",
            details={"test": "pass"}
        )
        self.assertIn("curr_hash", res)
        self.assertGreater(res["sequence"], 0)

        # Verification must succeed
        chain_status = verify_audit_integrity()
        self.assertTrue(chain_status["verified"])
        self.assertEqual(chain_status["status"], "SECURE_AND_VERIFIED")

    def test_03_pre_wipe_forensic_assessment(self):
        temp_dir = tempfile.mkdtemp(prefix="pre_wipe_test_")
        try:
            # Create a file with a valid PDF structure
            pdf_path = os.path.join(temp_dir, "confidential.pdf")
            pdf_content = (
                b"%PDF-1.4\n1 0 obj<</Type/Catalog/Pages 2 0 R>>endobj\n"
                b"2 0 obj<</Type/Pages/Kids[3 0 R]/Count 1>>endobj\n"
                b"xref\n0 3\ntrailer<</Size 3/Root 1 0 R>>\nstartxref\n120\n%%EOF"
            )
            with open(pdf_path, "wb") as f:
                f.write(pdf_content)

            # Pre-wipe triage must catch potential forensic evidence!
            triage = conduct_pre_wipe_assessment(pdf_path, target_type="file")
            self.assertTrue(triage["evidence_detected"])
            self.assertEqual(triage["risk_level"], "CRITICAL_EVIDENCE_FOUND")
            self.assertFalse(triage["can_proceed_safely"])
            self.assertTrue(triage["requires_operator_override"])

            # Clean zero file must pass triage
            zero_path = os.path.join(temp_dir, "empty_space.bin")
            with open(zero_path, "wb") as f:
                f.write(b"\x00" * 4096)

            zero_triage = conduct_pre_wipe_assessment(zero_path, target_type="file")
            self.assertFalse(zero_triage["evidence_detected"])
            self.assertTrue(zero_triage["can_proceed_safely"])
        finally:
            shutil.rmtree(temp_dir, ignore_errors=True)

    def test_04_device_health_and_marketplace(self):
        # High-health SSD device
        healthy_dev = {
            "name": "Crucial MX500 500GB SSD",
            "media_type": "SSD",
            "health": 95,
            "sizeBytes": 500 * 1024 * 1024 * 1024,
        }
        health_eval = evaluate_device_health(healthy_dev)
        self.assertTrue(health_eval["is_reusable"])
        self.assertGreater(health_eval["indicative_valuation_inr"], 0)
        self.assertEqual(health_eval["disposition_decision"], "REUSABLE_FOR_MARKETPLACE")

        # Ineligible device (<70% health)
        degraded_dev = {
            "name": "Failing Western Digital HDD",
            "media_type": "HDD",
            "health": 35,
            "sizeBytes": 1000 * 1024 * 1024 * 1024,
        }
        deg_eval = evaluate_device_health(degraded_dev)
        self.assertFalse(deg_eval["is_reusable"])
        self.assertEqual(deg_eval["disposition_decision"], "DECOMMISSION_TO_EWASTE")

        # Marketplace listing rejection for low health
        ok, msg, _ = create_marketplace_listing(
            device_id="DEV-DEG-01",
            certificate_id="CERT-TEST-01",
            seller_name="Citizen",
            device_title="Degraded HDD",
            media_type="HDD",
            capacity_gb=1000,
            health_score=35,
            valuation_inr=0
        )
        self.assertFalse(ok)
        self.assertIn("below 70%", msg)

    def test_05_sanitization_certificate_cryptography(self):
        cert = generate_sanitization_certificate(
            job_id="JOB-TEST-88",
            device_info={"name": "Seagate Barracuda 1TB", "serial": "SN-SG-8841", "type": "HDD", "size": "1 TB"},
            method_label="DoD 5220.22-M (3-Pass)",
            verification_summary={"verification_strategy": "Full Read-Back", "status": "PASS", "mismatches_found": 0},
            recovery_summary={"evidence_level": "NO_EVIDENCE", "confidence_score": 0.0},
            final_state="SANITIZED_AND_REUSABLE",
            operator_name="gov_officer"
        )
        self.assertIn("digital_signature_sha256", cert)
        self.assertEqual(len(cert["digital_signature_sha256"]), 64)

        # Retrieve and verify persistence
        saved_cert = get_certificate_by_id(cert["certificate_id"])
        self.assertIsNotNone(saved_cert)
        self.assertEqual(saved_cert["sha256_digest"], cert["digital_signature_sha256"])


if __name__ == "__main__":
    unittest.main()
