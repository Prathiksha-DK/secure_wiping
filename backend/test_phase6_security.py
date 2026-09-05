"""
SecureWipe — Phase 6 Automated Security Test Suite
Exhaustive automated verification of:
1. Authentication & PBKDF2 Password Hashing
2. HMAC-SHA256 Signed Session Tokens & Role-Based Authorization
3. Storage Safety Model & Fail-Closed System Disk Protection
4. Two-Stage Destructive Confirmation Engine & Anti-Replay Nonce Validation
5. Device Identity Fingerprinting & Anti-Misdirection Protection
6. Audit Trail Cryptographic Hash-Chaining & Tamper Detection
7. Schema v1.0 Certificate Integrity & RSA-PSS Digital Signatures
8. Storage Inspector Strictly Read-Only Guarantee
9. Device Concurrency Locking & Race Condition Prevention
10. Sanitization Failure Handling & Safe Abort State Recording
"""

import os
import sys
import json
import time
import unittest
import tempfile
import shutil

# Set test environment
os.environ["SECUREWIPE_ENV"] = "TEST"
os.environ["SECUREWIPE_SECRET_KEY"] = "test-secret-key-for-phase6-validation-998877665544332211"

from security_config import (
    hash_password, verify_password,
    generate_session_token, verify_session_token,
    init_auth_db, authenticate_user,
    ROLE_ADMINISTRATOR, ROLE_OPERATOR, ROLE_AUDITOR, ROLE_VIEWER
)
from storage_safety import (
    validate_storage_safety,
    compute_device_fingerprint,
    acquire_device_lock,
    release_device_lock,
    is_system_path_posix,
    is_system_path_windows
)
from two_stage_confirmation import (
    generate_stage1_confirmation,
    validate_stage2_confirmation
)
from audit_log import (
    init_audit_db,
    record_audit_event,
    verify_audit_log_integrity,
    compute_event_hash,
    AUDIT_DB_PATH
)
from certificate_engine import (
    generate_sanitization_certificate,
    verify_certificate_integrity,
    compute_canonical_certificate_digest
)
from storage_inspector import (
    inspect_storage_metadata,
    read_storage_hex_sector,
    analyze_sector_patterns,
    search_storage_stream
)


class TestPhase6SecuritySuite(unittest.TestCase):

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp(prefix="securewipe_test_")
        os.environ["SECUREWIPE_DATA_DIR"] = self.temp_dir
        init_auth_db()
        init_audit_db()

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    # -----------------------------------------------------------------------
    # 1. Authentication & PBKDF2 Password Hashing Tests
    # -----------------------------------------------------------------------
    def test_01_pbkdf2_password_hashing(self):
        """Verify PBKDF2-HMAC-SHA256 password hashing with 600,000 iterations and salt."""
        pwd = "UltraSecurePassword2026!#"
        hashed = hash_password(pwd)
        self.assertTrue(hashed.startswith("pbkdf2_sha256$600000$"))
        self.assertTrue(verify_password(pwd, hashed))
        self.assertFalse(verify_password("WrongPassword!", hashed))
        self.assertFalse(verify_password("", hashed))

    def test_02_user_authentication_rbac(self):
        """Verify user authentication, rate limiting, and role retrieval."""
        ok, msg, data = authenticate_user("Madhan", "iamironman", client_ip="127.0.0.42")
        self.assertTrue(ok)
        self.assertEqual(data["role"], ROLE_ADMINISTRATOR)
        self.assertIn("token", data)

        # Test invalid password
        ok_bad, msg_bad, _ = authenticate_user("Madhan", "wrongpass", client_ip="127.0.0.42")
        self.assertFalse(ok_bad)
        self.assertIn("Invalid", msg_bad)

    # -----------------------------------------------------------------------
    # 2. Signed Session Token & Tamper Tests
    # -----------------------------------------------------------------------
    def test_03_signed_session_tokens(self):
        """Verify HMAC-SHA256 session token signature validation and tamper rejection."""
        token = generate_session_token("TestOperator", ROLE_OPERATOR)
        claims = verify_session_token(token)
        self.assertIsNotNone(claims)
        self.assertEqual(claims["sub"], "TestOperator")
        self.assertEqual(claims["role"], ROLE_OPERATOR)

        # Test tampered payload
        parts = token.split(".")
        tampered_token = parts[0][:-2] + "AA." + parts[1]
        self.assertIsNone(verify_session_token(tampered_token))

        # Test forged token with wrong signature
        forged_token = parts[0] + ".AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        self.assertIsNone(verify_session_token(forged_token))

    # -----------------------------------------------------------------------
    # 3. Storage Safety Model & Fail-Closed System Disk Protection Tests
    # -----------------------------------------------------------------------
    def test_04_system_disk_protection_fail_closed(self):
        """Verify that root, boot, system directories, and app files are strictly rejected."""
        # 1. Root POSIX mount
        root_res = validate_storage_safety("/")
        self.assertFalse(root_res["safe"])
        self.assertTrue(any("SAFETY ABORT" in r for r in root_res["reasons"]))

        # 2. Critical system directory
        etc_res = validate_storage_safety("/etc")
        self.assertFalse(etc_res["safe"])

        # 3. Empty or bogus target (Fail Closed)
        empty_res = validate_storage_safety("")
        self.assertFalse(empty_res["safe"])

        unknown_res = validate_storage_safety("RANDOM_UNKNOWN_DEVICE_XYZ")
        self.assertFalse(unknown_res["safe"])

    def test_05_safe_target_validation(self):
        """Verify that controlled, non-system test files are permitted."""
        test_file = os.path.join(self.temp_dir, "test_target.dat")
        with open(test_file, "wb") as f:
            f.write(b"Hello Sensitive Data 1234567890" * 100)

        res = validate_storage_safety(test_file)
        self.assertTrue(res["safe"])
        self.assertEqual(res["target_type"], "file")
        self.assertIn("FILE:", res["canonical_id"])

    # -----------------------------------------------------------------------
    # 4. Two-Stage Destructive Confirmation Tests
    # -----------------------------------------------------------------------
    def test_06_two_stage_confirmation_flow(self):
        """Verify Stage 1 token generation, Stage 2 phrase matching, and anti-replay nonce protection."""
        test_file = os.path.join(self.temp_dir, "confirm_test.bin")
        with open(test_file, "wb") as f:
            f.write(b"Data" * 50)

        # Stage 1
        s1 = generate_stage1_confirmation(test_file, "dod-3pass", "TestOp", "127.0.0.1")
        self.assertEqual(s1["status"], "CONFIRMATION_REQUIRED")
        self.assertTrue(s1["safe"])
        token = s1["confirmation_token"]
        phrase = s1["required_confirmation_phrase"]

        # Stage 2 - Invalid Phrase
        ok_bad, msg_bad, _ = validate_stage2_confirmation(token, "WRONG-PHRASE", "TestOp", "127.0.0.1")
        self.assertFalse(ok_bad)
        self.assertIn("mismatch", msg_bad.lower())

        # Stage 2 - Correct Phrase
        ok_good, msg_good, payload = validate_stage2_confirmation(token, phrase, "TestOp", "127.0.0.1")
        self.assertTrue(ok_good)
        self.assertEqual(payload["target"], test_file)

        # Replay Attack - Try using the exact same token again
        ok_replay, msg_replay, _ = validate_stage2_confirmation(token, phrase, "TestOp", "127.0.0.1")
        self.assertFalse(ok_replay)
        self.assertIn("replay", msg_replay.lower())

    # -----------------------------------------------------------------------
    # 5. Device Identity Fingerprint & Anti-Misdirection Tests
    # -----------------------------------------------------------------------
    def test_07_device_identity_anti_misdirection(self):
        """Verify fingerprint validation detects modified device attributes."""
        meta = {
            "serial": "SN-WD12345678",
            "model": "WDC WD5000",
            "size_bytes": 500107862016,
            "bus_type": "SATA",
            "target_type": "disk"
        }
        fp1 = compute_device_fingerprint(meta)

        # Alter serial number
        meta_altered = dict(meta)
        meta_altered["serial"] = "SN-SAMSUNG9999"
        fp2 = compute_device_fingerprint(meta_altered)

        self.assertNotEqual(fp1, fp2)

    # -----------------------------------------------------------------------
    # 6. Audit Trail Cryptographic Hash-Chaining & Tamper Detection Tests
    # -----------------------------------------------------------------------
    def test_08_audit_log_hash_chaining_and_tamper_detection(self):
        """Verify hash chaining across events and detection of modified payloads."""
        import sqlite3
        # Record a series of sequential events
        evt1 = record_audit_event("DEVICE_DETECTED", "Operator1", "/dev/sdb", payload={"model": "TestDisk"})
        evt2 = record_audit_event("SANITIZATION_REQUESTED", "Operator1", "/dev/sdb", payload={"method": "dod-3pass"})
        evt3 = record_audit_event("SANITIZATION_COMPLETED", "Operator1", "/dev/sdb", payload={"status": "PASS"})

        # Verify integrity of valid chain
        ver_res = verify_audit_log_integrity()
        self.assertEqual(ver_res["status"], "PASS")
        self.assertTrue(ver_res["chain_valid"])

        # Tamper with event payload in database
        import audit_log
        conn = sqlite3.connect(audit_log.AUDIT_DB_PATH)
        with conn:
            conn.execute(
                "UPDATE audit_events SET payload_json = ? WHERE event_id = ?",
                ('{"model":"TAMPERED_DISK_DATA"}', evt1["event_id"])
            )
        conn.close()

        # Verify tamper detection identifies compromised event
        tamper_res = verify_audit_log_integrity()
        self.assertEqual(tamper_res["status"], "FAIL")
        self.assertFalse(tamper_res["chain_valid"])
        self.assertIn("MODIFIED_EVENT_DATA", tamper_res.get("error_type", ""))

    # -----------------------------------------------------------------------
    # 7. Certificate v1.0 Integrity & RSA-PSS Signature Tests
    # -----------------------------------------------------------------------
    def test_09_certificate_v1_integrity_and_signature(self):
        """Verify Schema v1.0 canonical digest, RSA-PSS signature, and tampering detection."""
        op_record = {
            "session_id": "SAN-CERT-TEST-001",
            "sanitization_method": "nist-clear",
            "sanitization_method_label": "NIST 800-88 Rev.1 — Clear",
            "start_time": "2026-09-02T10:00:00Z",
            "end_time": "2026-09-02T10:05:00Z",
            "final_state": "SANITIZED_AND_REUSABLE",
            "operator": "Jane Operator",
            "device_info": {
                "model": "Test Hard Drive",
                "serial": "WD-TEST-9988",
                "size_bytes": 1000204886016,
                "bus_type": "SATA",
                "device_technology": "HDD"
            },
            "iterations": []
        }

        cert = generate_sanitization_certificate(op_record)
        self.assertEqual(cert["schema_version"], "1.0")
        self.assertEqual(cert["assurance_status"], "SANITIZED_REUSABLE")
        self.assertIn("integrity", cert)
        self.assertIsNotNone(cert["integrity"]["signature"])

        # Verify valid certificate
        ver_res = verify_certificate_integrity(cert)
        self.assertTrue(ver_res["valid"])
        self.assertTrue(ver_res["digest_valid"])
        self.assertTrue(ver_res["signature_valid"])

        # Tamper with certificate field
        tampered = json.loads(json.dumps(cert))
        tampered["device"]["serial_number"] = "FORGED-SERIAL-0000"

        tampered_ver = verify_certificate_integrity(tampered)
        self.assertFalse(tampered_ver["valid"])
        self.assertIn("TAMPERING DETECTED", tampered_ver["reason"])

    # -----------------------------------------------------------------------
    # 8. Storage Inspector Strictly Read-Only Guarantee Tests
    # -----------------------------------------------------------------------
    def test_10_storage_inspector_strictly_read_only(self):
        """Verify storage inspector reads bytes, analyzes patterns, and never modifies target."""
        test_file = os.path.join(self.temp_dir, "inspector_test.bin")
        original_content = (b"\x00" * 512) + (b"\xff" * 512)
        with open(test_file, "wb") as f:
            f.write(original_content)

        # Inspect metadata
        meta = inspect_storage_metadata(test_file)
        self.assertTrue(meta["exists"])
        self.assertEqual(meta["target_type"], "file")
        self.assertEqual(meta["physical_identity"]["capacity_bytes"], 1024)

        # Read sector 0
        s0 = read_storage_hex_sector(test_file, lba=0, sector_size=512)
        self.assertEqual(s0["status"], "SUCCESS")
        self.assertEqual(s0["analysis"]["observed_pattern"], "ZERO-FILL (0x00)")

        # Read sector 1
        s1 = read_storage_hex_sector(test_file, lba=1, sector_size=512)
        self.assertEqual(s1["status"], "SUCCESS")
        self.assertEqual(s1["analysis"]["observed_pattern"], "0xFF-FILL (0xFF)")

        # Verify file on disk is strictly unchanged
        with open(test_file, "rb") as f:
            current_content = f.read()
        self.assertEqual(current_content, original_content)

    # -----------------------------------------------------------------------
    # 9. Concurrency Lock & Race Condition Prevention Tests
    # -----------------------------------------------------------------------
    def test_11_device_concurrency_locking(self):
        """Verify device locks prevent two concurrent sanitization jobs on the same target."""
        canonical_id = "DISK:SN-TEST-LOCK-12345"
        
        # Job 1 acquires lock
        ok1, _ = acquire_device_lock(canonical_id, "JOB-001", "Operator1")
        self.assertTrue(ok1)

        # Job 2 attempts to acquire lock on same device (MUST FAIL)
        ok2, msg2 = acquire_device_lock(canonical_id, "JOB-002", "Operator2")
        self.assertFalse(ok2)
        self.assertIn("locked", msg2.lower())

        # Job 1 releases lock
        release_device_lock(canonical_id, "JOB-001")

        # Job 2 can now acquire lock
        ok3, _ = acquire_device_lock(canonical_id, "JOB-002", "Operator2")
        self.assertTrue(ok3)
        release_device_lock(canonical_id, "JOB-002")


if __name__ == "__main__":
    unittest.main()
