"""
SecureWipe Phase 3 — Forensic Verification & Carver Test Suite
Tests A through F for automated validation of forensic capabilities.
"""

import os
import sys
import time
import zlib
import struct
import tempfile
import unittest

from forensic_signatures import (
    evaluate_buffer_signatures,
    validate_jpeg,
    validate_png,
    validate_pdf,
    validate_zip_and_office,
    validate_gzip,
    validate_bmp,
    validate_elf,
    validate_pe,
    validate_gif,
    validate_7z,
)
from forensic_carver import (
    scan_file_stream,
    scan_folder_stream,
    scan_disk_stream,
    EVIDENCE_NO_EVIDENCE,
    EVIDENCE_LOW_CONFIDENCE,
    EVIDENCE_PROBABLE,
    EVIDENCE_VALIDATED,
)
from sanitization_verifier import (
    verify_file_sanitization,
    verify_folder_sanitization,
    verify_disk_sanitization,
)
from sanitization_engine import (
    run_adaptive_sanitization,
    make_decision,
    FINAL_STATE_PASS,
    FINAL_STATE_WARNING,
    FINAL_STATE_FAIL,
)


class TestForensicVerificationEngine(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.mkdtemp(prefix="securewipe_test_")

    def tearDown(self):
        import shutil
        if os.path.exists(self.temp_dir):
            shutil.rmtree(self.temp_dir, ignore_errors=True)

    # -----------------------------------------------------------------------
    # TEST A: Known files -> sanitize -> recovery scan
    # -----------------------------------------------------------------------
    def test_a_known_files_sanitization_and_recovery(self):
        test_file = os.path.join(self.temp_dir, "document.pdf")
        # Create a valid minimal PDF
        pdf_content = b"%PDF-1.4\n1 0 obj<</Type/Catalog/Pages 2 0 R>>endobj\n2 0 obj<</Type/Pages/Kids[3 0 R]/Count 1>>endobj\nxref\n0 3\ntrailer<</Size 3/Root 1 0 R>>\nstartxref\n120\n%%EOF"
        with open(test_file, "wb") as f:
            f.write(pdf_content)

        # Before sanitization: carver must validate it
        pre_scan = scan_file_stream(test_file)
        self.assertEqual(pre_scan["evidence_level"], EVIDENCE_VALIDATED)
        self.assertGreaterEqual(pre_scan["confidence_score"], 70.0)

        # Sanitize file
        result = run_adaptive_sanitization(test_file, method="dod-3pass", max_iterations=2)
        self.assertEqual(result["final_state"], FINAL_STATE_PASS)
        self.assertFalse(os.path.exists(test_file))

        # Post sanitization: recovery scan must report NO_EVIDENCE
        post_scan = scan_file_stream(test_file)
        self.assertEqual(post_scan["evidence_level"], EVIDENCE_NO_EVIDENCE)

    # -----------------------------------------------------------------------
    # TEST B: Known files -> partial overwrite -> recovery scan
    # -----------------------------------------------------------------------
    def test_b_partial_overwrite_detection(self):
        test_file = os.path.join(self.temp_dir, "corrupted_archive.zip")
        # Create a ZIP header but zero out the tail
        zip_hdr = b"PK\x03\x04\x14\x00\x00\x00\x08\x00\x12\x34\x56\x78\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x08\x00\x00\x00test.txt"
        tail_zeros = b"\x00" * 4096
        with open(test_file, "wb") as f:
            f.write(zip_hdr + tail_zeros)

        scan = scan_file_stream(test_file)
        # Must detect as Valid Candidate / Probable (Level 2), NOT clean
        self.assertIn(scan["evidence_level"], (EVIDENCE_PROBABLE, EVIDENCE_LOW_CONFIDENCE))
        self.assertGreater(scan["confidence_score"], 0.0)

    # -----------------------------------------------------------------------
    # TEST C: Complete logical overwrite -> recovery scan
    # -----------------------------------------------------------------------
    def test_c_complete_logical_overwrite(self):
        test_file = os.path.join(self.temp_dir, "zero_fill.bin")
        with open(test_file, "wb") as f:
            f.write(b"\x00" * (1024 * 1024))  # 1 MiB zeros

        scan = scan_file_stream(test_file)
        self.assertEqual(scan["evidence_level"], EVIDENCE_NO_EVIDENCE)
        self.assertEqual(scan["confidence_score"], 0.0)

    # -----------------------------------------------------------------------
    # TEST D: Random data with accidental magic bytes (False Positive Rejection)
    # -----------------------------------------------------------------------
    def test_d_false_positive_rejection_on_random_noise(self):
        # Generate random bytes containing isolated accidental substrings like 'BM' or 'PK\x03\x04' without valid headers
        import random
        random_noise = bytearray(os.urandom(256 * 1024))
        # Insert an isolated "BM" without valid BMP dimensions
        random_noise[100:102] = b"BM"
        random_noise[102:106] = b"\x00\x00\x00\x00"  # Invalid size 0

        results = evaluate_buffer_signatures(bytes(random_noise), 0)
        validated = [r for r in results if r.level == 3]
        # Must NOT classify isolated noise as Level 3 Validated Artifacts
        self.assertEqual(len(validated), 0)

    # -----------------------------------------------------------------------
    # TEST E: Large test container -> Full & Stratified Scan Coverage
    # -----------------------------------------------------------------------
    def test_e_stratified_and_full_scan_coverage(self):
        container = os.path.join(self.temp_dir, "virtual_disk.img")
        total_size = 10 * 1024 * 1024  # 10 MiB
        # Fill with zeros
        with open(container, "wb") as f:
            f.write(b"\x00" * total_size)

        # Inject a PNG at 50% midpoint
        png_data = b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01\x08\x06\x00\x00\x00\x1f\x15\xc4\x89\x00\x00\x00\x00IEND\xaeB`\x82"
        midpoint = total_size // 2
        with open(container, "r+b") as f:
            f.seek(midpoint)
            f.write(png_data)

        # Scan virtual disk
        scan = scan_disk_stream(container, total_size)
        self.assertEqual(scan["scan_coverage_pct"], 100.0)
        self.assertEqual(scan["evidence_level"], EVIDENCE_VALIDATED)
        self.assertGreaterEqual(scan["counts"]["level_3_validated_artifacts"], 1)

        # Test stratified verification
        ver = verify_disk_sanitization(container, total_size, strategy="stratified")
        self.assertEqual(ver["status"], "PASS")
        self.assertGreater(len(ver["regions_checked"]), 0)

    # -----------------------------------------------------------------------
    # TEST F: Fragmented & Truncated file handling
    # -----------------------------------------------------------------------
    def test_f_fragmented_file_structural_tagging(self):
        # Truncated JPEG without EOI marker
        truncated_jpeg = b"\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01\x01\x00`\x00`\x00\x00" + (b"\xaa" * 512)
        results = evaluate_buffer_signatures(truncated_jpeg, 0)
        self.assertEqual(len(results), 1)
        res = results[0]
        self.assertEqual(res.format_name, "JPEG")
        self.assertEqual(res.level, 2)  # Level 2 Valid Candidate, not Level 3
        self.assertTrue(res.is_fragmented)


if __name__ == "__main__":
    unittest.main()
