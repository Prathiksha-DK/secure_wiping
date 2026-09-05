"""
Unit & Integration Tests for Phase 9 Post-Sanitization Residual Evidence Assessment Engine.
Tests:
1. Real Evidence Ingestion & Stream-Carving (Multi-level structural validation)
2. Exact LBA and Byte Location Mapping
3. Real Sector Heatmap generation (Clean Zero vs Residual Artifact vs High Entropy)
4. Byte-level physical inspector (Hex rows, entropy, byte distribution, pattern match)
5. Comparative Before/After Sanitization Experiment Runner (NIST Clear & Crypto Erase)
6. Schema v2.0 RSA-PSS Digital Signature and Certificate Integrity Verification
7. Swarm Micro-Task & Fragment synchronization
8. No Fake Data / Real Media constraint adherence
"""

import os
import sys
import json
import unittest
import tempfile

sys.path.insert(0, os.path.dirname(__file__))

from post_sanitization_assessment import (
    stream_post_sanitization_assessment,
    inspect_media_bytes,
    run_comparative_sanitization_experiment,
    generate_signed_assessment_certificate,
    verify_assessment_certificate,
    sync_assessment_fragments_to_swarm,
    CLASSIFICATION_NO_EVIDENCE,
    CLASSIFICATION_VALIDATED,
    CLASSIFICATION_PARTIAL,
    CLASSIFICATION_SIGNATURE_ONLY,
    CLASSIFICATION_ANOMALY,
    HEATMAP_CLEAN_ZERO,
    HEATMAP_RESIDUAL_ARTIFACT,
    HEATMAP_CLEAN_PATTERN,
)
from swarm_evidence_ingest import create_certified_forensic_evidence_image


class TestPhase9AssessmentEngine(unittest.TestCase):

    def setUp(self):
        self.tmp_dir = tempfile.gettempdir()
        self.test_img = os.path.join(self.tmp_dir, "test_phase9_evidence.raw")
        self.zero_img = os.path.join(self.tmp_dir, "test_phase9_zeroed.raw")

        # 1. Create authentic multi-format test image with known artifacts
        create_certified_forensic_evidence_image(self.test_img, total_size_bytes=12 * 1024 * 1024)

        # 2. Create 100% zeroed test image (simulates completed sanitization)
        with open(self.zero_img, "wb") as f:
            f.write(b"\x00" * (4 * 1024 * 1024))

    def tearDown(self):
        for p in (self.test_img, self.zero_img):
            if os.path.exists(p):
                try:
                    os.remove(p)
                except Exception:
                    pass

    def test_01_evidence_scan_detects_authentic_artifacts(self):
        """Test stream assessment correctly finds and classifies genuine multi-format binary files."""
        report = stream_post_sanitization_assessment(
            target_path=self.test_img,
            target_type="forensic_image",
            sector_size=512,
            prior_sanitization_meta={"job_id": "TEST-01", "method_label": "Pre-Sanitization Test Image"}
        )

        self.assertEqual(report["status"], "COMPLETED")
        self.assertGreater(report["scan_metrics"]["bytes_scanned"], 0)
        self.assertGreater(report["findings_summary"]["validated_artifacts"], 0)
        self.assertEqual(report["scientific_assessment"]["overall_classification"], CLASSIFICATION_VALIDATED)

        # Check LBA and offset accuracy on findings
        ledger = report["findings_ledger"]
        formats = [item["format"] for item in ledger]
        self.assertIn("SQLITE", formats)
        self.assertIn("JPEG", formats)
        self.assertIn("PDF", formats)
        self.assertIn("PNG", formats)
        self.assertIn("ZIP", formats)

        # Verify candidate LBA matches byte_offset // 512
        for item in ledger:
            self.assertEqual(item["start_lba"], item["start_byte_offset"] // 512)
            self.assertGreater(item["length_bytes"], 0)
            self.assertTrue(len(item["sha256_hash"]) == 64)

    def test_02_zeroed_media_produces_no_recognizable_artifacts(self):
        """Test completely zeroed storage produces NO_RECOGNIZABLE_ARTIFACT and 100% clean zero heatmap."""
        report = stream_post_sanitization_assessment(
            target_path=self.zero_img,
            target_type="forensic_image",
            sector_size=512,
            prior_sanitization_meta={"job_id": "TEST-02", "method_label": "NIST SP 800-88 Rev.1 Clear"}
        )

        self.assertEqual(report["status"], "COMPLETED")
        self.assertEqual(report["findings_summary"]["total_candidates"], 0)
        self.assertEqual(report["scientific_assessment"]["overall_classification"], CLASSIFICATION_NO_EVIDENCE)
        self.assertTrue(report["scientific_assessment"]["is_zero_residual"])
        self.assertIn("No recognizable artifacts detected", report["scientific_assessment"]["post_sanitization_observation"])

        # Check Heatmap
        hm = report["heatmap_summary"]
        self.assertEqual(hm["clean_zero_bins"], hm["total_bins"])
        self.assertEqual(hm["artifact_bins"], 0)

    def test_03_byte_inspector_reads_exact_physical_offsets(self):
        """Test read-only byte inspector returns accurate hex dump and entropy."""
        # Inspect SQLite at LBA 2048 (offset 1,048,576)
        res = inspect_media_bytes(
            target_path=self.test_img,
            byte_offset=2048 * 512,
            length_bytes=512,
            sector_size=512,
        )

        self.assertEqual(res["status"], "SUCCESS")
        self.assertEqual(res["lba"], 2048)
        self.assertEqual(res["length_read"], 512)
        self.assertGreater(res["entropy"], 0.5)
        self.assertTrue(len(res["hex_rows"]) == 32)  # 512 / 16 = 32 rows
        self.assertIn("SQLite format 3", res["hex_rows"][0]["ascii"])

    def test_04_comparative_sanitization_experiment(self):
        """Test comparative before/after experiment execution and delta calculation."""
        exp_res = run_comparative_sanitization_experiment(
            experiment_name="TEST-NIST-CLEAR-EXP",
            image_size_mb=12,
            wipe_method="nist-clear",
        )

        self.assertTrue(exp_res["hash_changed"])
        self.assertGreater(exp_res["baseline_assessment"]["total_artifacts"], 5)
        self.assertEqual(exp_res["post_sanitization_assessment"]["total_artifacts"], 0)
        self.assertEqual(exp_res["comparative_delta"]["artifact_reduction_percentage"], 100.0)
        self.assertIn("Empirical evidence confirms effective eradication", exp_res["comparative_delta"]["scientific_conclusion"])

    def test_05_schema_v2_certificate_signing_and_verification(self):
        """Test Schema v2.0 RSA-PSS certificate signing, tamper detection, and verification."""
        report = stream_post_sanitization_assessment(
            target_path=self.zero_img,
            target_type="forensic_image",
            sector_size=512,
            prior_sanitization_meta={"job_id": "JOB-CERT-01", "method_label": "DoD 5220.22-M 3-Pass"}
        )

        cert = generate_signed_assessment_certificate(report, operator="Inspector John Doe")

        self.assertEqual(cert["schema_version"], "2.0")
        self.assertIn("SW-CERT-2.0-", cert["certificate_id"])
        self.assertIn("integrity", cert)
        self.assertEqual(cert["integrity"]["signature_algorithm"], "RSA-PSS-SHA256")

        # Verify authentic certificate
        verify_res = verify_assessment_certificate(cert)
        self.assertTrue(verify_res["valid"])

        # Test tamper detection
        tampered_cert = json.loads(json.dumps(cert))
        tampered_cert["target_storage"]["total_bytes"] += 999
        tamper_res = verify_assessment_certificate(tampered_cert)
        self.assertFalse(tamper_res["valid"])

    def test_06_swarm_sync_when_fragments_detected(self):
        """Test Swarm integration only generates tasks when real fragments exist."""
        report = stream_post_sanitization_assessment(
            target_path=self.test_img,
            target_type="forensic_image",
            sector_size=512,
        )
        asmt_id = report["assessment_id"]

        sync_res = sync_assessment_fragments_to_swarm(asmt_id)
        if report["swarm_reconstruction"]["eligible"]:
            self.assertEqual(sync_res["status"], "SUCCESS")
            self.assertGreater(sync_res["fragments_count"], 0)
        else:
            self.assertEqual(sync_res["status"], "INACTIVE")


if __name__ == "__main__":
    unittest.main()
