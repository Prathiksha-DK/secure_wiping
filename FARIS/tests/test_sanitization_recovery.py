import os
import sys
import json
import shutil
import tempfile
import unittest
from pathlib import Path

# Add FARIS to path
FARIS_ROOT = Path(__file__).resolve().parent.parent
if str(FARIS_ROOT) not in sys.path:
    sys.path.insert(0, str(FARIS_ROOT))

from core.paths import resolve_case_dir, CASES_DIR
from core.case_manager import case_manager
from recovery.sanitization import (
    overwrite_analyzer,
    residual_analyzer,
    sector_block_engine,
    multipass_analyzer,
    journal_log_analyzer,
    ssd_nand_ftl_analyzer,
    wear_leveling_analyzer,
    hidden_unallocated_analyzer,
    previous_state_reconstructor,
    crypto_erase_analyzer,
    sanitization_manager,
)
from reporting.report_generator import report_generator
from recovery.adaptive_engine import adaptive_recovery_engine


class TestSanitizationRecovery(unittest.TestCase):
    """
    Comprehensive verification suite for FARIS Specialized Sanitization Recovery (Stages A through J).
    """

    def setUp(self):
        self.temp_dir = Path(tempfile.mkdtemp(prefix="faris_sanit_test_"))
        os.environ["FARIS_CASES_DIR"] = str(self.temp_dir)
        self.case_id = f"test_sanit_{int(self.temp_dir.stat().st_mtime)}"
        case_manager.create_case(self.case_id, "Sanitization Test Case", "Automated Examiner")

    def tearDown(self):
        os.environ.pop("FARIS_CASES_DIR", None)
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_stage_a_overwrite_analysis_zero_fill(self):
        """Stage A: Verifies 100% Zero-fill detection."""
        img_path = self.temp_dir / "zero_filled.raw"
        img_path.write_bytes(b"\x00" * (64 * 1024))

        res = overwrite_analyzer.analyze_patterns(img_path, scan_all=True)
        self.assertEqual(res["status"], "COMPLETED")
        self.assertEqual(res["distribution"]["zero_fill_percent"], 100.0)
        self.assertIn("ZERO_FILL", res["sanitization_type"])
        self.assertEqual(res["confidence"], "HIGH")

    def test_stage_a_overwrite_analysis_pattern_fill(self):
        """Stage A: Verifies repeated byte pattern (0xAA) detection."""
        img_path = self.temp_dir / "pattern_filled.raw"
        img_path.write_bytes(b"\xAA" * (64 * 1024))

        res = overwrite_analyzer.analyze_patterns(img_path, scan_all=True)
        self.assertEqual(res["status"], "COMPLETED")
        self.assertEqual(res["distribution"]["repeated_pattern_percent"], 100.0)
        self.assertIn("0xAA", res["pattern_frequencies"])

    def test_stage_a_overwrite_analysis_high_entropy(self):
        """Stage A: Verifies high-entropy pseudo-random wipe detection."""
        img_path = self.temp_dir / "random_filled.raw"
        img_path.write_bytes(os.urandom(64 * 1024))

        res = overwrite_analyzer.analyze_patterns(img_path, scan_all=True)
        self.assertEqual(res["status"], "COMPLETED")
        self.assertGreaterEqual(res["distribution"]["random_entropy_percent"], 85.0)
        self.assertIn("RANDOM_OR_CRYPTO", res["sanitization_type"])

    def test_stage_b_residual_data_analysis(self):
        """Stage B: Verifies surviving file signatures in unallocated sectors."""
        img_path = self.temp_dir / "residual_evidence.raw"
        png_magic = b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01\x08\x06\x00\x00\x00\x1f\x15\xc4\x89\x00\x00\x00\nIDATx\x9cc\x00\x01\x00\x00\x05\x00\x01\r\n-\xb4\x00\x00\x00\x00IEND\xaeB`\x82"
        data = (b"\x00" * 4096) + png_magic + (b"\x00" * (4096 - len(png_magic)))
        img_path.write_bytes(data)

        res = residual_analyzer.analyze_residuals(self.case_id, img_path)
        self.assertIn(res["status"], ("RESIDUAL_EVIDENCE_FOUND", "COMPLETED"))
        self.assertGreater(res["candidates_found"], 0)
        self.assertGreater(res["validated_candidates"], 0)
        self.assertTrue(any("PNG" in c["content_type"] for c in res["candidates"]))

    def test_stage_c_sector_block_recovery(self):
        """Stage C: Verifies partially overwritten sector and block boundary analysis."""
        img_path = self.temp_dir / "partial_sector.raw"
        sec0 = b"\x00" * 512
        sec1 = (b"CONFIDENTIAL FORENSIC EVIDENCE RECORD IDENTIFIER " * 3)[:128] + (b"\x00" * 384)
        img_path.write_bytes(sec0 + sec1 + sec0)

        res = sector_block_engine.recover_sector_blocks(self.case_id, img_path)
        self.assertEqual(res["status"], "RESIDUAL_EVIDENCE_FOUND")
        self.assertGreater(res["partially_overwritten_sectors"], 0)
        self.assertGreater(res["candidates_found"], 0)

    def test_stage_d_multipass_analysis(self):
        """Stage D: Verifies classification of multi-pass sanitization standards."""
        img_path = self.temp_dir / "multipass_test.raw"
        img_path.write_bytes(b"\x00" * 4096)

        # Zero-fill -> NIST SP 800-88 Clear
        res_zero = multipass_analyzer.analyze_multipass_sanitization(
            self.case_id, img_path, overwrite_distribution={"zero_fill_percent": 100.0}
        )
        self.assertIn("NIST SP 800-88 Clear", res_zero["matched_standard"])

        # Random -> NIST SP 800-88 Purge / DoD
        res_rnd = multipass_analyzer.analyze_multipass_sanitization(
            self.case_id, img_path, overwrite_distribution={"random_entropy_percent": 98.0}
        )
        self.assertIn("Purge", res_rnd["matched_standard"])

    def test_stage_e_journal_log_analysis(self):
        """Stage E: Verifies filesystem-aware journal analysis and N/A handling."""
        img_path = self.temp_dir / "journal_test.raw"
        img_path.write_bytes(b"\x00" * 4096)

        res_fat = journal_log_analyzer.analyze_journal_logs(self.case_id, img_path, fs_type="FAT32")
        self.assertEqual(res_fat["status"], "COMPLETED")
        self.assertFalse(res_fat["journal_supported"])

        res_raw = journal_log_analyzer.analyze_journal_logs(self.case_id, img_path, fs_type="RAW")
        self.assertEqual(res_raw["status"], "NOT_APPLICABLE")

    def test_stage_f_ssd_nand_ftl_analysis(self):
        """Stage F: Verifies SSD/NAND technology routing and honest NOT_ACCESSIBLE classification."""
        img_path = self.temp_dir / "solid_state_drive.raw"
        img_path.write_bytes(b"\x00" * 4096)

        # 1. SSD / Flash Drive -> NOT_ACCESSIBLE (honest reporting of hardware controller shielding)
        res_ssd = ssd_nand_ftl_analyzer.analyze_ssd_nand(self.case_id, img_path, device_type_hint="Samsung 980 NVMe SSD")
        self.assertEqual(res_ssd["status"], "NOT_ACCESSIBLE")
        self.assertEqual(res_ssd["media_technology"], "SSD")
        self.assertFalse(res_ssd["ftl_tables_accessible"])

        # 2. HDD -> NOT_APPLICABLE
        res_hdd = ssd_nand_ftl_analyzer.analyze_ssd_nand(self.case_id, img_path, device_type_hint="Seagate BarraCuda HDD 2TB")
        self.assertEqual(res_hdd["status"], "NOT_APPLICABLE")
        self.assertEqual(res_hdd["media_technology"], "HDD")

    def test_stage_g_wear_leveling_analysis(self):
        """Stage G: Verifies wear-leveling analysis and honest NOT_ACCESSIBLE / NOT_APPLICABLE classification."""
        img_path = self.temp_dir / "nvme_drive.raw"
        img_path.write_bytes(b"\x00" * 4096)

        # 1. SSD -> NOT_ACCESSIBLE (hardware controller firmware shields wear-leveling pools)
        res_ssd = wear_leveling_analyzer.analyze_wear_leveling(self.case_id, img_path, device_type_hint="Crucial P3 NVMe SSD")
        self.assertEqual(res_ssd["status"], "NOT_ACCESSIBLE")
        self.assertEqual(res_ssd["device_type"], "SSD")
        self.assertFalse(res_ssd["wear_leveling_accessible"])

        # 2. HDD -> NOT_APPLICABLE
        res_hdd = wear_leveling_analyzer.analyze_wear_leveling(self.case_id, img_path, device_type_hint="Western Digital Blue HDD")
        self.assertEqual(res_hdd["status"], "NOT_APPLICABLE")
        self.assertEqual(res_hdd["device_type"], "HDD")

    def test_stage_h_hidden_unallocated_analysis(self):
        """Stage H: Verifies partition gap, file slack, and unallocated cluster scanning."""
        img_path = self.temp_dir / "hidden_unalloc_test.raw"
        img_path.write_bytes(b"\x00" * 8192)

        discovered_mock = [
            {"filename": "document.docx", "inode": 42, "size": 3000},
            {"filename": "image.png", "inode": 43, "size": 7500}
        ]
        res = hidden_unallocated_analyzer.analyze_hidden_and_unallocated(
            self.case_id, img_path, cluster_size=4096, discovered_artifacts=discovered_mock
        )
        self.assertIn(res["status"], ("COMPLETED", "RESIDUAL_EVIDENCE_FOUND", "NO_RECOVERABLE_EVIDENCE"))
        self.assertEqual(res["files_evaluated_for_slack"], 2)
        self.assertGreater(res["total_file_slack_bytes"], 0)

    def test_stage_i_previous_state_reconstruction(self):
        """Stage I: Verifies fragment reconstruction and validator integration."""
        cand_file = self.temp_dir / "surviving_cand.txt"
        cand_file.write_text("CONFIDENTIAL INVESTIGATION PROVENANCE RECORD")

        candidates = [{
            "filename": cand_file.name,
            "relative_path": str(cand_file),
            "validation_status": "VALID"
        }]

        res = previous_state_reconstructor.reconstruct_previous_state(self.case_id, candidates)
        self.assertIn(res["status"], ("COMPLETED", "RESIDUAL_EVIDENCE_FOUND"))
        self.assertGreater(res["candidates_found"], 0)

    def test_stage_j_crypto_erase_analysis(self):
        """Stage J: Verifies cryptographic erasure analysis and honest verdict classification."""
        # 1. Encryption Header Detected -> status COMPLETED, ENCRYPTION_CONTAINER_DETECTED
        img_path = self.temp_dir / "bitlocker_vol.raw"
        img_path.write_bytes(b"-FVE-FS-" + os.urandom(4096))

        res = crypto_erase_analyzer.analyze_crypto_erasure(self.case_id, img_path)
        self.assertEqual(res["status"], "COMPLETED")
        self.assertEqual(res["crypto_verdict"], "ENCRYPTION_CONTAINER_DETECTED")
        self.assertTrue(res["is_encrypted_volume"])
        self.assertIn("BitLocker", res["detected_headers"][0])

        # 2. High Entropy Without Header -> status NO_RECOVERABLE_EVIDENCE, NO_RECOVERABLE_PLAINTEXT
        img_rnd = self.temp_dir / "high_entropy.raw"
        img_rnd.write_bytes(os.urandom(65536))
        res_rnd = crypto_erase_analyzer.analyze_crypto_erasure(self.case_id, img_rnd)
        self.assertEqual(res_rnd["status"], "NO_RECOVERABLE_EVIDENCE")
        self.assertEqual(res_rnd["crypto_verdict"], "NO_RECOVERABLE_PLAINTEXT")

    def test_sanitization_manager_full_pipeline(self):
        """Verifies full execution of Stages A through J by SanitizationManager."""
        img_path = self.temp_dir / "full_pipeline_test.raw"
        img_path.write_bytes(b"\x00" * 32768)

        progress_events = []
        def progress_cb(stage, status, pct, msg):
            progress_events.append((stage, status, pct, msg))

        res = sanitization_manager.run_sanitization_pipeline(
            self.case_id,
            img_path,
            progress_callback=progress_cb
        )

        self.assertIn("stages", res)
        stages = res["stages"]
        # Verify all 10 stages (A through J) were executed
        self.assertIn("stage_A_overwrite_analysis", stages)
        self.assertIn("stage_B_residual_analysis", stages)
        self.assertIn("stage_C_sector_block_recovery", stages)
        self.assertIn("stage_D_multipass_analysis", stages)
        self.assertIn("stage_E_journal_log_analysis", stages)
        self.assertIn("stage_F_ssd_nand_ftl", stages)
        self.assertIn("stage_G_wear_leveling", stages)
        self.assertIn("stage_H_hidden_unallocated", stages)
        self.assertIn("stage_I_reconstruction", stages)
        self.assertIn("stage_J_crypto_erase", stages)

        self.assertGreater(len(progress_events), 10)
        self.assertEqual(res["summary"]["total_sanitization_stages"], 10)

    def test_sanitization_reporting_integration(self):
        """Verifies report generation with Specialized Sanitization Recovery section."""
        img_path = self.temp_dir / "reporting_test.raw"
        img_path.write_bytes(b"\x00" * 32768)

        sanitization_manager.run_sanitization_pipeline(self.case_id, img_path)

        paths = report_generator.generate_all_reports(self.case_id)
        self.assertTrue(paths["json"].exists())
        self.assertTrue(paths["html"].exists())

        # Verify JSON report content
        with open(paths["json"], "r", encoding="utf-8") as f_json:
            j_data = json.load(f_json)
        self.assertIn("sanitization_recovery", j_data)
        self.assertIn("stages", j_data["sanitization_recovery"])

        # Verify HTML report content
        html_text = paths["html"].read_text(encoding="utf-8")
        self.assertIn("Specialized Sanitization Recovery Analysis", html_text)
        self.assertIn("Stage A: Overwrite Pattern Analysis", html_text)
        self.assertIn("Stage G: Wear-Leveling Analysis", html_text)
        self.assertIn("Stage J: Cryptographic-Erasure Analysis", html_text)


if __name__ == "__main__":
    unittest.main()
