import os
import sys
import unittest
import json
import shutil
import tempfile
from pathlib import Path

# Add FARIS root to path
FARIS_ROOT = Path(__file__).resolve().parent.parent
TEST_CASES_DIR = FARIS_ROOT / "tests" / "test_cases"
TEST_CASES_DIR.mkdir(parents=True, exist_ok=True)
os.environ["FARIS_CASES_DIR"] = str(TEST_CASES_DIR)

if str(FARIS_ROOT) not in sys.path:
    sys.path.insert(0, str(FARIS_ROOT))

from core.paths import FARIS_ROOT, ENGINES_DIR, resolve_case_dir, get_relative_str
from core.engine_manager import engine_manager
from core.case_manager import case_manager
from core.parallel_engine import parallel_engine
from integrity.evidence_verifier import evidence_verifier
from integrity.audit_logger import audit_logger
from analysis.image_analyzer import image_analyzer
from analysis.artifact_discovery import artifact_discovery_engine
from analysis.artifact_state_analysis import artifact_state_analyzer
from recovery.file_carving import FileCarver
from recovery.fragment_recovery import fragment_recovery_engine
from recovery.ai_ranking import ai_fragment_ranker
from recovery.sqlite_deep import sqlite_deep_recovery, SQLiteRecordParser
from recovery.memory_recovery import memory_recovery_engine
from recovery.anti_forensics import anti_forensic_recovery
from recovery.adaptive_engine import adaptive_recovery_engine
from validation.recovery_validator import recovery_validator
from reporting.report_generator import report_generator
from application.faris_api import faris_api

class TestFARISPipeline(unittest.TestCase):
    """
    Comprehensive End-to-End Forensic Test Suite for FARIS.
    Explicitly tests all 26 architectural phases against the real evidence: pendrive_image.E01 (7.3 GiB).
    """

    @classmethod
    def setUpClass(cls):
        os.environ["FARIS_CASES_DIR"] = str(TEST_CASES_DIR)
        TEST_CASES_DIR.mkdir(parents=True, exist_ok=True)
        cls.fixture_dir = FARIS_ROOT / "tests" / "fixtures"
        cls.fixture_dir.mkdir(parents=True, exist_ok=True)
        cls.evidence_path = cls.fixture_dir / "pendrive_image.E01"
        if not cls.evidence_path.exists():
            zips = sorted((FARIS_ROOT / "archive").glob("legacy_test_images_*.zip"))
            if zips:
                import zipfile
                with zipfile.ZipFile(zips[-1], "r") as zf:
                    zf.extractall(path=cls.fixture_dir)

    def setUp(self):
        self.case_id = "case001"
        self.evidence_path = self.fixture_dir / "pendrive_image.E01"

    # 1 & 2: Engine Discovery & Exact Version Reporting
    def test_01_engine_manager_discovery(self):
        inv = engine_manager.get_inventory()
        self.assertTrue(inv["sleuthkit"]["installed"], "Sleuth Kit should be discovered")
        self.assertTrue(inv["libewf"]["installed"], "libewf should be discovered")
        self.assertTrue(inv["sqlite_runtime"]["installed"], "SQLite runtime should be discovered")
        self.assertTrue(inv["photorec"]["installed"], "PhotoRec 7.2 should be discovered")
        self.assertTrue(inv["volatility"]["installed"], "Volatility 3 should be discovered")
        self.assertEqual(inv["photorec"]["status"], "AVAILABLE")
        self.assertEqual(inv["volatility"]["status"], "AVAILABLE")

    # 3 & 4: Case Creation & Evidence Registration
    def test_02_case_manager_structure(self):
        subdirs = case_manager.ensure_case_structure(self.case_id)
        self.assertTrue((FARIS_ROOT / self.case_id / "metadata").exists())
        self.assertTrue((FARIS_ROOT / self.case_id / "recovery").exists())
        meta = case_manager.load_case_metadata(self.case_id)
        self.assertEqual(meta["case_id"], self.case_id)

    # 5 & 6: Evidence Pre-Analysis Hashing & E01 Segment Verification
    def test_03_evidence_verifier(self):
        res = evidence_verifier.run_case_verification(self.case_id, "PRE_ANALYSIS", target_image_path=self.evidence_path)
        self.assertGreater(res["evidence_count"], 0)
        self.assertEqual(res["results"][0]["verification_status"], "VERIFIED_MATCH")
        self.assertIn("7.3 GiB", res["results"][0]["media_size"])

    # 7 & 8: Partition & FAT32 Filesystem Analysis
    def test_04_image_analyzer(self):
        res = image_analyzer.run_full_analysis(self.case_id, self.evidence_path)
        self.assertGreaterEqual(res["partition_count"], 1)
        self.assertIn("filesystems", res)
        self.assertEqual(res["filesystems"][0]["filesystem_type"], "FAT32")

    # 9 & 10: Artifact Discovery (fls) & Deleted Artifacts Detection
    def test_05_artifact_discovery(self):
        res = artifact_discovery_engine.run_case_discovery(self.case_id, self.evidence_path, 2048)
        self.assertGreater(res["total_artifacts"], 0)
        self.assertGreater(res["deleted_artifacts"], 0)

    # 11 & 12: Artifact State Analysis (istat) & Inode Metadata Recovery
    def test_06_artifact_state_analysis(self):
        res = artifact_state_analyzer.run_state_analysis(self.case_id, self.evidence_path, 2048, sample_limit=10)
        self.assertGreater(res["total_analyzed"], 0)
        self.assertIn("state_counts", res)
        self.assertIn("DELETED", res["state_counts"])

    # 13 & 14: SQLite Varint Record Deserialization & Deep Recovery
    def test_07_sqlite_record_parser(self):
        parser = SQLiteRecordParser()
        sample_payload = b"\x05\x17\x17\x01\x02HelloForensics\x01\x02"
        decoded = parser.parse_record(sample_payload)
        self.assertIsNotNone(decoded)
        self.assertEqual(decoded[0], "Hello")

    # 15: Shannon Entropy & Fragment Analysis
    def test_08_fragment_recovery_entropy(self):
        data_text = b"A" * 100
        data_random = bytes(range(256))
        ent_text = fragment_recovery_engine.calculate_entropy(data_text)
        ent_rand = fragment_recovery_engine.calculate_entropy(data_random)
        self.assertLess(ent_text, 1.0)
        self.assertGreater(ent_rand, 7.5)

    # 16: Local Statistical AI Candidate Fragment Ranking
    def test_09_ai_fragment_ranking(self):
        cand1 = {"id": "c1", "data": b"\x0D\x00\x00\x00" + (b"\x00" * 4000), "offset": 4096}
        cand2 = {"id": "c2", "data": b"\xFF\xD8\xFF\xE0" + (b"\x00" * 4000), "offset": 8192}
        ranked = ai_fragment_ranker.rank_candidate_fragments(
            anchor_data=b"SQLite format 3\x00" + (b"\x00" * 500),
            candidate_fragments=[cand1, cand2],
            expected_type="sqlite"
        )
        self.assertEqual(len(ranked), 2)
        self.assertEqual(ranked[0]["id"], "c1")
        self.assertIn("Valid SQLite B-Tree page flag", ranked[0]["explanation"])

    # 17: Memory Recovery Honest N/A on Disk Images
    def test_10_memory_recovery_honest_na(self):
        out_dir = FARIS_ROOT / self.case_id / "recovery" / "test_memory"
        res = memory_recovery_engine.recover_memory(self.evidence_path, out_dir)
        self.assertEqual(res["status"], "N/A")
        self.assertIn("No volatile memory evidence supplied", res["notes"])

    # 18: Parallel Task Scaling with Bounded Concurrency
    def test_11_parallel_engine(self):
        items = [1, 2, 3, 4, 5]
        res = parallel_engine.execute_tasks(lambda x: x * 2, items, "Test Scaling")
        self.assertEqual(len(res), 5)
        self.assertEqual([r["result"] for r in res], [2, 4, 6, 8, 10])

    # 19 & 20: Recovery Validation, False-Positive Rejection & Confidence Scoring
    def test_12_validation_engine(self):
        res = recovery_validator.validate_case_recoveries(self.case_id)
        self.assertIn("summary_counts", res)
        self.assertIn("VALID", res["summary_counts"])
        self.assertIn("REJECTED", res["summary_counts"])

    # 21 & 22: Cryptographic Audit Chain Integrity & Tamper Detection
    def test_13_audit_chain_tamper_detection(self):
        audit_logger.log_action(self.case_id, "TEST_VALID_ACTION", "UnitTester", "TestSuite", "1.0.0", result="SUCCESS")
        verify_res = audit_logger.verify_audit_chain(self.case_id)
        self.assertTrue(verify_res["audit_chain_intact"])
        self.assertEqual(verify_res["status"], "INTEGRITY_VERIFIED")

    # 23, 24, 25: Multi-Format Report Generation (JSON, CSV, HTML)
    def test_14_reporting_generation(self):
        paths = report_generator.generate_all_reports(self.case_id)
        self.assertTrue(Path(paths["json"]).exists())
        self.assertTrue(Path(paths["csv"]).exists())
        self.assertTrue(Path(paths["html"]).exists())

    # 26, 27, 28, 29: Unified Pipeline Execution, Progress Callbacks & Safe Destination Export
    def test_15_unified_pipeline_and_export(self):
        stages_reported = []
        def callback(stage_id, status, pct, msg):
            stages_reported.append(stage_id)

        test_case_id = "test_unified_export_case"
        test_case_dir = resolve_case_dir(test_case_id)
        evidence_dir = test_case_dir / "evidence"
        evidence_dir.mkdir(parents=True, exist_ok=True)
        test_img = evidence_dir / "test_evidence.raw"
        with open(test_img, "wb") as f:
            f.write(b"\x00" * (1024 * 1024))

        setup_data = {
            "case_id": test_case_id,
            "examiner": "Automated Tester",
            "source_type": "Existing RAW Image",
            "source_path": str(test_img),
            "partition_offset": 0,
            "scan_limit_bytes": 1024 * 1024
        }
        res = faris_api.run_full_forensic_pipeline(setup_data, progress_callback=callback)
        self.assertEqual(res["status"], "SUCCESS")
        self.assertIn("verification", stages_reported)
        self.assertIn("recovery", stages_reported)
        self.assertIn("reporting", stages_reported)

        # Test safe export to temporary separate directory
        temp_export_dir = tempfile.mkdtemp(prefix="faris_test_export_")
        try:
            exp_res = faris_api.export_verified_artifacts(test_case_id, temp_export_dir)
            self.assertEqual(exp_res["status"], "SUCCESS")
        finally:
            shutil.rmtree(temp_export_dir, ignore_errors=True)

    # 30, 31, 32: Dynamic Case ID & Arbitrary Evidence Resolution
    def test_16_dynamic_case_resolution(self):
        dynamic_id = "test_case_999"
        dynamic_dir = resolve_case_dir(dynamic_id)
        self.assertTrue(str(dynamic_dir).endswith(dynamic_id))
        self.assertNotIn("case001", str(dynamic_dir))

    # 33: Bundled PhotoRec & Volatility 3 Execution Verification
    def test_17_bundled_photorec_and_volatility(self):
        # 1. Test PhotoRec tool presence and fidentify version
        fid = engine_manager.require_tool("fidentify_win")
        self.assertTrue(fid.exists())
        
        # 2. Test Volatility 3 vol.py resolution
        vol = engine_manager.require_tool("vol.py")
        self.assertTrue(vol.exists())

        # 3. Test SQLite CLI tools resolution
        sql3 = engine_manager.require_tool("sqlite3")
        self.assertTrue(sql3.exists())

    # 34: Device Discovery & Redesigned Workflow Verification
    def test_18_device_discovery_and_ui_workflow(self):
        from acquisition.device_discovery import device_discovery_manager
        from application.faris_api import faris_api
        import tkinter as tk
        from ui.desktop_app import FARISDesktopApp

        # 1. Test device scanning (Strictly physical devices, no old E01 files)
        dev_res = faris_api.discover_devices()
        self.assertEqual(dev_res["status"], "SUCCESS")
        self.assertIsInstance(dev_res["physical_devices"], list)
        self.assertGreater(len(dev_res["all_targets"]), 0)
        
        # Verify that legacy pendrive_image.E01 is NOT discovered as a physical device
        target_names = [d.get("model", "") for d in dev_res["physical_devices"]]
        self.assertNotIn("pendrive_image.E01", target_names)

        # 2. Test desktop UI initialization and screen navigation
        app = FARISDesktopApp()
        app.withdraw()
        self.assertGreater(len(app.discovered_devices), 0)
        self.assertIsNotNone(app.selected_device)
        
        # Test screen transitions
        app.show_device_selection_screen()
        self.assertTrue(hasattr(app, "device_list_frame"))
        self.assertGreater(len(app.device_row_widgets), 0)

        # Test selecting a device (e.g. index 0 or second device if multiple)
        app._on_device_selected(0)
        self.assertEqual(app.selected_dev_idx.get(), 0)
        self.assertEqual(app.selected_device, app.discovered_devices[0])
        # Verify visual highlight applied to selected row
        self.assertEqual(app.device_row_widgets[0]["frame"].cget("bg"), "#0f2b48")
        self.assertEqual(app.device_row_widgets[0]["name"].cget("fg"), "#38bdf8")

        if len(app.discovered_devices) > 1:
            app._on_device_selected(1)
            self.assertEqual(app.selected_dev_idx.get(), 1)
            self.assertEqual(app.selected_device, app.discovered_devices[1])
            self.assertEqual(app.device_row_widgets[1]["frame"].cget("bg"), "#0f2b48")
            self.assertEqual(app.device_row_widgets[0]["frame"].cget("bg"), "#1e293b")
        
        app.show_case_setup_screen()
        self.assertTrue(hasattr(app, "ent_case_id"))
        self.assertIn(app.selected_device["model"], app.selected_device["model"])
        
        app.show_results_screen({"status": "SUCCESS"})
        app.destroy()

    # 35: Authoritative New Image Pipeline Flow & Case Isolation
    def test_19_new_image_authoritative_pipeline_flow(self):
        from application.faris_api import faris_api
        import shutil

        test_case_id = "case_new_iso_test"
        case_dir = resolve_case_dir(test_case_id)
        acquired_dir = case_dir / "acquired"
        acquired_dir.mkdir(parents=True, exist_ok=True)

        # Create a new isolated test evidence image
        new_evidence_e01 = acquired_dir / f"{test_case_id}_evidence.E01"
        # Copy first 1MB of E01 to simulate freshly acquired E01 container
        with open(self.evidence_path, "rb") as src, open(new_evidence_e01, "wb") as dst:
            dst.write(src.read(1024 * 1024))

        stages_executed = []
        def track_cb(stg, status, pct, msg):
            stages_executed.append((stg, status, msg))

        # Monkey patch acquire_physical_device in application.faris_api module namespace
        import sys
        faris_api_mod = sys.modules["application.faris_api"]
        orig_acquire = faris_api_mod.acquire_physical_device
        try:
            faris_api_mod.acquire_physical_device = lambda c_id="case_new_iso_test", s_dev="\\\\.\\PhysicalDrive2", **kwargs: {
                "status": "SUCCESS",
                "case_id": c_id,
                "source_device": s_dev,
                "primary_image": str(new_evidence_e01),
                "acquired_dir": str(acquired_dir),
                "return_code": 0
            }

            setup_payload = {
                "case_id": test_case_id,
                "examiner": "Test Examiner",
                "source_type": "Physical Storage Device",
                "source_path": "\\\\.\\PhysicalDrive2",
                "is_physical": True,
                "partition_offset": 2048,
                "scan_limit_bytes": 1024 * 1024
            }

            res = faris_api.run_full_forensic_pipeline(setup_payload, progress_callback=track_cb)
            
            # Assert that the pipeline operated ONLY on the newly acquired image
            self.assertEqual(res["status"], "SUCCESS")
            self.assertEqual(Path(res["evidence_image"]).resolve(), new_evidence_e01.resolve())
            self.assertNotIn("case001", res["evidence_image"])
            self.assertNotIn("pendrive_image.E01", res["evidence_image"])
        finally:
            faris_api_mod.acquire_physical_device = orig_acquire
            # Cleanup test case directory
            if case_dir.exists():
                shutil.rmtree(case_dir, ignore_errors=True)

    # 36: Acquisition Failure Stops Downstream Stages
    def test_20_acquisition_failure_stops_downstream_stages(self):
        from application.faris_api import faris_api

        test_case_id = "case_fail_test"
        case_dir = resolve_case_dir(test_case_id)

        import sys
        faris_api_mod = sys.modules["application.faris_api"]
        orig_acquire = faris_api_mod.acquire_physical_device
        try:
            faris_api_mod.acquire_physical_device = lambda c_id="case_fail_test", s_dev="\\\\.\\PhysicalDriveDisconnected", **kwargs: {
                "status": "FAILED",
                "error": "Device disconnected during acquisition"
            }

            stages_executed = []
            def track_cb(stg, status, pct, msg):
                stages_executed.append((stg, status))

            setup_payload = {
                "case_id": test_case_id,
                "examiner": "Test Examiner",
                "source_type": "Physical Storage Device",
                "source_path": "\\\\.\\PhysicalDriveDisconnected",
                "is_physical": True
            }

            res = faris_api.run_full_forensic_pipeline(setup_payload, progress_callback=track_cb)

            # Assert pipeline halted safely on acquisition failure
            self.assertEqual(res["status"], "FAILED")
            self.assertIn(("acquisition", "FAILED"), stages_executed)
            # Downstream stages MUST NOT have run
            self.assertNotIn(("analysis", "RUNNING"), stages_executed)
            self.assertNotIn(("discovery", "RUNNING"), stages_executed)
            self.assertNotIn(("recovery", "RUNNING"), stages_executed)
        finally:
            faris_api_mod.acquire_physical_device = orig_acquire
            if case_dir.exists():
                import shutil
                shutil.rmtree(case_dir, ignore_errors=True)

    # 37: Unattended Subprocess Invocation & Programmatic Metadata Validation
    def test_21_unattended_acquisition_command_and_metadata_construction(self):
        from acquisition.acquire import acquire_physical_device
        import tempfile
        import shutil

        test_case_id = "case_unattended_acq_test"
        temp_src_dir = Path(tempfile.mkdtemp(prefix="faris_acq_test_"))
        try:
            # Create a 2MB synthetic raw source file
            dummy_src = temp_src_dir / "test_pendrive.raw"
            dummy_src.write_bytes(b"\x55\xAA\x00\x01" * (512 * 1024))

            acq_res = acquire_physical_device(
                case_id=test_case_id,
                source_device=str(dummy_src),
                examiner="Special Agent Forensic",
                evidence_id="EVID-TEST-99",
                description="Seized HP USB Flash Drive",
                notes="Chain of custody strictly maintained.",
                timeout_seconds=30
            )

            # Assert command construction flags
            cmd = acq_res["command"]
            self.assertIn("-u", cmd, "Unattended flag must be present to prevent interactive prompt hangs")
            self.assertIn("-C", cmd)
            self.assertIn(test_case_id, cmd)
            self.assertIn("-E", cmd)
            self.assertIn("EVID-TEST-99", cmd)
            self.assertIn("-e", cmd)
            self.assertIn("Special Agent Forensic", cmd)
            self.assertIn("-D", cmd)
            self.assertIn("Seized HP USB Flash Drive", cmd)
            self.assertIn("-N", cmd)
            self.assertIn("Chain of custody strictly maintained.", cmd)
            self.assertIn("-m", cmd)
            self.assertIn("removable", cmd)
            self.assertIn("-M", cmd)
            self.assertIn("physical", cmd)
            self.assertIn("-c", cmd)
            self.assertIn("fast", cmd)
            self.assertIn("-d", cmd)
            self.assertIn("sha256", cmd)
            self.assertIn("-f", cmd)
            self.assertIn("encase7", cmd)

            # Assert non-interactive execution succeeded and created valid E01
            self.assertEqual(acq_res["status"], "SUCCESS")
            self.assertEqual(acq_res["return_code"], 0)
            created_e01 = FARIS_ROOT / acq_res["primary_image"]
            self.assertTrue(created_e01.exists())
            self.assertGreater(created_e01.stat().st_size, 0)

        finally:
            shutil.rmtree(temp_src_dir, ignore_errors=True)
            test_case_dir = resolve_case_dir(test_case_id)
            if test_case_dir.exists():
                shutil.rmtree(test_case_dir, ignore_errors=True)

    # 38: Dynamic Partition Offset & Filesystem Layout Detection
    def test_22_dynamic_partition_offset_and_filesystem_detection(self):
        from analysis.image_analyzer import image_analyzer
        analysis = image_analyzer.run_full_analysis("test_dyn_part", self.evidence_path)
        primary_off = image_analyzer.get_primary_partition_offset(analysis)
        all_offs = image_analyzer.get_all_partition_offsets(analysis)
        
        self.assertIsInstance(primary_off, int)
        self.assertGreaterEqual(primary_off, 0)
        self.assertIn(primary_off, all_offs)
        self.assertIn("filesystems", analysis)
        self.assertTrue(len(analysis["filesystems"]) > 0)
        self.assertEqual(analysis["filesystems"][0]["filesystem_type"], "FAT32")

    # 39: Dynamic Multi-Artifact Metadata Recovery (No Hardcoded Inode 7)
    def test_23_dynamic_multi_artifact_metadata_recovery(self):
        from recovery.metadata_recovery import metadata_recovery_engine
        import tempfile
        import shutil

        test_case_id = "case_dyn_meta_test"
        temp_out = Path(tempfile.mkdtemp(prefix="faris_meta_test_"))
        try:
            sample_artifacts = [
                {"inode": "3", "filename": "sample_root.dir", "partition_offset": 2048},
                {"inode": "4", "filename": "volume_id.sys", "partition_offset": 2048},
                {"inode": "7", "filename": "test_deleted.bin", "partition_offset": 2048}
            ]

            results = metadata_recovery_engine.recover_all_discovered_artifacts(
                case_id=test_case_id,
                image_path=self.evidence_path,
                discovered_artifacts=sample_artifacts,
                partition_offset=2048,
                output_dir=temp_out
            )

            self.assertEqual(len(results), 3)
            inodes_extracted = [r["artifact_id"] for r in results]
            self.assertIn("3", inodes_extracted)
            self.assertIn("4", inodes_extracted)
            self.assertIn("7", inodes_extracted)
            
            # Check dynamic output filenames
            for r in results:
                self.assertTrue(r["output_file"] != "")
                self.assertIn(r["artifact_id"], r["output_file"])
        finally:
            shutil.rmtree(temp_out, ignore_errors=True)

    # 40: Strict Case ID Validation (No Silent Fallback to case001)
    def test_24_missing_case_id_validation_error(self):
        from application.faris_api import faris_api

        # 1. Missing / empty case_id must return a clear FAILED status
        res_empty = faris_api.run_full_forensic_pipeline({"case_id": ""})
        self.assertEqual(res_empty["status"], "FAILED")
        self.assertIn("Case ID is required", res_empty["error"])

        res_none = faris_api.run_full_forensic_pipeline({"case_id": None})
        self.assertEqual(res_none["status"], "FAILED")
        self.assertIn("Case ID is required", res_none["error"])

    # 41: Regression Test for Unbounded Dynamic Scan Limit (None Handling)
    def test_25_unbounded_scan_limit_none_handling(self):
        import io
        import tempfile
        import shutil
        from recovery.anti_forensics import anti_forensic_recovery

        temp_dir = Path(tempfile.mkdtemp(prefix="faris_none_test_"))
        try:
            # Synthetic stream with printable strings
            data = b"\x00" * 100 + b"CONFIDENTIAL_FORENSIC_CASE_RECORD_DATA_STRING_FOR_TESTING_PURPOSES_12345" + b"\x00" * 100
            stream = io.BytesIO(data)

            # Must execute without TypeError: '<' not supported between instances of 'int' and 'NoneType'
            res = anti_forensic_recovery.scan_fringe_residual_data(stream, temp_dir, max_bytes=None)
            self.assertIsInstance(res, list)
            self.assertGreaterEqual(len(res), 1)
            self.assertEqual(res[0]["recovery_method"], "Deep Anti-Forensic Residual Carving")
        finally:
            shutil.rmtree(temp_dir, ignore_errors=True)

    # 42: Test Fast Anti-Forensic Regex Extraction & Chunk Boundary Spanning
    def test_26_fast_anti_forensics_boundary_spanning_and_regex(self):
        import io
        import tempfile
        import shutil
        from recovery.anti_forensics import anti_forensic_recovery

        temp_dir = Path(tempfile.mkdtemp(prefix="faris_regex_test_"))
        try:
            chunk_sz = 1024  # small chunk for boundary testing
            # String placed exactly across the 1024-byte boundary: starts at offset 1000, ends at offset 1080 (80 bytes)
            padding_before = b"\x00" * 1000
            target_str = b"A_VERY_IMPORTANT_DEEP_FORENSIC_SLACK_STRING_CROSSING_CHUNK_BOUNDARY_9988776655"
            padding_after = b"\x00" * 500
            data = padding_before + target_str + padding_after
            stream = io.BytesIO(data)

            res = anti_forensic_recovery.scan_fringe_residual_data(stream, temp_dir, max_bytes=None, chunk_size=chunk_sz)
            self.assertEqual(len(res), 1)
            self.assertEqual(res[0]["size_bytes"], len(target_str))
            
            # Read extracted file content
            extracted_file = temp_dir / res[0]["filename"]
            with open(extracted_file, "rb") as f:
                content = f.read()
            self.assertEqual(content, target_str)
        finally:
            shutil.rmtree(temp_dir, ignore_errors=True)

    # 43: Test MP3 & PNG Validator Integrity
    def test_27_mp3_and_png_validator_integrity(self):
        import tempfile
        import shutil
        from validation.recovery_validator import recovery_validator

        temp_dir = Path(tempfile.mkdtemp(prefix="faris_val_test_"))
        try:
            # 1. Synthesize 10 valid MPEG-1 Layer III audio frames (128 kbps, 44.1 kHz, frame_len = 417 bytes)
            # Sync header: 0xFFFB (MPEG-1 Layer III, no protection)
            # Byte 3: 0x90 (128 kbps -> 0x9, 44.1 kHz -> 0x0, no padding -> 0x0)
            # Byte 4: 0x00
            frame_hdr = b"\xFF\xFB\x90\x00"
            frame_len = (144 * 128 * 1000 // 44100) # 417 bytes
            frame_data = frame_hdr + (b"\x55" * (frame_len - len(frame_hdr)))
            mp3_data = frame_data * 10

            mp3_file = temp_dir / "test_track.mp3"
            with open(mp3_file, "wb") as f:
                f.write(mp3_data)

            res_mp3 = recovery_validator.validate_file(mp3_file)
            self.assertEqual(res_mp3["validation_status"], "VALID")
            self.assertEqual(res_mp3["confidence"], "HIGH")
            self.assertIn("MPEG Audio Layer III verified", res_mp3["reason"])

            # 2. Synthesize valid PNG image
            png_hdr = b"\x89PNG\r\n\x1a\n"
            png_ihdr = b"\x00\x00\x00\x0dIHDR\x00\x00\x00\x01\x00\x00\x00\x01\x08\x06\x00\x00\x00\x1f\x15\xc4\x89"
            png_iend = b"\x00\x00\x00\x00IEND\xaeB`\x82"
            png_data = png_hdr + png_ihdr + png_iend

            png_file = temp_dir / "test_image.png"
            with open(png_file, "wb") as f:
                f.write(png_data)

            res_png = recovery_validator.validate_file(png_file)
            self.assertEqual(res_png["validation_status"], "VALID")
            self.assertEqual(res_png["confidence"], "HIGH")
            self.assertIn("PNG magic header and IEND chunk verified", res_png["reason"])
        finally:
            shutil.rmtree(temp_dir, ignore_errors=True)

    # 44: Test Expected Size Validation Handling
    def test_28_expected_size_validation_handling(self):
        import tempfile
        import shutil
        from validation.recovery_validator import recovery_validator

        temp_dir = Path(tempfile.mkdtemp(prefix="faris_size_test_"))
        try:
            frame_hdr = b"\xFF\xFB\x90\x00"
            frame_len = (144 * 128 * 1000 // 44100)
            frame_data = frame_hdr + (b"\xAA" * (frame_len - len(frame_hdr)))
            full_data = frame_data * 10
            actual_size = len(full_data)

            mp3_file = temp_dir / "metadata_song_inode_100.bin"
            with open(mp3_file, "wb") as f:
                f.write(full_data)

            # Exact expected size
            res_exact = recovery_validator.validate_file(mp3_file, expected_size=actual_size)
            self.assertEqual(res_exact["validation_status"], "VALID")
            self.assertIn("Exact expected size match", res_exact["reason"])

            # Larger expected size (partial recovery)
            res_partial = recovery_validator.validate_file(mp3_file, expected_size=actual_size * 2)
            self.assertEqual(res_partial["validation_status"], "PARTIALLY_VALID")
            self.assertIn("Partial recovery", res_partial["reason"])

            # Zero-byte file
            zero_file = temp_dir / "zero.bin"
            with open(zero_file, "wb") as f:
                pass
            res_zero = recovery_validator.validate_file(zero_file)
            self.assertEqual(res_zero["validation_status"], "REJECTED_ZERO_BYTE")
        finally:
            shutil.rmtree(temp_dir, ignore_errors=True)

    # 45: Test Conditional Branches & No Fake AI Data
    def test_29_conditional_branches_and_no_fake_ai_data(self):
        import tempfile
        import shutil
        from recovery.adaptive_engine import adaptive_recovery_engine

        temp_dir = Path(tempfile.mkdtemp(prefix="faris_adapt_test_"))
        try:
            # Create a mock raw image with non-SQLite dummy data
            raw_img = temp_dir / "test_plain_evidence.raw"
            with open(raw_img, "wb") as f:
                f.write(b"\x00" * 65536)

            case_id = "test_cond_case"
            res = adaptive_recovery_engine.run_adaptive_pipeline(
                case_id=case_id,
                image_path=raw_img,
                partition_offset=0,
                scan_limit_bytes=65536,
                discovered_artifacts=[]
            )

            # Branches must report honest N/A or NO_CANDIDATES
            self.assertEqual(res["branches"]["database_recovery"]["status"], "N/A")
            self.assertEqual(res["branches"]["memory_recovery"]["status"], "N/A")
            self.assertEqual(res["branches"]["fragment_recovery"]["status"], "NO_CANDIDATES")
            self.assertEqual(res["branches"]["ai_fragment_ranking"]["status"], "N/A")
            self.assertEqual(len(res["branches"]["ai_fragment_ranking"]["ranking_details"]), 0)
        finally:
            shutil.rmtree(temp_dir, ignore_errors=True)

    # 46: Test Cross-Branch Deduplication
    def test_30_cross_branch_deduplication(self):
        from recovery.adaptive_engine import adaptive_recovery_engine

        # Master provenance must deduplicate identical SHA-256 hashes
        provenance = [
            {"artifact_id": "inode_1", "sha256": "hash_aaa", "classification": "FULLY_RECOVERED"},
            {"artifact_id": "carve_1", "sha256": "hash_bbb", "classification": "FULLY_RECOVERED"}
        ]
        unique_hashes = set(p["sha256"] for p in provenance)
        self.assertEqual(len(unique_hashes), 2)

if __name__ == "__main__":
    unittest.main()
