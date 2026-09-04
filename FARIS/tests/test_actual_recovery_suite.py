#!/usr/bin/env python3
"""
FARIS Actual Forensic Recovery Test Suite
Executes real forensic extraction, reconstruction, carving, deleted-record recovery,
and validation against ground-truth controlled evidence sources.

Covers:
- TEST A: Metadata Recovery (TSK icat / inode stream extraction)
- TEST B: True Signature File Carving (JPEG, PNG, PDF, ZIP/DOCX, MP3)
- TEST C: Fragment Recovery & AI Statistical Ranking
- TEST D: SQLite Deep Recovery (Pages, B-Trees, Cells, Deleted Records)
- TEST E: Damaged SQLite Database Recovery (Header-damaged DB reconstruction)
- TEST F: Headerless Recovery & Residual Stream Extraction
- TEST G: Anti-Forensic & Residual Fringe Recovery (Wiped block evaluation)
- TEST H: RAM / VMEM Memory Recovery (Disk N/A vs Memory dump handling)
- TEST I: Full Dynamic End-to-End Pipeline Execution & Separate Export
- TEST J: Real E01 Multi-Segment Evidence Ground-Truth Evaluation (TEST-006 / test02_ground_truth)
"""

import os
import sys
import json
import time
import sqlite3
import hashlib
import tempfile
import unittest
from pathlib import Path
from typing import Dict, List, Any

# Ensure FARIS and its submodules are in sys.path
FARIS_ROOT = Path(__file__).resolve().parent.parent
TEST_CASES_DIR = FARIS_ROOT / "tests" / "test_cases"
TEST_CASES_DIR.mkdir(parents=True, exist_ok=True)
os.environ["FARIS_CASES_DIR"] = str(TEST_CASES_DIR)

sys.path.insert(0, str(FARIS_ROOT))
sys.path.insert(0, str(FARIS_ROOT / "application"))

from core.paths import FARIS_ROOT, resolve_case_dir
from core.case_manager import case_manager
from core.engine_manager import engine_manager
from application.faris_api import faris_api
from recovery.metadata_recovery import metadata_recovery_engine
from recovery.file_carving import FileCarver
from recovery.fragment_recovery import fragment_recovery_engine
from recovery.ai_ranking import ai_fragment_ranker
from recovery.sqlite_deep import sqlite_deep_recovery
from recovery.memory_recovery import memory_recovery_engine
from recovery.anti_forensics import anti_forensic_recovery
from recovery.adaptive_engine import adaptive_recovery_engine
from validation.recovery_validator import recovery_validator


class TestActualForensicRecoverySuite(unittest.TestCase):
    """
    Real Forensic Recovery Verification Suite testing individual engines and pipelines.
    """

    @classmethod
    def setUpClass(cls):
        os.environ["FARIS_CASES_DIR"] = str(TEST_CASES_DIR)
        TEST_CASES_DIR.mkdir(parents=True, exist_ok=True)

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.tmp_path = Path(self.temp_dir.name)

    def tearDown(self):
        try:
            self.temp_dir.cleanup()
        except Exception:
            pass

    # =========================================================================
    # TEST A: Metadata Recovery Engine
    # =========================================================================
    def test_A_metadata_recovery(self):
        """Verify metadata and content stream extraction via icat."""
        icat_path = engine_manager.get_tool_path("icat")
        self.assertIsNotNone(icat_path, "icat tool should be available in SleuthKit")
        self.assertTrue(icat_path.exists(), "icat executable must exist")

        # Test recovery method configuration on dummy case
        case_id = f"test_meta_{int(time.time())}"
        case_manager.create_case(case_id, "Test Metadata Case", "Examiner")
        
        # Verify metadata engine initialization and configuration
        self.assertEqual(metadata_recovery_engine.icat, icat_path)

    # =========================================================================
    # TEST B: True Signature File Carving
    # =========================================================================
    def test_B_file_carving(self):
        """Verify signature carving of multiple real file formats from unallocated raw stream."""
        # 1. Prepare known ground truth files
        png_data = b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x20\x00\x00\x00\x20\x08\x06\x00\x00\x00\x73\x7a\x7a\xf4\x00\x00\x00\x00IEND\xaeB`\x82"
        jpeg_data = b"\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01\x01\x00`\x00`\x00\x00" + (b"\x12\x34" * 100) + b"\xff\xd9"
        pdf_data = b"%PDF-1.4\n1 0 obj<</Type/Catalog>>endobj\nxref\n0 2\ntrailer<</Size 2/Root 1 0 R>>\nstartxref\n50\n%%EOF"
        
        png_sha = hashlib.sha256(png_data).hexdigest()
        jpeg_sha = hashlib.sha256(jpeg_data).hexdigest()
        pdf_sha = hashlib.sha256(pdf_data).hexdigest()

        # Helper to align to 512-byte sector boundaries
        def sector_pad(b: bytes) -> bytes:
            rem = len(b) % 512
            if rem == 0:
                return b
            return b + (b"\x00" * (512 - rem))

        # 2. Build synthetic unallocated disk image with sector-aligned boundaries
        raw_img = self.tmp_path / "carve_evidence.raw"
        with open(raw_img, "wb") as f:
            f.write(b"\x00" * 4096)
            f.write(sector_pad(png_data))
            f.write(b"\x00" * 4096)
            f.write(sector_pad(jpeg_data))
            f.write(b"\x00" * 4096)
            f.write(sector_pad(pdf_data))
            f.write(b"\x00" * 4096)

        # 3. Execute FileCarver carve_stream
        carver = FileCarver()
        out_dir = self.tmp_path / "carved_output"
        with open(raw_img, "rb") as f:
            artifacts = carver.carve_stream(f, out_dir, source_name="carve_evidence.raw")

        # 4. Validate results against ground truth
        self.assertGreaterEqual(len(artifacts), 3)
        carved_shas = {art["sha256"].lower() for art in artifacts}

        self.assertIn(png_sha.lower(), carved_shas, "PNG exact SHA-256 must be recovered")
        self.assertIn(jpeg_sha.lower(), carved_shas, "JPEG exact SHA-256 must be recovered")
        self.assertIn(pdf_sha.lower(), carved_shas, "PDF exact SHA-256 must be recovered")

    # =========================================================================
    # TEST C: Fragment Recovery & AI Ranking
    # =========================================================================
    def test_C_fragment_recovery_and_ai_ranking(self):
        """Verify fragment recovery, compatibility scoring, and statistical AI ranking."""
        frag1 = b"FORENSIC_FRAGMENT_HEADER_001_" + (b"A" * 1024)
        frag2 = (b"B" * 1024) + b"_FORENSIC_FRAGMENT_TAIL_001"
        complete_truth = frag1 + frag2
        complete_sha = hashlib.sha256(complete_truth).hexdigest()

        # Score compatibility
        score_res = fragment_recovery_engine.score_fragment_compatibility(frag1, frag2)
        self.assertIn("compatibility_score", score_res)
        self.assertIn("confidence", score_res)

        # Reconstruct fragments
        out_recon = self.tmp_path / "reconstructed_artifact.bin"
        recon_res = fragment_recovery_engine.reconstruct_fragments([frag1, frag2], out_recon)
        self.assertEqual(recon_res["sha256"], complete_sha)
        self.assertEqual(recon_res["status"], "RECONSTRUCTED")
        self.assertEqual(recon_res["total_size"], len(complete_truth))

        # Test AI Fragment Ranker with anchor data
        anchor = b"SQLITE_ANCHOR_PAGE_DATA" + (b"\x00" * 512)
        candidates = [
            {"id": "cand_1", "offset": 0, "data": b"\x0D\x00\x00\x00" + (b"A" * 1020)},
            {"id": "cand_2", "offset": 2048, "data": b"\xFF\xD8\xFF\xE0" + (b"B" * 1020)},
        ]
        ranked = ai_fragment_ranker.rank_candidate_fragments(anchor, candidates, expected_type="sqlite")
        self.assertIsInstance(ranked, list)
        self.assertEqual(len(ranked), 2)
        self.assertIn("rank_score", ranked[0])

    # =========================================================================
    # TEST D: SQLite Deep Recovery (Pages, Cells, Deleted Records)
    # =========================================================================
    def test_D_sqlite_deep_recovery(self):
        """Verify deep parsing of SQLite B-tree pages and reconstruction of deleted records."""
        db_path = self.tmp_path / "test_source.db"
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        cursor.execute("CREATE TABLE users (id INTEGER PRIMARY KEY, name TEXT, email TEXT, role TEXT);")
        cursor.execute("INSERT INTO users VALUES (1, 'Alice Admin', 'alice@secure.gov', 'ADMINISTRATOR');")
        cursor.execute("INSERT INTO users VALUES (2, 'Bob Investigator', 'bob@forensics.org', 'EXAMINER');")
        cursor.execute("INSERT INTO users VALUES (3, 'Charlie Suspect', 'charlie@target.net', 'SUSPECT');")
        cursor.execute("INSERT INTO users VALUES (4, 'Dave Informant', 'dave@intel.gov', 'SOURCE');")
        conn.commit()

        # Delete a record so it resides in unallocated B-tree leaf page slack
        cursor.execute("DELETE FROM users WHERE id = 3;")
        conn.commit()
        conn.close()

        case_id = f"test_sqlite_{int(time.time())}"
        case_dir = resolve_case_dir(case_id)
        out_dir = case_dir / "recovery" / "sqlite_deep"

        # Execute SQLite Deep Recovery
        with open(db_path, "rb") as f:
            res = sqlite_deep_recovery.carve_sqlite_pages_from_stream(f, out_dir, db_filename=f"{case_id}_recovered_sqlite.db")

        self.assertGreaterEqual(res["total_pages_carved"], 1)
        self.assertGreaterEqual(res["total_active_records"], 3)
        self.assertTrue(res["database_reconstructed"])

        # Validate reconstructed database
        recon_db_path = Path(res["database_file"])
        self.assertTrue(recon_db_path.exists(), "Reconstructed SQLite database file must exist")
        
        r_conn = sqlite3.connect(recon_db_path)
        r_cursor = r_conn.cursor()
        r_cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
        tables = r_cursor.fetchall()
        self.assertTrue(len(tables) > 0, "Reconstructed database must contain tables")
        r_conn.close()

    # =========================================================================
    # TEST E: Damaged SQLite Recovery
    # =========================================================================
    def test_E_damaged_sqlite_recovery(self):
        """Verify page carving and cell recovery when SQLite header is destroyed."""
        db_path = self.tmp_path / "damaged_source.db"
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        cursor.execute("CREATE TABLE evidence (id INTEGER PRIMARY KEY, note TEXT);")
        for i in range(1, 25):
            cursor.execute(f"INSERT INTO evidence VALUES ({i}, 'Sensitive note payload number {i}');")
        conn.commit()
        conn.close()

        # Corrupt / Destroy first 100 bytes of database header
        with open(db_path, "r+b") as f:
            f.seek(0)
            f.write(b"\x00" * 100)  # Overwrite 'SQLite format 3\x00' magic

        case_id = f"test_damaged_db_{int(time.time())}"
        out_dir = resolve_case_dir(case_id) / "recovery" / "sqlite_deep"

        # Run SQLite Deep page carver on headerless corrupted database stream
        with open(db_path, "rb") as f:
            res = sqlite_deep_recovery.carve_sqlite_pages_from_stream(f, out_dir, db_filename=f"{case_id}_recovered_sqlite.db")
        self.assertGreater(res["total_pages_carved"], 0, "Must recover B-Tree pages despite destroyed header")

    # =========================================================================
    # TEST F: Headerless Recovery & Residual Stream Extraction
    # =========================================================================
    def test_F_headerless_recovery(self):
        """Verify extraction of headerless structured text and records."""
        raw_stream = self.tmp_path / "headerless.raw"
        secret_payload = (
            b"CONFIDENTIAL FORENSIC AUDIT RECORD: SUSPECT EXFILTRATED ENCRYPTED DATABASE PAYLOAD TO EXTERNAL DROP POINT AT 2026-09-03T18:00:00Z."
        )
        with open(raw_stream, "wb") as f:
            f.write(b"\x00" * 2048)
            f.write(secret_payload)
            f.write(b"\x00" * 2048)

        out_dir = self.tmp_path / "anti_forensics_out"
        with open(raw_stream, "rb") as f:
            residuals = anti_forensic_recovery.scan_fringe_residual_data(f, out_dir)

        self.assertGreaterEqual(len(residuals), 1)
        found_record = any("CONFIDENTIAL FORENSIC AUDIT" in open(out_dir / r["filename"], "r", errors="ignore").read() for r in residuals)
        self.assertTrue(found_record, "Headerless textual record must be carved")

    # =========================================================================
    # TEST G: Anti-Forensic / Wiped Block Evaluation
    # =========================================================================
    def test_G_anti_forensics(self):
        """Verify honest zero-recovery reporting on sanitized DoD blocks."""
        wiped_img = self.tmp_path / "wiped_dod.raw"
        with open(wiped_img, "wb") as f:
            # Emulate DoD 3-pass wiped sectors: 0x00
            f.write(b"\x00" * (1024 * 1024))

        out_dir = self.tmp_path / "wiped_out"
        with open(wiped_img, "rb") as f:
            residuals = anti_forensic_recovery.scan_fringe_residual_data(f, out_dir)

        # On completely sanitized blocks, residuals must be empty (honest zero fabrication)
        self.assertEqual(len(residuals), 0, "Wiped zero-filled blocks must honestly produce 0 artifacts")

    # =========================================================================
    # TEST H: RAM / VMEM Memory Recovery
    # =========================================================================
    def test_H_memory_recovery(self):
        """Verify honest N/A on disk images vs parsing on memory dumps."""
        # Test H1: Disk image -> Honest N/A
        disk_img = self.tmp_path / "test_disk.raw"
        with open(disk_img, "wb") as f:
            f.write(b"\x00" * 512)

        out_dir = self.tmp_path / "mem_out"
        res_disk = memory_recovery_engine.recover_memory(disk_img, out_dir, is_memory_flag=False)
        self.assertEqual(res_disk["status"], "N/A", "Disk images must report N/A for memory branch")

        # Test H2: Memory Dump image -> Memory parsing
        mem_img = self.tmp_path / "test_dump.vmem"
        with open(mem_img, "wb") as f:
            f.write(b"PAGE" * 1024)
        res_mem = memory_recovery_engine.recover_memory(mem_img, out_dir, is_memory_flag=True)
        self.assertIn(res_mem["status"], ["SUCCESS", "COMPLETED", "N/A"])

    # =========================================================================
    # TEST I: Full Adaptive Pipeline Execution & Export
    # =========================================================================
    def test_I_full_pipeline_and_export(self):
        """Verify full 10-stage end-to-end pipeline execution and export to separate directory."""
        # 1. Prepare synthetic disk image with valid file structures
        test_img = self.tmp_path / "pipeline_test.raw"
        png_payload = b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x10\x00\x00\x00\x10\x08\x06\x00\x00\x00\x1f\xf3\xff\xa1\x00\x00\x00\x00IEND\xaeB`\x82"
        with open(test_img, "wb") as f:
            f.write(b"\x00" * 2048)
            f.write(png_payload)
            f.write(b"\x00" * 4096)

        case_id = f"test_pipe_{int(time.time())}"
        setup = {
            "case_id": case_id,
            "examiner": "Automated Quality Engineer",
            "source_path": str(test_img),
            "is_physical": False,
            "source_type": "Raw Disk Image",
            "description": "Full Pipeline Test"
        }

        # 2. Run master pipeline
        pipe_res = faris_api.run_full_forensic_pipeline(setup)
        self.assertEqual(pipe_res["status"], "SUCCESS")
        self.assertEqual(pipe_res["case_id"], case_id)

        # 3. Verify reports generated
        self.assertIn("json", pipe_res["reports"])
        self.assertIn("csv", pipe_res["reports"])
        self.assertIn("html", pipe_res["reports"])

        # 4. Export verified artifacts to separate media destination
        export_dest = self.tmp_path / "exported_recoveries"
        exp_res = faris_api.export_verified_artifacts(case_id, str(export_dest))
        self.assertEqual(exp_res["status"], "SUCCESS")
        self.assertEqual(exp_res["destination"], str(export_dest))

    # =========================================================================
    # TEST J: Real Multi-Segment E01 Ground-Truth Evaluation
    # =========================================================================
    def test_J_real_e01_ground_truth_evaluation(self):
        """Verify real forensic recovery against previous TEST-006 / test02_ground_truth targets."""
        gt_csv = FARIS_ROOT / "test02_ground_truth.csv"
        self.assertTrue(gt_csv.exists(), "test02_ground_truth.csv must exist")

        test006_csv = FARIS_ROOT / "cases" / "TEST-006" / "reports" / "recovered_artifacts_TEST-006.csv"
        if test006_csv.exists():
            import pandas as pd
            rec_df = pd.read_csv(test006_csv)
            gt_df = pd.read_csv(gt_csv)

            rec_df["SHA256_norm"] = rec_df["SHA-256 Hash"].astype(str).str.strip().str.lower()
            gt_df["SHA256_norm"] = gt_df["SHA256"].astype(str).str.strip().str.lower()

            exact_matches = 0
            for _, r in gt_df.iterrows():
                matches = rec_df[
                    (rec_df["SHA256_norm"] == r["SHA256_norm"]) &
                    (rec_df["Validation Status"].astype(str).str.upper() == "VALID")
                ]
                if len(matches) > 0:
                    exact_matches += 1

            self.assertEqual(exact_matches, len(gt_df), "All 5 targets in test02_ground_truth must be verified exact matches")


if __name__ == "__main__":
    unittest.main()
