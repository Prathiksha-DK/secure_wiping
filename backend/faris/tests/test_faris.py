import os
import sys
import unittest
import json
import sqlite3

# Ensure backend root is on sys.path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from faris.config import FARIS_DB_PATH
from faris.db import init_faris_db, get_db_connection
from faris.hashing import compute_file_sha256, verify_file_integrity
from faris.sqlite_parser import read_varint, decode_record, parse_page_header
from faris.synthetic_generator import generate_synthetic_database
from faris.damage_simulator import simulate_damage
from faris.evaluator import evaluate_recovery_against_ground_truth
from faris.chain_of_custody import add_chain_event, verify_chain_integrity, get_chain_events
from faris.reports import generate_forensic_report

class TestFARIS(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        init_faris_db()

    def test_01_varint_parsing(self):
        # Test 1-byte varint
        buf = bytes([0x2A]) # 42
        val, count = read_varint(buf, 0)
        self.assertEqual(val, 42)
        self.assertEqual(count, 1)

        # Test multi-byte varint (0x81, 0x00 -> 128)
        buf2 = bytes([0x81, 0x00])
        val2, count2 = read_varint(buf2, 0)
        self.assertEqual(val2, 128)
        self.assertEqual(count2, 2)

    def test_02_synthetic_generator_and_damage_simulator(self):
        # 1. Generate clean DB with ground truth
        synth = generate_synthetic_database(num_records=30)
        self.assertTrue(os.path.exists(synth["db_path"]))
        self.assertGreater(synth["total_records"], 0)

        # 2. Simulate Header Wipe (anti-forensics)
        damaged = simulate_damage(synth["db_path"], scenario="header_wipe")
        self.assertTrue(os.path.exists(damaged["damaged_path"]))
        self.assertEqual(damaged["scenario"], "header_wipe")
        # Standard sqlite3 parser must fail on damaged file
        self.assertEqual(damaged["standard_sqlite_status"], "FAILED")

        # 3. Run FARIS recovery evaluation
        eval_res = evaluate_recovery_against_ground_truth(
            damaged_file_path=damaged["damaged_path"],
            ground_truth_json_path=synth["ground_truth_path"],
            dataset_name="Test Synthetic Suite",
            scenario="header_wipe"
        )

        self.assertGreater(eval_res["recovered_records"], 0)
        self.assertGreater(eval_res["precision_rate"], 70.0)
        self.assertEqual(eval_res["standard_sqlite_recovered"], 0)

    def test_03_chain_of_custody_integrity(self):
        case_id = "TEST-CHAIN-CASE"
        add_chain_event(case_id, "TEST_INIT", "Initial chain genesis", actor="Test Agent")
        add_chain_event(case_id, "EVIDENCE_ATTACHED", "Evidence EVD-001 attached", actor="Test Agent")
        add_chain_event(case_id, "SCAN_DONE", "Recovery scan finished", actor="Test Agent")

        verify = verify_chain_integrity(case_id)
        self.assertTrue(verify["verified"])
        self.assertEqual(verify["event_count"], 3)

    def test_04_reports_generation(self):
        # Create case & job
        case_id = "REPORT-CASE-01"
        synth = generate_synthetic_database(num_records=20)
        damaged = simulate_damage(synth["db_path"], scenario="header_wipe")
        eval_res = evaluate_recovery_against_ground_truth(damaged["damaged_path"], synth["ground_truth_path"])

        # Fetch last job
        conn = get_db_connection()
        job = conn.execute("SELECT job_id FROM faris_scan_jobs ORDER BY created_at DESC LIMIT 1").fetchone()
        conn.close()

        if job:
            html_rep = generate_forensic_report(case_id="BENCHMARK-CASE", job_id=job["job_id"], fmt="html")
            self.assertTrue(os.path.exists(html_rep["file_path"]))

            json_rep = generate_forensic_report(case_id="BENCHMARK-CASE", job_id=job["job_id"], fmt="json")
            self.assertTrue(os.path.exists(json_rep["file_path"]))

            csv_rep = generate_forensic_report(case_id="BENCHMARK-CASE", job_id=job["job_id"], fmt="csv")
            self.assertTrue(os.path.exists(csv_rep["file_path"]))

if __name__ == "__main__":
    unittest.main()
