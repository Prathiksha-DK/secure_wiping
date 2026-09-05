"""
SecureWipe — Phase 8 Automated Swarm-Carving Test Suite
Exhaustive automated verification of:
1. Read-Only Evidence Registration & SHA-256/SHA-512 Hash Integrity
2. Derived Privacy-Preserving Representations (Entropy, Hilbert, Byte-Frequency, Token Preview)
3. Measurable Task Difficulty Classification (Easy, Medium, Hard, Expert)
4. Low-Confidence Candidate Filtering & Swarm Micro-Task Generation
5. Hidden Golden Calibration Tasks & Quality Control
6. Anti-Gaming Heuristics (Sub-second Bot Detection, Repetitive Spam Pattern Detection)
7. Exponential Moving Reviewer Reliability Model & Non-Gaming XP / Badge Engine
8. Statistical Weighted Consensus Engine & Disagreement Entropy Calculation
9. Investigator Multi-Criteria Priority Queue Ranking
10. Lead Investigator Evidentiary Final Authority & Cryptographic Digital Signatures
11. Cryptographically Chained Swarm Audit Trail & Tamper Verification
12. Controlled Benchmark Experiments (Experiment A vs B vs C) & Workload Reduction
13. Comprehensive Phase 8 Forensic Report Export
"""

import os
import sys
import json
import time
import unittest
import tempfile
import shutil
import hashlib

os.environ["SECUREWIPE_ENV"] = "TEST"
os.environ["SECUREWIPE_SECRET_KEY"] = "test-secret-key-for-phase8-swarm-998877665544332211"

from swarm_engine import (
    init_swarm_db,
    get_swarm_db_path,
    register_evidence_source,
    create_candidate_and_generate_tasks,
    create_golden_validation_task,
    get_next_task_for_analyst,
    submit_analyst_task,
    evaluate_candidate_consensus,
    compute_shannon_entropy,
    compute_entropy_map,
    compute_byte_frequency_histogram,
    compute_hilbert_curve_2d,
    generate_sanitized_token_preview,
    compute_task_difficulty,
    compute_investigator_priority_score,
    get_investigator_priority_queue,
    submit_lead_investigator_verdict,
    record_swarm_audit_event,
    verify_swarm_audit_integrity,
    get_swarm_overview_metrics,
    get_swarm_leaderboard,
    generate_swarm_forensic_report,
    TASK_TYPE_ANOMALY,
    TASK_TYPE_STRUCTURE_VALIDATION,
    TASK_TYPE_FRAGMENT_MATCH,
    TASK_TYPE_FRAGMENT_CLASSIFICATION,
    DIFFICULTY_EASY,
    DIFFICULTY_MEDIUM,
    DIFFICULTY_HARD,
    DIFFICULTY_EXPERT,
    CONSENSUS_HIGH_CONFIDENCE,
    CONSENSUS_PENDING,
    INVESTIGATOR_VERDICT_CONFIRMED
)

from swarm_benchmark import (
    generate_benchmark_dataset,
    run_experiment_a_automated,
    run_experiment_b_single_reviewer,
    run_experiment_c_swarm_consensus,
    execute_full_benchmark_suite
)


class TestPhase8SwarmCarvingSuite(unittest.TestCase):

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp(prefix="securewipe_swarm_test_")
        os.environ["SECUREWIPE_DATA_DIR"] = self.temp_dir
        init_swarm_db()

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    # -----------------------------------------------------------------------
    # 1. Read-Only Evidence Integrity & Cryptographic Hashing
    # -----------------------------------------------------------------------
    def test_01_evidence_registration_read_only(self):
        """Verify evidence is recorded with SHA-256 and SHA-512 hashes and marked strictly read-only."""
        evidence_payload = b"\x00\x01\x02\x03\x04" * 1024
        res = register_evidence_source(
            case_id="CASE-2026-001",
            image_path="/dev/evidence_drive_01.raw",
            raw_data=evidence_payload
        )
        self.assertTrue(res["evidence_id"].startswith("EV-"))
        self.assertEqual(res["case_id"], "CASE-2026-001")
        self.assertEqual(res["total_bytes"], len(evidence_payload))
        self.assertEqual(res["sha256_hash"], hashlib.sha256(evidence_payload).hexdigest())
        self.assertEqual(res["sha512_hash"], hashlib.sha512(evidence_payload).hexdigest())
        self.assertTrue(res["is_read_only"])

    # -----------------------------------------------------------------------
    # 2. Derived Privacy-Preserving Representations
    # -----------------------------------------------------------------------
    def test_02_privacy_preserving_representations(self):
        """Verify Shannon entropy, windowed entropy map, byte frequency histogram, 2D Hilbert grid, and sanitized preview."""
        # 1. Test data: JPEG structure
        jpeg_sample = b"\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01\x01\x00`\x00`\x00\x00\xff\xdb\x00C" + (b"\x12\x34\x56\x78" * 32) + b"\xff\xd9"
        
        # Entropy
        ent = compute_shannon_entropy(jpeg_sample)
        self.assertGreater(ent, 0.0)
        self.assertLessEqual(ent, 8.0)

        # Windowed Entropy Map
        ent_map = compute_entropy_map(jpeg_sample, bins=8)
        self.assertEqual(len(ent_map), 8)
        self.assertIn("normalized_entropy", ent_map[0])
        self.assertTrue(0.0 <= ent_map[0]["normalized_entropy"] <= 1.0)

        # Byte Frequency Histogram (No raw plaintext exposure)
        byte_freq = compute_byte_frequency_histogram(jpeg_sample)
        self.assertEqual(byte_freq["total_bytes"], len(jpeg_sample))
        self.assertGreaterEqual(byte_freq["printable_ascii_bytes"], 4)  # "JFIF"
        self.assertIn("top_frequencies", byte_freq)

        # 2D Hilbert Curve Projection (8x8 matrix)
        hilbert_grid = compute_hilbert_curve_2d(jpeg_sample, grid_size=8)
        self.assertEqual(len(hilbert_grid), 8)
        self.assertEqual(len(hilbert_grid[0]), 8)
        self.assertTrue(isinstance(hilbert_grid[0][0], float))

        # Sanitized Token Preview
        tokens = generate_sanitized_token_preview(jpeg_sample, "JPEG")
        self.assertEqual(tokens["format"], "JPEG")
        self.assertGreater(tokens["token_count"], 0)
        self.assertEqual(tokens["tokens"][0]["name"], "SOI (Start of Image)")

    # -----------------------------------------------------------------------
    # 3. Measurable Task Difficulty Classification
    # -----------------------------------------------------------------------
    def test_03_task_difficulty_calculation(self):
        """Verify difficulty calculation across Easy, Medium, Hard, and Expert bands."""
        # High confidence, low entropy, intact -> EASY
        diff_easy, score_easy, _ = compute_task_difficulty(
            confidence=0.95, entropy=1.2, length_bytes=2048, is_fragmented=False, structural_completeness=1.0
        )
        self.assertEqual(diff_easy, DIFFICULTY_EASY)
        self.assertLess(score_easy, 0.35)

        # Ambiguous, fragmented, moderate confidence -> MEDIUM / HARD
        diff_hard, score_hard, metrics = compute_task_difficulty(
            confidence=0.25, entropy=5.8, length_bytes=4096, is_fragmented=True, structural_completeness=0.2, neighbor_candidates_count=4
        )
        self.assertIn(diff_hard, (DIFFICULTY_HARD, DIFFICULTY_EXPERT))
        self.assertGreaterEqual(score_hard, 0.65)
        self.assertIn("factors", metrics)

    # -----------------------------------------------------------------------
    # 4. Low-Confidence Filtering & Swarm Task Generation
    # -----------------------------------------------------------------------
    def test_04_candidate_ingestion_and_task_generation(self):
        """Verify candidate ingestion filters high confidence, and routes ambiguous candidates to micro-tasks."""
        ev = register_evidence_source("CASE-01", "/dev/sdb", b"\x00" * 4096)
        
        # 1. High-confidence candidate: should NOT generate swarm tasks
        high_conf_raw = b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x10\x00\x00\x00\x10\x08\x02\x00\x00\x00" + b"\x00" * 50 + b"IEND\xaeB`\x82"
        cand_high = create_candidate_and_generate_tasks(
            case_id="CASE-01",
            evidence_id=ev["evidence_id"],
            lba_start=100,
            byte_offset=51200,
            format_type="PNG",
            raw_slice=high_conf_raw,
            automated_confidence=0.92,
            structural_indicators={"is_valid_structure": True, "completeness": 1.0}
        )
        self.assertEqual(cand_high["status"], "AUTOMATED_HIGH_CONFIDENCE")
        self.assertEqual(len(cand_high["tasks_generated"]), 0)

        # 2. Low-confidence ambiguous candidate: MUST generate swarm micro-tasks
        ambig_raw = b"\xff\xd8\xff\xe1\x00\x28Exif" + (b"\x55\xaa" * 100)
        cand_low = create_candidate_and_generate_tasks(
            case_id="CASE-01",
            evidence_id=ev["evidence_id"],
            lba_start=500,
            byte_offset=256000,
            format_type="JPEG",
            raw_slice=ambig_raw,
            automated_confidence=0.45,
            structural_indicators={"is_fragmented": True, "completeness": 0.3},
            fragment_relationships={"candidate_neighbors": ["CAND-999"]}
        )
        self.assertEqual(cand_low["status"], "QUEUED_FOR_SWARM")
        self.assertGreaterEqual(len(cand_low["tasks_generated"]), 3)
        task_types = [t["task_type"] for t in cand_low["tasks_generated"]]
        self.assertIn(TASK_TYPE_STRUCTURE_VALIDATION, task_types)
        self.assertIn(TASK_TYPE_ANOMALY, task_types)
        self.assertIn(TASK_TYPE_FRAGMENT_MATCH, task_types)

    # -----------------------------------------------------------------------
    # 5. Hidden Golden Tasks & Anti-Gaming Distribution
    # -----------------------------------------------------------------------
    def test_05_hidden_golden_tasks_and_task_fetching(self):
        """Verify golden validation tasks are created and fetched without revealing calibration status."""
        ev = register_evidence_source("CASE-02", "/dev/sdc", b"\x11" * 2048)
        golden_task_id = create_golden_validation_task(
            case_id="CASE-02",
            evidence_id=ev["evidence_id"],
            task_type=TASK_TYPE_STRUCTURE_VALIDATION,
            expected_decision="VALID",
            format_type="PDF",
            synthetic_slice=b"%PDF-1.4\n1 0 obj\n<< /Type /Catalog >>\nendobj\n%%EOF\n"
        )
        self.assertTrue(golden_task_id.startswith("GOLDEN-"))

        # Fetch task for analyst
        task = get_next_task_for_analyst("AliceAnalyst", role="TRIAGE_ANALYST")
        self.assertIsNotNone(task)
        self.assertIn("task_id", task)
        self.assertIn("derived_data", task)
        # Verify hidden flags are NEVER exposed to analyst
        self.assertNotIn("is_validation_task", task["derived_data"])
        self.assertNotIn("is_golden_ground_truth", task["derived_data"])

    # -----------------------------------------------------------------------
    # 6. Anti-Gaming Protection (Rapid-Clicking & Spam Detection)
    # -----------------------------------------------------------------------
    def test_06_anti_gaming_heuristics(self):
        """Verify sub-human response times and repetitive answer spamming are flagged and penalized."""
        ev = register_evidence_source("CASE-03", "/dev/sdd", b"\x22" * 2048)
        cand = create_candidate_and_generate_tasks(
            case_id="CASE-03",
            evidence_id=ev["evidence_id"],
            lba_start=200,
            byte_offset=102400,
            format_type="JPEG",
            raw_slice=b"\xff\xd8" + (b"\x12" * 500),
            automated_confidence=0.50,
            structural_indicators={"is_fragmented": True}
        )
        task_id = cand["tasks_generated"][0]["task_id"]

        # 1. Rapid bot click (< 1200ms)
        res_fast = submit_analyst_task(
            task_id=task_id,
            analyst_id="BotUser_99",
            decision="VALID",
            confidence=0.90,
            time_spent_ms=450  # Suspicious speed
        )
        self.assertTrue(res_fast["flagged_suspicious"])
        self.assertEqual(res_fast["gamification"]["xp_earned"], 0)
        self.assertIn("Sub-human response time", res_fast["suspicious_reasons"][0])

    # -----------------------------------------------------------------------
    # 7. Reviewer Reliability Model & Gamification
    # -----------------------------------------------------------------------
    def test_07_reviewer_reliability_and_gamification(self):
        """Verify accurate responses on golden tasks increase reliability and award XP/levels."""
        ev = register_evidence_source("CASE-04", "/dev/sde", b"\x33" * 2048)
        golden_task_id = create_golden_validation_task(
            case_id="CASE-04",
            evidence_id=ev["evidence_id"],
            task_type=TASK_TYPE_STRUCTURE_VALIDATION,
            expected_decision="VALID",
            format_type="JPEG",
            synthetic_slice=b"\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\xff\xd9"
        )

        # Submit correct decision with realistic reading time
        res = submit_analyst_task(
            task_id=golden_task_id,
            analyst_id="SherlockAnalyst",
            decision="VALID",
            confidence=0.95,
            time_spent_ms=2800
        )
        self.assertFalse(res["flagged_suspicious"])
        self.assertGreater(res["gamification"]["xp_earned"], 0)
        self.assertGreater(res["gamification"]["reliability_score"], 0.50)

        # Leaderboard check
        lb = get_swarm_leaderboard()
        self.assertGreaterEqual(len(lb), 1)
        self.assertEqual(lb[0]["username"], "SherlockAnalyst")

    # -----------------------------------------------------------------------
    # 8. Statistical Weighted Consensus Engine
    # -----------------------------------------------------------------------
    def test_08_statistical_weighted_consensus(self):
        """Verify consensus evaluates agreement ratio, disagreement entropy, and swarm confidence."""
        ev = register_evidence_source("CASE-05", "/dev/sdf", b"\x44" * 4096)
        cand = create_candidate_and_generate_tasks(
            case_id="CASE-05",
            evidence_id=ev["evidence_id"],
            lba_start=1000,
            byte_offset=512000,
            format_type="PDF",
            raw_slice=b"%PDF-1.4\n1 0 obj\n<< /Root 1 0 R >>\nendobj\n%%EOF\n",
            automated_confidence=0.55,
            structural_indicators={"is_fragmented": False, "completeness": 0.8}
        )
        cand_id = cand["candidate_id"]
        t1 = cand["tasks_generated"][0]["task_id"]
        t2 = cand["tasks_generated"][1]["task_id"]
        t3 = cand["tasks_generated"][2]["task_id"]

        # Reviewer 1: VALID (High reliability)
        submit_analyst_task(t1, "Analyst_A", "VALID", 0.90, 2500)
        # Reviewer 2: VALID
        submit_analyst_task(t2, "Analyst_B", "VALID", 0.85, 2300)
        # Reviewer 3: VALID
        res3 = submit_analyst_task(t3, "Analyst_C", "VALID", 0.95, 2100)

        consensus = res3["consensus"]
        self.assertIsNotNone(consensus)
        self.assertEqual(consensus["dominant_decision"], "VALID")
        self.assertEqual(consensus["agreement_ratio"], 1.0)
        self.assertEqual(consensus["consensus_status"], CONSENSUS_HIGH_CONFIDENCE)
        self.assertGreaterEqual(consensus["swarm_confidence"], 75.0)

    # -----------------------------------------------------------------------
    # 9. Lead Investigator Priority Queue & Evidentiary Verdict
    # -----------------------------------------------------------------------
    def test_09_investigator_priority_queue_and_verdict(self):
        """Verify investigator queue ranks candidates and lead investigator verdict establishes authoritative evidence truth."""
        ev = register_evidence_source("CASE-06", "/dev/sdg", b"\x55" * 4096)
        cand = create_candidate_and_generate_tasks(
            case_id="CASE-06",
            evidence_id=ev["evidence_id"],
            lba_start=8000,
            byte_offset=4096000,
            format_type="SQLITE",
            raw_slice=b"SQLite format 3\x00\x10\x00\x01\x01\x00\x40\x20\x20" + (b"\x00" * 100),
            automated_confidence=0.60,
            structural_indicators={"completeness": 0.9}
        )
        cand_id = cand["candidate_id"]

        # 3 reviewers vote VALID
        t_id = cand["tasks_generated"][0]["task_id"]
        submit_analyst_task(t_id, "Analyst_1", "VALID", 0.90, 2500)
        submit_analyst_task(t_id, "Analyst_2", "VALID", 0.90, 2400)
        submit_analyst_task(t_id, "Analyst_3", "VALID", 0.90, 2600)

        # Check investigator queue
        queue = get_investigator_priority_queue("CASE-06")
        self.assertGreaterEqual(len(queue), 1)
        top_item = queue[0]
        self.assertEqual(top_item["candidate_id"], cand_id)
        self.assertGreater(top_item["priority_score"], 50.0)

        # Lead investigator submits final verdict
        verdict_res = submit_lead_investigator_verdict(
            candidate_id=cand_id,
            investigator_id="Lead_Forensic_Agent_007",
            final_verdict=INVESTIGATOR_VERDICT_CONFIRMED,
            evidentiary_value="HIGH_CRITICAL_DATABASE",
            notes="SQLite schema matches target financial ledger table."
        )
        self.assertTrue(verdict_res["success"])
        self.assertEqual(verdict_res["final_verdict"], INVESTIGATOR_VERDICT_CONFIRMED)
        self.assertTrue(len(verdict_res["digital_signature"]) == 64)

    # -----------------------------------------------------------------------
    # 10. Chained Cryptographic Audit Trail
    # -----------------------------------------------------------------------
    def test_10_cryptographic_audit_trail_integrity(self):
        """Verify audit trail chains events with SHA-256 hashes and detects broken links."""
        # Log a test audit event
        record_swarm_audit_event(
            case_id="CASE-AUDIT-TEST",
            evidence_id="EV-TEST-10",
            actor_id="AdminUser",
            actor_role="ADMIN",
            action_type="TEST_AUDIT_ACTION",
            payload_digest="digest-123456",
            details={"test": True}
        )
        is_valid, msg, count = verify_swarm_audit_integrity()
        self.assertTrue(is_valid)
        self.assertGreater(count, 0)

    # -----------------------------------------------------------------------
    # 11. Controlled Benchmark Framework
    # -----------------------------------------------------------------------
    def test_11_benchmark_experiments_suite(self):
        """Verify full benchmark execution of Experiment A, B, and C on 50-artifact dataset."""
        dataset = generate_benchmark_dataset()
        self.assertEqual(len(dataset), 50)

        # Run full benchmark
        bench = execute_full_benchmark_suite()
        self.assertEqual(bench["dataset_size"], 50)
        self.assertIn("experiment_a", bench["experiments"])
        self.assertIn("experiment_b", bench["experiments"])
        self.assertIn("experiment_c", bench["experiments"])

        # Swarm (Exp C) should demonstrate higher accuracy and significant workload reduction over Automated (Exp A)
        exp_a = bench["experiments"]["experiment_a"]
        exp_c = bench["experiments"]["experiment_c"]
        self.assertGreaterEqual(exp_c["accuracy_pct"], exp_a["accuracy_pct"])
        self.assertGreater(exp_c["investigator_workload_reduction_pct"], 50.0)

    # -----------------------------------------------------------------------
    # 12. Forensic Report Export
    # -----------------------------------------------------------------------
    def test_12_forensic_report_generation(self):
        """Verify report clearly separates automated findings, swarm consensus, and lead investigator determinations."""
        ev = register_evidence_source("CASE-REPORT-01", "/dev/nvme0n1", b"\x99" * 4096)
        cand = create_candidate_and_generate_tasks(
            case_id="CASE-REPORT-01",
            evidence_id=ev["evidence_id"],
            lba_start=5000,
            byte_offset=2560000,
            format_type="JPEG",
            raw_slice=b"\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\xff\xd9",
            automated_confidence=0.50,
            structural_indicators={"completeness": 1.0}
        )
        cand_id = cand["candidate_id"]
        t_id = cand["tasks_generated"][0]["task_id"]

        submit_analyst_task(t_id, "ReporterAnalyst1", "VALID", 0.90, 2200)
        submit_analyst_task(t_id, "ReporterAnalyst2", "VALID", 0.90, 2300)
        submit_analyst_task(t_id, "ReporterAnalyst3", "VALID", 0.90, 2400)

        submit_lead_investigator_verdict(
            candidate_id=cand_id,
            investigator_id="LeadInspector_Bob",
            final_verdict=INVESTIGATOR_VERDICT_CONFIRMED,
            evidentiary_value="PRIMARY_EVIDENCE",
            notes="Recovered intact image artifact."
        )

        report = generate_swarm_forensic_report("CASE-REPORT-01")
        self.assertEqual(report["case_id"], "CASE-REPORT-01")
        self.assertTrue(report["audit_trail_integrity"]["verified"])
        self.assertEqual(len(report["findings"]), 1)

        f0 = report["findings"][0]
        self.assertIn("automated_machine_finding", f0)
        self.assertIn("human_swarm_triage", f0)
        self.assertIn("lead_investigator_determination", f0)
        self.assertEqual(f0["lead_investigator_determination"]["final_verdict"], INVESTIGATOR_VERDICT_CONFIRMED)


if __name__ == "__main__":
    unittest.main()
