import json
import time
import uuid
import os
import sqlite3
from .db import get_db_connection
from .scanner import execute_carve_scan

def evaluate_recovery_against_ground_truth(damaged_file_path: str, ground_truth_json_path: str, dataset_name: str = "Synthetic Test", scenario: str = "header_wipe") -> dict:
    """Run FARIS recovery and evaluate accuracy against ground-truth records."""
    if not os.path.exists(ground_truth_json_path):
        raise FileNotFoundError("Ground truth JSON not found")

    with open(ground_truth_json_path, "r", encoding="utf-8") as f:
        gt_data = json.load(f)

    # Flatten ground truth strings/integers for fuzzy matching
    gt_total_records = gt_data.get("total_records", 0)
    gt_signatures = set()
    for tbl, rows in gt_data.get("tables", {}).items():
        for r in rows:
            # Create content tuple
            vals = tuple(sorted([str(v).strip() for v in r.values() if v is not None]))
            gt_signatures.add(vals)

    # Create temporary scan job in DB
    job_id = f"EVAL-JOB-{uuid.uuid4().hex[:8].upper()}"
    case_id = "BENCHMARK-CASE"
    evidence_id = "BENCHMARK-EVD"

    conn = get_db_connection()
    try:
        with conn:
            conn.execute("INSERT OR IGNORE INTO faris_cases (case_id, case_name, created_at, updated_at) VALUES (?, ?, ?, ?)", (case_id, "Evaluation Benchmark", int(time.time()), int(time.time())))
            conn.execute("INSERT OR IGNORE INTO faris_evidence (evidence_id, case_id, original_filename, stored_filename, file_size, sha256_hash, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)", (evidence_id, case_id, os.path.basename(damaged_file_path), os.path.basename(damaged_file_path), os.path.getsize(damaged_file_path), "EVAL_HASH", int(time.time())))
            conn.execute("""
                INSERT INTO faris_scan_jobs
                (job_id, evidence_id, case_id, mode, status, created_at)
                VALUES (?, ?, ?, 'Header-Independent', 'Queued', ?)
            """, (job_id, evidence_id, case_id, int(time.time())))
    finally:
        conn.close()

    # Run Carve Scan synchronously for evaluation
    execute_carve_scan(job_id, damaged_file_path, evidence_id, case_id, os.path.basename(damaged_file_path))

    # Inspect results
    conn = get_db_connection()
    try:
        job_row = conn.execute("SELECT * FROM faris_scan_jobs WHERE job_id = ?", (job_id,)).fetchone()
        records_rows = conn.execute("SELECT * FROM faris_recovered_records WHERE job_id = ?", (job_id,)).fetchall()

        recovered_count = len(records_rows)
        correct_count = 0
        false_positives = 0

        for r in records_rows:
            try:
                rec_vals = json.loads(r["column_values"])
                rec_sig = tuple(sorted([str(v).strip() for v in rec_vals if v is not None and v != "<TRUNCATED TEXT>"]))
                # Check if any ground truth signature is a subset or matches
                matched = False
                for gt_sig in gt_signatures:
                    overlap = len(set(rec_sig).intersection(set(gt_sig)))
                    if overlap >= 2 or (len(rec_sig) == 1 and overlap == 1):
                        matched = True
                        break
                if matched:
                    correct_count += 1
                else:
                    false_positives += 1
            except Exception:
                false_positives += 1

        precision = round((correct_count / max(recovered_count, 1)) * 100, 2)
        recall = round((correct_count / max(gt_total_records, 1)) * 100, 2)
        if precision + recall > 0:
            f1 = round((2 * precision * recall) / (precision + recall), 2)
        else:
            f1 = 0.0

        # Baseline: Test standard sqlite3
        std_sqlite_count = 0
        try:
            conn_std = sqlite3.connect(damaged_file_path)
            for tbl in ["users", "messages", "transactions"]:
                try:
                    c = conn_std.cursor()
                    c.execute(f"SELECT count(*) FROM {tbl}")
                    cnt = c.fetchone()[0]
                    std_sqlite_count += cnt
                except Exception:
                    pass
            conn_std.close()
        except Exception:
            std_sqlite_count = 0

        eval_id = f"EVAL-{uuid.uuid4().hex[:8].upper()}"
        duration = job_row["duration_sec"] if job_row else 0.0

        with conn:
            conn.execute("""
                INSERT INTO faris_evaluations
                (eval_id, dataset_name, damage_scenario, ground_truth_records, recovered_records,
                 correct_records, false_positives, precision_rate, recall_rate, f1_score, duration_sec, standard_sqlite_recovered, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                eval_id, dataset_name, scenario, gt_total_records, recovered_count,
                correct_count, false_positives, precision, recall, f1, duration, std_sqlite_count, int(time.time())
            ))

        return {
            "eval_id": eval_id,
            "dataset_name": dataset_name,
            "damage_scenario": scenario,
            "ground_truth_records": gt_total_records,
            "recovered_records": recovered_count,
            "correct_records": correct_count,
            "false_positives": false_positives,
            "precision_rate": precision,
            "recall_rate": recall,
            "f1_score": f1,
            "duration_sec": duration,
            "standard_sqlite_recovered": std_sqlite_count,
            "advantage_over_standard_sqlite": f"+{recovered_count - std_sqlite_count} records recovered"
        }
    finally:
        conn.close()
