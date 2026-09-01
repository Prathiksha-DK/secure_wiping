import sqlite3
import os
import json
import time
from .config import FARIS_DB_PATH

def get_db_connection():
    os.makedirs(os.path.dirname(FARIS_DB_PATH), exist_ok=True)
    conn = sqlite3.connect(FARIS_DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn

def init_faris_db():
    conn = get_db_connection()
    try:
        with conn:
            # 1. Cases
            conn.execute("""
                CREATE TABLE IF NOT EXISTS faris_cases (
                    case_id TEXT PRIMARY KEY,
                    case_name TEXT NOT NULL,
                    description TEXT DEFAULT '',
                    investigator TEXT DEFAULT 'Forensic Analyst',
                    status TEXT NOT NULL DEFAULT 'Active',
                    created_at INTEGER NOT NULL,
                    updated_at INTEGER NOT NULL
                )
            """)

            # 2. Evidence Files
            conn.execute("""
                CREATE TABLE IF NOT EXISTS faris_evidence (
                    evidence_id TEXT PRIMARY KEY,
                    case_id TEXT NOT NULL,
                    original_filename TEXT NOT NULL,
                    stored_filename TEXT NOT NULL,
                    file_size INTEGER NOT NULL,
                    sha256_hash TEXT NOT NULL,
                    status TEXT NOT NULL DEFAULT 'Preserved',
                    created_at INTEGER NOT NULL,
                    FOREIGN KEY (case_id) REFERENCES faris_cases (case_id) ON DELETE CASCADE
                )
            """)

            # 3. Scan Jobs
            conn.execute("""
                CREATE TABLE IF NOT EXISTS faris_scan_jobs (
                    job_id TEXT PRIMARY KEY,
                    evidence_id TEXT NOT NULL,
                    case_id TEXT NOT NULL,
                    mode TEXT NOT NULL DEFAULT 'Header-Independent',
                    detected_page_size INTEGER DEFAULT 4096,
                    status TEXT NOT NULL DEFAULT 'Queued',
                    progress INTEGER DEFAULT 0,
                    pages_scanned INTEGER DEFAULT 0,
                    candidates_found INTEGER DEFAULT 0,
                    validated_pages INTEGER DEFAULT 0,
                    records_recovered INTEGER DEFAULT 0,
                    duration_sec REAL DEFAULT 0.0,
                    error_message TEXT DEFAULT '',
                    created_at INTEGER NOT NULL,
                    completed_at INTEGER DEFAULT 0,
                    FOREIGN KEY (evidence_id) REFERENCES faris_evidence (evidence_id) ON DELETE CASCADE,
                    FOREIGN KEY (case_id) REFERENCES faris_cases (case_id) ON DELETE CASCADE
                )
            """)

            # 4. Page Candidates
            conn.execute("""
                CREATE TABLE IF NOT EXISTS faris_page_candidates (
                    candidate_id TEXT PRIMARY KEY,
                    job_id TEXT NOT NULL,
                    offset INTEGER NOT NULL,
                    page_size INTEGER NOT NULL,
                    page_type TEXT NOT NULL,
                    confidence_score REAL NOT NULL,
                    cell_count INTEGER DEFAULT 0,
                    reasons_json TEXT DEFAULT '[]',
                    validation_status TEXT NOT NULL DEFAULT 'Candidate',
                    created_at INTEGER NOT NULL,
                    FOREIGN KEY (job_id) REFERENCES faris_scan_jobs (job_id) ON DELETE CASCADE
                )
            """)

            # 5. Recovered Records
            conn.execute("""
                CREATE TABLE IF NOT EXISTS faris_recovered_records (
                    record_id TEXT PRIMARY KEY,
                    job_id TEXT NOT NULL,
                    evidence_id TEXT NOT NULL,
                    case_id TEXT NOT NULL,
                    byte_offset INTEGER NOT NULL,
                    page_offset INTEGER NOT NULL,
                    page_num INTEGER DEFAULT 0,
                    cell_idx INTEGER DEFAULT 0,
                    row_id INTEGER DEFAULT 0,
                    column_types TEXT DEFAULT '[]',
                    column_values TEXT DEFAULT '[]',
                    inferred_schema TEXT DEFAULT '{}',
                    confidence_score REAL NOT NULL,
                    confidence_level TEXT NOT NULL DEFAULT 'Medium',
                    reasons_json TEXT DEFAULT '[]',
                    provenance_json TEXT DEFAULT '{}',
                    created_at INTEGER NOT NULL,
                    FOREIGN KEY (job_id) REFERENCES faris_scan_jobs (job_id) ON DELETE CASCADE
                )
            """)

            # 6. Fragment Relationships
            conn.execute("""
                CREATE TABLE IF NOT EXISTS faris_fragment_relationships (
                    rel_id TEXT PRIMARY KEY,
                    job_id TEXT NOT NULL,
                    frag_a_offset INTEGER NOT NULL,
                    frag_b_offset INTEGER NOT NULL,
                    correlation_score REAL NOT NULL,
                    reasons_json TEXT DEFAULT '[]',
                    created_at INTEGER NOT NULL,
                    FOREIGN KEY (job_id) REFERENCES faris_scan_jobs (job_id) ON DELETE CASCADE
                )
            """)

            # 7. Timeline Events
            conn.execute("""
                CREATE TABLE IF NOT EXISTS faris_timeline_events (
                    event_id TEXT PRIMARY KEY,
                    case_id TEXT NOT NULL,
                    job_id TEXT NOT NULL,
                    record_id TEXT,
                    timestamp_str TEXT NOT NULL,
                    event_type TEXT NOT NULL DEFAULT 'Artifact Event',
                    summary TEXT NOT NULL,
                    confidence REAL DEFAULT 80.0,
                    is_inferred INTEGER DEFAULT 0,
                    provenance_json TEXT DEFAULT '{}',
                    created_at INTEGER NOT NULL
                )
            """)

            # 8. Chain of Custody (Immutable Hash-Chained Log)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS faris_chain_events (
                    event_id TEXT PRIMARY KEY,
                    case_id TEXT NOT NULL,
                    evidence_id TEXT,
                    timestamp TEXT NOT NULL,
                    action TEXT NOT NULL,
                    actor TEXT NOT NULL DEFAULT 'System / FARIS',
                    details TEXT NOT NULL,
                    prev_hash TEXT NOT NULL,
                    event_hash TEXT NOT NULL,
                    sequence_num INTEGER NOT NULL
                )
            """)

            # 9. Reports
            conn.execute("""
                CREATE TABLE IF NOT EXISTS faris_reports (
                    report_id TEXT PRIMARY KEY,
                    case_id TEXT NOT NULL,
                    evidence_id TEXT,
                    job_id TEXT,
                    format TEXT NOT NULL,
                    report_name TEXT NOT NULL,
                    file_path TEXT NOT NULL,
                    summary_json TEXT DEFAULT '{}',
                    created_at INTEGER NOT NULL
                )
            """)

            # 10. Evaluations / Benchmarks
            conn.execute("""
                CREATE TABLE IF NOT EXISTS faris_evaluations (
                    eval_id TEXT PRIMARY KEY,
                    dataset_name TEXT NOT NULL,
                    damage_scenario TEXT NOT NULL,
                    ground_truth_records INTEGER NOT NULL,
                    recovered_records INTEGER NOT NULL,
                    correct_records INTEGER NOT NULL,
                    false_positives INTEGER NOT NULL,
                    precision_rate REAL NOT NULL,
                    recall_rate REAL NOT NULL,
                    f1_score REAL NOT NULL,
                    duration_sec REAL NOT NULL,
                    standard_sqlite_recovered INTEGER DEFAULT 0,
                    created_at INTEGER NOT NULL
                )
            """)

            # Indices for rapid querying
            conn.execute("CREATE INDEX IF NOT EXISTS idx_faris_evidence_case ON faris_evidence(case_id)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_faris_jobs_evidence ON faris_scan_jobs(evidence_id)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_faris_records_job ON faris_recovered_records(job_id)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_faris_timeline_case ON faris_timeline_events(case_id)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_faris_chain_case ON faris_chain_events(case_id)")

    finally:
        conn.close()
