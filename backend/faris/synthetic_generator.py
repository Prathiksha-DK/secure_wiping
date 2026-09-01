import sqlite3
import os
import time
import json
import uuid
from .config import FARIS_LAB_DIR

def generate_synthetic_database(num_records: int = 50) -> dict:
    """Generate a clean synthetic SQLite database with known ground truth records for testing."""
    os.makedirs(FARIS_LAB_DIR, exist_ok=True)
    db_id = f"synth_{uuid.uuid4().hex[:6]}"
    db_filename = f"{db_id}_ground_truth.db"
    db_path = os.path.join(FARIS_LAB_DIR, db_filename)

    conn = sqlite3.connect(db_path)
    ground_truth = {
        "db_filename": db_filename,
        "db_path": db_path,
        "tables": {
            "users": [],
            "messages": [],
            "transactions": []
        },
        "total_records": 0
    }

    try:
        with conn:
            conn.execute("""
                CREATE TABLE users (
                    id INTEGER PRIMARY KEY,
                    username TEXT NOT NULL,
                    email TEXT NOT NULL,
                    role TEXT NOT NULL,
                    created_at TEXT NOT NULL
                )
            """)

            conn.execute("""
                CREATE TABLE messages (
                    id INTEGER PRIMARY KEY,
                    sender TEXT NOT NULL,
                    recipient TEXT NOT NULL,
                    content TEXT NOT NULL,
                    sent_at TEXT NOT NULL
                )
            """)

            conn.execute("""
                CREATE TABLE transactions (
                    id INTEGER PRIMARY KEY,
                    account_id INTEGER NOT NULL,
                    amount REAL NOT NULL,
                    currency TEXT NOT NULL,
                    status TEXT NOT NULL,
                    tx_time INTEGER NOT NULL
                )
            """)

            users_data = [
                ("alice_sec", "alice@enterprise.org", "Administrator", "2026-08-15 08:30:00"),
                ("bob_ops", "bob@enterprise.org", "Operator", "2026-08-15 09:15:00"),
                ("charlie_audit", "charlie@enterprise.org", "Auditor", "2026-08-15 10:00:00"),
                ("david_dev", "david@enterprise.org", "Engineer", "2026-08-15 11:20:00"),
                ("eva_analyst", "eva@enterprise.org", "Forensic Specialist", "2026-08-15 12:45:00")
            ]

            for u in users_data:
                cur = conn.execute(
                    "INSERT INTO users (username, email, role, created_at) VALUES (?, ?, ?, ?)",
                    u
                )
                ground_truth["tables"]["users"].append({
                    "id": cur.lastrowid, "username": u[0], "email": u[1], "role": u[2], "created_at": u[3]
                })

            messages_templates = [
                ("alice_sec", "bob_ops", "Confirming server maintenance window at 22:00 UTC", "2026-08-20 14:10:00"),
                ("bob_ops", "alice_sec", "Backup snapshot completed successfully before routine wipe", "2026-08-20 14:15:22"),
                ("charlie_audit", "alice_sec", "Audit certificate request for compliance review", "2026-08-21 09:04:10"),
                ("david_dev", "bob_ops", "Deploying forensic module FARIS to production cluster", "2026-08-21 10:30:00"),
                ("eva_analyst", "charlie_audit", "Chain of custody log verified with SHA-256 integrity", "2026-08-21 16:45:11"),
                ("alice_sec", "david_dev", "Security verification test scheduled for tomorrow", "2026-08-22 08:12:30"),
                ("bob_ops", "eva_analyst", "Target device HP v236w connected to port 8743", "2026-08-22 11:00:00"),
                ("charlie_audit", "david_dev", "Report generated for forensic case archive", "2026-08-22 15:20:00")
            ]

            # Generate messages up to num_records / 2
            for i in range(max(10, num_records // 2)):
                tmpl = messages_templates[i % len(messages_templates)]
                cur = conn.execute(
                    "INSERT INTO messages (sender, recipient, content, sent_at) VALUES (?, ?, ?, ?)",
                    (tmpl[0], tmpl[1], f"{tmpl[2]} [Seq #{i+1}]", tmpl[3])
                )
                ground_truth["tables"]["messages"].append({
                    "id": cur.lastrowid, "sender": tmpl[0], "recipient": tmpl[1], "content": f"{tmpl[2]} [Seq #{i+1}]", "sent_at": tmpl[3]
                })

            # Generate transactions
            base_time = 1787200000
            for i in range(max(10, num_records // 2)):
                cur = conn.execute(
                    "INSERT INTO transactions (account_id, amount, currency, status, tx_time) VALUES (?, ?, ?, ?, ?)",
                    (1000 + (i % 5), round(150.0 + (i * 24.5), 2), "USD", "COMPLETED", base_time + (i * 3600))
                )
                ground_truth["tables"]["transactions"].append({
                    "id": cur.lastrowid, "account_id": 1000 + (i % 5), "amount": round(150.0 + (i * 24.5), 2), "currency": "USD", "status": "COMPLETED", "tx_time": base_time + (i * 3600)
                })

            total_rec = len(ground_truth["tables"]["users"]) + len(ground_truth["tables"]["messages"]) + len(ground_truth["tables"]["transactions"])
            ground_truth["total_records"] = total_rec

    finally:
        conn.close()

    gt_path = os.path.join(FARIS_LAB_DIR, f"{db_id}_ground_truth.json")
    with open(gt_path, "w", encoding="utf-8") as f:
        json.dump(ground_truth, f, indent=2)

    return {
        "db_filename": db_filename,
        "db_path": db_path,
        "file_size": os.path.getsize(db_path),
        "total_records": ground_truth["total_records"],
        "ground_truth_path": gt_path,
        "tables": {k: len(v) for k, v in ground_truth["tables"].items()}
    }
