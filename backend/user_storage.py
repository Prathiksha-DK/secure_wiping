import os
import sqlite3
import time
from typing import Dict

DB_DIR = os.path.join(os.path.dirname(__file__), "data")
DB_PATH = os.path.join(DB_DIR, "storage.db")


def init_db() -> None:
    os.makedirs(DB_DIR, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    try:
        with conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT NOT NULL,
                    companyName TEXT,
                    position TEXT,
                    address TEXT,
                    personalInfo TEXT,
                    created_at INTEGER NOT NULL
                )
                """
            )
            conn.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_users_username ON users(username)
                """
            )
    finally:
        conn.close()


essential_fields = ["username"]


def insert_user(payload: Dict) -> int:
    username = (payload.get("username") or "").strip()
    if not username:
        raise ValueError("'username' is required")

    companyName = (payload.get("companyName") or "").strip()
    position = (payload.get("position") or "").strip()
    address = (payload.get("address") or "").strip()
    personalInfo = (payload.get("personalInfo") or "").strip()
    ts = int(time.time())

    conn = sqlite3.connect(DB_PATH)
    try:
        with conn:
            cur = conn.execute(
                """
                INSERT INTO users (username, companyName, position, address, personalInfo, created_at)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (username, companyName, position, address, personalInfo, ts),
            )
            return int(cur.lastrowid)
    finally:
        conn.close()


def get_user_by_username(username: str):
    uname = (username or "").strip()
    if not uname:
        raise ValueError("'username' is required")
    conn = sqlite3.connect(DB_PATH)
    try:
        conn.row_factory = sqlite3.Row
        cur = conn.execute(
            "SELECT companyName, position, address, personalInfo FROM users WHERE username = ? ORDER BY id DESC LIMIT 1",
            (uname,),
        )
        row = cur.fetchone()
        if not row:
            return None
        return {
            "companyName": row["companyName"],
            "position": row["position"],
            "address": row["address"],
            "personalInfo": row["personalInfo"],
        }
    finally:
        conn.close()

