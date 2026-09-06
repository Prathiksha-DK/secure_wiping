"""
Secure Authentication & Role-Based Access Control (RBAC) Module
Part of NTRO Adaptive Sanitization & Forensic Recovery Platform.

Roles:
  - individual: Personal device sanitization, health assessment, certificate retrieval, marketplace.
  - government: LAN device discovery, authorized remote/bulk sanitization, audit compliance.
  - forensic: Case management, read-only inspection, file carving, recovery assessment, reporting.
"""

import os
import sqlite3
import hashlib
import secrets
import time
from typing import Dict, Any, Optional, Tuple

DB_DIR = os.path.join(os.path.dirname(__file__), "data")
PLATFORM_DB = os.path.join(DB_DIR, "platform.db")

ROLES = {
    "individual": {
        "label": "Individual User",
        "description": "Personal device sanitization, health assessment & private marketplace",
        "allowed_routes": ["/individual", "/api/sanitization", "/api/lifecycle", "/api/certificates"]
    },
    "government": {
        "label": "Government / Organization User",
        "description": "LAN fleet discovery, authorized remote wipe & compliance audits",
        "allowed_routes": ["/government", "/api/devices", "/api/sanitization", "/api/audit", "/api/certificates"]
    },
    "forensic": {
        "label": "Forensic Investigator",
        "description": "Evidence preservation, read-only inspection, deep file carving & reporting",
        "allowed_routes": ["/forensic", "/api/forensics", "/api/inspector", "/faris", "/api/audit"]
    }
}

SESSION_TTL_SECONDS = 24 * 3600  # 24 hours


def get_db() -> sqlite3.Connection:
    os.makedirs(DB_DIR, exist_ok=True)
    conn = sqlite3.connect(PLATFORM_DB)
    conn.row_factory = sqlite3.Row
    return conn


def init_platform_db() -> None:
    """Initialize all platform tables including users, sessions, devices, and audit."""
    conn = get_db()
    try:
        with conn:
            # 1. Users Table
            conn.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE NOT NULL,
                    password_hash TEXT NOT NULL,
                    salt TEXT NOT NULL,
                    role TEXT NOT NULL,
                    email TEXT DEFAULT '',
                    organization TEXT DEFAULT '',
                    status TEXT NOT NULL DEFAULT 'active',
                    failed_attempts INTEGER NOT NULL DEFAULT 0,
                    last_login_at INTEGER DEFAULT 0,
                    created_at INTEGER NOT NULL
                )
            """)

            # 2. Sessions Table
            conn.execute("""
                CREATE TABLE IF NOT EXISTS sessions (
                    token TEXT PRIMARY KEY,
                    user_id INTEGER NOT NULL,
                    username TEXT NOT NULL,
                    role TEXT NOT NULL,
                    created_at INTEGER NOT NULL,
                    expires_at INTEGER NOT NULL,
                    FOREIGN KEY (user_id) REFERENCES users(id)
                )
            """)

            # 3. Devices Table
            conn.execute("""
                CREATE TABLE IF NOT EXISTS devices (
                    id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    connection_type TEXT NOT NULL DEFAULT 'local', -- local, gov_lan, remote
                    serial_number TEXT DEFAULT '',
                    bus_type TEXT DEFAULT '',
                    media_type TEXT DEFAULT 'HDD', -- HDD, SSD, USB
                    capacity_bytes INTEGER DEFAULT 0,
                    health_status TEXT DEFAULT 'Healthy',
                    health_score INTEGER DEFAULT 100,
                    ip_address TEXT DEFAULT '127.0.0.1',
                    agent_version TEXT DEFAULT '1.0.0',
                    is_authorized INTEGER DEFAULT 1,
                    authorized_by TEXT DEFAULT '',
                    status TEXT DEFAULT 'online', -- online, offline, paired, pending_auth
                    last_seen INTEGER NOT NULL
                )
            """)

            # 4. Hash-Chained Audit Logs Table
            conn.execute("""
                CREATE TABLE IF NOT EXISTS audit_logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    sequence INTEGER UNIQUE NOT NULL,
                    prev_hash TEXT NOT NULL,
                    curr_hash TEXT NOT NULL,
                    timestamp TEXT NOT NULL,
                    user_id TEXT NOT NULL,
                    role TEXT NOT NULL,
                    device_id TEXT DEFAULT '',
                    operation TEXT NOT NULL,
                    status TEXT NOT NULL,
                    details_json TEXT DEFAULT '{}'
                )
            """)

            # 5. Certificates Table
            conn.execute("""
                CREATE TABLE IF NOT EXISTS certificates (
                    id TEXT PRIMARY KEY,
                    certificate_number TEXT UNIQUE NOT NULL,
                    job_id TEXT NOT NULL,
                    device_info_json TEXT NOT NULL,
                    sanitization_method TEXT NOT NULL,
                    verification_result TEXT NOT NULL,
                    recovery_assessment TEXT NOT NULL,
                    final_state TEXT NOT NULL,
                    operator_name TEXT NOT NULL,
                    sha256_digest TEXT NOT NULL,
                    created_at INTEGER NOT NULL
                )
            """)

            # 6. Forensic Cases Table
            conn.execute("""
                CREATE TABLE IF NOT EXISTS forensic_cases (
                    id TEXT PRIMARY KEY,
                    case_number TEXT UNIQUE NOT NULL,
                    title TEXT NOT NULL,
                    investigator TEXT NOT NULL,
                    target_source TEXT NOT NULL,
                    evidence_level TEXT NOT NULL,
                    confidence_score REAL NOT NULL,
                    artifacts_json TEXT NOT NULL,
                    report_hash TEXT NOT NULL,
                    created_at INTEGER NOT NULL
                )
            """)

            # 7. Private Marketplace Listings Table
            conn.execute("""
                CREATE TABLE IF NOT EXISTS marketplace_listings (
                    id TEXT PRIMARY KEY,
                    device_id TEXT NOT NULL,
                    certificate_id TEXT NOT NULL,
                    seller_name TEXT NOT NULL,
                    device_title TEXT NOT NULL,
                    media_type TEXT NOT NULL,
                    capacity_gb REAL NOT NULL,
                    health_score INTEGER NOT NULL,
                    estimated_value_inr INTEGER NOT NULL,
                    status TEXT NOT NULL DEFAULT 'listed', -- listed, transferred, ewaste
                    agreement_terms TEXT DEFAULT '',
                    created_at INTEGER NOT NULL
                )
            """)

        # Seed initial default role accounts if empty
        _seed_default_users(conn)
    finally:
        conn.close()


def _hash_password(password: str, salt: Optional[str] = None) -> Tuple[str, str]:
    if salt is None:
        salt = secrets.token_hex(16)
    # PBKDF2-HMAC-SHA256 with 100,000 iterations
    pwd_bytes = password.encode("utf-8")
    salt_bytes = salt.encode("utf-8")
    key = hashlib.pbkdf2_hmac("sha256", pwd_bytes, salt_bytes, 100000)
    return key.hex(), salt


def _verify_password(password: str, salt: str, expected_hash: str) -> bool:
    calc_hash, _ = _hash_password(password, salt)
    return secrets.compare_digest(calc_hash, expected_hash)


def _seed_default_users(conn: sqlite3.Connection) -> None:
    cur = conn.cursor()
    cur.execute("SELECT COUNT(*) FROM users")
    count = cur.fetchone()[0]
    if count == 0:
        default_accounts = [
            ("citizen_user", "Individual@2026", "individual", "citizen@securewipe.gov.in", "Public Sector / Citizen"),
            ("gov_officer", "GovAdmin@2026", "government", "officer@gov.ntro.in", "National Technical Research Org"),
            ("forensic_analyst", "Forensic@2026", "forensic", "investigator@forensics.ntro.in", "Cyber Forensic Division"),
        ]
        now = int(time.time())
        for uname, pwd, role, email, org in default_accounts:
            h, s = _hash_password(pwd)
            cur.execute("""
                INSERT INTO users (username, password_hash, salt, role, email, organization, status, created_at)
                VALUES (?, ?, ?, ?, ?, ?, 'active', ?)
            """, (uname, h, s, role, email, org, now))
        conn.commit()


def authenticate_user(username: str, password: str) -> Tuple[bool, str, Optional[Dict[str, Any]]]:
    """Authenticate username and password. Checks lockout and updates last login."""
    conn = get_db()
    try:
        cur = conn.cursor()
        cur.execute("SELECT * FROM users WHERE username = ?", (username.strip(),))
        user = cur.fetchone()

        if not user:
            return False, "Invalid username or password", None

        user_dict = dict(user)

        if user_dict["status"] != "active":
            return False, "Account is suspended. Contact system administrator.", None

        if user_dict["failed_attempts"] >= 5:
            return False, "Account locked due to 5 consecutive failed logins.", None

        if not _verify_password(password, user_dict["salt"], user_dict["password_hash"]):
            # Increment failed attempts
            cur.execute("UPDATE users SET failed_attempts = failed_attempts + 1 WHERE id = ?", (user_dict["id"],))
            conn.commit()
            return False, "Invalid username or password", None

        # Reset failed attempts and record login
        now = int(time.time())
        cur.execute("UPDATE users SET failed_attempts = 0, last_login_at = ? WHERE id = ?", (now, user_dict["id"]))

        # Create session
        token = secrets.token_urlsafe(32)
        expires_at = now + SESSION_TTL_SECONDS
        cur.execute("""
            INSERT INTO sessions (token, user_id, username, role, created_at, expires_at)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (token, user_dict["id"], user_dict["username"], user_dict["role"], now, expires_at))
        conn.commit()

        return True, "Login successful", {
            "token": token,
            "user_id": user_dict["id"],
            "username": user_dict["username"],
            "role": user_dict["role"],
            "role_label": ROLES.get(user_dict["role"], {}).get("label", user_dict["role"]),
            "email": user_dict["email"],
            "organization": user_dict["organization"],
            "expires_at": expires_at
        }
    finally:
        conn.close()


def register_user(username: str, password: str, role: str, email: str = "", org: str = "") -> Tuple[bool, str]:
    """Register a new user account with role enforcement."""
    if role not in ROLES:
        return False, f"Invalid role. Must be one of: {list(ROLES.keys())}"
    if len(password) < 8:
        return False, "Password must be at least 8 characters long."

    conn = get_db()
    try:
        cur = conn.cursor()
        cur.execute("SELECT id FROM users WHERE username = ?", (username.strip(),))
        if cur.fetchone():
            return False, "Username already exists"

        h, s = _hash_password(password)
        now = int(time.time())
        cur.execute("""
            INSERT INTO users (username, password_hash, salt, role, email, organization, status, created_at)
            VALUES (?, ?, ?, ?, ?, ?, 'active', ?)
        """, (username.strip(), h, s, role, email.strip(), org.strip(), now))
        conn.commit()
        return True, "User registered successfully"
    except Exception as e:
        return False, str(e)
    finally:
        conn.close()


def validate_session(token: str) -> Optional[Dict[str, Any]]:
    """Validate a session token and return user details if valid and unexpired."""
    if not token:
        return None
    conn = get_db()
    try:
        cur = conn.cursor()
        now = int(time.time())
        cur.execute("""
            SELECT s.token, s.user_id, s.username, s.role, s.expires_at, u.email, u.organization, u.status
            FROM sessions s
            JOIN users u ON s.user_id = u.id
            WHERE s.token = ? AND s.expires_at > ?
        """, (token, now))
        row = cur.fetchone()
        if not row or row["status"] != "active":
            return None
        return dict(row)
    finally:
        conn.close()


def terminate_session(token: str) -> bool:
    """Invalidate session token upon logout."""
    conn = get_db()
    try:
        with conn:
            conn.execute("DELETE FROM sessions WHERE token = ?", (token,))
        return True
    except Exception:
        return False
    finally:
        conn.close()
