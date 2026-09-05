"""
SecureWipe — Security Configuration & Authentication/Authorization Module
Provides environment management, cryptographic password hashing, signed session tokens,
and role-based access control (RBAC).
"""

import os
import sys
import time
import json
import hmac
import base64
import hashlib
import sqlite3
import secrets
import tempfile
from typing import Dict, Any, Optional, Tuple, List
from functools import wraps
from flask import request, jsonify

# ---------------------------------------------------------------------------
# Environment Modes
# ---------------------------------------------------------------------------
ENV_DEVELOPMENT = "DEVELOPMENT"
ENV_TEST = "TEST"
ENV_PRODUCTION = "PRODUCTION"

APP_ENV = os.environ.get("SECUREWIPE_ENV", os.environ.get("NODE_ENV", ENV_DEVELOPMENT)).upper()
if APP_ENV not in (ENV_DEVELOPMENT, ENV_TEST, ENV_PRODUCTION):
    APP_ENV = ENV_DEVELOPMENT

IS_PRODUCTION = (APP_ENV == ENV_PRODUCTION)
IS_TEST = (APP_ENV == ENV_TEST)
IS_DEVELOPMENT = (APP_ENV == ENV_DEVELOPMENT)

# ---------------------------------------------------------------------------
# Secret Keys & Cryptographic Configuration
# ---------------------------------------------------------------------------
_DEFAULT_DEV_SECRET = "securewipe-insecure-dev-secret-key-do-not-use-in-prod-0987654321"

def get_secret_key() -> str:
    key = os.environ.get("SECUREWIPE_SECRET_KEY")
    if key:
        return key
    if IS_PRODUCTION:
        raise RuntimeError("CRITICAL SECURITY ERROR: SECUREWIPE_SECRET_KEY environment variable MUST be set in PRODUCTION mode.")
    return _DEFAULT_DEV_SECRET

# Host & Port Defaults
DEFAULT_HOST = "127.0.0.1" if IS_PRODUCTION else "0.0.0.0"
DEFAULT_PORT = int(os.environ.get("SECUREWIPE_PORT", "9758"))

# Allowed CORS Origins
ALLOWED_ORIGINS = os.environ.get("SECUREWIPE_ALLOWED_ORIGINS", "http://localhost:3000,http://127.0.0.1:3000,http://localhost:3001,http://127.0.0.1:3001").split(",")

# ---------------------------------------------------------------------------
# Role Definitions
# ---------------------------------------------------------------------------
ROLE_ADMINISTRATOR = "ADMINISTRATOR"
ROLE_OPERATOR = "OPERATOR"
ROLE_AUDITOR = "AUDITOR"
ROLE_VIEWER = "VIEWER"
ROLE_LEAD_INVESTIGATOR = "LEAD_INVESTIGATOR"
ROLE_FORENSIC_ANALYST = "FORENSIC_ANALYST"
ROLE_TRIAGE_ANALYST = "TRIAGE_ANALYST"
ROLE_REVIEWER = "REVIEWER"

ALL_ROLES = [
    ROLE_ADMINISTRATOR, ROLE_OPERATOR, ROLE_AUDITOR, ROLE_VIEWER,
    ROLE_LEAD_INVESTIGATOR, ROLE_FORENSIC_ANALYST, ROLE_TRIAGE_ANALYST, ROLE_REVIEWER
]

# Permissions mapping
ROLE_PERMISSIONS = {
    ROLE_ADMINISTRATOR: ["*"],
    ROLE_OPERATOR: [
        "device:read", "inspector:read", "sanitization:request", "sanitization:execute",
        "verification:execute", "certificate:generate", "certificate:read", "history:read",
        "compliance:read", "disposal:manage", "swarm:read", "swarm:triage"
    ],
    ROLE_AUDITOR: [
        "device:read", "inspector:read", "certificate:read", "certificate:verify",
        "history:read", "audit:read", "compliance:read", "readiness:read", "swarm:read", "swarm:audit"
    ],
    ROLE_VIEWER: [
        "device:read", "history:read", "stats:read", "swarm:read"
    ],
    ROLE_LEAD_INVESTIGATOR: [
        "device:read", "inspector:read", "swarm:read", "swarm:triage", "swarm:investigator",
        "swarm:verdict", "swarm:benchmark", "swarm:report", "audit:read", "certificate:read"
    ],
    ROLE_FORENSIC_ANALYST: [
        "device:read", "inspector:read", "swarm:read", "swarm:triage", "swarm:benchmark", "swarm:report"
    ],
    ROLE_TRIAGE_ANALYST: [
        "swarm:read", "swarm:triage"
    ],
    ROLE_REVIEWER: [
        "swarm:read", "swarm:triage", "swarm:review"
    ]
}

# ---------------------------------------------------------------------------
# Cryptographic Password Hashing (PBKDF2-HMAC-SHA256)
# ---------------------------------------------------------------------------
PBKDF2_ITERATIONS = 600_000

def hash_password(password: str, salt: Optional[bytes] = None) -> str:
    """Hash password using PBKDF2-HMAC-SHA256 with 600,000 iterations."""
    if not salt:
        salt = secrets.token_bytes(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, PBKDF2_ITERATIONS)
    salt_b64 = base64.b64encode(salt).decode("utf-8")
    hash_b64 = base64.b64encode(dk).decode("utf-8")
    return f"pbkdf2_sha256${PBKDF2_ITERATIONS}${salt_b64}${hash_b64}"

def verify_password(password: str, hashed: str) -> bool:
    """Verify password against formatted PBKDF2-HMAC-SHA256 hash."""
    try:
        parts = hashed.split("$")
        if len(parts) != 4 or parts[0] != "pbkdf2_sha256":
            return False
        iterations = int(parts[1])
        salt = base64.b64decode(parts[2].encode("utf-8"))
        expected_dk = base64.b64decode(parts[3].encode("utf-8"))
        dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
        return hmac.compare_digest(dk, expected_dk)
    except Exception:
        return False

# ---------------------------------------------------------------------------
# Signed Session Token Engine (HMAC-SHA256)
# ---------------------------------------------------------------------------
TOKEN_VALIDITY_SECONDS = 8 * 3600  # 8 hours

def generate_session_token(username: str, role: str, extra: Optional[Dict[str, Any]] = None) -> str:
    """Generate a tamper-proof HMAC-SHA256 signed session token."""
    now = int(time.time())
    payload = {
        "sub": username,
        "role": role,
        "iat": now,
        "exp": now + TOKEN_VALIDITY_SECONDS,
        "nonce": secrets.token_hex(8),
    }
    if extra:
        payload.update(extra)
    payload_json = json.dumps(payload, separators=(',', ':'), sort_keys=True)
    payload_b64 = base64.urlsafe_b64encode(payload_json.encode("utf-8")).decode("utf-8").rstrip("=")
    
    secret = get_secret_key().encode("utf-8")
    sig = hmac.new(secret, payload_b64.encode("utf-8"), hashlib.sha256).digest()
    sig_b64 = base64.urlsafe_b64encode(sig).decode("utf-8").rstrip("=")
    
    return f"{payload_b64}.{sig_b64}"

def verify_session_token(token: str) -> Optional[Dict[str, Any]]:
    """Verify signed session token and return claims if valid and unexpired."""
    if not token or "." not in token:
        return None
    try:
        parts = token.split(".")
        if len(parts) != 2:
            return None
        payload_b64, sig_b64 = parts
        
        # Verify signature
        secret = get_secret_key().encode("utf-8")
        expected_sig = hmac.new(secret, payload_b64.encode("utf-8"), hashlib.sha256).digest()
        expected_sig_b64 = base64.urlsafe_b64encode(expected_sig).decode("utf-8").rstrip("=")
        
        if not hmac.compare_digest(sig_b64, expected_sig_b64):
            return None
        
        # Decode payload
        rem = len(payload_b64) % 4
        padded = payload_b64 + ("=" * (4 - rem) if rem else "")
        payload_json = base64.urlsafe_b64decode(padded.encode("utf-8")).decode("utf-8")
        claims = json.loads(payload_json)
        
        # Check expiration
        now = int(time.time())
        if claims.get("exp", 0) < now:
            return None
            
        return claims
    except Exception:
        return None

# ---------------------------------------------------------------------------
# User Database Management
# ---------------------------------------------------------------------------
def _get_auth_db_path() -> str:
    data_dir = os.environ.get("SECUREWIPE_DATA_DIR")
    if not data_dir:
        data_dir = os.path.join(os.path.dirname(__file__), "data")
        try:
            os.makedirs(data_dir, exist_ok=True)
            # test write
            test_file = os.path.join(data_dir, ".write_test")
            with open(test_file, "w") as f:
                f.write("ok")
            os.remove(test_file)
        except Exception:
            data_dir = os.path.join(tempfile.gettempdir(), "securewipe_data")
            os.makedirs(data_dir, exist_ok=True)
    os.makedirs(data_dir, exist_ok=True)
    return os.path.join(data_dir, "auth.db")

AUTH_DB_PATH = _get_auth_db_path()

def init_auth_db() -> None:
    global AUTH_DB_PATH
    AUTH_DB_PATH = _get_auth_db_path()
    conn = sqlite3.connect(AUTH_DB_PATH)
    try:
        with conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE NOT NULL,
                    password_hash TEXT NOT NULL,
                    role TEXT NOT NULL,
                    full_name TEXT DEFAULT '',
                    email TEXT DEFAULT '',
                    organization TEXT DEFAULT '',
                    created_at INTEGER NOT NULL,
                    is_active INTEGER DEFAULT 1
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS failed_logins (
                    ip_address TEXT PRIMARY KEY,
                    attempts INTEGER DEFAULT 0,
                    last_attempt INTEGER DEFAULT 0,
                    locked_until INTEGER DEFAULT 0
                )
            """)
            
            # Seed default users if empty
            cursor = conn.execute("SELECT COUNT(*) FROM users")
            if cursor.fetchone()[0] == 0:
                # Seed Master Administrator (default credentials - operator must change in prod)
                admin_hash = hash_password("iamironman")
                worker_hash = hash_password("iambenten")
                auditor_hash = hash_password("auditor2026")
                
                conn.execute("""
                    INSERT INTO users (username, password_hash, role, full_name, email, organization, created_at, is_active)
                    VALUES (?, ?, ?, ?, ?, ?, ?, 1)
                """, ("Madhan", admin_hash, ROLE_ADMINISTRATOR, "Master Administrator", "admin@securewipe.local", "SecureWipe Core", int(time.time())))
                
                conn.execute("""
                    INSERT INTO users (username, password_hash, role, full_name, email, organization, created_at, is_active)
                    VALUES (?, ?, ?, ?, ?, ?, ?, 1)
                """, ("Worker", worker_hash, ROLE_OPERATOR, "Field Sanitization Operator", "operator@securewipe.local", "Operations", int(time.time())))

                conn.execute("""
                    INSERT INTO users (username, password_hash, role, full_name, email, organization, created_at, is_active)
                    VALUES (?, ?, ?, ?, ?, ?, ?, 1)
                """, ("Auditor", auditor_hash, ROLE_AUDITOR, "Compliance Auditor", "auditor@securewipe.local", "Audit Dept", int(time.time())))
    finally:
        conn.close()

def authenticate_user(username: str, password: str, client_ip: str = "127.0.0.1") -> Tuple[bool, str, Optional[Dict[str, Any]]]:
    """Authenticate user with rate-limiting & brute force protection."""
    now = int(time.time())
    conn = sqlite3.connect(AUTH_DB_PATH)
    try:
        # Check IP lock
        conn.row_factory = sqlite3.Row
        lock_row = conn.execute("SELECT attempts, locked_until FROM failed_logins WHERE ip_address = ?", (client_ip,)).fetchone()
        if lock_row and lock_row["locked_until"] > now:
            remaining = lock_row["locked_until"] - now
            return False, f"Too many failed attempts. Try again in {remaining} seconds.", None
        
        user_row = conn.execute("SELECT id, username, password_hash, role, full_name, email, is_active FROM users WHERE username = ?", (username,)).fetchone()
        if not user_row:
            _record_failed_attempt(conn, client_ip, now)
            return False, "Invalid username or password.", None
            
        if not user_row["is_active"]:
            return False, "Account is disabled. Contact an administrator.", None
            
        if not verify_password(password, user_row["password_hash"]):
            _record_failed_attempt(conn, client_ip, now)
            return False, "Invalid username or password.", None
            
        # Reset failed attempts on success
        with conn:
            conn.execute("DELETE FROM failed_logins WHERE ip_address = ?", (client_ip,))
            
        user_data = {
            "id": user_row["id"],
            "username": user_row["username"],
            "role": user_row["role"],
            "full_name": user_row["full_name"],
            "email": user_row["email"],
        }
        token = generate_session_token(user_row["username"], user_row["role"])
        user_data["token"] = token
        return True, "Authenticated successfully.", user_data
    finally:
        conn.close()

def _record_failed_attempt(conn: sqlite3.Connection, client_ip: str, now: int) -> None:
    with conn:
        row = conn.execute("SELECT attempts FROM failed_logins WHERE ip_address = ?", (client_ip,)).fetchone()
        attempts = (row[0] + 1) if row else 1
        locked_until = (now + 300) if attempts >= 5 else 0  # 5 minute lock
        conn.execute("""
            INSERT OR REPLACE INTO failed_logins (ip_address, attempts, last_attempt, locked_until)
            VALUES (?, ?, ?, ?)
        """, (client_ip, attempts, now, locked_until))

# ---------------------------------------------------------------------------
# Flask Authentication & RBAC Decorators
# ---------------------------------------------------------------------------
def extract_auth_claims() -> Optional[Dict[str, Any]]:
    """Extract and verify token from Authorization header or cookie."""
    auth_header = request.headers.get("Authorization", "")
    token = None
    if auth_header.startswith("Bearer "):
        token = auth_header[7:].strip()
    elif "session_token" in request.cookies:
        token = request.cookies.get("session_token")
    elif "session" in request.cookies:
        try:
            raw = request.cookies.get("session")
            if raw and raw.startswith("{"):
                parsed = json.loads(raw)
                token = parsed.get("token")
        except Exception:
            pass
            
    if not token:
        return None
    return verify_session_token(token)

def require_auth(allowed_roles: Optional[List[str]] = None):
    """Decorator to enforce valid authentication and optional role restrictions."""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            claims = extract_auth_claims()
            if not claims:
                # In development mode or local loopback connection, fallback to local Master Administrator
                remote = request.remote_addr or "127.0.0.1"
                if IS_DEVELOPMENT or remote in ("127.0.0.1", "::1", "localhost"):
                    request.current_user = {"sub": "Madhan", "role": ROLE_ADMINISTRATOR}
                    return f(*args, **kwargs)
                return jsonify({"status": "error", "code": "UNAUTHORIZED", "message": "Authentication required. Please provide a valid Bearer token."}), 401
            
            user_role = claims.get("role", "")
            if allowed_roles and user_role not in allowed_roles and user_role != ROLE_ADMINISTRATOR:
                return jsonify({
                    "status": "error",
                    "code": "FORBIDDEN",
                    "message": f"Access denied. Role '{user_role}' is not authorized for this operation. Required: {allowed_roles}"
                }), 403
                
            request.current_user = claims
            return f(*args, **kwargs)
        return decorated_function
    return decorator
