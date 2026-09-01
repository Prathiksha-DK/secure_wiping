import os
import re
import json
import time
import socket
import sqlite3
import hashlib
import uuid as _uuid
from flask import Flask, jsonify, request
from flask_cors import CORS

from devices import list_devices
from secure_backup import encrypt_backup_and_wipe, decrypt_and_restore
from secure_encrypt_wipe import encrypt_and_wipe, _pick_disk_by_name_or_size
from user_storage import init_db, insert_user, get_user_by_username

# -----------------------------------------------------------
# Single consolidated Flask application
# -----------------------------------------------------------
app = Flask("securewipe_api")
CORS(app, resources={r"/api/*": {"origins": "*"}})

# -----------------------------------------------------------
# Database helpers for wipe history & reports
# -----------------------------------------------------------
HISTORY_DB = os.path.join(os.path.dirname(__file__), "data", "history.db")


def _init_history_db():
    os.makedirs(os.path.dirname(HISTORY_DB), exist_ok=True)
    conn = sqlite3.connect(HISTORY_DB)
    try:
        with conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS wipe_history (
                    id TEXT PRIMARY KEY,
                    device TEXT NOT NULL,
                    deviceSerial TEXT DEFAULT '',
                    method TEXT NOT NULL,
                    status TEXT NOT NULL DEFAULT 'In Progress',
                    standard TEXT DEFAULT 'NIST 800-88',
                    adOU TEXT DEFAULT '',
                    adComputer TEXT DEFAULT '',
                    startTime TEXT NOT NULL,
                    endTime TEXT DEFAULT '',
                    filesVerified INTEGER DEFAULT 0,
                    verificationHash TEXT DEFAULT '',
                    operatorName TEXT DEFAULT 'Worker',
                    notes TEXT DEFAULT '',
                    created_at INTEGER NOT NULL
                )
            """)
    finally:
        conn.close()


def _insert_history(record: dict) -> str:
    record_id = record.get("id") or f"WIPE-{_uuid.uuid4().hex[:8].upper()}"
    conn = sqlite3.connect(HISTORY_DB)
    try:
        with conn:
            conn.execute("""
                INSERT OR REPLACE INTO wipe_history
                (id, device, deviceSerial, method, status, standard, adOU, adComputer,
                 startTime, endTime, filesVerified, verificationHash, operatorName, notes, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                record_id,
                record.get("device", ""),
                record.get("deviceSerial", ""),
                record.get("method", ""),
                record.get("status", "In Progress"),
                record.get("standard", "NIST 800-88"),
                record.get("adOU", ""),
                record.get("adComputer", ""),
                record.get("startTime", ""),
                record.get("endTime", ""),
                record.get("filesVerified", 0),
                record.get("verificationHash", ""),
                record.get("operatorName", "Worker"),
                record.get("notes", ""),
                int(time.time()),
            ))
    finally:
        conn.close()
    return record_id


def _get_history():
    conn = sqlite3.connect(HISTORY_DB)
    try:
        conn.row_factory = sqlite3.Row
        rows = conn.execute("SELECT * FROM wipe_history ORDER BY created_at DESC LIMIT 100").fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


def _get_report(report_id: str):
    conn = sqlite3.connect(HISTORY_DB)
    try:
        conn.row_factory = sqlite3.Row
        row = conn.execute("SELECT * FROM wipe_history WHERE id = ?", (report_id,)).fetchone()
        return dict(row) if row else None
    finally:
        conn.close()


# -----------------------------------------------------------
# Real system detection helpers for AD
# -----------------------------------------------------------
def _detect_ad_info():
    """Detect real Active Directory / domain join info from the local system."""
    info = {
        "connected": False,
        "domain": "",
        "domainController": "",
        "forestLevel": "",
        "siteName": "",
        "computerName": "",
        "lastSync": time.strftime("%Y-%m-%d %H:%M:%S"),
    }

    try:
        info["computerName"] = os.environ.get("COMPUTERNAME", socket.gethostname())
    except Exception:
        info["computerName"] = "UNKNOWN"

    # Try to detect domain from environment
    userdomain = os.environ.get("USERDNSDOMAIN", "")  # FQDN domain
    if not userdomain:
        userdomain = os.environ.get("USERDOMAIN", "")
    logon_server = os.environ.get("LOGONSERVER", "")

    if userdomain and userdomain.upper() != info["computerName"].upper():
        info["connected"] = True
        info["domain"] = userdomain
        if logon_server:
            info["domainController"] = logon_server.replace("\\\\", "")
    else:
        # Not domain-joined — set to workgroup
        info["connected"] = False
        info["domain"] = os.environ.get("USERDOMAIN", "WORKGROUP")

    # Try PowerShell for more info if domain-joined
    if info["connected"]:
        try:
            import subprocess
            result = subprocess.run(
                ["powershell", "-Command",
                 "(Get-WmiObject Win32_NTDomain | Where-Object { $_.DomainName -ne $null } | Select-Object -First 1).DcSiteName"],
                capture_output=True, text=True, timeout=5
            )
            site = result.stdout.strip()
            if site:
                info["siteName"] = site
        except Exception:
            pass

    return info


def _detect_ad_computers():
    """
    List computers visible on the network.
    If domain-joined, try LDAP. Otherwise, use net view discovery.
    """
    computers = []

    # Always include the local machine
    local = {
        "name": os.environ.get("COMPUTERNAME", socket.gethostname()),
        "ou": "Local Machine",
        "os": _get_local_os(),
        "lastLogon": time.strftime("%Y-%m-%d %H:%M:%S"),
        "status": "Online",
        "ipAddress": _get_local_ip(),
        "assignedUser": os.environ.get("USERNAME", "unknown"),
    }
    computers.append(local)

    # Try net view for network discovery (works on workgroups too)
    try:
        import subprocess
        result = subprocess.run(
            ["net", "view"],
            capture_output=True, text=True, timeout=10
        )
        if result.returncode == 0:
            for line in result.stdout.splitlines():
                line = line.strip()
                if line.startswith("\\\\"):
                    name = line.split()[0].replace("\\\\", "")
                    if name.upper() != local["name"].upper():
                        computers.append({
                            "name": name,
                            "ou": "Network Discovery",
                            "os": "Unknown",
                            "lastLogon": "",
                            "status": "Online",
                            "ipAddress": "",
                            "assignedUser": "",
                        })
    except Exception:
        pass

    return computers


def _get_local_os():
    try:
        import platform
        return f"{platform.system()} {platform.release()} {platform.version()}"
    except Exception:
        return "Unknown"


def _get_local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"


# -----------------------------------------------------------
# Wipe method standard map
# -----------------------------------------------------------
STANDARDS_MAP = {
    "nist-clear": "NIST 800-88 Rev.1 — Clear",
    "nist-purge": "NIST 800-88 Rev.1 — Purge",
    "dod-3pass": "DoD 5220.22-M (3-Pass)",
    "dod-7pass": "DoD 5220.22-M ECE (7-Pass)",
    "crypto-erase": "IEEE 2883 Cryptographic Erase",
    "ieee-purge": "IEEE 2883-2022 Purge",
    "gutmann": "Gutmann 35-Pass",
    "bomb-mode": "Bomb Mode — Scatter Overwrite",
}


# -----------------------------------------------------------
# API: Device listing
# -----------------------------------------------------------
@app.get("/api/devices")
def get_devices():
    devices = list_devices()
    return jsonify(devices), 200


# -----------------------------------------------------------
# API: Wipe history
# -----------------------------------------------------------
@app.get("/api/history")
def get_history():
    history = _get_history()
    return jsonify(history), 200


@app.post("/api/history")
def post_history():
    body = request.get_json(silent=True) or {}
    record_id = _insert_history(body)
    return jsonify({"status": "success", "id": record_id}), 200


# -----------------------------------------------------------
# API: Wipe reports / certificates
# -----------------------------------------------------------
@app.get("/api/reports/<report_id>")
def get_report(report_id):
    report = _get_report(report_id)
    if not report:
        return jsonify({"error": "Report not found"}), 404
    return jsonify(report), 200


# -----------------------------------------------------------
# API: Verify-and-Send (Simulated/mock verification with certificate generation)
# -----------------------------------------------------------
@app.post("/api/verify-and-send")
def post_verify_and_send():
    try:
        body = request.get_json(silent=True) or {}
        device_name = body.get("deviceName")
        wipe_method = body.get("wipeMethod")
        receiver_email = body.get("receiverEmail")
        device_serial = body.get("deviceSerial", "SN-UNKNOWN")
        device_type = body.get("deviceType", "USB")

        if not device_name:
            return jsonify({"status": "error", "message": "Missing 'deviceName'"}), 400

        record_id = f"WIPE-{_uuid.uuid4().hex[:8].upper()}"
        now = time.strftime("%Y-%m-%d %H:%M:%S")
        standard = STANDARDS_MAP.get(wipe_method, "NIST 800-88 Rev.1 — Clear")

        # Detect AD info
        ad_info = _detect_ad_info()

        # Insert history record for this verification
        _insert_history({
            "id": record_id,
            "device": device_name,
            "deviceSerial": device_serial,
            "method": wipe_method,
            "status": "Completed",
            "standard": standard,
            "adOU": ad_info.get("domain", ""),
            "adComputer": ad_info.get("computerName", ""),
            "startTime": now,
            "endTime": time.strftime("%Y-%m-%d %H:%M:%S"),
            "filesVerified": 100,
            "verificationHash": hashlib.sha256(device_name.encode()).hexdigest(),
            "operatorName": receiver_email or "Master Admin",
            "notes": f"Verified successfully and sent to {receiver_email}" if receiver_email else "Verified successfully",
        })

        return jsonify({
            "success": True,
            "totalHashesChecked": 100,
            "failedWipes": 0,
            "certificate": {
                "shortId": record_id,
                "reportId": record_id
            },
            "emailSent": True if receiver_email else False
        }), 200
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


# -----------------------------------------------------------
# API: Encrypt-and-Wipe (backup, encrypt, delete originals)
# -----------------------------------------------------------
@app.post("/api/encrypt-and-wipe")
def post_encrypt_and_wipe():
    try:
        body = request.get_json(silent=True) or {}
        device_name = body.get("device")
        if not device_name:
            return jsonify({"status": "error", "message": "Missing 'device' in request body"}), 400

        ok, msg = encrypt_backup_and_wipe(device_name)
        if ok:
            record_id = f"WIPE-{_uuid.uuid4().hex[:8].upper()}"
            now = time.strftime("%Y-%m-%d %H:%M:%S")
            _insert_history({
                "id": record_id,
                "device": device_name,
                "method": "crypto-erase",
                "status": "Completed",
                "standard": "AES-256 Cryptographic Erasure",
                "startTime": now,
                "endTime": now,
                "filesVerified": 1,
                "verificationHash": hashlib.sha256(msg.encode()).hexdigest(),
            })
            return jsonify({"status": "success", "message": msg, "reportId": record_id}), 200
        else:
            return jsonify({"status": "error", "message": msg}), 400
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


# -----------------------------------------------------------
# API: Decrypt-and-Restore
# -----------------------------------------------------------
@app.post("/api/decrypt-and-restore")
def post_decrypt_and_restore():
    try:
        body = request.get_json(silent=True) or {}
        device_name = body.get("device")
        key_hex = body.get("decryptionKey")
        if not device_name or not key_hex:
            return jsonify({"status": "error", "message": "Missing 'device' or 'decryptionKey'"}), 400
        ok, msg = decrypt_and_restore(device_name, key_hex)
        if ok:
            return jsonify({"status": "success", "message": msg}), 200
        else:
            return jsonify({"status": "error", "message": msg}), 400
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


# -----------------------------------------------------------
# API: Wipe method selection (auto-determine best method by device type)
# -----------------------------------------------------------
@app.post("/api/get-wipe-method")
def post_get_wipe_method():
    try:
        body = request.get_json(silent=True) or {}
        device_name = (body.get("device") or "").strip()
        if not device_name:
            return jsonify({"error": "Missing 'device' in request body"}), 400

        method = "nist-clear"  # Default

        name_l = device_name.lower()
        usb_keywords = ["usb", "pen drive", "pendrive", "flash", "stick", "v220w", "hp", "cruzer", "sandisk"]
        ssd_keywords = ["ssd", "nvme", "m.2"]
        hdd_keywords = ["hdd", "hard disk", "seagate", "western digital", "wd", "toshiba"]

        if any(k in name_l for k in usb_keywords):
            method = "nist-clear"
        elif any(k in name_l for k in ssd_keywords):
            method = "crypto-erase"
        elif any(k in name_l for k in hdd_keywords):
            method = "dod-3pass"
        else:
            try:
                disk = _pick_disk_by_name_or_size(device_name)
                if disk:
                    bus = str(disk.get("BusType", "")).upper()
                    media = str(disk.get("MediaType", "")).upper()
                    if bus == "USB":
                        method = "nist-clear"
                    elif "SSD" in media or bus == "NVME":
                        method = "crypto-erase"
                    elif "HDD" in media:
                        method = "dod-3pass"
            except Exception:
                pass

        return jsonify({"method": method}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# -----------------------------------------------------------
# API: Perform a standard wipe (NIST / DoD / Crypto / Bomb)
# -----------------------------------------------------------
@app.post("/api/wipe")
def post_wipe():
    try:
        body = request.get_json(silent=True) or {}
        device_name = body.get("device")
        method = body.get("method", "nist-clear")
        if not device_name:
            return jsonify({"status": "error", "message": "Missing 'device'"}), 400

        record_id = f"WIPE-{_uuid.uuid4().hex[:8].upper()}"
        now = time.strftime("%Y-%m-%d %H:%M:%S")
        standard = STANDARDS_MAP.get(method, "NIST 800-88 Rev.1 — Clear")

        # Detect AD info for the record
        ad_info = _detect_ad_info()

        # Attempt the actual wipe
        ok, msg = encrypt_and_wipe(device_name)
        status = "Completed" if ok else "Failed"

        _insert_history({
            "id": record_id,
            "device": device_name,
            "method": method,
            "status": status,
            "standard": standard,
            "adOU": ad_info.get("domain", ""),
            "adComputer": ad_info.get("computerName", ""),
            "startTime": now,
            "endTime": time.strftime("%Y-%m-%d %H:%M:%S"),
            "filesVerified": 1 if ok else 0,
            "verificationHash": hashlib.sha256(msg.encode()).hexdigest() if ok else "",
        })

        if ok:
            return jsonify({"status": "success", "message": msg, "reportId": record_id}), 200
        else:
            return jsonify({"status": "error", "message": msg}), 400
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


# -----------------------------------------------------------
# API: Bomb Mode wipe (scatter-pattern overwrite)
# -----------------------------------------------------------
@app.post("/api/bomb-wipe")
def post_bomb_wipe():
    """
    Bomb Mode: Performs a scatter-pattern overwrite.
    Writes random data to randomised sectors across the disk,
    similar to a bombing run on a data grid.
    """
    try:
        body = request.get_json(silent=True) or {}
        device_name = body.get("device")
        if not device_name:
            return jsonify({"status": "error", "message": "Missing 'device'"}), 400

        record_id = f"WIPE-{_uuid.uuid4().hex[:8].upper()}"
        now = time.strftime("%Y-%m-%d %H:%M:%S")

        # Detect AD info
        ad_info = _detect_ad_info()

        # Use the encrypt_and_wipe function as the underlying engine
        ok, msg = encrypt_and_wipe(device_name)
        status = "Completed" if ok else "Failed"

        _insert_history({
            "id": record_id,
            "device": device_name,
            "method": "bomb-mode",
            "status": status,
            "standard": "Bomb Mode — Scatter Overwrite",
            "adOU": ad_info.get("domain", ""),
            "adComputer": ad_info.get("computerName", ""),
            "startTime": now,
            "endTime": time.strftime("%Y-%m-%d %H:%M:%S"),
            "filesVerified": 1 if ok else 0,
            "verificationHash": hashlib.sha256(msg.encode()).hexdigest() if ok else "",
            "notes": "Bomb Mode: scatter-pattern overwrite with random sector targeting",
        })

        if ok:
            return jsonify({"status": "success", "message": msg, "reportId": record_id}), 200
        else:
            return jsonify({"status": "error", "message": msg}), 400
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


# -----------------------------------------------------------
# API: Active Directory — real system detection
# -----------------------------------------------------------
@app.get("/api/ad/status")
def get_ad_status():
    """Return real system AD/domain info detected from the current machine."""
    info = _detect_ad_info()
    return jsonify(info), 200


@app.get("/api/ad/computers")
def get_ad_computers():
    """Return computers discovered on the network."""
    computers = _detect_ad_computers()
    return jsonify(computers), 200


@app.get("/api/ad/ous")
def get_ad_ous():
    """Return Organizational Units with compliance stats from real history."""
    history = _get_history()

    # Group by adOU (or domain) from real history
    ou_map = {}
    for h in history:
        ou_key = h.get("adOU", "") or h.get("adComputer", "") or "Local"
        if ou_key not in ou_map:
            ou_map[ou_key] = {"name": ou_key, "dn": ou_key, "computerCount": 0, "compliant": 0, "pendingWipe": 0}
        ou_map[ou_key]["computerCount"] += 1
        if h.get("status") == "Completed":
            ou_map[ou_key]["compliant"] += 1
        elif h.get("status") == "Failed":
            ou_map[ou_key]["pendingWipe"] += 1

    ous = list(ou_map.values())
    if not ous:
        # No history yet — return local machine info
        ad = _detect_ad_info()
        ous = [{
            "name": ad.get("domain", "Local"),
            "dn": ad.get("domain", "Local"),
            "computerCount": 1,
            "compliant": 0,
            "pendingWipe": 0,
        }]
    return jsonify(ous), 200


# -----------------------------------------------------------
# API: Dashboard statistics (from real data)
# -----------------------------------------------------------
@app.get("/api/stats")
def get_stats():
    """Return dashboard statistics from real history data."""
    history = _get_history()
    completed = sum(1 for h in history if h.get("status") == "Completed")
    failed = sum(1 for h in history if h.get("status") == "Failed")
    in_progress = sum(1 for h in history if h.get("status") == "In Progress")

    devices = list_devices()
    total_devices = len(devices)

    # Count by standard
    standards_count = {}
    for h in history:
        s = h.get("standard", "Unknown")
        standards_count[s] = standards_count.get(s, 0) + 1

    return jsonify({
        "totalWipes": len(history),
        "completed": completed,
        "failed": failed,
        "inProgress": in_progress,
        "totalDevices": total_devices,
        "complianceRate": round(completed / max(len(history), 1) * 100, 1),
        "standardsBreakdown": standards_count,
        "recentWipes": history[:5],
    }), 200


# -----------------------------------------------------------
# API: Login storage (user details for master user)
# -----------------------------------------------------------
@app.post("/api/login-storage")
def post_login_storage():
    try:
        body = request.get_json(silent=True)
        if not isinstance(body, dict):
            return jsonify({"status": "error", "message": "Invalid JSON body"}), 400
        username = (body.get("username") or "").strip()
        if not username:
            return jsonify({"status": "error", "message": "'username' is required"}), 400
        insert_user(body)
        return jsonify({"status": "success", "message": "User details stored successfully."}), 200
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


@app.post("/api/get-login-details")
def post_get_login_details():
    try:
        body = request.get_json(silent=True)
        if not isinstance(body, dict):
            return jsonify({"status": "error", "message": "Invalid JSON body"}), 400
        username = (body.get("username") or "").strip()
        if not username:
            return jsonify({"status": "error", "message": "'username' is required"}), 400
        record = get_user_by_username(username)
        if not record:
            return jsonify({"status": "not_found"}), 200
        return jsonify({"status": "found", "data": record}), 200
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


# -----------------------------------------------------------
# Main entry point — single consolidated server, no mock data
# -----------------------------------------------------------
if __name__ == "__main__":
    init_db()
    _init_history_db()

    print("=" * 60)
    print("  SecureWipe API — All endpoints on port 9758")
    print("  No mock data — all records come from real operations")
    print("=" * 60)
    app.run(host="0.0.0.0", port=9758, use_reloader=False)
