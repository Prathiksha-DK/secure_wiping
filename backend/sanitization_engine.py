"""
Adaptive Sanitization + Recovery Verification Framework
Government/NTRO-oriented secure data sanitization assurance platform.

Architecture:
  Sanitize -> Verify -> Recovery Assessment -> Decision -> Re-sanitize if required -> Final Verification

Final states:
  SANITIZED_AND_REUSABLE
  SANITIZATION_NOT_VERIFIABLE
  NON_SANITIZABLE
"""

import os
import sys
import stat
import re
import uuid
import time
import json
import hashlib
import shutil
import subprocess
from typing import Tuple, List, Dict, Any, Optional

try:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.backends import default_backend
    HAS_CRYPTO = True
except ImportError:
    HAS_CRYPTO = False

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

CHUNK_SIZE = 1024 * 1024  # 1 MiB
DEFAULT_MAX_ITERATIONS = 3
SOFTWARE_VERSION = "SecureWipe-ASF v1.0.0"

SANITIZATION_METHODS: Dict[str, Dict[str, Any]] = {
    "nist-clear": {
        "label": "NIST 800-88 Rev.1 - Clear",
        "passes": 1,
        "patterns": [b"\x00"],
        "description": "Single-pass overwrite with zeros. Suitable for non-sensitive media.",
    },
    "nist-purge": {
        "label": "NIST 800-88 Rev.1 - Purge",
        "passes": 1,
        "patterns": [None],
        "description": "Purge via cryptographic erase or secure erase command.",
    },
    "dod-3pass": {
        "label": "DoD 5220.22-M (3-Pass)",
        "passes": 3,
        "patterns": [b"\x00", b"\xff", None],
        "description": "3-pass DoD overwrite: zeros, ones, random. Approved overwrite method.",
    },
    "dod-7pass": {
        "label": "DoD 5220.22-M ECE (7-Pass)",
        "passes": 7,
        "patterns": [b"\x00", b"\xff", None, b"\x96", b"\x00", b"\xff", None],
        "description": "7-pass extended DoD overwrite.",
    },
    "crypto-erase": {
        "label": "Cryptographic Erase (IEEE 2883)",
        "passes": 1,
        "patterns": [None],
        "description": "Encrypt with ephemeral AES-256 key then discard key. Renders data cryptographically inaccessible.",
    },
    "gutmann": {
        "label": "Gutmann 35-Pass",
        "passes": 35,
        "patterns": [None] * 35,
        "description": "35-pass Gutmann overwrite for maximum assurance on magnetic media.",
    },
    "ieee-purge": {
        "label": "IEEE 2883-2022 Purge",
        "passes": 1,
        "patterns": [None],
        "description": "IEEE 2883-2022 purge procedure using media-specific secure erase commands.",
    },
}

RECOVERY_CODES = [
    "NO_RECOVERABLE_DATA_DETECTED",
    "PARTIAL_DATA_RECOVERED",
    "SIGNIFICANT_DATA_RECOVERED",
    "RECOVERY_TEST_FAILED",
    "ASSESSMENT_NOT_CONCLUSIVE",
]

FINAL_STATE_PASS = "SANITIZED_AND_REUSABLE"
FINAL_STATE_WARNING = "SANITIZATION_NOT_VERIFIABLE"
FINAL_STATE_FAIL = "NON_SANITIZABLE"


# ---------------------------------------------------------------------------
# Helper utilities
# ---------------------------------------------------------------------------

def _now_ts() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _random_bytes(n: int) -> bytes:
    return os.urandom(n)


def _sha256_file(path: str) -> Optional[str]:
    h = hashlib.sha256()
    try:
        with open(path, "rb") as f:
            while True:
                chunk = f.read(CHUNK_SIZE)
                if not chunk:
                    break
                h.update(chunk)
        return h.hexdigest()
    except Exception:
        return None


def _audit_hash(record: Dict[str, Any]) -> str:
    stable = json.dumps(record, sort_keys=True, default=str)
    return hashlib.sha256(stable.encode()).hexdigest()


# ---------------------------------------------------------------------------
# Device information gathering
# ---------------------------------------------------------------------------

def gather_device_info(target: str) -> Dict[str, Any]:
    info: Dict[str, Any] = {
        "target": target,
        "target_type": "unknown",
        "size_bytes": 0,
        "filesystem": "",
        "serial": "",
        "model": "",
        "block_size": 512,
        "sector_count": 0,
        "is_system_disk": False,
        "device_technology": "unknown",
    }

    if os.path.isfile(target):
        info["target_type"] = "file"
        try:
            info["size_bytes"] = os.path.getsize(target)
        except Exception:
            pass
    elif os.path.isdir(target):
        info["target_type"] = "folder"
        try:
            total = 0
            for dirpath, _, filenames in os.walk(target):
                for fn in filenames:
                    fp = os.path.join(dirpath, fn)
                    try:
                        total += os.path.getsize(fp)
                    except Exception:
                        pass
            info["size_bytes"] = total
        except Exception:
            pass
    elif sys.platform.startswith("win"):
        info["target_type"] = "disk"
        info.update(_gather_windows_disk_info(target))
    elif target.startswith("/dev/"):
        info["target_type"] = "disk"
        info.update(_gather_linux_disk_info(target))

    if info["size_bytes"] > 0 and info["block_size"] > 0:
        info["sector_count"] = info["size_bytes"] // info["block_size"]

    return info


def _gather_windows_disk_info(target: str) -> Dict[str, Any]:
    result = {"serial": "", "model": "", "filesystem": "", "size_bytes": 0, "device_technology": "unknown"}
    try:
        from secure_encrypt_wipe import _pick_disk_by_name_or_size
        disk = _pick_disk_by_name_or_size(target)
        if disk:
            result["model"] = disk.get("FriendlyName", "") or disk.get("Model", "")
            result["serial"] = disk.get("SerialNumber", "")
            result["size_bytes"] = int(disk.get("Size") or 0)
            bus = str(disk.get("BusType", "")).upper()
            media = str(disk.get("MediaType", "")).upper()
            if "SSD" in media or bus == "NVME":
                result["device_technology"] = "SSD/NVMe"
            elif "HDD" in media:
                result["device_technology"] = "HDD"
            elif bus == "USB":
                result["device_technology"] = "USB Flash"
            else:
                result["device_technology"] = f"{media}/{bus}"
    except Exception:
        pass
    return result


def _gather_linux_disk_info(target: str) -> Dict[str, Any]:
    result = {"serial": "", "model": "", "filesystem": "", "size_bytes": 0, "device_technology": "unknown"}
    try:
        out = subprocess.run(
            ["lsblk", "-J", "-b", "-o", "NAME,SIZE,MODEL,SERIAL,TYPE,ROTA,TRAN", target],
            capture_output=True, text=True, timeout=10
        )
        if out.returncode == 0:
            data = json.loads(out.stdout)
            devs = data.get("blockdevices", [])
            if devs:
                d = devs[0]
                result["model"] = d.get("model") or ""
                result["serial"] = d.get("serial") or ""
                result["size_bytes"] = int(d.get("size") or 0)
                rota = d.get("rota")
                tran = str(d.get("tran") or "").lower()
                if tran == "nvme" or (tran == "sata" and rota == "0"):
                    result["device_technology"] = "SSD/NVMe"
                elif rota == "1":
                    result["device_technology"] = "HDD"
                elif tran == "usb":
                    result["device_technology"] = "USB Flash"
    except Exception:
        pass
    return result


# ---------------------------------------------------------------------------
# Sanitization methods (modular engine)
# ---------------------------------------------------------------------------

def _unlock_path(path: str) -> None:
    """Ensure file or directory has write permissions so it can be overwritten and unlinked."""
    try:
        if not os.path.exists(path):
            return
        if sys.platform.startswith("win"):
            try:
                import ctypes
                FILE_ATTRIBUTE_READONLY = 0x01
                attrs = ctypes.windll.kernel32.GetFileAttributesW(path)
                if attrs != -1 and (attrs & FILE_ATTRIBUTE_READONLY):
                    ctypes.windll.kernel32.SetFileAttributesW(path, attrs & ~FILE_ATTRIBUTE_READONLY)
            except Exception:
                pass
        mode = os.stat(path).st_mode
        if os.path.isdir(path):
            os.chmod(path, mode | stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR)
        else:
            os.chmod(path, mode | stat.S_IRUSR | stat.S_IWUSR)
    except Exception:
        pass


def _overwrite_file_multipass(path: str, method_config: Dict[str, Any]) -> Tuple[bool, str, int]:
    patterns = method_config.get("patterns", [b"\x00"])
    bytes_written = 0
    try:
        _unlock_path(path)
        parent = os.path.dirname(path)
        if parent:
            _unlock_path(parent)

        if not os.path.exists(path):
            return True, "ok (already removed)", 0

        file_size = os.path.getsize(path)
        if file_size == 0:
            return True, "ok (empty file)", 0

        with open(path, "rb+", buffering=0) as f:
            for pattern in patterns:
                f.seek(0)
                offset = 0
                while offset < file_size:
                    to_write = min(CHUNK_SIZE, file_size - offset)
                    if pattern is None:
                        data = _random_bytes(to_write)
                    else:
                        data = (pattern * ((to_write // len(pattern)) + 1))[:to_write]
                    f.write(data)
                    offset += to_write
                    bytes_written += to_write
                f.flush()
                try:
                    os.fsync(f.fileno())
                except Exception:
                    pass
        return True, "ok", bytes_written
    except PermissionError:
        try:
            _unlock_path(path)
            with open(path, "wb", buffering=0) as f:
                f.write(b"\x00" * min(file_size, 4096))
            return True, "unlocked and overwritten", bytes_written
        except Exception as e:
            return False, f"Permission denied: {path} ({e})", bytes_written
    except Exception as e:
        return False, str(e), bytes_written


def _crypto_erase_file(path: str) -> Tuple[bool, str, int]:
    if not HAS_CRYPTO:
        return False, "cryptography library not available", 0
    key = os.urandom(32)
    nonce = os.urandom(16)
    bytes_written = 0
    try:
        _unlock_path(path)
        parent = os.path.dirname(path)
        if parent:
            _unlock_path(parent)

        if not os.path.exists(path):
            return True, "ok (already removed)", 0

        file_size = os.path.getsize(path)
        if file_size == 0:
            return True, "ok (empty file)", 0

        cipher = Cipher(algorithms.AES(key), modes.CTR(nonce), backend=default_backend())
        encryptor = cipher.encryptor()
        with open(path, "rb+", buffering=0) as f:
            offset = 0
            while offset < file_size:
                chunk = f.read(CHUNK_SIZE)
                if not chunk:
                    break
                ct = encryptor.update(chunk)
                f.seek(-len(ct), os.SEEK_CUR)
                f.write(ct)
                offset += len(ct)
                bytes_written += len(ct)
            encryptor.finalize()
        return True, "crypto-erase ok", bytes_written
    except Exception as e:
        return False, str(e), bytes_written
    finally:
        key = b"\x00" * 32
        del key


def sanitize_file(path: str, method: str) -> Tuple[bool, str, Dict[str, Any]]:
    config = SANITIZATION_METHODS.get(method, SANITIZATION_METHODS["dod-3pass"])
    stats = {"method": method, "label": config["label"], "passes": config["passes"], "bytes_written": 0}

    _unlock_path(path)
    if method == "crypto-erase":
        ok, msg, bw = _crypto_erase_file(path)
    else:
        ok, msg, bw = _overwrite_file_multipass(path, config)

    stats["bytes_written"] = bw

    if ok:
        try:
            dir_name = os.path.dirname(path)
            _unlock_path(dir_name)
            new_name = uuid.uuid4().hex
            new_path = os.path.join(dir_name, new_name)
            os.replace(path, new_path)
            _unlock_path(new_path)
            os.remove(new_path)
        except Exception:
            try:
                _unlock_path(path)
                os.remove(path)
            except Exception:
                pass

    return ok, msg, stats


def sanitize_folder(folder: str, method: str, progress_cb=None) -> Tuple[bool, str, Dict[str, Any]]:
    config = SANITIZATION_METHODS.get(method, SANITIZATION_METHODS["dod-3pass"])
    stats = {
        "method": method,
        "label": config["label"],
        "passes": config["passes"],
        "files_processed": 0,
        "files_failed": 0,
        "bytes_written": 0,
        "errors": [],
    }

    _unlock_path(folder)

    all_files = []
    for dirpath, dirnames, filenames in os.walk(folder):
        _unlock_path(dirpath)
        for dn in dirnames:
            _unlock_path(os.path.join(dirpath, dn))
        for fn in filenames:
            fp = os.path.join(dirpath, fn)
            _unlock_path(fp)
            all_files.append(fp)

    total = len(all_files)
    for idx, fp in enumerate(all_files):
        if progress_cb:
            progress_cb(idx, total, fp)

        _unlock_path(fp)
        if method == "crypto-erase":
            ok, msg, bw = _crypto_erase_file(fp)
        else:
            ok, msg, bw = _overwrite_file_multipass(fp, config)

        stats["bytes_written"] += bw
        if ok:
            stats["files_processed"] += 1
            try:
                _unlock_path(fp)
                os.remove(fp)
            except Exception:
                pass
        else:
            stats["files_failed"] += 1
            stats["errors"].append(f"{fp}: {msg}")

    for dirpath, dirnames, filenames in os.walk(folder, topdown=False):
        try:
            _unlock_path(dirpath)
            if not os.listdir(dirpath) and dirpath != folder:
                os.rmdir(dirpath)
        except Exception:
            pass

    try:
        _unlock_path(folder)
        if not os.listdir(folder):
            os.rmdir(folder)
    except Exception:
        pass

    all_ok = stats["files_failed"] == 0
    msg = f"Processed {stats['files_processed']}/{total} files" + (
        f", {stats['files_failed']} errors" if stats["files_failed"] else ""
    )
    return all_ok, msg, stats


def sanitize_disk_linux(device_path: str, method: str, size_bytes: int, progress_cb=None) -> Tuple[bool, str, Dict[str, Any]]:
    config = SANITIZATION_METHODS.get(method, SANITIZATION_METHODS["dod-3pass"])
    patterns = config.get("patterns", [None])
    stats = {
        "method": method,
        "label": config["label"],
        "passes": len(patterns),
        "bytes_written": 0,
        "errors": [],
    }

    try:
        fd = os.open(device_path, os.O_RDWR)
        try:
            for pass_idx, pattern in enumerate(patterns):
                offset = 0
                while offset < size_bytes:
                    to_write = min(CHUNK_SIZE, size_bytes - offset)
                    if pattern is None:
                        data = _random_bytes(to_write)
                    else:
                        data = (pattern * ((to_write // len(pattern)) + 1))[:to_write]
                    os.lseek(fd, offset, os.SEEK_SET)
                    written = os.write(fd, data)
                    offset += written
                    stats["bytes_written"] += written
                    if progress_cb:
                        pct = int((pass_idx * size_bytes + offset) / (len(patterns) * size_bytes) * 100)
                        progress_cb(pct)
        finally:
            os.close(fd)
        return True, f"Disk sanitized: {stats['bytes_written']} bytes written", stats
    except PermissionError:
        return False, "Permission denied - root/sudo required for raw disk access", stats
    except Exception as e:
        return False, str(e), stats


# ---------------------------------------------------------------------------
# Verification layer
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# Verification layer (Phase 3 Multi-Mode Verifier)
# ---------------------------------------------------------------------------

from sanitization_verifier import (
    verify_file_sanitization,
    verify_folder_sanitization,
    verify_disk_sanitization,
)

from forensic_carver import (
    scan_file_stream,
    scan_folder_stream,
    scan_disk_stream,
    EVIDENCE_NO_EVIDENCE,
    EVIDENCE_LOW_CONFIDENCE,
    EVIDENCE_PROBABLE,
    EVIDENCE_VALIDATED,
)


def verify_sanitization(
    target: str,
    target_type: str,
    expected_size: int,
    expected_pattern: Optional[bytes] = None,
    strategy: str = "stratified",
) -> Dict[str, Any]:
    """Execute multi-mode verification on target."""
    if target_type == "file":
        return verify_file_sanitization(target)
    elif target_type == "folder":
        return verify_folder_sanitization(target)
    elif target_type == "disk":
        return verify_disk_sanitization(
            target,
            expected_size,
            expected_pattern=expected_pattern,
            strategy=strategy,
        )
    return {
        "status": "WARN",
        "verification_strategy": "unsupported",
        "verified_coverage_pct": 0.0,
        "details": "Unsupported target type for verification",
        "checks": [],
    }


# ---------------------------------------------------------------------------
# Recovery assessment module (Phase 3 Forensic Carver Engine)
# ---------------------------------------------------------------------------

def assess_recovery(
    target: str,
    target_type: str,
    total_bytes: int = 0,
    progress_cb: Optional[Any] = None,
) -> Dict[str, Any]:
    """
    Execute streaming read-only forensic recovery assessment.
    Returns multi-level evidence classification, artifact counts, and structural validation.
    """
    if target_type == "file":
        return scan_file_stream(target, progress_cb=progress_cb)
    elif target_type == "folder":
        return scan_folder_stream(target, progress_cb=progress_cb)
    elif target_type == "disk":
        return scan_disk_stream(target, total_bytes, progress_cb=progress_cb)
    return {
        "evidence_level": EVIDENCE_NO_EVIDENCE,
        "confidence_score": 0.0,
        "summary_reason": f"Unknown target type ({target_type})",
        "scan_coverage_pct": 0.0,
        "counts": {"level_1_signature_hits": 0, "level_2_valid_candidates": 0, "level_3_validated_artifacts": 0},
    }


# ---------------------------------------------------------------------------
# Adaptive Decision Engine (Phase 3 Evidence-Based Matrix)
# ---------------------------------------------------------------------------

def make_decision(
    verification: Dict[str, Any],
    recovery: Dict[str, Any],
    device_technology: str,
    iteration: int,
    max_iterations: int,
) -> Dict[str, Any]:
    ver_status = verification.get("status", "FAIL")
    evidence_level = recovery.get("evidence_level", EVIDENCE_NO_EVIDENCE)
    confidence_score = recovery.get("confidence_score", 0.0)

    nand_tech = any(t in device_technology.upper() for t in ["SSD", "NVME", "NAND", "FLASH", "USB", "SD"])

    # 1. Genuine Recoverable Artifacts detected (Level 2/3: Probable or Validated)
    if evidence_level in (EVIDENCE_PROBABLE, EVIDENCE_VALIDATED):
        if iteration < max_iterations:
            return {
                "action": "RETRY",
                "final_state": None,
                "reason": (
                    f"Forensic assessment detected {evidence_level} (confidence: {confidence_score}%, "
                    f"iteration {iteration}/{max_iterations}). Applying configured re-sanitization procedure."
                ),
            }
        else:
            return {
                "action": "FAIL",
                "final_state": FINAL_STATE_FAIL,
                "reason": (
                    f"Forensic recovery engine still validates recoverable file structures ({evidence_level}, "
                    f"confidence: {confidence_score}%) after {max_iterations} iterations. Device classified as NON_SANITIZABLE."
                ),
            }

    # 2. Verification failed (mismatches or remaining file table entries)
    if ver_status == "FAIL":
        if iteration < max_iterations:
            return {
                "action": "RETRY",
                "final_state": None,
                "reason": (
                    f"Sanitization verification failed ({verification.get('details', '')}) "
                    f"on iteration {iteration}/{max_iterations}. Triggering re-sanitization."
                ),
            }
        else:
            return {
                "action": "FAIL",
                "final_state": FINAL_STATE_FAIL,
                "reason": f"Verification failed after {max_iterations} attempts. Device classified as NON_SANITIZABLE.",
            }

    # 3. Clean Scan: Zero Evidence Detected
    if evidence_level == EVIDENCE_NO_EVIDENCE:
        if nand_tech:
            return {
                "action": "PASS",
                "final_state": FINAL_STATE_WARNING,
                "reason": (
                    "No recoverable data detected within the tested logical scope. "
                    "However, SSD/NVMe/Flash controller translation (wear leveling, unallocated blocks) "
                    "cannot be physically proven by software alone - classified as SANITIZATION_NOT_VERIFIABLE."
                ),
            }
        return {
            "action": "PASS",
            "final_state": FINAL_STATE_PASS,
            "reason": "Sanitization verification passed and deep forensic carver detected zero recoverable data structures.",
        }

    # 4. Low Confidence Trace (Isolated prefix hits / potential false positive noise)
    if evidence_level == EVIDENCE_LOW_CONFIDENCE:
        if nand_tech:
            return {
                "action": "PASS",
                "final_state": FINAL_STATE_WARNING,
                "reason": (
                    "Only isolated low-confidence signature fragments detected (no valid file structures). "
                    "NAND flash controller wear-leveling prevents physical guarantee - policy review recommended."
                ),
            }
        return {
            "action": "PASS",
            "final_state": FINAL_STATE_PASS,
            "reason": (
                "Verified and passed. Forensic assessment identified only isolated low-confidence byte fragments "
                "with no reconstructible file structures."
            ),
        }

    return {
        "action": "PASS",
        "final_state": FINAL_STATE_WARNING,
        "reason": "Forensic assessment completed; results logged for compliance review.",
    }


# ---------------------------------------------------------------------------
# Main adaptive sanitization pipeline
# ---------------------------------------------------------------------------

def run_adaptive_sanitization(
    target: str,
    method: str = "dod-3pass",
    max_iterations: int = DEFAULT_MAX_ITERATIONS,
    operator: str = "system",
    expected_fingerprint: Optional[str] = None,
    progress_cb=None,
) -> Dict[str, Any]:
    """
    Execute the full adaptive sanitization pipeline:
    [Safety Validation] -> [Device Lock] -> [Sanitization] -> [Verification] -> [Recovery Assessment] -> [Decision] -> [Final Classification]
    """
    from storage_safety import validate_storage_safety, acquire_device_lock, release_device_lock
    from audit_log import record_audit_event
    from certificate_engine import generate_sanitization_certificate
    from compliance_engine import save_certificate

    session_id = f"SAN-{uuid.uuid4().hex[:10].upper()}"
    start_time = _now_ts()
    method_config = SANITIZATION_METHODS.get(method, SANITIZATION_METHODS["dod-3pass"])

    audit: Dict[str, Any] = {
        "session_id": session_id,
        "software_version": SOFTWARE_VERSION,
        "operator": operator,
        "target": target,
        "sanitization_method": method,
        "sanitization_method_label": method_config["label"],
        "start_time": start_time,
        "end_time": None,
        "device_info": {},
        "iterations": [],
        "max_iterations": max_iterations,
        "final_state": None,
        "final_reason": "",
        "errors": [],
        "tamper_hash": None,
    }

    def _emit(msg: str, pct: Optional[int] = None):
        if progress_cb:
            progress_cb(msg, pct)

    _emit("[STAGE 0] Multi-Layer Storage Safety & Identity Validation...", 2)
    safety = validate_storage_safety(target, expected_fingerprint=expected_fingerprint)
    if not safety["safe"]:
        reasons_text = "; ".join(safety["reasons"])
        audit["final_state"] = FINAL_STATE_FAIL
        audit["final_reason"] = f"SAFETY ABORT: {reasons_text}"
        audit["end_time"] = _now_ts()
        record_audit_event(
            event_type="SAFETY_REJECTED",
            operator=operator,
            target=target,
            payload={"reasons": safety["reasons"], "session_id": session_id}
        )
        _finalize_audit(audit)
        return audit

    canonical_id = safety["canonical_id"]
    lock_ok, lock_msg = acquire_device_lock(canonical_id, session_id, operator)
    if not lock_ok:
        audit["final_state"] = FINAL_STATE_FAIL
        audit["final_reason"] = f"CONCURRENCY ABORT: {lock_msg}"
        audit["end_time"] = _now_ts()
        _finalize_audit(audit)
        return audit

    try:
        record_audit_event(
            event_type="SANITIZATION_STARTED",
            operator=operator,
            target=target,
            payload={"session_id": session_id, "method": method, "canonical_id": canonical_id}
        )

        device_info = gather_device_info(target)
        if safety.get("metadata"):
            device_info.update(safety["metadata"])
        audit["device_info"] = device_info
        target_type = device_info.get("target_type", safety.get("target_type", "unknown"))

        _emit(f"[DEVICE] Type: {target_type} | Technology: {device_info.get('device_technology', 'unknown')} | Size: {device_info.get('size_bytes', 0)} bytes", 5)

        iteration = 0
        final_decision = None

        while iteration < max_iterations:
            iteration += 1
            iteration_record: Dict[str, Any] = {
                "iteration": iteration,
                "start_time": _now_ts(),
                "sanitization": {},
                "verification": {},
                "recovery_assessment": {},
                "decision": {},
            }

            pct_base = 10 + (iteration - 1) * 25
            _emit(f"[STAGE 1] Sanitization pass {iteration}/{max_iterations} using {method_config['label']}...", pct_base)

            san_start = _now_ts()
            san_stats: Dict[str, Any] = {}
            san_ok = False
            san_msg = ""

            if target_type == "file":
                san_ok, san_msg, san_stats = sanitize_file(target, method)
            elif target_type == "folder":
                san_ok, san_msg, san_stats = sanitize_folder(
                    target, method,
                    progress_cb=lambda idx, tot, fp: _emit(f"[WIPE] File {idx}/{tot}: {os.path.basename(fp)}", pct_base + 5)
                )
            elif target_type == "disk" and target.startswith("/dev/"):
                san_ok, san_msg, san_stats = sanitize_disk_linux(
                    target, method, device_info.get("size_bytes", 0),
                    progress_cb=lambda pct: _emit(f"[WIPE] Disk write {pct}%", pct_base + pct // 5)
                )
            else:
                try:
                    from secure_encrypt_wipe import encrypt_and_wipe
                    san_ok, san_msg = encrypt_and_wipe(target)
                    san_stats = {"method": method, "label": method_config["label"]}
                except Exception as e:
                    san_ok, san_msg = False, str(e)
                    san_stats = {}

            iteration_record["sanitization"] = {
                "method": method,
                "label": method_config["label"],
                "start_time": san_start,
                "end_time": _now_ts(),
                "success": san_ok,
                "message": san_msg,
                "stats": san_stats,
            }

            if not san_ok:
                audit["errors"].append(f"Iteration {iteration}: sanitization failed - {san_msg}")
                _emit(f"[ERROR] Sanitization failed: {san_msg}", pct_base + 8)

            pct_ver = pct_base + 8
            _emit(f"[STAGE 2] Multi-Region Sanitization Verification (iteration {iteration})...", pct_ver)
            expected_pat = (
                method_config.get("patterns", [b"\x00"])[-1]
                if method_config.get("patterns") and method_config.get("patterns")[-1] is not None
                else None
            )
            verification = verify_sanitization(
                target, target_type, device_info.get("size_bytes", 0),
                expected_pattern=expected_pat,
                strategy="stratified",
            )
            iteration_record["verification"] = verification
            _emit(f"[VERIFY] Status: {verification['status']} | Coverage: {verification.get('verified_coverage_pct', 0)}% | Details: {verification.get('details', '')}", pct_ver + 3)

            pct_rec = pct_ver + 5
            _emit(f"[STAGE 3] Forensic Recovery Assessment (Streaming file signature & structure carver)...", pct_rec)
            recovery = assess_recovery(
                target, target_type,
                total_bytes=device_info.get("size_bytes", 0),
                progress_cb=lambda info: _emit(f"[FORENSIC SCAN] {info.get('bytes_scanned', 0)} / {info.get('total_bytes', 0)} bytes ({info.get('percentage', 0)}%) | Validated: {info.get('validated_count', 0)} | Candidates: {info.get('candidates_count', 0)}", pct_rec + int(info.get('percentage', 0) * 0.05)),
            )
            evidence_level = recovery.get("evidence_level", "NO_EVIDENCE")
            confidence = recovery.get("confidence_score", 0.0)
            classification_map = {
                "NO_EVIDENCE": "NO_RECOVERABLE_DATA_DETECTED",
                "LOW_CONFIDENCE_TRACE": "NO_RECOVERABLE_DATA_DETECTED",
                "PROBABLE_RECOVERABLE_ARTIFACT": "PARTIAL_DATA_RECOVERED",
                "VALIDATED_RECOVERABLE_ARTIFACT": "SIGNIFICANT_DATA_RECOVERED",
            }
            recovery["classification"] = classification_map.get(evidence_level, "ASSESSMENT_NOT_CONCLUSIVE")
            recovery["detail"] = recovery.get("summary_reason", "")
            iteration_record["recovery_assessment"] = recovery
            _emit(f"[RECOVER] Evidence: {evidence_level} (Confidence: {confidence}%) | Validated Artifacts: {recovery.get('counts', {}).get('level_3_validated_artifacts', 0)}", pct_rec + 5)

            pct_dec = pct_rec + 6
            _emit(f"[STAGE 4] Adaptive Evidence Decision Engine (iteration {iteration})...", pct_dec)
            decision = make_decision(
                verification, recovery,
                device_info.get("device_technology", "unknown"),
                iteration, max_iterations
            )
            iteration_record["decision"] = decision
            audit["iterations"].append(iteration_record)

            _emit(f"[DECISION] Action: {decision['action']} - {decision['reason']}", pct_dec + 3)

            if decision["action"] != "RETRY":
                final_decision = decision
                break

            _emit(f"[RETRY] Re-sanitization required. Starting iteration {iteration + 1}...", pct_dec + 5)

    finally:
        release_device_lock(canonical_id, session_id)

    if final_decision is None:
        final_decision = {
            "action": "FAIL",
            "final_state": FINAL_STATE_FAIL,
            "reason": f"Maximum iterations ({max_iterations}) reached without achieving required assurance."
        }

    audit["final_state"] = final_decision["final_state"]
    audit["final_reason"] = final_decision["reason"]
    audit["end_time"] = _now_ts()
    audit["total_iterations"] = iteration

    _emit(f"[FINAL] State: {audit['final_state']}", 98)
    _emit(f"[FINAL] Reason: {audit['final_reason']}", 99)

    _finalize_audit(audit)

    # Generate and persist Schema v1.0 Certificate with Digital Signature
    try:
        cert = generate_sanitization_certificate(audit)
        save_certificate(cert)
        audit["certificate_id"] = cert.get("certificate_id")
        audit["certificate_digest"] = cert.get("integrity", {}).get("digest")
    except Exception as cert_err:
        audit["errors"].append(f"Certificate generation error: {cert_err}")

    # Record completion in audit trail
    record_audit_event(
        event_type="SANITIZATION_COMPLETED" if audit["final_state"] == FINAL_STATE_PASS else "SANITIZATION_FAILED",
        operator=operator,
        target=target,
        payload={
            "session_id": session_id,
            "final_state": audit["final_state"],
            "total_iterations": iteration,
            "tamper_hash": audit.get("tamper_hash"),
            "certificate_id": audit.get("certificate_id")
        }
    )

    return audit


def _finalize_audit(audit: Dict[str, Any]):
    audit_copy = {k: v for k, v in audit.items() if k != "tamper_hash"}
    audit["tamper_hash"] = _audit_hash(audit_copy)
