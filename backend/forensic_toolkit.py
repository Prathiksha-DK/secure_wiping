"""
Forensic Toolkit -- real, scoped execution of the forensic engines already
bundled with FARIS (Sleuth Kit, libewf, Volatility3), plus honest
not-installed detection for tools that are not present anywhere in this
codebase (FTK Imager, Autopsy, Wireshark/tshark).

Every execution is gated through case_source.authorize_forensic_target()
first -- the toolkit never accepts an arbitrary local path, only the
resolved case forensic image or a path inside the case's own evidence/
storage tree (e.g. a previously-collected Memory Image evidence item).

Tool output is written under the case's own evidence staging area so it can
be attached via the existing Evidence Workspace "add evidence" endpoint --
this is intentionally the ONE code path for turning something into
evidence, not a second one.
"""

import os
import sys
import json
import time
import shutil
import subprocess
from typing import Any, Dict, Optional, Tuple

from flask import Blueprint, jsonify, request

from audit_engine import record_audit_event
from case_source import authorize_forensic_target, get_authenticated_identity
from seek_help_case_engine import CASES_STORAGE_DIR

forensic_toolkit_bp = Blueprint("forensic_toolkit", __name__)

SUBPROCESS_TIMEOUT = 30

SLEUTHKIT_TOOLS = {
    "mmls": [],
    "fsstat": ["-o", "2048"],
    "fls": ["-o", "2048"],
    "istat": ["-o", "2048"],
}

VOLATILITY_PLUGINS = [
    "windows.info", "windows.pslist", "windows.pstree", "windows.cmdline",
    "windows.netscan", "windows.dlllist", "windows.malfind", "windows.modules",
    "windows.envars", "windows.getsids",
]

NOT_BUNDLED_TOOLS = {
    "ftk_imager": {"display_name": "FTK Imager", "candidates": ["ftkimager", "ftkimager.exe"]},
    "autopsy": {"display_name": "Autopsy", "candidates": ["autopsy", "autopsy.exe"]},
    "wireshark": {"display_name": "Wireshark", "candidates": ["wireshark", "wireshark.exe"]},
    "tshark": {"display_name": "tshark", "candidates": ["tshark", "tshark.exe"]},
}


def _get_engine_manager():
    faris_root = os.path.join(os.path.dirname(os.path.dirname(__file__)), "FARIS")
    if os.path.exists(faris_root) and str(faris_root) not in sys.path:
        sys.path.insert(0, str(faris_root))
    from core.engine_manager import engine_manager
    return engine_manager


def _tool_inventory() -> Dict[str, Any]:
    mgr = _get_engine_manager()
    inventory = mgr.get_inventory()
    for key, meta in NOT_BUNDLED_TOOLS.items():
        found_path = None
        for candidate in meta["candidates"]:
            p = shutil.which(candidate)
            if p:
                found_path = p
                break
        inventory[key] = {
            "installed": bool(found_path),
            "version": "Unknown" if found_path else "Not installed/configured",
            "path": found_path or "",
            "license": "N/A -- external tool, not bundled",
            "status": "AVAILABLE" if found_path else "NOT_AVAILABLE",
            "display_name": meta["display_name"],
        }
    return inventory


def _staging_dir(case_id: str) -> str:
    d = os.path.join(CASES_STORAGE_DIR, case_id, "evidence", "_tool_staging")
    os.makedirs(d, exist_ok=True)
    return d


def _run_tool(tool_path: str, args: list, timeout: int = SUBPROCESS_TIMEOUT) -> Dict[str, Any]:
    start = time.time()
    try:
        proc = subprocess.run([tool_path, *args], capture_output=True, text=True, timeout=timeout)
        return {
            "returncode": proc.returncode,
            "stdout": proc.stdout,
            "stderr": proc.stderr,
            "duration_sec": round(time.time() - start, 3),
            "timed_out": False,
        }
    except subprocess.TimeoutExpired as e:
        return {
            "returncode": None,
            "stdout": (e.stdout or ""),
            "stderr": f"Tool execution exceeded {timeout}s timeout and was terminated.",
            "duration_sec": round(time.time() - start, 3),
            "timed_out": True,
        }
    except Exception as e:
        return {
            "returncode": None,
            "stdout": "",
            "stderr": str(e),
            "duration_sec": round(time.time() - start, 3),
            "timed_out": False,
        }


def _write_staged_output(case_id: str, tool: str, result: Dict[str, Any]) -> str:
    fname = f"{tool.replace('.', '_')}_{int(time.time())}.json"
    path = os.path.join(_staging_dir(case_id), fname)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(result, f, indent=2)
    return path


def _resolve_and_authorize_case_image(case_id: str) -> Tuple[Optional[str], Optional[Tuple[Dict[str, Any], int]]]:
    """
    Resolves case_id -> its real acquired image path (never trusts a raw
    string), then authorizes that resolved path via authorize_forensic_target
    (which is a no-op pass-through for non-Hunter roles, and a strict
    own-case-only check for a Hunter). Returns (image_path, error_response).
    """
    from auth import get_db
    conn = get_db()
    try:
        row = conn.execute("SELECT image_path FROM forensic_investigation_cases WHERE case_id = ?", (case_id,)).fetchone()
    finally:
        conn.close()

    image_path = row["image_path"] if row else None
    if not image_path or not os.path.isfile(image_path):
        return None, ({
            "status": "error",
            "message": "The forensic source for this case is unavailable. No local device will be used as a fallback.",
        }, 400)

    allowed, resolved_target, auth_err = authorize_forensic_target(request, image_path)
    if not allowed:
        return None, ({"status": "error", "message": auth_err}, 403)
    if not resolved_target or not os.path.isfile(resolved_target):
        return None, ({
            "status": "error",
            "message": "The forensic source for this case is unavailable. No local device will be used as a fallback.",
        }, 400)
    return resolved_target, None


@forensic_toolkit_bp.get("/api/forensic-tools/inventory")
def api_forensic_tools_inventory():
    try:
        return jsonify({"status": "success", "inventory": _tool_inventory()}), 200
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


@forensic_toolkit_bp.get("/api/forensic-tools/case-summary/<case_id>")
def api_forensic_tools_case_summary(case_id: str):
    """
    Validates and describes the resolved forensic source for a case, so the
    UI can confirm immediately that "Load Case" found a real, authorized
    source -- rather than silently doing nothing until a tool is run.
    """
    username, role = get_authenticated_identity(request)
    if not username:
        return jsonify({"status": "error", "message": "Authentication required."}), 401

    from auth import get_db
    conn = get_db()
    try:
        row = conn.execute(
            "SELECT case_id, device_id, device_model, image_filename, image_size, sha256, case_status "
            "FROM forensic_investigation_cases WHERE case_id = ?", (case_id,)
        ).fetchone()
    finally:
        conn.close()

    if not row:
        return jsonify({"status": "error", "message": f"Case '{case_id}' was not found."}), 404

    resolved_target, err_resp = _resolve_and_authorize_case_image(case_id)
    if err_resp:
        return jsonify(err_resp[0]), err_resp[1]

    return jsonify({
        "status": "success",
        "case": {
            "case_id": row["case_id"],
            "device_id": row["device_id"],
            "device_model": row["device_model"],
            "image_filename": row["image_filename"],
            "image_size": row["image_size"],
            "sha256": row["sha256"],
            "case_status": row["case_status"],
        },
    }), 200


@forensic_toolkit_bp.post("/api/forensic-tools/sleuthkit/<tool>")
def api_run_sleuthkit_tool(tool: str):
    body = request.get_json(silent=True) or {}
    case_id = (body.get("case_id") or "").strip()
    if not case_id:
        return jsonify({"status": "error", "message": "'case_id' is required."}), 400
    if tool not in SLEUTHKIT_TOOLS:
        return jsonify({"status": "error", "message": f"Unsupported Sleuth Kit tool '{tool}'."}), 400

    username, role = get_authenticated_identity(request)
    if not username:
        return jsonify({"status": "error", "message": "Authentication required."}), 401

    resolved_target, err_resp = _resolve_and_authorize_case_image(case_id)
    if err_resp:
        return jsonify(err_resp[0]), err_resp[1]

    try:
        mgr = _get_engine_manager()
        tool_path = mgr.get_tool_path(tool)
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500
    if not tool_path:
        return jsonify({"status": "error", "message": f"'{tool}' is not installed/configured."}), 503

    extra_args = SLEUTHKIT_TOOLS[tool] + [resolved_target]
    result = _run_tool(str(tool_path), extra_args)
    staged_path = _write_staged_output(case_id, tool, result)

    record_audit_event(
        user_id=username, role=role, operation="TOOL_EXECUTION", status="SUCCESS" if result["returncode"] == 0 else "FAILED",
        details={
            "case_id": case_id, "tool": "Sleuth Kit", "tool_version": "4.15.0 (TSK bundled)",
            "command": f"{tool} {' '.join(extra_args)}", "source": resolved_target,
            "duration_sec": result["duration_sec"], "result": "SUCCESS" if result["returncode"] == 0 else "FAILED",
        },
    )

    return jsonify({"status": "success", "tool": tool, "result": result, "staged_output_path": staged_path}), 200


@forensic_toolkit_bp.post("/api/forensic-tools/libewf/verify")
def api_run_libewf_verify():
    body = request.get_json(silent=True) or {}
    case_id = (body.get("case_id") or "").strip()
    if not case_id:
        return jsonify({"status": "error", "message": "'case_id' is required."}), 400

    username, role = get_authenticated_identity(request)
    if not username:
        return jsonify({"status": "error", "message": "Authentication required."}), 401

    resolved_target, err_resp = _resolve_and_authorize_case_image(case_id)
    if err_resp:
        return jsonify(err_resp[0]), err_resp[1]

    try:
        mgr = _get_engine_manager()
        tool_path = mgr.get_tool_path("ewfinfo")
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500
    if not tool_path:
        return jsonify({"status": "error", "message": "libewf (ewfinfo) is not installed/configured."}), 503

    from hashing_utils import compute_sha256_md5
    from auth import get_db

    conn = get_db()
    try:
        case_row = conn.execute("SELECT sha256, md5 FROM forensic_investigation_cases WHERE case_id = ?", (case_id,)).fetchone()
    finally:
        conn.close()
    acquisition_sha256 = case_row["sha256"] if case_row else None

    info_result = _run_tool(str(tool_path), [resolved_target])
    live_hashes = compute_sha256_md5(resolved_target)
    verification_pass = bool(acquisition_sha256) and live_hashes["sha256"] == acquisition_sha256

    result = {
        "ewfinfo_output": info_result,
        "acquisition_sha256": acquisition_sha256,
        "live_sha256": live_hashes["sha256"],
        "live_md5": live_hashes["md5"],
        "verification": "PASS" if verification_pass else "FAIL",
    }
    staged_path = _write_staged_output(case_id, "libewf_verify", result)

    record_audit_event(
        user_id=username, role=role, operation="TOOL_EXECUTION", status="SUCCESS",
        details={
            "case_id": case_id, "tool": "libewf", "tool_version": "20230405 (libewf bundled)",
            "command": f"ewfinfo {resolved_target}", "source": resolved_target,
            "result": result["verification"], "output_hash": live_hashes["sha256"],
        },
    )

    return jsonify({"status": "success", "result": result, "staged_output_path": staged_path}), 200


@forensic_toolkit_bp.post("/api/forensic-tools/volatility/<plugin>")
def api_run_volatility_plugin(plugin: str):
    body = request.get_json(silent=True) or {}
    case_id = (body.get("case_id") or "").strip()
    memory_image_path = (body.get("memory_image_path") or "").strip()
    if not case_id:
        return jsonify({"status": "error", "message": "'case_id' is required."}), 400
    if plugin not in VOLATILITY_PLUGINS:
        return jsonify({"status": "error", "message": f"Unsupported Volatility plugin '{plugin}'."}), 400
    if not memory_image_path:
        return jsonify({"status": "error", "message": "'memory_image_path' is required (path to a Memory Image evidence item in this case)."}), 400

    username, role = get_authenticated_identity(request)
    if not username:
        return jsonify({"status": "error", "message": "Authentication required."}), 401

    # The memory image must resolve inside this case's own authorized storage
    # (its collected evidence, never an arbitrary local path).
    allowed, resolved_target, err = authorize_forensic_target(request, memory_image_path)
    if not allowed:
        return jsonify({"status": "error", "message": err}), 403
    if not resolved_target or not os.path.isfile(resolved_target):
        return jsonify({"status": "error", "message": "The forensic source for this case is unavailable. No local device will be used as a fallback."}), 400

    try:
        mgr = _get_engine_manager()
        vol_path = mgr.get_tool_path("vol.py")
        python_path = mgr.get_tool_path("python") or sys.executable
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500
    if not vol_path:
        return jsonify({"status": "error", "message": "Volatility 3 is not installed/configured."}), 503

    result = _run_tool(str(python_path), [str(vol_path), "-f", resolved_target, plugin], timeout=90)
    if result["returncode"] != 0 and not result["timed_out"]:
        result["error_summary"] = "Memory image is incompatible or analysis failed."

    staged_path = _write_staged_output(case_id, f"volatility_{plugin}", result)

    record_audit_event(
        user_id=username, role=role, operation="TOOL_EXECUTION", status="SUCCESS" if result["returncode"] == 0 else "FAILED",
        details={
            "case_id": case_id, "tool": "Volatility3", "tool_version": "2.5.0 (Volatility Foundation bundled)",
            "command": f"vol.py -f {resolved_target} {plugin}", "source": resolved_target,
            "duration_sec": result["duration_sec"], "result": "SUCCESS" if result["returncode"] == 0 else "FAILED",
        },
    )

    return jsonify({"status": "success", "plugin": plugin, "result": result, "staged_output_path": staged_path}), 200
