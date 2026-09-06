"""
Case-Source Security Foundation.

Single, strict authorization resolver for the Hunter case-scoped forensic
workflow. Consolidates the identity-resolution helpers that used to be
duplicated separately in app.py, central_device_registry.py, and
seek_help_case_engine.py, and removes the unsigned userRole-cookie identity
fallback for this security-critical path: a Hunter/forensic identity here
must come from a real, validated session -- never a client-controlled cookie.

Non-Hunter roles are unaffected: authorize_forensic_target() is a pass-through
for every role except "hunter".
"""

import os
import json
from typing import Any, Dict, Optional, Tuple

from auth import validate_session


def get_authenticated_identity(request) -> Tuple[str, str]:
    """
    Returns (username, role) from a real, validated session only.
    Returns ("", "") if unauthenticated -- never guesses an identity from an
    unsigned client-controlled cookie.
    """
    auth_header = request.headers.get("Authorization", "")
    token = ""
    if auth_header.startswith("Bearer "):
        token = auth_header.split(" ", 1)[1].strip()
    if not token:
        token = request.cookies.get("session_token", "") or request.cookies.get("session", "")
        if token.startswith("{"):
            try:
                data = json.loads(token)
                token = data.get("token", "")
            except Exception:
                pass
    if token:
        sess = validate_session(token)
        if sess and sess.get("username"):
            return sess["username"], sess.get("role", "individual")
    return "", ""


def resolve_hunter_case_source(username: str) -> Optional[Dict[str, Any]]:
    """
    Resolves the single authorized forensic source for a Hunter: their one
    active claimed case. Returns None (BLOCK) if there is no active case, or
    if the case's image file no longer exists on disk -- never falls back to
    anything else.

    Returns the FULL forensic_investigation_cases row (all existing columns:
    device_capacity, device_capacity_readable, device_serial, etc.) plus a
    "source_type" key, so this is a drop-in replacement for the raw dict
    get_hunter_active_case_record() used to return directly to callers.
    """
    if not username:
        return None
    from central_device_registry import get_hunter_active_case_record
    active_case = get_hunter_active_case_record(username)
    if not active_case:
        return None
    image_path = str(active_case.get("image_path") or "")
    if not image_path or not os.path.isfile(image_path):
        return None
    result = dict(active_case)
    result["source_type"] = "FORENSIC_IMAGE"
    return result


def get_request_hunter_context(request) -> Tuple[bool, str, Optional[Dict[str, Any]]]:
    """
    Hardened replacement for the old per-file _get_request_hunter_context
    helpers. Returns (is_hunter, username, resolved_case_source_or_None).
    """
    username, role = get_authenticated_identity(request)
    if role != "hunter":
        return False, username, None
    return True, username, resolve_hunter_case_source(username)


NO_FALLBACK_MESSAGE = (
    "The forensic source for this case is unavailable. "
    "No local device will be used as a fallback."
)


def authorize_forensic_target(request, requested_path: str) -> Tuple[bool, str, Optional[str]]:
    """
    role != hunter -> unrestricted (preserves existing behavior for every other role)
    role == hunter -> requires a resolved case source; the requested path must match
                       it (or a path within the case's own storage directory, e.g.
                       its evidence/ subfolder); ALWAYS returns the resolved case
                       image path on a direct match, never the caller's raw string.

    Returns (allowed, resolved_target, error_message).
    """
    is_hunter, _username, case_source = get_request_hunter_context(request)
    if not is_hunter:
        return True, requested_path, None
    if not case_source:
        return False, "", (
            NO_FALLBACK_MESSAGE
            + " Please claim an active investigation case with a valid forensic "
              "image first."
        )

    clean = str(requested_path or "").strip()
    case_dev_id = str(case_source.get("device_id") or "").strip()
    case_img_path = str(case_source.get("image_path") or "").strip()
    case_id = str(case_source.get("case_id") or "").strip()
    case_img_name = str(case_source.get("image_filename") or "").strip()
    case_model = str(case_source.get("device_model") or "").strip().lower()

    if not clean:
        return True, case_img_path, None

    if (
        clean in (case_dev_id, case_id, case_img_name, case_img_path)
        or (case_img_path and clean.lower() == case_img_path.lower())
        or (case_model and case_model in clean.lower())
    ):
        return True, case_img_path, None

    # Allow paths inside the case's own storage directory (e.g. its evidence/
    # subfolder) -- needed by the Evidence Workspace and Forensic Toolkit,
    # which write/read only under the case's own tree, never the raw image.
    case_dir = os.path.dirname(case_img_path) if case_img_path else ""
    case_root = os.path.dirname(case_dir) if case_dir else ""
    if case_root and os.path.exists(case_root) and clean.startswith(case_root):
        return True, clean, None

    return False, "", (
        f"Access Denied: As a Threat & Forensic Hunter, you are strictly scoped to "
        f"device '{case_dev_id}' and the forensic image assigned to Case {case_id}."
    )
