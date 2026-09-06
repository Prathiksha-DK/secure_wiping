"""
SecureWipe — Two-Stage Destructive Confirmation Engine
Generates single-use, cryptographically signed confirmation tokens for high-risk
sanitization operations and validates strict stage-2 explicit user confirmations.
"""

import time
import json
import hmac
import base64
import hashlib
import secrets
from typing import Dict, Any, Tuple, Optional
from security_config import get_secret_key
from storage_safety import validate_storage_safety, compute_device_fingerprint

CONFIRMATION_TOKEN_TTL = 300  # 5 minutes validity

# In-memory store of consumed token nonces to prevent replay attacks
_consumed_tokens: Dict[str, float] = {}

def generate_stage1_confirmation(
    target: str,
    method: str,
    operator: str,
    client_ip: str = "127.0.0.1"
) -> Dict[str, Any]:
    """
    Stage 1: Inspect device, validate safety, display full details,
    and generate a cryptographically signed confirmation token.
    """
    # 1. Validate Storage Safety
    safety = validate_storage_safety(target)
    if not safety["safe"]:
        return {
            "status": "SAFETY_REJECTED",
            "safe": False,
            "target": target,
            "reasons": safety["reasons"],
            "message": "Target device failed safety checks and cannot be queued for sanitization."
        }
        
    meta = safety.get("metadata", {})
    serial = meta.get("serial") or "NO-SERIAL"
    model = meta.get("model") or target
    target_type = safety.get("target_type", "disk")
    fingerprint = safety.get("fingerprint", "")
    
    clean_id = re_sub_phrase(serial if serial != "NO-SERIAL" else model)
    confirmation_phrase = f"CONFIRM-WIPE-{clean_id.upper()}"
    
    now = int(time.time())
    token_payload = {
        "target": target,
        "canonical_id": safety["canonical_id"],
        "target_type": target_type,
        "method": method,
        "operator": operator,
        "fingerprint": fingerprint,
        "confirmation_phrase": confirmation_phrase,
        "client_ip": client_ip,
        "iat": now,
        "exp": now + CONFIRMATION_TOKEN_TTL,
        "nonce": secrets.token_hex(16),
    }
    
    payload_json = json.dumps(token_payload, separators=(',', ':'), sort_keys=True)
    payload_b64 = base64.urlsafe_b64encode(payload_json.encode("utf-8")).decode("utf-8").rstrip("=")
    
    secret = get_secret_key().encode("utf-8")
    sig = hmac.new(secret, payload_b64.encode("utf-8"), hashlib.sha256).digest()
    sig_b64 = base64.urlsafe_b64encode(sig).decode("utf-8").rstrip("=")
    
    token = f"{payload_b64}.{sig_b64}"
    
    return {
        "status": "CONFIRMATION_REQUIRED",
        "safe": True,
        "target": target,
        "canonical_id": safety["canonical_id"],
        "target_type": target_type,
        "device_summary": {
            "device": target,
            "model": model,
            "serial": serial,
            "capacity_bytes": meta.get("size_bytes", 0),
            "path": meta.get("path") or target,
            "target_type": target_type,
            "bus_type": meta.get("bus_type", ""),
        },
        "method": method,
        "confirmation_token": token,
        "expires_in_seconds": CONFIRMATION_TOKEN_TTL,
        "required_confirmation_phrase": confirmation_phrase,
        "instructions": (
            f"Review the device details above. To proceed with irreversible data destruction, "
            f"type the exact phrase '{confirmation_phrase}' and submit with this token."
        )
    }

def validate_stage2_confirmation(
    confirmation_token: str,
    typed_phrase: str,
    operator: str,
    client_ip: str = "127.0.0.1"
) -> Tuple[bool, str, Optional[Dict[str, Any]]]:
    """
    Stage 2: Validate token cryptographic signature, check expiration,
    verify single-use nonce, match confirmation phrase, and re-verify device identity.
    """
    if not confirmation_token or "." not in confirmation_token:
        return False, "Invalid confirmation token format.", None
        
    parts = confirmation_token.split(".")
    if len(parts) != 2:
        return False, "Malformed confirmation token.", None
        
    payload_b64, sig_b64 = parts
    secret = get_secret_key().encode("utf-8")
    expected_sig = hmac.new(secret, payload_b64.encode("utf-8"), hashlib.sha256).digest()
    expected_sig_b64 = base64.urlsafe_b64encode(expected_sig).decode("utf-8").rstrip("=")
    
    if not hmac.compare_digest(sig_b64, expected_sig_b64):
        return False, "Confirmation token signature verification failed (tampered or invalid key).", None
        
    try:
        rem = len(payload_b64) % 4
        padded = payload_b64 + ("=" * (4 - rem) if rem else "")
        payload_json = base64.urlsafe_b64decode(padded.encode("utf-8")).decode("utf-8")
        payload = json.loads(payload_json)
    except Exception as e:
        return False, f"Failed to parse confirmation token: {e}", None
        
    # Check expiration
    now = time.time()
    if payload.get("exp", 0) < now:
        return False, "Confirmation token has expired. Please re-initiate the confirmation request.", None
        
    # Check single-use nonce (replay prevention)
    nonce = payload.get("nonce", "")
    _cleanup_expired_nonces(now)
    if nonce in _consumed_tokens:
        return False, "Confirmation token has already been consumed (replay attempt detected).", None
        
    # Verify typed phrase matches exactly
    expected_phrase = payload.get("confirmation_phrase", "")
    if (typed_phrase or "").strip() != expected_phrase:
        return False, f"Confirmation phrase mismatch. Expected '{expected_phrase}', received '{typed_phrase}'.", None
        
    # Re-validate device hardware fingerprint (Anti-Misdirection Check)
    target = payload.get("target", "")
    expected_fp = payload.get("fingerprint", "")
    safety = validate_storage_safety(target, expected_fingerprint=expected_fp)
    if not safety["safe"]:
        return False, f"Pre-wipe safety revalidation failed: {'; '.join(safety['reasons'])}", None
        
    # Mark token as consumed
    _consumed_tokens[nonce] = payload.get("exp", now + CONFIRMATION_TOKEN_TTL)
    
    return True, "Stage 2 confirmation verified successfully.", payload

def _cleanup_expired_nonces(now: float) -> None:
    expired = [k for k, exp in _consumed_tokens.items() if exp < now]
    for k in expired:
        del _consumed_tokens[k]

def re_sub_phrase(s: str) -> str:
    import re
    # Keep only alphanumeric and dashes
    return re.sub(r"[^A-Za-z0-9_\-]", "", s)
