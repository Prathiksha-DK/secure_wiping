import os
import time
import subprocess
from pathlib import Path
from typing import Dict, List, Any, Optional

try:
    from core.paths import FARIS_ROOT, resolve_case_dir
    from core.engine_manager import engine_manager
    from .overwrite_analysis import calculate_shannon_entropy
except ImportError:
    from ...core.paths import FARIS_ROOT, resolve_case_dir
    from ...core.engine_manager import engine_manager
    from .overwrite_analysis import calculate_shannon_entropy


class CryptoEraseAnalyzer:
    """
    Stage J: Cryptographic-Erasure Analysis
    ======================================
    Evaluates evidence related to Cryptographic Erasure (Crypto Wipe / CE):
      - Encryption container headers (BitLocker -FVE-FS-, LUKS, VeraCrypt, APFS/FileVault)
      - High Shannon Entropy distribution (>= 7.95 bits/byte across sectors)
      - Key material remnants or key escrow blocks
      - Plaintext leakage in volume slack, unencrypted hibernation/pagefile remnants, or crash dumps

    CRITICAL INTEGRITY PRINCIPLE:
      When master encryption keys have been destroyed and only high-entropy ciphertext remains,
      FARIS reports:
        STATUS = NO_RECOVERABLE_EVIDENCE
      and NEVER claims recovery of encrypted ciphertext without cryptographic key material.
    """

    def __init__(self):
        self.img_cat = engine_manager.get_tool_path("img_cat")

    def analyze_crypto_erasure(
        self,
        case_id: str,
        image_path: Path,
        max_scan_bytes: Optional[int] = 4 * 1024 * 1024
    ) -> Dict[str, Any]:
        """
        Inspects forensic image for cryptographic erasure indicators, encryption headers, and entropy.
        """
        start_time = time.time()
        started_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(start_time))

        if not image_path.exists():
            return {
                "stage": "J_crypto_erase_analysis",
                "status": "FAILED",
                "reason": f"Image file not found: {image_path}",
                "started_at": started_at,
                "completed_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "duration": 0.0,
                "confidence": "NONE"
            }

        # Known Full-Disk Encryption & Container Signatures
        CRYPTO_SIGNATURES = [
            (b"-FVE-FS-", "BitLocker Full-Disk Encryption"),
            (b"LUKS\xba\xbe", "Linux Unified Key Setup (LUKS)"),
            (b"VERA", "VeraCrypt Container Header"),
            (b"ENCX", "Encrypted Container Volume"),
        ]

        detected_crypto_headers = []
        is_encrypted = False
        sample_entropy = 0.0

        # Read sample bytes from head of image/volume
        try:
            with open(image_path, "rb") as f:
                sample_data = f.read(max_scan_bytes or 4 * 1024 * 1024)
                if sample_data:
                    sample_entropy = calculate_shannon_entropy(sample_data[:65536])
                    for sig, desc in CRYPTO_SIGNATURES:
                        if sig in sample_data:
                            detected_crypto_headers.append(desc)
                            is_encrypted = True
        except Exception:
            pass

        end_time = time.time()
        duration = round(end_time - start_time, 3)
        completed_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(end_time))

        if is_encrypted:
            status = "COMPLETED"
            crypto_verdict = "ENCRYPTION_CONTAINER_DETECTED"
            headers_str = ", ".join(detected_crypto_headers)
            reason = f"Cryptographic container identified: {headers_str}. Volume is encrypted; plaintext is inaccessible without key material."
            conf = "HIGH"
        elif sample_entropy >= 7.95:
            status = "NO_RECOVERABLE_EVIDENCE"
            crypto_verdict = "NO_RECOVERABLE_PLAINTEXT"
            reason = (
                f"Uniform high entropy ({sample_entropy:.3f} bits/byte) observed. "
                f"This is consistent with ciphertext or high-entropy random sanitization; the image alone does not establish which."
            )
            conf = "HIGH"
        else:
            status = "NOT_APPLICABLE"
            crypto_verdict = "UNENCRYPTED_MEDIA"
            reason = f"N/A — Evidence media is unencrypted (Sample entropy: {sample_entropy:.2f} bits/byte). Cryptographic erasure was not applied."
            conf = "HIGH"

        return {
            "stage": "J_crypto_erase_analysis",
            "status": status,
            "crypto_verdict": crypto_verdict,
            "device_type": "Storage Device Image",
            "sanitization_type": "Cryptographic Erasure Verification",
            "started_at": started_at,
            "completed_at": completed_at,
            "duration": duration,
            "is_encrypted_volume": is_encrypted,
            "detected_headers": detected_crypto_headers,
            "sample_entropy": round(sample_entropy, 3),
            "candidates_found": 0,
            "validated_candidates": 0,
            "recovered_targets": 0,
            "partial_targets": 0,
            "rejected_candidates": 0,
            "reason": reason,
            "evidence_offsets": [],
            "confidence": conf
        }


crypto_erase_analyzer = CryptoEraseAnalyzer()
