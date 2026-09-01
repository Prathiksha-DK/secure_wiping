import hashlib
import os
from .config import DEFAULT_CHUNK_SIZE

def compute_file_sha256(file_path: str, chunk_size: int = DEFAULT_CHUNK_SIZE) -> str:
    """Compute SHA-256 hash using streaming chunks to handle large files efficiently."""
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"File not found: {file_path}")

    hasher = hashlib.sha256()
    with open(file_path, "rb") as f:
        while True:
            chunk = f.read(chunk_size)
            if not chunk:
                break
            hasher.update(chunk)
    return hasher.hexdigest().upper()

def verify_file_integrity(file_path: str, expected_hash: str) -> dict:
    """Verify if current file hash matches expected hash."""
    current_hash = compute_file_sha256(file_path)
    matches = (current_hash.upper() == expected_hash.strip().upper())
    return {
        "expected_hash": expected_hash.strip().upper(),
        "current_hash": current_hash,
        "verified": matches,
        "status": "MATCH" if matches else "MISMATCH"
    }
