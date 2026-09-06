"""
Shared file-hashing helper.

Extracts the SHA-256 + MD5 streaming-hash pattern that was previously
duplicated inline in seek_help_case_engine.py's acquire_raw_forensic_image()
and ntro_platform_api.py's ISO upload handlers, so new code (the Evidence
Workspace, Forensic Toolkit) computes hashes the same well-tested way
instead of re-implementing it a third time.
"""

import hashlib
from typing import Dict

DEFAULT_CHUNK_SIZE = 65536


def compute_sha256_md5(file_path: str, chunk_size: int = DEFAULT_CHUNK_SIZE) -> Dict[str, str]:
    """
    Streams a file once, computing SHA-256 and MD5 simultaneously.
    Returns {"sha256": <hex>, "md5": <hex>}. Never fabricates a hash --
    raises if the file cannot be read.
    """
    hasher_sha = hashlib.sha256()
    hasher_md5 = hashlib.md5()
    with open(file_path, "rb") as f:
        while True:
            buf = f.read(chunk_size)
            if not buf:
                break
            hasher_sha.update(buf)
            hasher_md5.update(buf)
    return {"sha256": hasher_sha.hexdigest(), "md5": hasher_md5.hexdigest()}
