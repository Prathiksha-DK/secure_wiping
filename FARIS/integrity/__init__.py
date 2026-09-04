"""
FARIS Integrity Module
Cryptographic verification, hashing, audit trails, and evidence integrity.
"""

from .evidence_verifier import EvidenceVerifier, evidence_verifier

__all__ = [
    "EvidenceVerifier",
    "evidence_verifier",
]
