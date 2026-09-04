"""
FARIS Validation Module
Forensic validation, structural integrity checks, false-positive detection, and confidence scoring.
"""

from .recovery_validator import RecoveryValidator, recovery_validator

__all__ = [
    "RecoveryValidator",
    "recovery_validator",
]
