"""
FARIS Core Module
Forensic Adaptive Recovery and Integrity System
"""

from .paths import FARIS_ROOT, get_path, resolve_case_dir, get_relative_str
from .engine_manager import EngineManager, engine_manager

__all__ = [
    "FARIS_ROOT",
    "get_path",
    "resolve_case_dir",
    "get_relative_str",
    "EngineManager",
    "engine_manager",
]
