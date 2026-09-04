import os
import sys
from pathlib import Path
from typing import Union, Optional

def _determine_faris_root() -> Path:
    """
    Dynamically determines the FARIS root directory.
    Works whether running from source (.py) or compiled binary (PyInstaller/cx_Freeze).
    Never uses machine-specific or hard-coded absolute paths.
    """
    if getattr(sys, "frozen", False) and hasattr(sys, "_MEIPASS"):
        # Running inside PyInstaller bundle
        return Path(sys.executable).resolve().parent
    elif getattr(sys, "frozen", False):
        return Path(sys.executable).resolve().parent
    else:
        # Running from source - core/paths.py is 2 levels below FARIS root
        return Path(__file__).resolve().parent.parent

# Global FARIS root directory
FARIS_ROOT: Path = _determine_faris_root()

# Standard FARIS subdirectories
ENGINES_DIR: Path = FARIS_ROOT / "engines"
RUNTIME_DIR: Path = FARIS_ROOT / "runtime"
CASES_DIR: Path = FARIS_ROOT / "cases"
LICENSES_DIR: Path = FARIS_ROOT / "licenses"
LOGS_DIR: Path = FARIS_ROOT / "logs"
CONFIG_DIR: Path = FARIS_ROOT / "config"

def get_path(*subpaths: Union[str, Path]) -> Path:
    """
    Resolves a path relative to the FARIS root.
    """
    return FARIS_ROOT.joinpath(*subpaths)

def get_cases_dir() -> Path:
    """
    Returns the active cases directory.
    Can be overridden via the FARIS_CASES_DIR environment variable (e.g. during automated tests).
    """
    override = os.environ.get("FARIS_CASES_DIR")
    if override:
        p = Path(override).resolve()
        p.mkdir(parents=True, exist_ok=True)
        return p
    return CASES_DIR

def resolve_case_dir(case_id: str) -> Path:
    """
    Resolves a case directory by ID, supporting both legacy 'case001' and 'cases/<case_id>'.
    Falls back to real CASES_DIR if the case already exists there (e.g. during tests referencing ground-truth cases).
    """
    legacy_dir = FARIS_ROOT / case_id
    if legacy_dir.exists() and legacy_dir.is_dir():
        return legacy_dir

    active_cases_dir = get_cases_dir()
    active_case_path = active_cases_dir / case_id

    # If FARIS_CASES_DIR is overridden for tests, but the case exists in the real CASES_DIR and not in the test dir:
    if active_cases_dir != CASES_DIR and not active_case_path.exists():
        real_case_path = CASES_DIR / case_id
        if real_case_path.exists():
            return real_case_path

    return active_case_path

def get_relative_str(target: Union[str, Path]) -> str:
    """
    Converts any path into a FARIS-relative path string.
    Guarantees no user-specific absolute prefixes (C:\\Users..., D:\\...) are exposed.
    """
    p = Path(target).resolve()
    try:
        rel = p.relative_to(FARIS_ROOT)
        return str(rel).replace("\\", "/")
    except ValueError:
        # Fallback if outside root
        return p.name
