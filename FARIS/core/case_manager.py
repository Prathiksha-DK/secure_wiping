import os
import json
import datetime
from pathlib import Path
from typing import Dict, List, Optional, Any
from .paths import FARIS_ROOT, CASES_DIR, get_cases_dir, resolve_case_dir, get_relative_str

STANDARD_SUBDIRS = [
    "evidence",
    "acquired",
    "analysis",
    "recovery",
    "validated",
    "exported",
    "reports",
    "audit",
    "hashes",
    "logs",
    "metadata"
]

class CaseManager:
    """
    Manages FARIS forensic case directories, metadata schemas, and evidence registry.
    Seamlessly integrates with legacy cases (e.g. case001) while enforcing standard forensic structure.
    """

    def __init__(self, root_dir: Optional[Path] = None):
        self.root_dir = root_dir or FARIS_ROOT

    @property
    def cases_dir(self) -> Path:
        return get_cases_dir()

    def list_cases(self) -> List[str]:
        """
        Lists all registered case IDs in the FARIS workspace.
        """
        cases = []
        # Check active cases directory
        cases_dir = self.cases_dir
        if cases_dir.exists():
            for item in cases_dir.iterdir():
                if item.is_dir() and not item.name.startswith("."):
                    cases.append(item.name)

        # Check root level legacy cases (e.g. case001)
        for item in self.root_dir.iterdir():
            if item.is_dir() and item.name.lower().startswith("case") and item.name not in cases:
                cases.append(item.name)

        return sorted(cases)

    def get_case_dir(self, case_id: str) -> Path:
        """
        Returns the resolved directory for a case.
        """
        return resolve_case_dir(case_id)

    def ensure_case_structure(self, case_id: str) -> Dict[str, Path]:
        """
        Ensures standard subdirectories exist for a case without altering existing evidence files.
        """
        case_dir = self.get_case_dir(case_id)
        case_dir.mkdir(parents=True, exist_ok=True)
        subdirs = {}
        for sub in STANDARD_SUBDIRS:
            p = case_dir / sub
            p.mkdir(parents=True, exist_ok=True)
            subdirs[sub] = p
        return subdirs

    def get_metadata_path(self, case_id: str) -> Path:
        case_dir = self.get_case_dir(case_id)
        # Prefer metadata/case_metadata.json, fallback to case_metadata.json in root of case
        meta_dir_file = case_dir / "metadata" / "case_metadata.json"
        if meta_dir_file.exists():
            return meta_dir_file
        return case_dir / "case_metadata.json"

    def load_case_metadata(self, case_id: str) -> Dict[str, Any]:
        """
        Loads metadata for a case. If none exists, creates default forensic metadata.
        """
        meta_file = self.get_metadata_path(case_id)
        if meta_file.exists():
            try:
                with open(meta_file, "r", encoding="utf-8") as f:
                    return json.load(f)
            except Exception:
                pass

        # Build initial metadata
        case_dir = self.get_case_dir(case_id)
        # Scan for existing E01 files strictly in THIS case directory
        e01_files = list((case_dir / "acquired").glob("*.E01"))
        if not e01_files:
            e01_files = list((case_dir / "evidence").glob("*.E01"))
        if not e01_files:
            e01_files = list(case_dir.glob("*.E01"))

        if e01_files:
            main_e01 = e01_files[0]
            base_name = main_e01.stem
            segments = sorted([p.name for p in main_e01.parent.glob(f"{base_name}.E*")])
            evidence_list.append({
                "evidence_id": f"EVID_{base_name}",
                "evidence_type": "Disk Image (EWF / EnCase 7)",
                "image_format": "E01",
                "primary_image": get_relative_str(main_e01),
                "segments": segments,
                "verification_status": "PENDING_VERIFICATION",
                "acquisition_timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat()
            })

        default_meta = {
            "case_id": case_id,
            "case_name": f"Forensic Case {case_id}",
            "created_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "operator": "FARIS Forensics Examiner",
            "evidence": evidence_list,
            "analysis_history": [],
            "recovery_history": [],
            "validation_history": [],
            "report_history": []
        }

        self.save_case_metadata(case_id, default_meta)
        return default_meta

    def get_primary_evidence(self, case_id: str) -> Optional[Path]:
        """
        Returns the authoritative primary evidence image Path for a case.
        """
        case_dir = self.get_case_dir(case_id)
        meta = self.load_case_metadata(case_id)
        if meta.get("evidence"):
            p_str = meta["evidence"][0].get("primary_image")
            if p_str:
                p = Path(p_str)
                if not p.is_absolute():
                    p = self.root_dir / p_str
                if p.exists():
                    return p
                # Check within case directory
                p_case = case_dir / p_str
                if p_case.exists():
                    return p_case

        # Search inside case subdirectories strictly for this case
        for search_path in [case_dir / "acquired", case_dir / "evidence", case_dir]:
            if search_path.exists():
                for ext in ["*.E01", "*.raw", "*.dd", "*.img"]:
                    found = list(search_path.glob(ext))
                    if found:
                        return found[0]
        return None

    def save_case_metadata(self, case_id: str, metadata: Dict[str, Any]) -> None:
        """
        Saves updated case metadata to disk.
        """
        case_dir = self.get_case_dir(case_id)
        meta_dir = case_dir / "metadata"
        meta_dir.mkdir(parents=True, exist_ok=True)
        meta_file = meta_dir / "case_metadata.json"

        with open(meta_file, "w", encoding="utf-8") as f:
            json.dump(metadata, f, indent=2)

    def create_case(self, case_id: str, case_name: str, operator: str = "Examiner") -> Dict[str, Any]:
        """
        Creates a new forensic case structure and initializes metadata.
        """
        self.ensure_case_structure(case_id)
        meta = {
            "case_id": case_id,
            "case_name": case_name,
            "created_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "operator": operator,
            "evidence": [],
            "analysis_history": [],
            "recovery_history": [],
            "validation_history": [],
            "report_history": []
        }
        self.save_case_metadata(case_id, meta)
        return meta

    def register_evidence(self, case_id: str, evidence_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Registers an evidence source into the case metadata.
        """
        meta = self.load_case_metadata(case_id)
        meta["evidence"].append(evidence_data)
        self.save_case_metadata(case_id, meta)
        return meta

    def log_operation(self, case_id: str, stage: str, details: Dict[str, Any]) -> None:
        """
        Logs a stage operation into the case history metadata.
        """
        meta = self.load_case_metadata(case_id)
        entry = {
            "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "stage": stage,
            "details": details
        }
        history_key = f"{stage}_history"
        if history_key not in meta:
            meta[history_key] = []
        meta[history_key].append(entry)
        self.save_case_metadata(case_id, meta)

# Singleton instance
case_manager = CaseManager()
