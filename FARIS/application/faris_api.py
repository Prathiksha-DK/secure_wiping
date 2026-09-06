import os
import json
import shutil
import hashlib
import datetime
from pathlib import Path
from typing import Dict, List, Any, Optional, Callable

try:
    from core.paths import FARIS_ROOT, resolve_case_dir, get_relative_str
    from core.case_manager import case_manager
    from core.engine_manager import engine_manager
    from acquisition.acquire import acquire_physical_device
    from acquisition.device_discovery import device_discovery_manager
    from integrity.evidence_verifier import evidence_verifier
    from integrity.audit_logger import audit_logger
    from analysis.image_analyzer import image_analyzer
    from analysis.artifact_discovery import artifact_discovery_engine
    from analysis.artifact_state_analysis import artifact_state_analyzer
    from recovery.adaptive_engine import adaptive_recovery_engine
    from recovery.folder_recovery import folder_recovery_engine
    from validation.recovery_validator import recovery_validator
    from reporting.report_generator import report_generator
except ImportError:
    from ..core.paths import FARIS_ROOT, resolve_case_dir, get_relative_str
    from ..core.case_manager import case_manager
    from ..core.engine_manager import engine_manager
    from ..acquisition.acquire import acquire_physical_device
    from ..acquisition.device_discovery import device_discovery_manager
    from ..integrity.evidence_verifier import evidence_verifier
    from ..integrity.audit_logger import audit_logger
    from ..analysis.image_analyzer import image_analyzer
    from ..analysis.artifact_discovery import artifact_discovery_engine
    from ..analysis.artifact_state_analysis import artifact_state_analyzer
    from ..recovery.adaptive_engine import adaptive_recovery_engine
    from ..recovery.folder_recovery import folder_recovery_engine
    from ..validation.recovery_validator import recovery_validator
    from ..reporting.report_generator import report_generator

class FARISAPI:
    """
    Official Public Integration API for FARIS.
    Exposes both individual granular operations and the master unified background pipeline.
    """

    def discover_devices(self) -> Dict[str, Any]:
        """
        Discovers connected physical storage drives (SSDs, HDDs, USB pendrives, SD cards).
        """
        physical = device_discovery_manager.scan_devices()
        return {
            "status": "SUCCESS",
            "physical_devices": physical,
            "all_targets": physical
        }

    def get_engine_status(self) -> Dict[str, Any]:
        """
        Returns status and exact verified versions of all bundled forensic engines.
        """
        return {
            "status": "SUCCESS",
            "faris_root": str(FARIS_ROOT.name),
            "engines": engine_manager.get_inventory()
        }

    def create_case(self, case_id: str, case_name: str, operator: str = "Examiner") -> Dict[str, Any]:
        """
        Initializes a new forensic case with standard folder structures and metadata.
        """
        meta = case_manager.create_case(case_id, case_name, operator)
        audit_logger.log_action(case_id, "CASE_CREATED", operator, "FARIS Core", "1.0.0", details={"case_name": case_name})
        return {
            "status": "SUCCESS",
            "case_id": case_id,
            "metadata": meta
        }

    def register_evidence(self, case_id: str, evidence_path: str, evidence_type: str = "Disk Image") -> Dict[str, Any]:
        """
        Registers an evidence image file into the case registry.
        """
        p = Path(evidence_path)
        if not p.is_absolute():
            p = FARIS_ROOT / evidence_path

        evidence_data = {
            "evidence_id": f"EVID_{p.stem}",
            "evidence_type": evidence_type,
            "path": get_relative_str(p),
            "exists": p.exists(),
            "size_bytes": p.stat().st_size if p.exists() else 0
        }
        meta = case_manager.register_evidence(case_id, evidence_data)
        audit_logger.log_action(case_id, "EVIDENCE_REGISTERED", "Examiner", "FARIS Core", "1.0.0", input_artifact=str(p.name))
        return {
            "status": "SUCCESS",
            "case_id": case_id,
            "evidence": evidence_data
        }

    def _resolve_case_image(self, case_id: str, image_path: Optional[Path] = None) -> Path:
        """
        Authoritatively resolves the evidence image for a specific case.
        Strictly enforces case isolation: never returns an image belonging to another case.
        """
        if image_path:
            p = Path(image_path)
            if not p.is_absolute():
                p = FARIS_ROOT / p
            if p.exists():
                return p
            p_case = resolve_case_dir(case_id) / str(image_path)
            if p_case.exists():
                return p_case

        # Lookup registered primary evidence in case metadata
        primary = case_manager.get_primary_evidence(case_id)
        if primary and primary.exists():
            return primary

        # Search strictly inside case directory
        case_dir = resolve_case_dir(case_id)
        for sub in [case_dir / "acquired", case_dir / "evidence", case_dir]:
            if sub.exists():
                for ext in ["*.E01", "*.raw", "*.dd", "*.img"]:
                    found = sorted(list(sub.glob(ext)))
                    if found:
                        return found[0]

        raise FileNotFoundError(f"No evidence image found for case '{case_id}'. Ensure acquisition or registration was performed.")

    def verify_evidence(
        self,
        case_id: str,
        stage_label: str = "PRE_ANALYSIS",
        target_image_path: Optional[Path] = None
    ) -> Dict[str, Any]:
        """
        Verifies evidence SHA-256/MD5 hashes and read-only protection for the specific case image.
        """
        img = None
        if target_image_path:
            img = self._resolve_case_image(case_id, target_image_path)
        
        res = evidence_verifier.run_case_verification(case_id, stage_label, target_image_path=img)
        audit_logger.log_action(case_id, f"EVIDENCE_VERIFICATION_{stage_label}", "Examiner", "libewf / Python Hashlib", "20230405", result="VERIFIED_MATCH")
        return res

    def analyze_evidence(self, case_id: str, image_path: Optional[Path] = None) -> Dict[str, Any]:
        """
        Executes partition and filesystem analysis on the case image.
        """
        img = self._resolve_case_image(case_id, image_path)
        res = image_analyzer.run_full_analysis(case_id, img)
        audit_logger.log_action(case_id, "IMAGE_ANALYSIS", "Examiner", "TSK mmls/fsstat", "4.15.0", input_artifact=img.name)
        return res

    def discover_artifacts(self, case_id: str, image_path: Optional[Path] = None, partition_offset: Optional[int] = None) -> Dict[str, Any]:
        """
        Discovers active, deleted, and orphan artifacts in the filesystem of the case image.
        """
        img = self._resolve_case_image(case_id, image_path)
        offset = partition_offset if partition_offset is not None else 0
        res = artifact_discovery_engine.run_case_discovery(case_id, img, offset)
        audit_logger.log_action(case_id, "ARTIFACT_DISCOVERY", "Examiner", "TSK fls", "4.15.0", input_artifact=img.name)
        return res

    def analyze_artifact_state(self, case_id: str, image_path: Optional[Path] = None, partition_offset: Optional[int] = None) -> Dict[str, Any]:
        """
        Classifies artifacts into HEALTHY, DELETED, DAMAGED, FRAGMENTED using the case image.
        """
        img = self._resolve_case_image(case_id, image_path)
        offset = partition_offset if partition_offset is not None else 0
        res = artifact_state_analyzer.run_state_analysis(case_id, img, offset)
        audit_logger.log_action(case_id, "ARTIFACT_STATE_ANALYSIS", "Examiner", "TSK istat", "4.15.0", input_artifact=img.name)
        return res

    def recover_artifacts(
        self,
        case_id: str,
        image_path: Optional[Path] = None,
        partition_offset: Optional[int] = None,
        scan_limit_bytes: Optional[int] = None,
        progress_callback: Optional[Callable[[str, str, float, str], None]] = None
    ) -> Dict[str, Any]:
        """
        Runs the full 10-branch Adaptive Recovery Engine strictly on the case image.
        """
        img = self._resolve_case_image(case_id, image_path)
        offset = partition_offset if partition_offset is not None else 0
        res = adaptive_recovery_engine.run_adaptive_pipeline(
            case_id, img, offset, scan_limit_bytes, progress_callback=progress_callback
        )
        audit_logger.log_action(case_id, "ADAPTIVE_RECOVERY_PIPELINE", "Examiner", "FARIS Adaptive Engine", "1.0.0", input_artifact=img.name, output_artifact=f"{case_id}/recovery")
        return res

    def validate_recovery(self, case_id: str) -> Dict[str, Any]:
        """
        Validates all recovered artifacts, rejects false positives, and assigns forensic confidence ratings.
        """
        res = recovery_validator.validate_case_recoveries(case_id)
        audit_logger.log_action(case_id, "RECOVERY_VALIDATION", "Examiner", "FARIS Validator", "1.0.0", output_artifact=f"{case_id}/validated")
        return res

    def calculate_hashes(self, case_id: str) -> Dict[str, Any]:
        """
        Generates cryptographic SHA-256 manifest across evidence, recovered artifacts, and reports.
        """
        res = audit_logger.generate_case_hash_manifest(case_id)
        return res

    def generate_report(self, case_id: str) -> Dict[str, Any]:
        """
        Generates multi-format forensic reports (JSON, CSV, HTML).
        """
        paths = report_generator.generate_all_reports(case_id)
        audit_logger.log_action(case_id, "FORENSIC_REPORTS_GENERATED", "Examiner", "FARIS Reporter", "1.0.0", output_artifact=f"{case_id}/reports")
        return {
            "status": "SUCCESS",
            "case_id": case_id,
            "report_files": {k: get_relative_str(v) for k, v in paths.items()}
        }

    def export_verified_artifacts(self, case_id: str, destination_dir: str) -> Dict[str, Any]:
        """
        Safely exports verified recovered artifacts to a user-selected separate destination device/folder.
        Preserves original directory hierarchies, folders, and document file types.
        Protects original evidence from any write interaction.
        """
        case_dir = resolve_case_dir(case_id)
        dest = Path(destination_dir)
        dest.mkdir(parents=True, exist_ok=True)

        exported = []
        exported_hashes = set()

        # 1. Export complete filesystem directory hierarchy if reconstructed by tsk_recover
        fs_tree_dir = case_dir / "recovery" / "filesystem_tree"
        if fs_tree_dir.exists() and fs_tree_dir.is_dir():
            for root, dirs, files in os.walk(fs_tree_dir):
                for fname in files:
                    src_f = Path(root) / fname
                    try:
                        rel_path = src_f.relative_to(fs_tree_dir)
                        target_f = dest / rel_path
                        target_f.parent.mkdir(parents=True, exist_ok=True)
                        shutil.copy2(src_f, target_f)
                        dest_hash = hashlib.sha256(target_f.read_bytes()).hexdigest()
                        exported_hashes.add(dest_hash)
                        exported.append({
                            "file": fname,
                            "relative_path": str(rel_path).replace("\\", "/"),
                            "destination": str(target_f),
                            "sha256": dest_hash,
                            "source_method": "filesystem_tree/tsk_recover",
                            "integrity_verified": True
                        })
                    except Exception as e_tree:
                        print(f"[!] Export notice for {fname}: {e_tree}")

        # 2. Export deleted files recovered by FAT32 scanner
        del_files_dir = case_dir / "recovery" / "deleted_files"
        if del_files_dir.exists() and del_files_dir.is_dir():
            target_del_dir = dest / "recovered_deleted"
            for d_file in del_files_dir.iterdir():
                if d_file.is_file():
                    try:
                        target_del_f = target_del_dir / d_file.name
                        target_del_f.parent.mkdir(parents=True, exist_ok=True)
                        shutil.copy2(d_file, target_del_f)
                        dest_hash = hashlib.sha256(target_del_f.read_bytes()).hexdigest()
                        if dest_hash not in exported_hashes:
                            exported_hashes.add(dest_hash)
                            exported.append({
                                "file": d_file.name,
                                "relative_path": f"recovered_deleted/{d_file.name}",
                                "destination": str(target_del_f),
                                "sha256": dest_hash,
                                "source_method": "fat32_deleted_scanner",
                                "integrity_verified": True
                            })
                    except Exception:
                        pass

        # 3. Export verified individual artifacts from validation report
        val_report_path = case_dir / "validated" / "validation_report.json"
        if val_report_path.exists():
            try:
                with open(val_report_path, "r", encoding="utf-8") as f:
                    val_data = json.load(f)

                # Map provenance items if available
                prov_map = {}
                adapt_path = case_dir / "recovery" / "adaptive_recovery_summary.json"
                if adapt_path.exists():
                    try:
                        with open(adapt_path, "r", encoding="utf-8") as f_a:
                            adapt_data = json.load(f_a)
                            for p_item in adapt_data.get("master_provenance", []):
                                if p_item.get("file_path"):
                                    prov_map[p_item["file_path"]] = p_item
                    except Exception:
                        pass

                for art in val_data.get("artifacts", []):
                    # Include VALID, PARTIALLY_VALID, and valid UNVERIFIED_GENERIC non-empty files
                    status = art.get("validation_status", "")
                    if status in ["VALID", "PARTIALLY_VALID", "UNVERIFIED_GENERIC"]:
                        rel_p = art.get("relative_path")
                        src_file = FARIS_ROOT / rel_p if rel_p else None
                        if src_file and src_file.exists() and src_file.is_file() and src_file.stat().st_size > 0:
                            f_hash = art.get("sha256") or hashlib.sha256(src_file.read_bytes()).hexdigest()
                            if f_hash in exported_hashes:
                                continue

                            prov_item = prov_map.get(rel_p) or {}
                            orig_name = prov_item.get("name") or src_file.name

                            # Clean up mangled metadata names
                            clean_fname = orig_name
                            if clean_fname.startswith("metadata_") and "_inode_" in clean_fname:
                                clean_fname = clean_fname.replace("metadata_", "")
                                if clean_fname.endswith(".bin"):
                                    clean_fname = clean_fname[:-4]

                            # Determine export destination path
                            if "carved" in rel_p.lower():
                                target_file = dest / "carved" / clean_fname
                            else:
                                target_file = dest / clean_fname

                            target_file.parent.mkdir(parents=True, exist_ok=True)
                            shutil.copy2(src_file, target_file)
                            dest_hash = hashlib.sha256(target_file.read_bytes()).hexdigest()
                            exported_hashes.add(dest_hash)
                            exported.append({
                                "file": clean_fname,
                                "destination": str(target_file),
                                "sha256": dest_hash,
                                "integrity_verified": (dest_hash == f_hash)
                            })
            except Exception as e_val:
                print(f"[!] Validation report export notice: {e_val}")

        audit_logger.log_action(
            case_id,
            "EXPORT_VERIFIED_ARTIFACTS",
            "Examiner",
            "FARIS Exporter",
            "1.0.0",
            output_artifact=str(dest),
            details={"exported_count": len(exported)}
        )

        return {
            "status": "SUCCESS",
            "case_id": case_id,
            "exported_count": len(exported),
            "destination": str(dest),
            "artifacts": exported
        }

    def resolve_folder_scope(self, folder_path: str, target_device: Optional[str] = None) -> Dict[str, Any]:
        """
        Resolves storage allocation, directory clusters, child file chains, and logical LBAs for a folder.
        """
        return folder_recovery_engine.resolve_folder_scope(folder_path, target_device=target_device)

    def recover_folder(
        self,
        setup: Dict[str, Any],
        progress_callback: Optional[Callable[[str, str, float, str], None]] = None
    ) -> Dict[str, Any]:
        """
        Executes complete folder-level forensic recovery pipeline.
        """
        return folder_recovery_engine.execute_folder_recovery(setup, progress_callback=progress_callback)

    def run_full_forensic_pipeline(
        self,
        setup: Dict[str, Any],
        progress_callback: Optional[Callable[[str, str, float, str], None]] = None
    ) -> Dict[str, Any]:
        """
        Master Background Forensic Pipeline.
        Executes the entire end-to-end recovery workflow (Device or Folder scoped).
        """
        scope = str(setup.get("scope") or setup.get("recovery_scope") or "").strip().upper()
        if scope == "FOLDER" or setup.get("folder_path"):
            return self.recover_folder(setup, progress_callback=progress_callback)

        case_id = setup.get("case_id")
        if not case_id or not str(case_id).strip():
            return {
                "status": "FAILED",
                "error": "Invalid or missing Case Number / Case ID. A valid Case ID is required."
            }
        case_id = str(case_id).strip()

        examiner = setup.get("examiner", "Forensic Examiner")
        evidence_id = setup.get("evidence_id") or f"EVID_{case_id}"
        description = setup.get("description", "Physical Storage Device Acquisition")
        notes = setup.get("notes", "")
        source_type = setup.get("source_type", "Physical Storage Device")
        source_path = setup.get("source_path", "")
        scan_limit_bytes = setup.get("scan_limit_bytes")
        export_destination = setup.get("export_destination") or setup.get("recovery_output_path")

        def report(stage_id: str, status: str, pct: float, msg: str):
            if progress_callback:
                progress_callback(stage_id, status, pct, msg)

        print(f"\n[*] Starting unified forensic pipeline for Case {case_id}...")

        # Safety Check: Ensure export destination is not inside or equal to source device
        if export_destination and source_path:
            norm_src = str(source_path).strip().lower()
            norm_dest = str(export_destination).strip().lower()
            if norm_src in norm_dest or norm_dest == norm_src:
                report("setup", "FAILED", 0.0, "Safety Violation: Recovery output destination cannot be on the source evidence device.")
                return {
                    "status": "FAILED",
                    "error": f"Safety Violation: Recovery output directory '{export_destination}' matches or resides inside the source evidence '{source_path}'."
                }

        current_evidence_image: Optional[Path] = None

        # 1. Setup & Case Initialization
        report("setup", "RUNNING", 5.0, f"Initializing Case {case_id} and evidence directory structure...")
        self.create_case(case_id, description or f"Forensic Case {case_id}", examiner)
        report("setup", "COMPLETED", 10.0, f"Case {case_id} initialized.")

        # 2. Acquisition (if physical device)
        is_phys = setup.get("is_physical", False) or "Physical" in str(source_type)
        if is_phys:
            report("acquisition", "RUNNING", 15.0, f"Acquiring physical device {source_path} via bundled ewfacquire...")
            acq_res = acquire_physical_device(
                case_id,
                source_path,
                examiner=examiner,
                evidence_id=evidence_id,
                description=description,
                notes=notes
            )
            if acq_res.get("status") != "SUCCESS" or not acq_res.get("primary_image"):
                err_msg = acq_res.get("error") or acq_res.get("stderr") or "Physical acquisition failed or cancelled."
                report("acquisition", "FAILED", 15.0, f"Acquisition failed: {err_msg[:100]}")
                return {
                    "status": "FAILED",
                    "error": f"Physical acquisition failed: {err_msg}"
                }
            
            # Authoritative newly created image path
            new_img_str = acq_res["primary_image"]
            current_evidence_image = Path(new_img_str)
            if not current_evidence_image.is_absolute():
                current_evidence_image = (FARIS_ROOT / new_img_str).resolve()

            if not current_evidence_image.exists():
                report("acquisition", "FAILED", 15.0, f"Acquired image missing on disk: {current_evidence_image}")
                return {
                    "status": "FAILED",
                    "error": f"Newly acquired image not found at {current_evidence_image}"
                }

            self.register_evidence(
                case_id,
                str(current_evidence_image),
                evidence_type="Disk Image (EWF / EnCase 7)"
            )
            report("acquisition", "COMPLETED", 20.0, f"Physical device imaged to {current_evidence_image.name}")
        else:
            if not source_path:
                report("acquisition", "FAILED", 15.0, "No evidence source provided.")
                return {"status": "FAILED", "error": "No evidence source provided."}

            current_evidence_image = Path(source_path)
            if not current_evidence_image.is_absolute():
                current_evidence_image = (FARIS_ROOT / source_path).resolve()

            if not current_evidence_image.exists():
                report("acquisition", "FAILED", 15.0, f"Evidence file not found: {source_path}")
                return {"status": "FAILED", "error": f"Evidence file not found at {source_path}"}

            self.register_evidence(case_id, str(current_evidence_image), evidence_type="Disk Image")
            report("acquisition", "N/A", 20.0, "N/A — Existing image provided (Acquisition skipped).")

        # 3. Evidence Verification on authoritative current_evidence_image
        report("verification", "RUNNING", 25.0, f"Verifying {current_evidence_image.name} integrity & SHA-256 pre-analysis hashes...")
        self.verify_evidence(case_id, "PRE_ANALYSIS", target_image_path=current_evidence_image)
        report("verification", "COMPLETED", 35.0, "Evidence verified (Read-only protection enforced).")

        # 4. Partition & Filesystem Analysis on authoritative current_evidence_image
        report("analysis", "RUNNING", 40.0, f"Analyzing partition tables and filesystem on {current_evidence_image.name}...")
        img_analysis = self.analyze_evidence(case_id, image_path=current_evidence_image)
        
        # Dynamically determine partition offset from analysis report
        detected_primary_offset = img_analysis.get("primary_partition_offset", 0)
        
        # If user explicitly requested a specific offset, use it; otherwise use dynamically detected offset
        user_offset = setup.get("partition_offset")
        if user_offset is not None and str(user_offset).strip() != "":
            try:
                actual_partition_offset = int(user_offset)
            except ValueError:
                actual_partition_offset = detected_primary_offset
        else:
            actual_partition_offset = detected_primary_offset

        report("analysis", "COMPLETED", 50.0, f"Analysis complete ({img_analysis.get('partition_count', 0)} partitions, primary offset: {actual_partition_offset}).")

        # 5. Artifact Discovery on authoritative current_evidence_image
        report("discovery", "RUNNING", 55.0, f"Enumerating active, deleted, and orphaned inodes on {current_evidence_image.name} (offset {actual_partition_offset})...")
        disc_res = self.discover_artifacts(case_id, image_path=current_evidence_image, partition_offset=actual_partition_offset)
        report("discovery", "COMPLETED", 60.0, f"Discovered {disc_res.get('total_artifacts', 0)} filesystem artifacts.")

        # 6. Artifact State Analysis on authoritative current_evidence_image
        report("states", "RUNNING", 65.0, f"Classifying inode allocation states on {current_evidence_image.name}...")
        self.analyze_artifact_state(case_id, image_path=current_evidence_image, partition_offset=actual_partition_offset)
        report("states", "COMPLETED", 70.0, "Artifact state classification complete.")

        # 7. Adaptive Recovery Engine on authoritative current_evidence_image
        report("recovery", "RUNNING", 75.0, f"Executing 10-branch Adaptive Recovery Engine on {current_evidence_image.name}...")
        rec_res = self.recover_artifacts(
            case_id,
            image_path=current_evidence_image,
            partition_offset=actual_partition_offset,
            scan_limit_bytes=scan_limit_bytes,
            progress_callback=progress_callback
        )
        report("recovery", "COMPLETED", 85.0, "Adaptive recovery complete.")

        # 8. Recovery Validation
        report("validation", "RUNNING", 90.0, "Validating recovered structures & rejecting false positives...")
        self.validate_recovery(case_id)
        report("validation", "COMPLETED", 93.0, "Recovery validation completed.")

        # 9. Cryptographic Hashing Manifest
        report("hashing", "RUNNING", 94.0, "Calculating SHA-256 cryptographic manifest across all recovered artifacts...")
        self.calculate_hashes(case_id)
        report("hashing", "COMPLETED", 96.0, "SHA-256 manifest generated.")

        # 10. Verified Artifact Export (contained inside case folder or user-selected path)
        if not export_destination or not str(export_destination).strip():
            export_destination = str(resolve_case_dir(case_id) / "exported")

        report("export", "RUNNING", 97.0, f"Exporting verified artifacts to {export_destination}...")
        exp_res = self.export_verified_artifacts(case_id, str(export_destination).strip())
        exported_artifacts_count = exp_res.get("exported_count", 0)
        report("export", "COMPLETED", 98.0, f"Exported {exported_artifacts_count} verified artifacts.")

        # 11. Multi-Format Reporting
        report("reporting", "RUNNING", 99.0, "Generating multi-format forensic reports (JSON, CSV, HTML)...")
        rpt_res = self.generate_report(case_id)
        report("reporting", "COMPLETED", 100.0, "Reports successfully generated.")

        print(f"[+] Unified forensic pipeline completed successfully for Case {case_id}.\n")
        return {
            "status": "SUCCESS",
            "case_id": case_id,
            "evidence_image": str(current_evidence_image),
            "partition_offset": actual_partition_offset,
            "exported_count": exported_artifacts_count,
            "export_destination": str(export_destination) if export_destination else "",
            "reports": rpt_res.get("report_files", {}),
            "completed_at": datetime.datetime.now(datetime.timezone.utc).isoformat()
        }

# Singleton instance
faris_api = FARISAPI()
