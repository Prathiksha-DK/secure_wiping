import os
import time
import json
from pathlib import Path
from typing import Dict, List, Any, Optional, Callable

try:
    from core.paths import FARIS_ROOT, resolve_case_dir, get_relative_str
    from integrity.audit_logger import audit_logger
    from .overwrite_analysis import overwrite_analyzer
    from .residual_analysis import residual_analyzer
    from .sector_block_recovery import sector_block_engine
    from .multipass_analysis import multipass_analyzer
    from .journal_log_analysis import journal_log_analyzer
    from .ssd_nand_ftl_analysis import ssd_nand_ftl_analyzer
    from .wear_leveling_analysis import wear_leveling_analyzer
    from .hidden_unallocated_analysis import hidden_unallocated_analyzer
    from .previous_state_reconstruction import previous_state_reconstructor
    from .crypto_erase_analysis import crypto_erase_analyzer
except ImportError:
    from ...core.paths import FARIS_ROOT, resolve_case_dir, get_relative_str
    from ...integrity.audit_logger import audit_logger
    from .overwrite_analysis import overwrite_analyzer
    from .residual_analysis import residual_analyzer
    from .sector_block_recovery import sector_block_engine
    from .multipass_analysis import multipass_analyzer
    from .journal_log_analysis import journal_log_analyzer
    from .ssd_nand_ftl_analysis import ssd_nand_ftl_analyzer
    from .wear_leveling_analysis import wear_leveling_analyzer
    from .hidden_unallocated_analysis import hidden_unallocated_analyzer
    from .previous_state_reconstruction import previous_state_reconstructor
    from .crypto_erase_analysis import crypto_erase_analyzer


class SanitizationManager:
    """
    Master Sanitization Recovery Orchestrator
    =========================================
    Executes and coordinates all 10 specialized sanitization recovery stages (A through J):
      - Stage A: Overwrite Pattern Analysis
      - Stage B: Residual Data / Remnant Analysis
      - Stage C: Sector / Block-Level Recovery
      - Stage D: Multi-Pass Pattern Analysis
      - Stage E: File-System Journal / Log Analysis
      - Stage F: SSD / NAND Remnant Analysis
      - Stage G: Wear-Leveling Analysis
      - Stage H: Hidden / Unallocated Area Analysis
      - Stage I: Previous-State Reconstruction
      - Stage J: Cryptographic-Erasure Analysis

    Strict Integrity Principles:
      - Capability-aware execution (NAND and Wear-leveling report NOT_ACCESSIBLE; no simulated recoveries).
      - Overwritten media honestly reports NO_RECOVERABLE_EVIDENCE.
      - Full tamper-evident SHA-256 forward audit chaining.
    """

    def run_sanitization_pipeline(
        self,
        case_id: str,
        image_path: Path,
        partition_offset: int = 0,
        discovered_artifacts: Optional[List[Dict[str, Any]]] = None,
        device_hint: Optional[str] = None,
        scan_limit_bytes: Optional[int] = None,
        progress_callback: Optional[Callable[[str, str, float, str], None]] = None
    ) -> Dict[str, Any]:
        """
        Executes Stages A through J in exact logical sequence.
        """
        case_dir = resolve_case_dir(case_id)
        sanitization_dir = case_dir / "recovery" / "sanitization"
        sanitization_dir.mkdir(parents=True, exist_ok=True)

        def emit_stage(stage_code: str, stage_name: str, status: str, pct: float, msg: str):
            if progress_callback:
                progress_callback(
                    f"sanitization_{stage_code.lower()}",
                    status,
                    pct,
                    f"Stage {stage_code}  {stage_name}  {status} — {msg}"
                )

        sanitization_results: Dict[str, Any] = {
            "case_id": case_id,
            "evidence_image": get_relative_str(image_path),
            "partition_offset": partition_offset,
            "stages": {},
            "sanitization_artifacts": [],
            "summary": {}
        }

        print("\n========================================================")
        print(" FARIS SPECIALIZED SANITIZATION RECOVERY — STARTING")
        print("========================================================")

        # ----------------------------------------------------
        # Stage A: Overwrite Pattern Analysis
        # ----------------------------------------------------
        print("\n[Stage A/10] Overwrite Pattern Analysis...")
        emit_stage("A", "Overwrite Pattern Analysis", "RUNNING", 85.2, "Characterizing sector patterns (0x00, 0xFF, constant, entropy)...")
        stage_a = overwrite_analyzer.analyze_patterns(
            image_path,
            sample_limit_bytes=scan_limit_bytes or 32 * 1024 * 1024
        )
        sanitization_results["stages"]["stage_A_overwrite_analysis"] = stage_a
        audit_logger.log_action(
            case_id,
            "SANITIZATION_STAGE_A_OVERWRITE_ANALYSIS",
            "Examiner",
            "FARIS Overwrite Pattern Analyzer",
            "1.0.0",
            input_artifact=image_path.name,
            result=stage_a.get("status", "COMPLETED"),
            details={"distribution": stage_a.get("distribution", {})}
        )
        emit_stage("A", "Overwrite Pattern Analysis", stage_a.get("status", "COMPLETED"), 85.6, stage_a.get("reason", "Completed."))

        # ----------------------------------------------------
        # Stage B: Residual Data / Remnant Analysis
        # ----------------------------------------------------
        print("\n[Stage B/10] Residual Data / Remnant Analysis...")
        emit_stage("B", "Residual Data / Remnant Analysis", "RUNNING", 85.8, "Searching for surviving fragments and headers outside wiped regions...")
        stage_b = residual_analyzer.analyze_residuals(
            case_id,
            image_path,
            non_pattern_extents=stage_a.get("residual_extents"),
            max_scan_bytes=scan_limit_bytes or 32 * 1024 * 1024,
            output_dir=sanitization_dir / "residuals"
        )
        sanitization_results["stages"]["stage_B_residual_analysis"] = stage_b
        audit_logger.log_action(
            case_id,
            "SANITIZATION_STAGE_B_RESIDUAL_ANALYSIS",
            "Examiner",
            "FARIS Residual Data Analyzer",
            "1.0.0",
            input_artifact=image_path.name,
            result=stage_b.get("status", "COMPLETED"),
            details={"candidates_found": stage_b.get("candidates_found", 0)}
        )
        emit_stage("B", "Residual Data / Remnant Analysis", stage_b.get("status", "COMPLETED"), 86.2, stage_b.get("reason", "Completed."))

        # ----------------------------------------------------
        # Stage C: Sector / Block-Level Recovery
        # ----------------------------------------------------
        print("\n[Stage C/10] Sector / Block-Level Recovery...")
        emit_stage("C", "Sector / Block-Level Recovery", "RUNNING", 86.4, "Examining physical 512B/4096B sector boundaries and partial overwrites...")
        stage_c = sector_block_engine.recover_sector_blocks(
            case_id,
            image_path,
            max_scan_bytes=scan_limit_bytes or 16 * 1024 * 1024,
            output_dir=sanitization_dir / "sectors"
        )
        sanitization_results["stages"]["stage_C_sector_block_recovery"] = stage_c
        audit_logger.log_action(
            case_id,
            "SANITIZATION_STAGE_C_SECTOR_BLOCK_RECOVERY",
            "Examiner",
            "FARIS Sector Block Engine",
            "1.0.0",
            input_artifact=image_path.name,
            result=stage_c.get("status", "COMPLETED"),
            details={"recovered_blocks": len(stage_c.get("recovered_blocks", []))}
        )
        emit_stage("C", "Sector / Block-Level Recovery", stage_c.get("status", "COMPLETED"), 86.8, stage_c.get("reason", "Completed."))

        # ----------------------------------------------------
        # Stage D: Multi-Pass Pattern Analysis
        # ----------------------------------------------------
        print("\n[Stage D/10] Multi-Pass Pattern Analysis...")
        emit_stage("D", "Multi-Pass Pattern Analysis", "RUNNING", 87.0, "Classifying sanitization signatures against NIST SP 800-88 and DoD standards...")
        stage_d = multipass_analyzer.analyze_multipass_sanitization(
            case_id,
            image_path,
            overwrite_distribution=stage_a.get("distribution")
        )
        sanitization_results["stages"]["stage_D_multipass_analysis"] = stage_d
        audit_logger.log_action(
            case_id,
            "SANITIZATION_STAGE_D_MULTIPASS",
            "Examiner",
            "FARIS Multi-Pass Analyzer",
            "1.0.0",
            input_artifact=image_path.name,
            result=stage_d.get("status", "COMPLETED"),
            details={"matched_standard": stage_d.get("matched_standard", "")}
        )
        emit_stage("D", "Multi-Pass Pattern Analysis", stage_d.get("status", "COMPLETED"), 87.4, stage_d.get("reason", "Completed."))

        # ----------------------------------------------------
        # Stage E: File-System Journal / Log Analysis
        # ----------------------------------------------------
        print("\n[Stage E/10] File-System Journal / Log Analysis...")
        emit_stage("E", "File-System Journal / Log Analysis", "RUNNING", 87.6, "Examining filesystem journals, $LogFile, and metadata transaction logs...")
        stage_e = journal_log_analyzer.analyze_journal_logs(
            case_id,
            image_path,
            partition_offset=partition_offset,
            output_dir=sanitization_dir / "journal"
        )
        sanitization_results["stages"]["stage_E_journal_log_analysis"] = stage_e
        audit_logger.log_action(
            case_id,
            "SANITIZATION_STAGE_E_JOURNAL_LOGS",
            "Examiner",
            "FARIS Journal Log Analyzer",
            "1.0.0",
            input_artifact=image_path.name,
            result=stage_e.get("status", "COMPLETED"),
            details={"filesystem": stage_e.get("filesystem", "UNKNOWN")}
        )
        emit_stage("E", "File-System Journal / Log Analysis", stage_e.get("status", "COMPLETED"), 88.0, stage_e.get("reason", "Completed."))

        # ----------------------------------------------------
        # Stage F: SSD / NAND Remnant Analysis
        # ----------------------------------------------------
        print("\n[Stage F/10] SSD / NAND Remnant Analysis...")
        emit_stage("F", "SSD / NAND Remnant Analysis", "RUNNING", 88.2, "Evaluating Solid-State/NAND media characteristics and controller shielding...")
        stage_f = ssd_nand_ftl_analyzer.analyze_ssd_nand(
            case_id,
            image_path,
            device_type_hint=device_hint
        )
        sanitization_results["stages"]["stage_F_ssd_nand_ftl"] = stage_f
        audit_logger.log_action(
            case_id,
            "SANITIZATION_STAGE_F_SSD_NAND",
            "Examiner",
            "FARIS SSD/NAND Analyzer",
            "1.0.0",
            input_artifact=image_path.name,
            result=stage_f.get("status", "COMPLETED"),
            details={"media_technology": stage_f.get("media_technology", "Unknown")}
        )
        emit_stage("F", "SSD / NAND Remnant Analysis", stage_f.get("status", "COMPLETED"), 88.4, stage_f.get("reason", "Completed."))

        # ----------------------------------------------------
        # Stage G: Wear-Leveling Analysis
        # ----------------------------------------------------
        print("\n[Stage G/10] Wear-Leveling Analysis...")
        emit_stage("G", "Wear-Leveling Analysis", "RUNNING", 88.6, "Evaluating wear-leveling pools and hardware controller firmware accessibility...")
        stage_g = wear_leveling_analyzer.analyze_wear_leveling(
            case_id,
            image_path,
            device_type_hint=device_hint
        )
        sanitization_results["stages"]["stage_G_wear_leveling"] = stage_g
        audit_logger.log_action(
            case_id,
            "SANITIZATION_STAGE_G_WEAR_LEVELING",
            "Examiner",
            "FARIS Wear-Leveling Analyzer",
            "1.0.0",
            input_artifact=image_path.name,
            result=stage_g.get("status", "COMPLETED"),
            details={"wear_leveling_accessible": stage_g.get("wear_leveling_accessible", False)}
        )
        emit_stage("G", "Wear-Leveling Analysis", stage_g.get("status", "COMPLETED"), 88.8, stage_g.get("reason", "Completed."))

        # ----------------------------------------------------
        # Stage H: Hidden / Unallocated Area Analysis (includes Slack)
        # ----------------------------------------------------
        print("\n[Stage H/10] Hidden / Unallocated Area Analysis...")
        emit_stage("H", "Hidden / Unallocated Area Analysis", "RUNNING", 89.0, "Analyzing partition gaps, volume slack, file slack, and unallocated clusters...")
        stage_h = hidden_unallocated_analyzer.analyze_hidden_and_unallocated(
            case_id,
            image_path,
            partition_offset=partition_offset,
            discovered_artifacts=discovered_artifacts,
            max_scan_bytes=scan_limit_bytes or 8 * 1024 * 1024,
            output_dir=sanitization_dir / "hidden_unallocated"
        )
        sanitization_results["stages"]["stage_H_hidden_unallocated"] = stage_h
        audit_logger.log_action(
            case_id,
            "SANITIZATION_STAGE_H_HIDDEN_UNALLOCATED",
            "Examiner",
            "FARIS Hidden & Unallocated Analyzer",
            "1.0.0",
            input_artifact=image_path.name,
            result=stage_h.get("status", "COMPLETED"),
            details={"unmapped_gaps": stage_h.get("unmapped_partition_gaps", 0), "slack_bytes": stage_h.get("total_file_slack_bytes", 0)}
        )
        emit_stage("H", "Hidden / Unallocated Area Analysis", stage_h.get("status", "COMPLETED"), 89.2, stage_h.get("reason", "Completed."))

        # ----------------------------------------------------
        # Stage I: Previous-State Reconstruction
        # ----------------------------------------------------
        print("\n[Stage I/10] Previous-State Reconstruction...")
        emit_stage("I", "Previous-State Reconstruction", "RUNNING", 89.4, "Attempting reconstruction from surviving residual fragments and unallocated remnants...")
        stage_i = previous_state_reconstructor.reconstruct_previous_state(
            case_id,
            residual_candidates=stage_b.get("candidates", []),
            output_dir=sanitization_dir / "reconstructed"
        )
        sanitization_results["stages"]["stage_I_reconstruction"] = stage_i
        audit_logger.log_action(
            case_id,
            "SANITIZATION_STAGE_I_RECONSTRUCTION",
            "Examiner",
            "FARIS Previous-State Reconstructor",
            "1.0.0",
            input_artifact=image_path.name,
            result=stage_i.get("status", "COMPLETED"),
            details={"reconstructed_count": len(stage_i.get("reconstructed_artifacts", []))}
        )
        emit_stage("I", "Previous-State Reconstruction", stage_i.get("status", "COMPLETED"), 89.6, stage_i.get("reason", "Completed."))

        # ----------------------------------------------------
        # Stage J: Cryptographic-Erasure Analysis
        # ----------------------------------------------------
        print("\n[Stage J/10] Cryptographic-Erasure Analysis...")
        emit_stage("J", "Cryptographic-Erasure Analysis", "RUNNING", 89.8, "Inspecting for encryption volume headers, entropy distribution, and crypto-wipe remnants...")
        stage_j = crypto_erase_analyzer.analyze_crypto_erasure(
            case_id,
            image_path
        )
        sanitization_results["stages"]["stage_J_crypto_erase"] = stage_j
        audit_logger.log_action(
            case_id,
            "SANITIZATION_STAGE_J_CRYPTO_ERASE",
            "Examiner",
            "FARIS Crypto Erase Analyzer",
            "1.0.0",
            input_artifact=image_path.name,
            result=stage_j.get("status", "COMPLETED"),
            details={"is_encrypted": stage_j.get("is_encrypted_volume", False)}
        )
        emit_stage("J", "Cryptographic-Erasure Analysis", stage_j.get("status", "COMPLETED"), 90.0, stage_j.get("reason", "Completed."))

        # Aggregate Summary Metrics
        sanitization_results["summary"] = {
            "total_sanitization_stages": 10,
            "stages_completed": sum(1 for s in sanitization_results["stages"].values() if s.get("status") in ("COMPLETED", "RESIDUAL_EVIDENCE_FOUND")),
            "stages_na": sum(1 for s in sanitization_results["stages"].values() if s.get("status") == "NOT_APPLICABLE"),
            "stages_not_accessible": sum(1 for s in sanitization_results["stages"].values() if s.get("status") == "NOT_ACCESSIBLE"),
            "stages_no_evidence": sum(1 for s in sanitization_results["stages"].values() if s.get("status") == "NO_RECOVERABLE_EVIDENCE"),
            "total_residual_candidates": stage_b.get("candidates_found", 0),
            "total_sector_blocks_found": stage_c.get("candidates_found", 0),
            "reconstructed_artifacts": len(stage_i.get("reconstructed_artifacts", []))
        }

        # Save summary JSON
        summary_file = sanitization_dir / "sanitization_summary.json"
        with open(summary_file, "w", encoding="utf-8") as f_sum:
            json.dump(sanitization_results, f_sum, indent=2)

        print("\n========================================================")
        print(" FARIS SPECIALIZED SANITIZATION RECOVERY — COMPLETED")
        print(f" Summary saved to: {summary_file}")
        print("========================================================")

        return sanitization_results


sanitization_manager = SanitizationManager()
