import os
import csv
import json
import datetime
from pathlib import Path
from typing import Dict, List, Any, Optional

try:
    from core.paths import FARIS_ROOT, resolve_case_dir, get_relative_str
    from core.case_manager import case_manager
    from core.engine_manager import engine_manager
    from integrity.audit_logger import audit_logger
except ImportError:
    from ..core.paths import FARIS_ROOT, resolve_case_dir, get_relative_str
    from ..core.case_manager import case_manager
    from ..core.engine_manager import engine_manager
    from ..integrity.audit_logger import audit_logger

class ReportGenerator:
    """
    Forensic Multi-Format Report Generator.
    Produces comprehensive, standards-compliant JSON, CSV, and standalone HTML reports.
    """

    def generate_all_reports(self, case_id: str) -> Dict[str, Path]:
        """
        Generates JSON, CSV, and HTML reports for a given case.
        """
        case_dir = resolve_case_dir(case_id)
        reports_dir = case_dir / "reports"
        reports_dir.mkdir(parents=True, exist_ok=True)

        meta = case_manager.load_case_metadata(case_id)
        engines_inv = engine_manager.get_inventory()
        audit_status = audit_logger.verify_audit_chain(case_id)

        # Load analysis files if present
        analysis_dir = case_dir / "analysis"
        img_analysis = {}
        if (analysis_dir / "image_analysis.json").exists():
            with open(analysis_dir / "image_analysis.json", "r", encoding="utf-8") as f:
                img_analysis = json.load(f)

        disc_artifacts = {}
        if (analysis_dir / "discovered_artifacts.json").exists():
            with open(analysis_dir / "discovered_artifacts.json", "r", encoding="utf-8") as f:
                disc_artifacts = json.load(f)

        art_states = {}
        if (analysis_dir / "artifact_states.json").exists():
            with open(analysis_dir / "artifact_states.json", "r", encoding="utf-8") as f:
                art_states = json.load(f)

        # Load validation files
        validated_dir = case_dir / "validated"
        val_report = {}
        if (validated_dir / "validation_report.json").exists():
            with open(validated_dir / "validation_report.json", "r", encoding="utf-8") as f:
                val_report = json.load(f)

        # Load specialized sanitization recovery summary if present
        sanitization_dir = case_dir / "recovery" / "sanitization"
        sanitization_report = {}
        if (sanitization_dir / "sanitization_summary.json").exists():
            try:
                with open(sanitization_dir / "sanitization_summary.json", "r", encoding="utf-8") as f_san:
                    sanitization_report = json.load(f_san)
            except Exception:
                pass

        # Build Master JSON Report
        master_report = {
            "faris_version": "1.0.0",
            "report_generated_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "case_id": case_id,
            "case_metadata": meta,
            "engine_inventory": engines_inv,
            "audit_chain_verification": audit_status,
            "image_analysis": img_analysis,
            "artifact_discovery": {
                "total_discovered": disc_artifacts.get("total_artifacts", 0),
                "active_count": disc_artifacts.get("active_artifacts", 0),
                "deleted_count": disc_artifacts.get("deleted_artifacts", 0)
            },
            "artifact_states": art_states.get("state_counts", {}),
            "sanitization_recovery": sanitization_report,
            "validated_artifacts": val_report.get("artifacts", []),
            "validation_summary": val_report.get("summary_counts", {})
        }

        # 1. Save JSON Report
        json_path = reports_dir / f"forensic_report_{case_id}.json"
        with open(json_path, "w", encoding="utf-8") as f_json:
            json.dump(master_report, f_json, indent=2)

        # 2. Save CSV Report
        csv_path = reports_dir / f"recovered_artifacts_{case_id}.csv"
        with open(csv_path, "w", newline="", encoding="utf-8") as f_csv:
            writer = csv.writer(f_csv)
            writer.writerow(["File Name", "Relative Path", "Validation Status", "Confidence", "Size (Bytes)", "SHA-256 Hash", "Forensic Reason"])
            for a in val_report.get("artifacts", []):
                writer.writerow([
                    a.get("file", ""),
                    a.get("relative_path", ""),
                    a.get("validation_status", ""),
                    a.get("confidence", ""),
                    a.get("size_bytes", 0),
                    a.get("sha256", ""),
                    a.get("reason", "")
                ])

        # 3. Save Standalone HTML Report
        html_path = reports_dir / f"forensic_report_{case_id}.html"
        self._generate_html_report(html_path, master_report)

        print(f"[+] Multi-format reporting completed for case '{case_id}':")
        print(f"    - JSON: {json_path}")
        print(f"    - CSV:  {csv_path}")
        print(f"    - HTML: {html_path}")

        return {
            "json": json_path,
            "csv": csv_path,
            "html": html_path
        }

    def _generate_html_report(self, output_path: Path, data: Dict[str, Any]):
        case_id = data.get("case_id", "N/A")
        gen_time = data.get("report_generated_at", "N/A")
        meta = data.get("case_metadata", {})
        val_summary = data.get("validation_summary", {})
        artifacts = data.get("validated_artifacts", [])
        engines = data.get("engine_inventory", {})
        audit = data.get("audit_chain_verification", {})

        html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>FARIS Forensic Report — Case {case_id}</title>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; margin: 0; padding: 30px; background-color: #f8fafc; color: #1e293b; }}
        .header {{ border-bottom: 2px solid #0f172a; padding-bottom: 20px; margin-bottom: 30px; }}
        h1 {{ margin: 0 0 10px 0; color: #0f172a; font-size: 26px; }}
        .meta-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 15px; margin-bottom: 30px; }}
        .card {{ background: #ffffff; border: 1px solid #e2e8f0; border-radius: 8px; padding: 18px; box-shadow: 0 1px 3px rgba(0,0,0,0.05); }}
        .card-title {{ font-size: 12px; font-weight: 600; text-transform: uppercase; color: #64748b; margin-bottom: 8px; }}
        .card-value {{ font-size: 20px; font-weight: 700; color: #0f172a; }}
        table {{ width: 100%; border-collapse: collapse; background: #ffffff; border-radius: 8px; overflow: hidden; margin-top: 15px; border: 1px solid #e2e8f0; }}
        th, td {{ padding: 12px 16px; text-align: left; font-size: 13px; border-bottom: 1px solid #e2e8f0; }}
        th {{ background-color: #f1f5f9; font-weight: 600; color: #334155; }}
        .badge {{ display: inline-block; padding: 4px 8px; border-radius: 4px; font-size: 11px; font-weight: 600; text-transform: uppercase; }}
        .badge-valid {{ background: #dcfce7; color: #166534; }}
        .badge-medium {{ background: #fef9c3; color: #854d0e; }}
        .badge-low {{ background: #fee2e2; color: #991b1b; }}
        .badge-ok {{ background: #e0f2fe; color: #0369a1; }}
        .hash {{ font-family: monospace; font-size: 11px; color: #475569; word-break: break-all; }}
        h2 {{ font-size: 18px; color: #0f172a; margin-top: 30px; }}
        .footer {{ margin-top: 50px; font-size: 12px; color: #94a3b8; text-align: center; border-top: 1px solid #e2e8f0; padding-top: 20px; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>FARIS — Forensic Recovery & Verification Report</h1>
        <div><strong>Case ID:</strong> {case_id} &nbsp;|&nbsp; <strong>Generated:</strong> {gen_time} &nbsp;|&nbsp; <strong>Examiner:</strong> {meta.get("operator", "Forensic Examiner")}</div>
    </div>

    <div class="meta-grid">
        <div class="card">
            <div class="card-title">Valid Recovered</div>
            <div class="card-value" style="color: #16a34a;">{val_summary.get("VALID", 0)}</div>
        </div>
        <div class="card">
            <div class="card-title">Partially Valid</div>
            <div class="card-value" style="color: #ca8a04;">{val_summary.get("PARTIALLY_VALID", 0)}</div>
        </div>
        <div class="card">
            <div class="card-title">Rejected / False Positives</div>
            <div class="card-value" style="color: #dc2626;">{val_summary.get("REJECTED", 0)}</div>
        </div>
        <div class="card">
            <div class="card-title">Audit Chain Integrity</div>
            <div class="card-value" style="color: #0284c7;">{audit.get("status", "VERIFIED")}</div>
        </div>
    </div>

    <h2>Bundled Forensic Engines</h2>
    <table>
        <tr><th>Engine</th><th>Version</th><th>Status</th></tr>
        <tr><td>The Sleuth Kit (TSK)</td><td>{engines.get("sleuthkit", {}).get("version", "4.15.0")}</td><td><span class="badge badge-valid">Active</span></td></tr>
        <tr><td>libewf</td><td>{engines.get("libewf", {}).get("version", "20230405")}</td><td><span class="badge badge-valid">Active</span></td></tr>
        <tr><td>PhotoRec / Native Carver</td><td>FARIS Zero-Dependency Signature Carver</td><td><span class="badge badge-valid">Active</span></td></tr>
    </table>

    <h2>Recovered & Validated Artifacts Catalog</h2>
    <table>
        <thead>
            <tr>
                <th>Artifact</th>
                <th>Status</th>
                <th>Confidence</th>
                <th>Size (Bytes)</th>
                <th>SHA-256 Provenance Hash</th>
                <th>Forensic Explanation</th>
            </tr>
        </thead>
        <tbody>
"""
        if not artifacts:
            html_content += "<tr><td colspan='6' style='text-align:center;'>No artifacts evaluated.</td></tr>"
        else:
            for a in artifacts:
                st = a.get("validation_status", "UNKNOWN")
                badge_cls = "badge-valid" if st == "VALID" else ("badge-medium" if "PARTIAL" in st else "badge-low")
                conf = a.get("confidence", "LOW")
                html_content += f"""
            <tr>
                <td><strong>{a.get("file", "")}</strong></td>
                <td><span class="badge {badge_cls}">{st}</span></td>
                <td><strong>{conf}</strong></td>
                <td>{a.get("size_bytes", 0):,}</td>
                <td class="hash">{a.get("sha256", "N/A")}</td>
                <td>{a.get("reason", "")}</td>
            </tr>
"""

        sanitization_stages = data.get("sanitization_recovery", {}).get("stages", {})

        html_content += f"""
        </tbody>
    </table>

    <h2>Specialized Sanitization Recovery Analysis</h2>
    <table>
        <thead>
            <tr>
                <th>Stage</th>
                <th>Status</th>
                <th>Sanitization Type / Media</th>
                <th>Confidence</th>
                <th>Forensic Finding / Reason</th>
            </tr>
        </thead>
        <tbody>
"""
        if not sanitization_stages:
            html_content += "<tr><td colspan='5' style='text-align:center;'>No specialized sanitization analysis recorded.</td></tr>"
        else:
            stage_labels = [
                ("stage_A_overwrite_analysis", "Stage A: Overwrite Pattern Analysis"),
                ("stage_B_residual_analysis", "Stage B: Residual Data / Remnant Analysis"),
                ("stage_C_sector_block_recovery", "Stage C: Sector / Block-Level Recovery"),
                ("stage_D_multipass_analysis", "Stage D: Multi-Pass Pattern Analysis"),
                ("stage_E_journal_log_analysis", "Stage E: File-System Journal / Log Analysis"),
                ("stage_F_ssd_nand_ftl", "Stage F: SSD / NAND Remnant Analysis"),
                ("stage_G_wear_leveling", "Stage G: Wear-Leveling Analysis"),
                ("stage_H_hidden_unallocated", "Stage H: Hidden / Unallocated Area Analysis"),
                ("stage_I_reconstruction", "Stage I: Previous-State Reconstruction"),
                ("stage_J_crypto_erase", "Stage J: Cryptographic-Erasure Analysis"),
            ]
            for s_key, s_label in stage_labels:
                s_data = sanitization_stages.get(s_key, {})
                s_status = s_data.get("status", "N/A")
                s_type = s_data.get("sanitization_type", "N/A")
                s_conf = s_data.get("confidence", "HIGH")
                s_reason = s_data.get("reason", "N/A")

                if s_status in ("COMPLETED", "VALID", "FULLY_RECOVERED", "RESIDUAL_EVIDENCE_FOUND"):
                    b_cls = "badge-valid"
                elif s_status in ("PARTIALLY_VALID", "PARTIALLY_RECOVERED"):
                    b_cls = "badge-medium"
                elif s_status in ("NOT_ACCESSIBLE", "NOT_APPLICABLE", "N/A"):
                    b_cls = "badge-ok"
                else:
                    b_cls = "badge-low"

                html_content += f"""
            <tr>
                <td><strong>{s_label}</strong></td>
                <td><span class="badge {b_cls}">{s_status}</span></td>
                <td>{s_type}</td>
                <td><strong>{s_conf}</strong></td>
                <td>{s_reason}</td>
            </tr>
"""

        html_content += f"""
        </tbody>
    </table>

    <div class="footer">
        Generated by FARIS (Forensic Adaptive Recovery and Integrity System) v1.0.0 — Offline & Air-Gapped Verification Standard
    </div>
</body>
</html>
"""
        with open(output_path, "w", encoding="utf-8") as f_html:
            f_html.write(html_content)

# Singleton instance
report_generator = ReportGenerator()
