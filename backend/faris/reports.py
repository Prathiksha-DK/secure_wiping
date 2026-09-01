import os
import json
import csv
import time
import uuid
from .config import FARIS_REPORTS_DIR, FARIS_VERSION, ENGINE_VERSION
from .db import get_db_connection
from .chain_of_custody import get_chain_events

def generate_forensic_report(case_id: str, job_id: str, fmt: str = "html") -> dict:
    """Generate a comprehensive forensic report in HTML, JSON, or CSV format."""
    os.makedirs(FARIS_REPORTS_DIR, exist_ok=True)
    conn = get_db_connection()

    try:
        case_row = conn.execute("SELECT * FROM faris_cases WHERE case_id = ?", (case_id,)).fetchone()
        job_row = conn.execute("SELECT * FROM faris_scan_jobs WHERE job_id = ?", (job_id,)).fetchone()

        if not case_row or not job_row:
            raise ValueError("Case or Scan Job not found")

        evidence_row = conn.execute("SELECT * FROM faris_evidence WHERE evidence_id = ?", (job_row["evidence_id"],)).fetchone()
        records_rows = conn.execute("SELECT * FROM faris_recovered_records WHERE job_id = ? ORDER BY confidence_score DESC", (job_id,)).fetchall()
        pages_rows = conn.execute("SELECT * FROM faris_page_candidates WHERE job_id = ? ORDER BY offset ASC", (job_id,)).fetchall()
        timeline_rows = conn.execute("SELECT * FROM faris_timeline_events WHERE job_id = ? ORDER BY timestamp_str ASC", (job_id,)).fetchall()
        chain_rows = get_chain_events(case_id)

        case_data = dict(case_row)
        job_data = dict(job_row)
        evidence_data = dict(evidence_row) if evidence_row else {}
        records_data = [dict(r) for r in records_rows]
        pages_data = [dict(p) for p in pages_rows]
        timeline_data = [dict(t) for t in timeline_rows]

        report_id = f"RPT-{uuid.uuid4().hex[:8].upper()}"
        report_time_str = time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime())

        if fmt == "json":
            out_filename = f"{report_id}_{case_id}.json"
            out_path = os.path.join(FARIS_REPORTS_DIR, out_filename)
            report_payload = {
                "report_id": report_id,
                "generated_at": report_time_str,
                "faris_version": FARIS_VERSION,
                "engine_version": ENGINE_VERSION,
                "case": case_data,
                "evidence": evidence_data,
                "scan_job": job_data,
                "summary": {
                    "pages_scanned": job_data.get("pages_scanned", 0),
                    "candidates_found": job_data.get("candidates_found", 0),
                    "validated_pages": job_data.get("validated_pages", 0),
                    "records_recovered": len(records_data),
                    "duration_sec": job_data.get("duration_sec", 0.0)
                },
                "recovered_records": records_data,
                "detected_pages": pages_data,
                "timeline": timeline_data,
                "chain_of_custody": chain_rows
            }
            with open(out_path, "w", encoding="utf-8") as f:
                json.dump(report_payload, f, indent=2)

        elif fmt == "csv":
            out_filename = f"{report_id}_{case_id}.csv"
            out_path = os.path.join(FARIS_REPORTS_DIR, out_filename)
            with open(out_path, "w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow(["Record_ID", "Case_ID", "Evidence_ID", "Row_ID", "Confidence_Score", "Confidence_Level", "Byte_Offset", "Page_Num", "Cell_Index", "Column_Types", "Column_Values", "Reasons"])
                for r in records_data:
                    writer.writerow([
                        r["record_id"],
                        r["case_id"],
                        r["evidence_id"],
                        r["row_id"],
                        r["confidence_score"],
                        r["confidence_level"],
                        r["byte_offset"],
                        r["page_num"],
                        r["cell_idx"],
                        r["column_types"],
                        r["column_values"],
                        r["reasons_json"]
                    ])

        else:
            # HTML format (Professional Forensic Layout)
            out_filename = f"{report_id}_{case_id}.html"
            out_path = os.path.join(FARIS_REPORTS_DIR, out_filename)

            records_table_rows = ""
            for r in records_data[:100]:  # Up to 100 in main preview
                vals = json.loads(r["column_values"])
                val_str = ", ".join([f"'{v}'" if isinstance(v, str) else str(v) for v in vals[:6]])
                conf_badge = f"<span class='badge badge-{r['confidence_level'].lower()}'>{r['confidence_score']}% ({r['confidence_level']})</span>"
                records_table_rows += f"""
                <tr>
                    <td class="mono">{r['record_id']}</td>
                    <td>{r['row_id']}</td>
                    <td>{conf_badge}</td>
                    <td class="mono">0x{r['byte_offset']:08X}</td>
                    <td>Page {r['page_num']} (Cell #{r['cell_idx']})</td>
                    <td class="mono values-cell">{val_str}</td>
                </tr>
                """

            timeline_items = ""
            for t in timeline_data[:30]:
                inf_tag = "<span class='tag-inferred'>Inferred</span>" if t['is_inferred'] else "<span class='tag-explicit'>Explicit</span>"
                timeline_items += f"""
                <li class="timeline-item">
                    <span class="timeline-time">{t['timestamp_str']}</span>
                    {inf_tag}
                    <div class="timeline-content"><strong>{t['event_type']}</strong>: {t['summary']}</div>
                </li>
                """

            chain_items = ""
            for c in chain_rows:
                chain_items += f"""
                <tr>
                    <td>#{c['sequence_num']}</td>
                    <td>{c['timestamp']}</td>
                    <td><strong>{c['action']}</strong></td>
                    <td>{c['details']}</td>
                    <td class="mono hash-cell">{c['event_hash'][:16]}...{c['event_hash'][-8:]}</td>
                </tr>
                """

            html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>FARIS Forensic Recovery Report - {case_data['case_name']}</title>
<style>
    body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; background: #0f172a; color: #f8fafc; margin: 0; padding: 40px; }}
    .container {{ max-width: 1100px; margin: 0 auto; background: #1e293b; border-radius: 12px; border: 1px solid #334155; padding: 40px; box-shadow: 0 20px 25px -5px rgba(0, 0, 0, 0.5); }}
    .header {{ border-bottom: 2px solid #3b82f6; padding-bottom: 20px; margin-bottom: 30px; display: flex; justify-content: space-between; align-items: center; }}
    .title {{ font-size: 24px; font-weight: bold; color: #60a5fa; margin: 0; }}
    .subtitle {{ font-size: 14px; color: #94a3b8; margin-top: 4px; }}
    .meta-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 16px; margin-bottom: 30px; }}
    .meta-card {{ background: #0f172a; padding: 16px; border-radius: 8px; border: 1px solid #334155; }}
    .meta-card .label {{ font-size: 11px; text-transform: uppercase; color: #94a3b8; letter-spacing: 0.5px; }}
    .meta-card .val {{ font-size: 16px; font-weight: 600; color: #f8fafc; margin-top: 4px; word-break: break-all; }}
    h2 {{ font-size: 18px; color: #38bdf8; border-bottom: 1px solid #334155; padding-bottom: 8px; margin-top: 36px; }}
    table {{ width: 100%; border-collapse: collapse; margin-top: 16px; font-size: 13px; }}
    th, td {{ padding: 10px 12px; text-align: left; border-bottom: 1px solid #334155; }}
    th {{ background: #0f172a; color: #94a3b8; font-weight: 600; text-transform: uppercase; font-size: 11px; }}
    .mono {{ font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace; font-size: 12px; }}
    .badge {{ padding: 3px 8px; border-radius: 4px; font-weight: 600; font-size: 11px; display: inline-block; }}
    .badge-high {{ background: #065f46; color: #34d399; border: 1px solid #059669; }}
    .badge-medium {{ background: #854d0e; color: #facc15; border: 1px solid #ca8a04; }}
    .badge-low {{ background: #991b1b; color: #f87171; border: 1px solid #dc2626; }}
    .badge-candidate {{ background: #374151; color: #9ca3af; }}
    .tag-explicit {{ background: #1e3a8a; color: #93c5fd; padding: 2px 6px; border-radius: 4px; font-size: 10px; margin-left: 8px; }}
    .tag-inferred {{ background: #713f12; color: #fde047; padding: 2px 6px; border-radius: 4px; font-size: 10px; margin-left: 8px; }}
    .timeline {{ list-style: none; padding-left: 0; margin-top: 16px; }}
    .timeline-item {{ padding: 12px 16px; background: #0f172a; border-left: 3px solid #38bdf8; margin-bottom: 8px; border-radius: 0 6px 6px 0; }}
    .timeline-time {{ font-weight: 600; color: #38bdf8; font-size: 13px; }}
    .timeline-content {{ margin-top: 4px; color: #cbd5e1; font-size: 13px; }}
    .footer {{ margin-top: 40px; padding-top: 20px; border-top: 1px solid #334155; font-size: 12px; color: #64748b; text-align: center; }}
    @media print {{
        body {{ background: #fff; color: #000; padding: 0; }}
        .container {{ background: #fff; border: none; box-shadow: none; padding: 0; }}
        .meta-card {{ background: #f8fafc; border-color: #cbd5e1; }}
        .meta-card .val {{ color: #0f172a; }}
        th {{ background: #f1f5f9; color: #475569; }}
        td, th {{ border-color: #e2e8f0; }}
        .timeline-item {{ background: #f8fafc; border-left-color: #0284c7; }}
    }}
</style>
</head>
<body>
<div class="container">
    <div class="header">
        <div>
            <h1 class="title">FARIS Forensic Recovery & Integrity Report</h1>
            <div class="subtitle">Forensic Artifact Recovery & Integrity System — {FARIS_VERSION}</div>
        </div>
        <div style="text-align: right;">
            <div class="mono" style="color: #38bdf8; font-weight: bold;">{report_id}</div>
            <div style="font-size: 12px; color: #94a3b8;">Generated: {report_time_str}</div>
        </div>
    </div>

    <div class="meta-grid">
        <div class="meta-card">
            <div class="label">Case Name</div>
            <div class="val">{case_data['case_name']}</div>
            <div style="font-size: 12px; color: #64748b; margin-top: 2px;">{case_data['case_id']}</div>
        </div>
        <div class="meta-card">
            <div class="label">Evidence File</div>
            <div class="val">{evidence_data.get('original_filename', 'N/A')}</div>
            <div style="font-size: 12px; color: #64748b; margin-top: 2px;">{evidence_data.get('file_size', 0):,} bytes</div>
        </div>
        <div class="meta-card">
            <div class="label">Evidence SHA-256</div>
            <div class="val mono" style="font-size: 11px;">{evidence_data.get('sha256_hash', 'N/A')}</div>
        </div>
        <div class="meta-card">
            <div class="label">Recovery Mode</div>
            <div class="val" style="color: #38bdf8;">{job_data.get('mode', 'Header-Independent')}</div>
            <div style="font-size: 12px; color: #64748b; margin-top: 2px;">Page Size: {job_data.get('detected_page_size', 4096)}B</div>
        </div>
        <div class="meta-card">
            <div class="label">SQLite Pages Detected</div>
            <div class="val">{job_data.get('validated_pages', 0)} / {job_data.get('pages_scanned', 0)}</div>
        </div>
        <div class="meta-card">
            <div class="label">Records Recovered</div>
            <div class="val" style="color: #34d399;">{len(records_data)}</div>
        </div>
    </div>

    <h2>1. Recovered Evidence Artifacts ({len(records_data)} Records)</h2>
    <table>
        <thead>
            <tr>
                <th>Record ID</th>
                <th>Row ID</th>
                <th>Confidence</th>
                <th>Byte Offset</th>
                <th>Location</th>
                <th>Carved Values</th>
            </tr>
        </thead>
        <tbody>
            {records_table_rows if records_table_rows else "<tr><td colspan='6'>No records recovered.</td></tr>"}
        </tbody>
    </table>

    <h2>2. Forensic Chronological Timeline</h2>
    <ul class="timeline">
        {timeline_items if timeline_items else "<li class='timeline-item'>No timestamped events identified in carved artifacts.</li>"}
    </ul>

    <h2>3. Chain of Custody & Hash Audit Trail</h2>
    <table>
        <thead>
            <tr>
                <th>Seq</th>
                <th>Timestamp</th>
                <th>Action</th>
                <th>Details</th>
                <th>SHA-256 Hash</th>
            </tr>
        </thead>
        <tbody>
            {chain_items}
        </tbody>
    </table>

    <div class="footer">
        Report generated by FARIS ({ENGINE_VERSION}). Original evidence is preserved read-only.
    </div>
</div>
</body>
</html>
"""
            with open(out_path, "w", encoding="utf-8") as f:
                f.write(html_content)

        # Register in database
        with conn:
            conn.execute("""
                INSERT INTO faris_reports
                (report_id, case_id, evidence_id, job_id, format, report_name, file_path, summary_json, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                report_id,
                case_id,
                job_data.get("evidence_id"),
                job_id,
                fmt.upper(),
                f"FARIS_{case_id}_{report_id}.{fmt}",
                out_path,
                json.dumps({"total_records": len(records_data), "validated_pages": job_data.get("validated_pages", 0)}),
                int(time.time())
            ))

        return {
            "report_id": report_id,
            "format": fmt.upper(),
            "file_name": out_filename,
            "file_path": out_path,
            "download_url": f"/api/faris/reports/download/{report_id}"
        }

    finally:
        conn.close()
