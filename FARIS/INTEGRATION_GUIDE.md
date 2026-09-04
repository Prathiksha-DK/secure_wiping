# FARIS — Integration & Developer Guide

## Overview
**FARIS (Forensic Adaptive Recovery and Integrity System)** is a self-contained, air-gapped forensic recovery and verification platform. It is engineered to be embedded seamlessly into host applications (such as data wiping tools or incident response suites) with zero cloud dependencies, zero external network requests, and zero machine-specific path requirements.

---

## 1. Quick Integration Example

To integrate FARIS into your host Python application:

```python
from FARIS.application.faris_api import faris_api

# 1. Verify bundled forensic engines
status = faris_api.get_engine_status()
print(f"Engines ready: {status['status']}")

# 2. Open / Register Case
case_id = "case001"

# 3. Pre-Analysis Cryptographic Verification
ver_res = faris_api.verify_evidence(case_id, stage_label="PRE_ANALYSIS")

# 4. Partition & Filesystem Analysis
analysis_res = faris_api.analyze_evidence(case_id)

# 5. Artifact Discovery & Classification
discovery_res = faris_api.discover_artifacts(case_id)

# 6. Execute Master Adaptive Recovery Pipeline (10 branches)
recovery_res = faris_api.recover_artifacts(case_id)

# 7. Structural Integrity Validation & False-Positive Filtering
validation_res = faris_api.validate_recovery(case_id)

# 8. Generate Multi-Format Reports (JSON, CSV, HTML)
report_paths = faris_api.generate_report(case_id)
print("Reports generated at:", report_paths["report_files"])

# 9. Safely Export Verified Recovered Artifacts to External Storage (Separate USB / Drive)
faris_api.export_verified_artifacts(case_id, destination_dir="E:/Exported_Recoveries")
```

---

## 2. API Method Reference

| Method | Parameters | Returns | Description |
| :--- | :--- | :--- | :--- |
| `get_engine_status()` | None | `Dict` | Health & versions of Sleuth Kit, libewf, and carvers. |
| `create_case()` | `case_id, case_name, operator` | `Dict` | Initializes standardized case structure & metadata. |
| `register_evidence()` | `case_id, evidence_path, type` | `Dict` | Registers disk/memory image into case catalog. |
| `verify_evidence()` | `case_id, stage_label` | `Dict` | Pre/Post SHA-256 and read-only integrity verification. |
| `analyze_evidence()` | `case_id, [image_filename]` | `Dict` | MBR/GPT partition layout and FAT/NTFS analysis. |
| `discover_artifacts()`| `case_id, [partition_offset]` | `Dict` | Enumerates active, deleted, and orphan inodes (`fls`). |
| `analyze_artifact_state()`| `case_id, [partition_offset]` | `Dict` | Classifies items: HEALTHY, DELETED, DAMAGED, FRAGMENTED. |
| `recover_artifacts()` | `case_id, [partition_offset, limit]` | `Dict` | Runs 10-branch Adaptive Recovery Engine. |
| `validate_recovery()` | `case_id` | `Dict` | Performs deep format checks & false-recovery rejection. |
| `calculate_hashes()` | `case_id` | `Dict` | Generates reproducible SHA-256 case manifest. |
| `generate_report()` | `case_id` | `Dict` | Produces standalone JSON, CSV, and HTML reports. |
| `export_verified_artifacts()` | `case_id, destination_dir` | `Dict` | Copies verified artifacts to separate media & verifies hashes. |

---

## 3. Package Portability & Deployment Rules

1. **Relative Paths**: All engine executions, image accesses, and report generations use `FARIS_ROOT` dynamic resolution.
2. **Read-Only Protection**: The original evidence file (`.E01` or `.raw`) is never opened for write operations.
3. **No External Network Calls**: All operations run locally and air-gapped.
4. **Desktop UI Launcher**: Double-click `faris.bat` or run `python launch_faris.py` to start the standalone desktop interface.
