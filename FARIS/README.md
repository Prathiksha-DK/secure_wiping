# FARIS — Forensic Adaptive Recovery and Integrity System

**FARIS** is a self-contained, air-gapped, offline digital-forensics recovery and verification platform engineered for high-integrity evidence recovery and seamless integration into partner applications (such as data wiping and forensic verification tools).

---

## 1. Key Architectural Capabilities

1. **Evidence Protection & Non-Destructive Operation**:
   * All evidence (E01 segments, raw disk images) is handled in strict read-only mode.
   * Recovered artifacts are written exclusively to isolated case workspaces.
   * Supports pre-analysis and post-analysis cryptographic SHA-256 verification.
2. **Automated 10-Branch Adaptive Recovery Engine**:
   * **Branch 1**: Inode metadata recovery (`icat`).
   * **Branch 2**: True signature-based file carving (JPEG, PNG, PDF, ZIP, SQLite, MP4, EVTX, REGF, OLE).
   * **Branch 3**: Structure & Fragment recovery.
   * **Branch 4**: Local statistical AI candidate fragment ranking (Shannon entropy, Chi-square byte frequency, B-Tree flag matching).
   * **Branch 5**: Database type detection & routing.
   * **Branch 6**: Memory recovery branch (with honest `N/A` for disk images).
   * **Branch 7**: SQLite deep page carving, B-Tree cell deserialization, and unallocated deleted record parsing.
   * **Branch 8**: SQLite candidate database reconstruction & PRAGMA quick_check verification.
   * **Branch 9**: Deep / Anti-Forensic residual slack and fringe text carving.
   * **Branch 10**: Bounded parallel processing execution (2 to 4 workers).
3. **Recovery Validation & False-Positive Filter**:
   * Evaluates format parsers (SQLite integrity, ZIP CRC, image markers).
   * Detects and rejects zero-fill false recoveries (>98% null bytes).
   * Assigns evidence-based confidence ratings (`HIGH`, `MEDIUM`, `LOW`) with detailed forensic explanations.
4. **Cryptographic Chain of Custody**:
   * Append-only audit trail with SHA-256 cryptographic chaining (`previous_hash + record -> current_hash`).
   * Tamper detection and chain validation.
5. **Multi-Format Forensic Reporting**:
   * Automatic generation of JSON, CSV, and standalone HTML reports.
6. **Unified 3-Screen Desktop User Interface**:
   * **Screen 1**: Case & Evidence Setup (hardware write-blocker warnings, source selector).
   * **Screen 2**: Single Background Pipeline Execution (real-time progress bar, stage checklist).
   * **Screen 3**: Comprehensive Results Tabs (Overview, Artifacts, Database, Fragments, Integrity, Chain of Custody, Reports & Safe Export).

---

## 2. Directory Structure

```
FARIS/
├── acquisition/               # Physical acquisition (ewfacquire)
├── analysis/                  # Partition, filesystem & artifact analysis (mmls, fsstat, fls, istat)
├── recovery/                  # 10-branch adaptive recovery engine & SQLite deep recovery
├── core/                      # Dynamic paths, engine manager, case manager, parallel engine
├── integrity/                 # SHA-256 evidence verifier & cryptographically chained audit logger
├── validation/                # Format validators, false-positive filter & confidence scoring
├── reporting/                 # JSON, CSV, standalone HTML report generator
├── application/               # Public FARISAPI integration interface
├── ui/                        # Unified 3-screen Tkinter desktop UI
├── config/                    # Portable JSON configuration
├── engines/                   # Bundled standalone engines (The Sleuth Kit v4.15.0, libewf v20230405)
├── licenses/                  # Third-party engine licenses & inventory
├── tests/                     # 16-test comprehensive automated verification suite
├── case001/                   # Active case evidence (pendrive_image.E01..E08) and workspace
├── launch_faris.bat           # Portable Windows double-click launcher
├── launch_faris.py            # Desktop UI entrypoint
├── INTEGRATION_GUIDE.md       # Integration reference for host applications
└── README.md                  # Master documentation
```

---

## 3. Quick Start

### Launching the Desktop UI
Double-click `launch_faris.bat` or run:
```powershell
python launch_faris.py
```

### Embedding FARIS in Python
```python
from FARIS.application.faris_api import faris_api

setup = {
    "case_id": "case001",
    "examiner": "Forensic Examiner",
    "source_type": "Existing E01 Image",
    "source_path": "case001/pendrive_image.E01"
}

# Run the complete unified forensic pipeline
result = faris_api.run_full_forensic_pipeline(setup)
print("Pipeline Status:", result["status"])

# Safely export verified recovered artifacts to a separate drive
faris_api.export_verified_artifacts("case001", "E:/Exported_Recoveries")
```

### Running the Test Suite
```powershell
python -m unittest discover -s tests -p "test_*.py"
```

---

## 4. Hardware Write-Blocking Notice

FARIS enforces strict read-only access at the software level. For acquisition of live physical storage media, a certified **hardware write-blocker** is strongly recommended to prevent physical drive alteration.
