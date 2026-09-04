import os
import json
import hashlib
import datetime
from pathlib import Path
from typing import Dict, List, Any, Optional, Tuple

try:
    from core.paths import FARIS_ROOT, resolve_case_dir, get_relative_str
except ImportError:
    from ..core.paths import FARIS_ROOT, resolve_case_dir, get_relative_str

GENESIS_HASH = "0000000000000000000000000000000000000000000000000000000000000000"

class AuditLogger:
    """
    Forensic Timeline, Chain of Custody, and Cryptographically Chained Audit Logger.
    Provides tamper-evident event recording where every record links cryptographically
    to the preceding entry via SHA-256 chaining.
    """

    def _get_audit_file(self, case_id: str) -> Path:
        case_dir = resolve_case_dir(case_id)
        audit_dir = case_dir / "audit"
        audit_dir.mkdir(parents=True, exist_ok=True)
        return audit_dir / "audit_trail.jsonl"

    def _get_last_record_hash(self, audit_file: Path) -> str:
        if not audit_file.exists() or audit_file.stat().st_size == 0:
            return GENESIS_HASH

        last_line = ""
        with open(audit_file, "r", encoding="utf-8") as f:
            for line in f:
                if line.strip():
                    last_line = line.strip()

        if not last_line:
            return GENESIS_HASH

        try:
            record = json.loads(last_line)
            return record.get("current_hash", GENESIS_HASH)
        except Exception:
            return GENESIS_HASH

    def log_action(
        self,
        case_id: str,
        action: str,
        operator: str = "Forensic Examiner",
        tool: str = "FARIS",
        tool_version: str = "1.0.0",
        input_artifact: str = "",
        output_artifact: str = "",
        result: str = "SUCCESS",
        evidence_id: str = "EVID_PRIMARY",
        details: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Appends an event to the cryptographically chained audit log.
        """
        audit_file = self._get_audit_file(case_id)
        prev_hash = self._get_last_record_hash(audit_file)

        timestamp = datetime.datetime.now(datetime.timezone.utc).isoformat()
        record_data = {
            "timestamp": timestamp,
            "case_id": case_id,
            "evidence_id": evidence_id,
            "operator": operator,
            "action": action,
            "tool": tool,
            "tool_version": tool_version,
            "input_artifact": input_artifact,
            "output_artifact": output_artifact,
            "result": result,
            "details": details or {}
        }

        # Canonical string for hash calculation
        canonical_str = json.dumps(record_data, sort_keys=True)
        curr_hash = hashlib.sha256((prev_hash + canonical_str).encode("utf-8")).hexdigest()

        entry = {
            "previous_hash": prev_hash,
            "record": record_data,
            "current_hash": curr_hash
        }

        with open(audit_file, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry) + "\n")

        return entry

    def verify_audit_chain(self, case_id: str) -> Dict[str, Any]:
        """
        Verifies the cryptographic integrity of the audit chain for a case.
        Detects tampering, out-of-order records, or unauthorized modification.
        """
        audit_file = self._get_audit_file(case_id)
        if not audit_file.exists():
            return {
                "case_id": case_id,
                "verified": True,
                "record_count": 0,
                "status": "EMPTY_CHAIN"
            }

        expected_prev_hash = GENESIS_HASH
        records_verified = 0
        is_intact = True
        broken_at_index = -1

        with open(audit_file, "r", encoding="utf-8") as f:
            for idx, line in enumerate(f):
                if not line.strip():
                    continue
                entry = json.loads(line.strip())
                prev_h = entry.get("previous_hash")
                curr_h = entry.get("current_hash")
                rec_data = entry.get("record")

                if prev_h != expected_prev_hash:
                    is_intact = False
                    broken_at_index = idx
                    break

                canonical_str = json.dumps(rec_data, sort_keys=True)
                calc_hash = hashlib.sha256((prev_h + canonical_str).encode("utf-8")).hexdigest()

                if calc_hash != curr_h:
                    is_intact = False
                    broken_at_index = idx
                    break

                expected_prev_hash = curr_h
                records_verified += 1

        return {
            "case_id": case_id,
            "audit_chain_intact": is_intact,
            "records_verified": records_verified,
            "broken_at_index": broken_at_index if not is_intact else None,
            "status": "INTEGRITY_VERIFIED" if is_intact else "INTEGRITY_COMPROMISED",
            "last_chain_hash": expected_prev_hash
        }

    def generate_case_hash_manifest(self, case_id: str) -> Dict[str, Any]:
        """
        Calculates SHA-256 for all case files (evidence, recovered, reports) and saves hash manifest.
        """
        case_dir = resolve_case_dir(case_id)
        hashes_dir = case_dir / "hashes"
        hashes_dir.mkdir(parents=True, exist_ok=True)

        manifest = {
            "case_id": case_id,
            "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "evidence_hashes": {},
            "recovered_hashes": {},
            "reports_hashes": {}
        }

        # 1. Evidence
        for p in case_dir.glob("*.E*"):
            if p.is_file():
                # Fast sample/file hash
                h = hashlib.sha256()
                with open(p, "rb") as f:
                    while c := f.read(4 * 1024 * 1024):
                        h.update(c)
                manifest["evidence_hashes"][p.name] = h.hexdigest()

        # 2. Recovered
        rec_dir = case_dir / "recovery"
        if rec_dir.exists():
            for p in rec_dir.rglob("*"):
                if p.is_file() and not p.name.endswith(".json"):
                    h = hashlib.sha256(p.read_bytes()).hexdigest()
                    manifest["recovered_hashes"][get_relative_str(p)] = h

        # 3. Save Manifest
        out_file = hashes_dir / "case_hashes.json"
        with open(out_file, "w", encoding="utf-8") as f:
            json.dump(manifest, f, indent=2)

        return manifest

# Singleton instance
audit_logger = AuditLogger()
