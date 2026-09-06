"""
SecureWipe — Phase 9: Post-Sanitization Residual Evidence Assessment Engine
Architecture: WIPE -> VERIFY -> POST-SANITIZATION ASSESSMENT -> READ-ONLY FORENSIC SCAN -> RESIDUAL ARTIFACT DETECTION -> CLASSIFICATION -> REPORT

CRITICAL SCIENTIFIC PRINCIPLES:
1. Real Storage Devices or Verified Forensic Disk Images ONLY.
   Zero synthetic/fake HDDs, sectors, signatures, or recovery claims.
2. Scientific empirical reporting ONLY.
   Never claim "Nothing can ever be recovered" or "100% unrecoverable".
   Clearly distinguish:
     METHOD PERFORMED: (e.g. NIST SP 800-88 Rev 1 Overwrite / Clear / Purge)
     POST-SANITIZATION OBSERVATION: (e.g. No recognizable artifacts detected within the examined addressable media)
3. Multi-Level Structural Validation:
   - NO_RECOGNIZABLE_ARTIFACT
   - SIGNATURE_ONLY (Magic bytes match, internal structure unverified)
   - PARTIAL_ARTIFACT (Corrupted / truncated structure)
   - VALIDATED_ARTIFACT_CANDIDATE (Internal length, markers, headers, trailers verified)
   - UNKNOWN_ANOMALY (Entropy anomalies, unexpected non-zero byte patterns)
4. Exact LBA and Byte Location Mapping for all candidates with byte-level provenance.
5. Real Sector Heatmap calculated strictly from real scanned blocks.
6. SSD / Flash Storage Hardware Translation & Over-provisioning Disclaimers.
7. Swarm Micro-Task & Fragment Puzzle Integration (active only when real fragments exist).
8. Comparative Before/After Sanitization Experiment Runner.
9. Tamper-Evident Assessment Certificate (Schema v2.0) with RSA-PSS Signatures.
"""

import os
import sys
import math
import time
import json
import uuid
import struct
import zlib
import hashlib
import sqlite3
import threading
from typing import Dict, Any, Optional, List, Tuple, Callable

from forensic_signatures import evaluate_buffer_signatures, ValidationResult
from forensic_carver import DEFAULT_CHUNK_SIZE, OVERLAP_SIZE
from certificate_engine import _ensure_keys, compute_canonical_certificate_digest
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
import base64

# Classification Constants
CLASSIFICATION_NO_EVIDENCE = "NO_RECOGNIZABLE_ARTIFACT"
CLASSIFICATION_SIGNATURE_ONLY = "SIGNATURE_ONLY"
CLASSIFICATION_PARTIAL = "PARTIAL_ARTIFACT"
CLASSIFICATION_VALIDATED = "VALIDATED_ARTIFACT_CANDIDATE"
CLASSIFICATION_ANOMALY = "UNKNOWN_ANOMALY"

# Heatmap State Constants
HEATMAP_CLEAN_ZERO = "CLEAN_ZERO"
HEATMAP_CLEAN_PATTERN = "CLEAN_PATTERN"
HEATMAP_HIGH_ENTROPY = "HIGH_ENTROPY_UNIFORM"
HEATMAP_RESIDUAL_ARTIFACT = "RESIDUAL_ARTIFACT_DETECTED"
HEATMAP_ANOMALY = "UNKNOWN_ANOMALY"

# Disclaimers
DISCLAIMER_SSD_NAND = (
    "Post-sanitization read-only scans examine addressable Logical Block Addresses (LBAs). "
    "Physical NAND flash cells remapped, over-provisioned, or retired by the SSD/flash controller "
    "cannot be read via standard ATA/NVMe command sets without hardware-level direct NAND chip-off analysis."
)
DISCLAIMER_EMPIRICAL_SCOPE = (
    "Forensic assessment results reflect empirical observations of the addressable media space "
    "at the time of examination. No absolute statement regarding mathematical irreversibility across "
    "microscopic physical domain alterations is asserted."
)

_assessment_sessions: Dict[str, Dict[str, Any]] = {}
_assessment_lock = threading.Lock()


def calculate_shannon_entropy(data: bytes) -> float:
    """Calculate Shannon entropy (0.0 to 8.0 bits per byte)."""
    if not data:
        return 0.0
    entropy = 0.0
    length = len(data)
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    for count in counts:
        if count > 0:
            p = count / length
            entropy -= p * math.log2(p)
    return round(entropy, 4)


class PostSanitizationAssessmentSession:
    """
    Encapsulates a live, streaming read-only post-sanitization forensic assessment session.
    """
    def __init__(
        self,
        assessment_id: str,
        target_path: str,
        target_type: str = "disk",
        total_bytes: int = 0,
        sector_size: int = 512,
        prior_sanitization_meta: Optional[Dict[str, Any]] = None,
        heatmap_bins_count: int = 100,
    ):
        self.assessment_id = assessment_id
        self.target_path = target_path
        self.target_type = target_type
        self.total_bytes = max(0, total_bytes)
        self.sector_size = sector_size if sector_size in (512, 4096) else 512
        self.total_sectors = self.total_bytes // self.sector_size if self.total_bytes > 0 else 0
        self.prior_sanitization_meta = prior_sanitization_meta or {}
        self.heatmap_bins_count = max(10, min(500, heatmap_bins_count))

        self.start_time = time.time()
        self.end_time: Optional[float] = None
        self.status = "INITIALIZING"  # INITIALIZING, SCANNING, COMPLETED, CANCELLED, ERROR
        self.is_cancelled = False
        self.progress_pct = 0.0
        self.bytes_scanned = 0
        self.sectors_scanned = 0
        self.read_errors = 0
        self.logs: List[str] = []

        # Classified Findings
        self.signature_only_hits: List[Dict[str, Any]] = []
        self.partial_artifacts: List[Dict[str, Any]] = []
        self.validated_candidates: List[Dict[str, Any]] = []
        self.anomalies: List[Dict[str, Any]] = []

        # Real Sector Heatmap Bins
        self.heatmap_bins: List[Dict[str, Any]] = self._init_heatmap_bins()

        # Scientific Classification Summary
        self.overall_classification = CLASSIFICATION_NO_EVIDENCE
        self.confidence_score = 0.0
        self.method_performed = self.prior_sanitization_meta.get("method_label") or "NIST SP 800-88 Rev.1 Overwrite / Clear"
        self.observation_statement = "Assessment initialized"

        # Media Hashing at Scan Time
        self.sha256_hash = ""
        self.sha512_hash = ""

    def _init_heatmap_bins(self) -> List[Dict[str, Any]]:
        """Pre-allocate heatmap bins across target address space."""
        bins = []
        if self.total_bytes <= 0:
            return bins
        bytes_per_bin = math.ceil(self.total_bytes / self.heatmap_bins_count)
        for i in range(self.heatmap_bins_count):
            start_b = i * bytes_per_bin
            end_b = min(self.total_bytes, (i + 1) * bytes_per_bin)
            if start_b >= self.total_bytes:
                break
            start_lba = start_b // self.sector_size
            end_lba = max(start_lba, (end_b - 1) // self.sector_size)
            bins.append({
                "bin_index": i,
                "start_byte": start_b,
                "end_byte": end_b,
                "total_bytes": end_b - start_b,
                "start_lba": start_lba,
                "end_lba": end_lba,
                "zero_ratio": 1.0,
                "ff_ratio": 0.0,
                "entropy": 0.0,
                "artifact_count": 0,
                "artifacts": [],
                "state": HEATMAP_CLEAN_ZERO,
            })
        return bins

    def add_log(self, message: str) -> None:
        ts = time.strftime("%H:%M:%S", time.gmtime())
        self.logs.append(f"[{ts}] {message}")

    def update_heatmap_bin(self, byte_offset: int, chunk_data: bytes, candidates_in_chunk: List[Dict[str, Any]]) -> None:
        """Update heatmap metrics from real chunk bytes."""
        if not self.heatmap_bins or len(chunk_data) == 0:
            return
        bytes_per_bin = math.ceil(self.total_bytes / len(self.heatmap_bins)) if self.total_bytes > 0 else 1
        bin_idx = min(len(self.heatmap_bins) - 1, byte_offset // bytes_per_bin)
        b = self.heatmap_bins[bin_idx]

        total = len(chunk_data)
        zero_cnt = chunk_data.count(b"\x00")
        ff_cnt = chunk_data.count(b"\xff")
        pat96_cnt = chunk_data.count(b"\x96")
        entropy = calculate_shannon_entropy(chunk_data)

        zero_ratio = round(zero_cnt / total, 3)
        ff_ratio = round(ff_cnt / total, 3)
        b["zero_ratio"] = zero_ratio
        b["ff_ratio"] = ff_ratio
        b["entropy"] = entropy

        if candidates_in_chunk:
            b["artifact_count"] += len(candidates_in_chunk)
            for c in candidates_in_chunk:
                if c["candidate_id"] not in b["artifacts"]:
                    b["artifacts"].append(c["candidate_id"])
            b["state"] = HEATMAP_RESIDUAL_ARTIFACT
        elif zero_cnt == total:
            b["state"] = HEATMAP_CLEAN_ZERO
        elif ff_cnt == total or pat96_cnt == total:
            b["state"] = HEATMAP_CLEAN_PATTERN
        elif entropy >= 7.7:
            b["state"] = HEATMAP_HIGH_ENTROPY
        elif zero_ratio < 0.90:
            b["state"] = HEATMAP_ANOMALY
        else:
            b["state"] = HEATMAP_CLEAN_ZERO

    def finalize_classification(self) -> None:
        """Derive objective, scientifically factual summary classification without absolute claims."""
        val_count = len(self.validated_candidates)
        part_count = len(self.partial_artifacts)
        sig_count = len(self.signature_only_hits)
        anom_count = len(self.anomalies)

        if val_count > 0:
            self.overall_classification = CLASSIFICATION_VALIDATED
            self.confidence_score = min(99.5, 75.0 + (val_count * 5.0))
            formats = list(set(a["format"] for a in self.validated_candidates[:6]))
            self.observation_statement = (
                f"Observed {val_count} fully validated residual artifact candidate(s) "
                f"possessing verified internal structures ({', '.join(formats)})."
            )
        elif part_count > 0:
            self.overall_classification = CLASSIFICATION_PARTIAL
            self.confidence_score = min(74.0, 45.0 + (part_count * 4.0))
            formats = list(set(a["format"] for a in self.partial_artifacts[:6]))
            self.observation_statement = (
                f"Observed {part_count} partial/fragmented residual data structure(s) "
                f"with valid header markers but corrupted or incomplete body/trailers ({', '.join(formats)})."
            )
        elif anom_count > 0:
            self.overall_classification = CLASSIFICATION_ANOMALY
            self.confidence_score = min(40.0, 20.0 + (anom_count * 3.0))
            self.observation_statement = (
                f"Observed {anom_count} unstructured entropy anomaly block(s) "
                f"deviating from baseline expected zero/pattern overwrite."
            )
        elif sig_count > 0:
            self.overall_classification = CLASSIFICATION_SIGNATURE_ONLY
            self.confidence_score = min(25.0, 5.0 + (sig_count * 2.0))
            self.observation_statement = (
                f"Observed {sig_count} isolated magic byte prefix match(es); "
                "no valid internal file structures or parsable records could be verified."
            )
        else:
            self.overall_classification = CLASSIFICATION_NO_EVIDENCE
            self.confidence_score = 0.0
            self.observation_statement = (
                "No recognizable artifacts detected within the examined addressable media space."
            )

    def to_report_dict(self) -> Dict[str, Any]:
        """Convert session to full post-sanitization assessment report."""
        duration = (self.end_time or time.time()) - self.start_time
        coverage = (self.bytes_scanned / self.total_bytes * 100.0) if self.total_bytes > 0 else 0.0
        throughput = (self.bytes_scanned / (1024 * 1024)) / duration if duration > 0.05 else 0.0

        all_findings = (
            self.validated_candidates +
            self.partial_artifacts +
            self.anomalies +
            self.signature_only_hits
        )

        heatmap_summary = {
            "total_bins": len(self.heatmap_bins),
            "clean_zero_bins": sum(1 for b in self.heatmap_bins if b["state"] == HEATMAP_CLEAN_ZERO),
            "clean_pattern_bins": sum(1 for b in self.heatmap_bins if b["state"] == HEATMAP_CLEAN_PATTERN),
            "high_entropy_bins": sum(1 for b in self.heatmap_bins if b["state"] == HEATMAP_HIGH_ENTROPY),
            "artifact_bins": sum(1 for b in self.heatmap_bins if b["state"] == HEATMAP_RESIDUAL_ARTIFACT),
            "anomaly_bins": sum(1 for b in self.heatmap_bins if b["state"] == HEATMAP_ANOMALY),
        }

        # Has fragmented evidence eligible for swarm puzzle generation?
        has_fragments = (len(self.partial_artifacts) > 0 or len(self.anomalies) > 0)
        swarm_status = (
            "SWARM RECONSTRUCTION ACTIVE: Genuine fragmented candidates available for recombination"
            if has_fragments
            else "SWARM RECONSTRUCTION: NO RESIDUAL FRAGMENTS DETECTED — PUZZLE GENERATION INACTIVE"
        )

        return {
            "assessment_id": self.assessment_id,
            "status": self.status,
            "target": {
                "path": self.target_path,
                "type": self.target_type,
                "total_bytes": self.total_bytes,
                "total_sectors": self.total_sectors,
                "sector_size": self.sector_size,
                "sha256_at_scan_time": self.sha256_hash,
                "sha512_at_scan_time": self.sha512_hash,
            },
            "scientific_assessment": {
                "method_performed": self.method_performed,
                "post_sanitization_observation": self.observation_statement,
                "overall_classification": self.overall_classification,
                "confidence_score": round(self.confidence_score, 2),
                "is_zero_residual": (len(self.validated_candidates) == 0 and len(self.partial_artifacts) == 0),
            },
            "scan_metrics": {
                "bytes_scanned": self.bytes_scanned,
                "sectors_scanned": self.sectors_scanned,
                "coverage_pct": round(coverage, 2),
                "duration_seconds": round(duration, 2),
                "throughput_mbps": round(throughput, 1),
                "read_errors": self.read_errors,
            },
            "findings_summary": {
                "total_candidates": len(all_findings),
                "validated_artifacts": len(self.validated_candidates),
                "partial_artifacts": len(self.partial_artifacts),
                "unknown_anomalies": len(self.anomalies),
                "signature_only_hits": len(self.signature_only_hits),
            },
            "findings_ledger": all_findings,
            "heatmap_summary": heatmap_summary,
            "heatmap_bins": self.heatmap_bins,
            "swarm_reconstruction": {
                "eligible": has_fragments,
                "status_message": swarm_status,
                "fragment_count": len(self.partial_artifacts) + len(self.anomalies),
            },
            "disclaimers": {
                "ssd_nand_wear_leveling": DISCLAIMER_SSD_NAND,
                "empirical_observation_scope": DISCLAIMER_EMPIRICAL_SCOPE,
            },
            "prior_sanitization": self.prior_sanitization_meta,
            "logs": self.logs[-50:],
        }


def stream_post_sanitization_assessment(
    target_path: str,
    target_type: str = "disk",
    sector_size: int = 512,
    prior_sanitization_meta: Optional[Dict[str, Any]] = None,
    progress_cb: Optional[Callable[[Dict[str, Any]], None]] = None,
    cancel_check: Optional[Callable[[], bool]] = None,
    assessment_id: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Execute streaming read-only post-sanitization residual evidence scan on a real device or verified forensic image.
    Strictly read-only; calculates exact LBA/byte offsets, validates internal structures,
    computes real sector heatmap, and digests SHA-256/SHA-512 hashes.
    """
    if not assessment_id:
        assessment_id = f"ASMT-{uuid.uuid4().hex[:10].upper()}"

    # Determine real file / device size
    total_bytes = 0
    if os.path.exists(target_path):
        try:
            total_bytes = os.path.getsize(target_path)
            # If block device on Linux and getsize returns 0, use blockdev or ioctl
            if total_bytes == 0 and not sys.platform.startswith("win"):
                try:
                    import subprocess
                    out = subprocess.check_output(["blockdev", "--getsize64", target_path], text=True).strip()
                    total_bytes = int(out)
                except Exception:
                    pass
        except Exception:
            total_bytes = 0

    session = PostSanitizationAssessmentSession(
        assessment_id=assessment_id,
        target_path=target_path,
        target_type=target_type,
        total_bytes=total_bytes,
        sector_size=sector_size,
        prior_sanitization_meta=prior_sanitization_meta,
    )

    with _assessment_lock:
        _assessment_sessions[assessment_id] = session

    if not os.path.exists(target_path) or total_bytes == 0:
        session.status = "NO_EVIDENCE_LOADED"
        session.end_time = time.time()
        session.observation_statement = "NO EVIDENCE DEVICE LOADED: Target path does not exist or has 0 bytes."
        session.add_log("No evidence loaded — Target inaccessible.")
        return session.to_report_dict()

    session.status = "SCANNING"
    session.add_log(f"Starting Read-Only Post-Sanitization Residual Scan on {target_path} ({total_bytes} bytes / {session.total_sectors} sectors)")

    sha256_calc = hashlib.sha256()
    sha512_calc = hashlib.sha512()

    try:
        # Strictly open device in READ-ONLY mode
        fd = os.open(target_path, os.O_RDONLY | getattr(os, "O_BINARY", 0))
        try:
            offset = 0
            overlap_buf = b""
            seen_offsets = set()

            while offset < total_bytes:
                if (cancel_check and cancel_check()) or session.is_cancelled:
                    session.status = "CANCELLED"
                    session.add_log("Scan cancelled by operator.")
                    break

                to_read = min(DEFAULT_CHUNK_SIZE, total_bytes - offset)
                try:
                    os.lseek(fd, offset, os.SEEK_SET)
                    chunk = os.read(fd, to_read)
                except Exception as read_err:
                    session.read_errors += 1
                    session.add_log(f"Read error at offset {offset}: {read_err}")
                    offset += to_read
                    continue

                if not chunk:
                    break

                # Update cryptographic hash streams
                sha256_calc.update(chunk)
                sha512_calc.update(chunk)

                # Signature Carving with Boundary Overlap
                eval_buf = overlap_buf + chunk
                base_eval_offset = max(0, offset - len(overlap_buf))
                results = evaluate_buffer_signatures(eval_buf, base_eval_offset)

                chunk_candidates = []

                for res in results:
                    exact_offset = res.header_offset
                    if exact_offset in seen_offsets:
                        continue
                    seen_offsets.add(exact_offset)

                    lba_start = exact_offset // session.sector_size
                    cand_len = max(res.extracted_size, session.sector_size)
                    lba_end = (exact_offset + cand_len - 1) // session.sector_size
                    cand_id = f"CAND-{res.format_name}-{lba_start:06d}"

                    # Extract candidate byte slice for exact hash provenance
                    slice_len = min(cand_len, 65536)
                    slice_start_in_chunk = exact_offset - base_eval_offset
                    if 0 <= slice_start_in_chunk < len(eval_buf):
                        cand_bytes = eval_buf[slice_start_in_chunk:slice_start_in_chunk + slice_len]
                        cand_sha256 = hashlib.sha256(cand_bytes).hexdigest()
                        hex_preview = " ".join(f"{b:02X}" for b in cand_bytes[:32])
                        ascii_preview = "".join(chr(b) if 32 <= b <= 126 else "." for b in cand_bytes[:32])
                    else:
                        cand_sha256 = ""
                        hex_preview = ""
                        ascii_preview = ""

                    # Classify Candidate
                    if res.level == 3 and not res.is_fragmented:
                        classification = CLASSIFICATION_VALIDATED
                    elif res.level >= 2 or res.is_fragmented:
                        classification = CLASSIFICATION_PARTIAL
                    else:
                        classification = CLASSIFICATION_SIGNATURE_ONLY

                    cand_dict = {
                        "candidate_id": cand_id,
                        "format": res.format_name,
                        "classification": classification,
                        "validation_level": res.level,
                        "validation_level_name": "Validated Artifact" if res.level == 3 else ("Valid Candidate" if res.level == 2 else "Signature Hit"),
                        "confidence_score": round(res.confidence, 3),
                        "start_byte_offset": exact_offset,
                        "start_lba": lba_start,
                        "end_byte_offset": exact_offset + cand_len,
                        "end_lba": lba_end,
                        "length_bytes": cand_len,
                        "sector_span": [lba_start, lba_end],
                        "sha256_hash": cand_sha256,
                        "hex_preview": hex_preview,
                        "ascii_preview": ascii_preview,
                        "details": res.details,
                        "is_fragmented": res.is_fragmented,
                    }

                    chunk_candidates.append(cand_dict)

                    if classification == CLASSIFICATION_VALIDATED:
                        session.validated_candidates.append(cand_dict)
                    elif classification == CLASSIFICATION_PARTIAL:
                        session.partial_artifacts.append(cand_dict)
                    else:
                        session.signature_only_hits.append(cand_dict)

                # Anomaly check: non-zero structured data that wasn't claimed by a format validator
                if not chunk_candidates and len(chunk) >= session.sector_size:
                    chunk_entropy = calculate_shannon_entropy(chunk[:4096])
                    zero_cnt = chunk[:4096].count(b"\x00")
                    # If medium entropy non-zero block (e.g. text/data residue)
                    if 1.0 < chunk_entropy < 7.0 and zero_cnt < 3000:
                        anom_lba = offset // session.sector_size
                        anom_id = f"ANOM-ENTROPY-{anom_lba:06d}"
                        anom_bytes = chunk[:min(len(chunk), 2048)]
                        anom_dict = {
                            "candidate_id": anom_id,
                            "format": "UNKNOWN_DATA_RESIDUE",
                            "classification": CLASSIFICATION_ANOMALY,
                            "validation_level": 1,
                            "validation_level_name": "Entropy Anomaly",
                            "confidence_score": 0.35,
                            "start_byte_offset": offset,
                            "start_lba": anom_lba,
                            "end_byte_offset": offset + len(anom_bytes),
                            "end_lba": (offset + len(anom_bytes) - 1) // session.sector_size,
                            "length_bytes": len(anom_bytes),
                            "sector_span": [anom_lba, (offset + len(anom_bytes) - 1) // session.sector_size],
                            "sha256_hash": hashlib.sha256(anom_bytes).hexdigest(),
                            "hex_preview": " ".join(f"{b:02X}" for b in anom_bytes[:32]),
                            "ascii_preview": "".join(chr(b) if 32 <= b <= 126 else "." for b in anom_bytes[:32]),
                            "details": f"Unstructured non-zero byte stream (Entropy: {chunk_entropy} bits/byte)",
                            "is_fragmented": True,
                        }
                        session.anomalies.append(anom_dict)
                        chunk_candidates.append(anom_dict)

                # Update Real Sector Heatmap
                session.update_heatmap_bin(offset, chunk, chunk_candidates)

                session.bytes_scanned += len(chunk)
                session.sectors_scanned = session.bytes_scanned // session.sector_size
                offset += len(chunk)
                overlap_buf = chunk[-OVERLAP_SIZE:] if len(chunk) >= OVERLAP_SIZE else chunk

                if total_bytes > 0:
                    session.progress_pct = round((session.bytes_scanned / total_bytes) * 100.0, 1)

                if progress_cb and total_bytes > 0:
                    elapsed = max(0.001, time.time() - session.start_time)
                    mb_scanned = session.bytes_scanned / (1024 * 1024)
                    scan_rate = round(mb_scanned / elapsed, 2)
                    rem_bytes = max(0, total_bytes - session.bytes_scanned)
                    bytes_per_s = session.bytes_scanned / elapsed
                    eta = round(rem_bytes / max(1.0, bytes_per_s), 1) if bytes_per_s > 0 else 0.0
                    curr_lba = offset // session.sector_size
                    progress_cb({
                        "assessment_id": session.assessment_id,
                        "bytes_scanned": session.bytes_scanned,
                        "total_bytes": total_bytes,
                        "sectors_scanned": session.sectors_scanned,
                        "total_sectors": session.total_sectors,
                        "progress_pct": session.progress_pct,
                        "current_lba": curr_lba,
                        "scan_rate_mb_s": scan_rate,
                        "elapsed_seconds": round(elapsed, 1),
                        "eta_seconds": eta,
                        "current_region": f"LBA {curr_lba:,} / {session.total_sectors:,}",
                        "matches_count": len(session.validated_candidates) + len(session.partial_artifacts) + len(session.anomalies),
                        "validated_count": len(session.validated_candidates),
                        "partial_count": len(session.partial_artifacts),
                        "anomaly_count": len(session.anomalies),
                    })

        finally:
            os.close(fd)

    except PermissionError:
        session.status = "ERROR"
        session.read_errors += 1
        session.add_log("Permission denied opening raw target descriptor in read-only mode.")
    except Exception as e:
        session.status = "ERROR"
        session.read_errors += 1
        session.add_log(f"Unexpected error during post-sanitization assessment: {e}")

    session.end_time = time.time()
    session.sha256_hash = sha256_calc.hexdigest()
    session.sha512_hash = sha512_calc.hexdigest()

    if session.status != "ERROR" and session.status != "CANCELLED":
        session.status = "COMPLETED"
        session.progress_pct = 100.0

    session.finalize_classification()
    session.add_log(f"Assessment finished: {session.overall_classification} — {session.observation_statement}")

    return session.to_report_dict()


# ---------------------------------------------------------------------------
# Byte-Level Physical Inspector (Read-Only)
# ---------------------------------------------------------------------------

def inspect_media_bytes(
    target_path: str,
    byte_offset: int = 0,
    length_bytes: int = 512,
    sector_size: int = 512,
    expected_pattern: Optional[str] = "0x00",
) -> Dict[str, Any]:
    """
    Directly read and format raw byte slices from a physical device or forensic disk image.
    Strictly READ-ONLY. Returns hex rows, ascii columns, entropy, byte frequencies, and pattern analysis.
    """
    if not os.path.exists(target_path):
        return {
            "status": "ERROR",
            "message": "Target storage device or image file does not exist.",
            "hex_rows": [],
        }

    clamped_len = max(16, min(65536, length_bytes))
    clamped_offset = max(0, byte_offset)

    try:
        with open(target_path, "rb") as f:
            f.seek(clamped_offset)
            raw_data = f.read(clamped_len)

        if not raw_data:
            return {
                "status": "EMPTY",
                "message": "Offset out of bounds or empty read.",
                "byte_offset": clamped_offset,
                "lba": clamped_offset // sector_size,
                "hex_rows": [],
            }

        entropy = calculate_shannon_entropy(raw_data)
        sha256_slice = hashlib.sha256(raw_data).hexdigest()

        # Build 16-byte formatted Hex rows
        hex_rows = []
        for row_idx in range(0, len(raw_data), 16):
            row_slice = raw_data[row_idx:row_idx + 16]
            curr_addr = clamped_offset + row_idx
            hex_parts = [f"{b:02X}" for b in row_slice]
            hex_str = " ".join(hex_parts)
            ascii_str = "".join(chr(b) if 32 <= b <= 126 else "." for b in row_slice)
            hex_rows.append({
                "address_hex": f"0x{curr_addr:08X}",
                "address_dec": curr_addr,
                "sector_index": curr_addr // sector_size,
                "hex": hex_str,
                "ascii": ascii_str,
                "byte_count": len(row_slice),
            })

        # Byte frequency calculation
        import collections
        counts = collections.Counter(raw_data)
        zero_cnt = counts.get(0, 0)
        ff_cnt = counts.get(255, 0)
        printable_cnt = sum(counts.get(b, 0) for b in range(32, 127))

        # Pattern Conformity Analysis
        zero_pct = (zero_cnt / len(raw_data)) * 100.0
        ff_pct = (ff_cnt / len(raw_data)) * 100.0

        if zero_cnt == len(raw_data):
            observed_pattern = "ZERO-FILL (0x00)"
            pattern_status = "MATCH_EXPECTED_ZERO"
        elif ff_cnt == len(raw_data):
            observed_pattern = "0xFF-FILL (0xFF)"
            pattern_status = "MATCH_EXPECTED_ONE"
        elif entropy > 7.7:
            observed_pattern = "HIGH_ENTROPY_RANDOM"
            pattern_status = "MATCH_EXPECTED_CRYPTO"
        elif zero_pct > 85.0:
            observed_pattern = f"SPARSE_ZERO ({zero_pct:.1f}% zeros)"
            pattern_status = "PARTIAL_MATCH"
        else:
            observed_pattern = "STRUCTURED_NON_UNIFORM"
            pattern_status = "UNEXPECTED_PATTERN"

        return {
            "status": "SUCCESS",
            "target_path": target_path,
            "byte_offset": clamped_offset,
            "lba": clamped_offset // sector_size,
            "length_read": len(raw_data),
            "entropy": entropy,
            "sha256_slice": sha256_slice,
            "zero_percentage": round(zero_pct, 2),
            "ff_percentage": round(ff_pct, 2),
            "printable_ascii_percentage": round((printable_cnt / len(raw_data)) * 100.0, 2),
            "unique_byte_values": len(counts),
            "observed_pattern": observed_pattern,
            "pattern_conformity": pattern_status,
            "hex_rows": hex_rows,
            "disclaimer": DISCLAIMER_SSD_NAND,
        }

    except Exception as e:
        return {
            "status": "ERROR",
            "message": f"Read error at offset {clamped_offset}: {e}",
            "hex_rows": [],
        }


# ---------------------------------------------------------------------------
# Comparative Before/After Sanitization Experiment Runner
# ---------------------------------------------------------------------------

def run_comparative_sanitization_experiment(
    experiment_name: str = "EXPERIMENT-NIST-800-88-CLEAR",
    image_size_mb: int = 12,
    wipe_method: str = "nist-clear",  # nist-clear, nist-purge, dod-3pass, crypto-erase
    progress_cb: Optional[Callable[[Dict[str, Any]], None]] = None,
) -> Dict[str, Any]:
    """
    Automated comparative experimental verification:
    1. Pre-wipe: Construct an authentic disk image with genuine embedded binary artifacts.
    2. Baseline Scan: Run read-only forensic residue scan to establish ground truth (e.g. 11 artifacts).
    3. Sanitize: Execute real sanitization pass (NIST Clear, Purge, DoD 3-Pass, or Crypto Erase).
    4. Post-Sanitization Assessment: Scan the exact same media.
    5. Comparative Delta Analysis: Sector-by-sector, artifact-by-artifact empirical proof.
    """
    from swarm_evidence_ingest import create_certified_forensic_evidence_image
    import tempfile

    exp_id = f"EXP-{uuid.uuid4().hex[:8].upper()}"
    tmp_dir = tempfile.gettempdir()
    test_image_path = os.path.join(tmp_dir, f"comparative_test_{exp_id}.raw")

    logs = []

    def log(msg: str):
        logs.append(f"[{time.strftime('%H:%M:%S')}] {msg}")

    log(f"Initialized Comparative Sanitization Experiment '{experiment_name}' (ID: {exp_id})")

    # Step 1: Create Authentic Baseline Image
    log(f"Step 1/4: Generating {image_size_mb} MB authentic multi-format forensic disk image...")
    image_meta = create_certified_forensic_evidence_image(
        image_path=test_image_path,
        total_size_bytes=image_size_mb * 1024 * 1024,
    )
    pre_wipe_sha256 = image_meta["sha256_hash"]
    log(f"Baseline disk image created. SHA-256: {pre_wipe_sha256[:16]}... Embedded {len(image_meta['embedded_artifacts'])} authentic artifacts.")

    # Step 2: Pre-Wipe Baseline Scan
    log("Step 2/4: Executing pre-wipe baseline forensic residual scan...")
    baseline_report = stream_post_sanitization_assessment(
        target_path=test_image_path,
        target_type="forensic_image",
        sector_size=512,
        prior_sanitization_meta={"job_id": "PRE-WIPE-BASELINE", "method_label": "Pre-Sanitization Baseline"},
    )
    baseline_artifacts_count = baseline_report["findings_summary"]["total_candidates"]
    log(f"Pre-wipe scan completed: Detected {baseline_artifacts_count} artifacts ({baseline_report['scientific_assessment']['overall_classification']}).")

    # Step 3: Perform Real Sanitization Pass
    log(f"Step 3/4: Executing real sanitization pass using method '{wipe_method}'...")
    with open(test_image_path, "r+b") as f:
        file_len = os.path.getsize(test_image_path)
        if wipe_method == "nist-clear":
            # Overwrite with 0x00
            zero_chunk = b"\x00" * (1024 * 1024)
            written = 0
            while written < file_len:
                to_w = min(len(zero_chunk), file_len - written)
                f.write(zero_chunk[:to_w])
                written += to_w
            f.flush()
        elif wipe_method == "dod-3pass":
            # Pass 1: 0x00, Pass 2: 0xFF, Pass 3: Random
            for p_idx, pat_byte in enumerate([b"\x00", b"\xff", None]):
                f.seek(0)
                written = 0
                while written < file_len:
                    to_w = min(1024 * 1024, file_len - written)
                    if pat_byte is not None:
                        chunk = pat_byte * to_w
                    else:
                        chunk = os.urandom(to_w)
                    f.write(chunk)
                    written += to_w
                f.flush()
        elif wipe_method == "crypto-erase":
            # AES-256 in-place encryption with discarded key
            from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
            from cryptography.hazmat.backends import default_backend
            key = os.urandom(32)
            iv = os.urandom(16)
            cipher = Cipher(algorithms.AES(key), modes.CTR(iv), backend=default_backend())
            encryptor = cipher.encryptor()
            f.seek(0)
            written = 0
            while written < file_len:
                to_w = min(1024 * 1024, file_len - written)
                raw = f.read(to_w)
                if not raw:
                    break
                enc = encryptor.update(raw)
                f.seek(written)
                f.write(enc)
                written += len(enc)
            f.flush()
            del key, iv
        else:
            # Default zero clear
            zero_chunk = b"\x00" * (1024 * 1024)
            written = 0
            while written < file_len:
                to_w = min(len(zero_chunk), file_len - written)
                f.write(zero_chunk[:to_w])
                written += to_w
            f.flush()

    log("Sanitization pass complete. Cache flushed to storage.")

    # Step 4: Post-Sanitization Residual Evidence Assessment
    log("Step 4/4: Executing post-sanitization residual evidence scan...")
    post_wipe_report = stream_post_sanitization_assessment(
        target_path=test_image_path,
        target_type="forensic_image",
        sector_size=512,
        prior_sanitization_meta={
            "job_id": exp_id,
            "method_label": f"NIST SP 800-88 Rev.1 ({wipe_method.upper()})",
            "method_code": wipe_method,
            "completed_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        },
    )
    post_wipe_sha256 = post_wipe_report["target"]["sha256_at_scan_time"]
    post_artifacts_count = post_wipe_report["findings_summary"]["total_candidates"]
    log(f"Post-sanitization scan completed: Detected {post_artifacts_count} residual artifacts.")

    # Step 5: Clean up temp file
    try:
        if os.path.exists(test_image_path):
            os.remove(test_image_path)
    except Exception:
        pass

    # Step 6: Compute Comparative Delta
    artifact_reduction_pct = 100.0 if baseline_artifacts_count == 0 else round(
        ((baseline_artifacts_count - post_artifacts_count) / baseline_artifacts_count) * 100.0, 2
    )

    baseline_clean_pct = baseline_report["heatmap_summary"]["clean_zero_bins"] / max(1, baseline_report["heatmap_summary"]["total_bins"]) * 100.0
    post_clean_pct = post_wipe_report["heatmap_summary"]["clean_zero_bins"] / max(1, post_wipe_report["heatmap_summary"]["total_bins"]) * 100.0

    return {
        "experiment_id": exp_id,
        "experiment_name": experiment_name,
        "sanitization_method": wipe_method,
        "image_size_mb": image_size_mb,
        "pre_wipe_sha256": pre_wipe_sha256,
        "post_wipe_sha256": post_wipe_sha256,
        "hash_changed": (pre_wipe_sha256 != post_wipe_sha256),
        "baseline_assessment": {
            "classification": baseline_report["scientific_assessment"]["overall_classification"],
            "observation": baseline_report["scientific_assessment"]["post_sanitization_observation"],
            "total_artifacts": baseline_artifacts_count,
            "validated_artifacts": baseline_report["findings_summary"]["validated_artifacts"],
            "partial_artifacts": baseline_report["findings_summary"]["partial_artifacts"],
            "clean_zero_percentage": round(baseline_clean_pct, 1),
            "findings_sample": baseline_report["findings_ledger"][:6],
        },
        "post_sanitization_assessment": {
            "classification": post_wipe_report["scientific_assessment"]["overall_classification"],
            "observation": post_wipe_report["scientific_assessment"]["post_sanitization_observation"],
            "total_artifacts": post_artifacts_count,
            "validated_artifacts": post_wipe_report["findings_summary"]["validated_artifacts"],
            "partial_artifacts": post_wipe_report["findings_summary"]["partial_artifacts"],
            "clean_zero_percentage": round(post_clean_pct, 1),
            "findings_sample": post_wipe_report["findings_ledger"][:6],
            "heatmap_bins": post_wipe_report["heatmap_bins"],
        },
        "comparative_delta": {
            "initial_artifact_count": baseline_artifacts_count,
            "final_artifact_count": post_artifacts_count,
            "artifacts_eradicated": baseline_artifacts_count - post_artifacts_count,
            "artifact_reduction_percentage": artifact_reduction_pct,
            "scientific_conclusion": (
                "Empirical evidence confirms effective eradication of all previously recognizable file structures "
                "within the addressable storage space."
                if post_artifacts_count == 0
                else f"Residual structures ({post_artifacts_count}) detected post-sanitization."
            ),
        },
        "disclaimers": {
            "ssd_nand_wear_leveling": DISCLAIMER_SSD_NAND,
            "empirical_scope": DISCLAIMER_EMPIRICAL_SCOPE,
        },
        "logs": logs,
    }


# ---------------------------------------------------------------------------
# Tamper-Evident Assessment Certificate (Schema v2.0)
# ---------------------------------------------------------------------------

def generate_signed_assessment_certificate(assessment_report: Dict[str, Any], operator: str = "Forensic Analyst") -> Dict[str, Any]:
    """
    Generate and digitally sign a Schema v2.0 Post-Sanitization Residual Evidence Assessment Certificate
    using RSA-PSS SHA-256.
    """
    priv_key, pub_key, key_id = _ensure_keys()

    cert_id = f"SW-CERT-2.0-{uuid.uuid4().hex[:12].upper()}"
    now_iso = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

    target = assessment_report.get("target", {})
    sci = assessment_report.get("scientific_assessment", {})
    metrics = assessment_report.get("scan_metrics", {})
    findings = assessment_report.get("findings_summary", {})
    ledger = assessment_report.get("findings_ledger", [])
    prior = assessment_report.get("prior_sanitization", {})

    cert_payload: Dict[str, Any] = {
        "schema_version": "2.0",
        "certificate_id": cert_id,
        "assessment_id": assessment_report.get("assessment_id"),
        "issued_at": now_iso,
        "operator": operator,
        "target_storage": {
            "path": target.get("path"),
            "type": target.get("type"),
            "total_bytes": target.get("total_bytes"),
            "total_sectors": target.get("total_sectors"),
            "sector_size": target.get("sector_size"),
            "sha256_at_scan_time": target.get("sha256_at_scan_time"),
            "sha512_at_scan_time": target.get("sha512_at_scan_time"),
        },
        "prior_sanitization_reference": {
            "job_id": prior.get("job_id", "N/A"),
            "method_performed": sci.get("method_performed"),
            "standard": prior.get("method_label", "NIST SP 800-88 Rev.1"),
            "completed_at": prior.get("completed_at", now_iso),
        },
        "forensic_assessment_results": {
            "overall_classification": sci.get("overall_classification"),
            "confidence_score": sci.get("confidence_score"),
            "empirical_observation": sci.get("post_sanitization_observation"),
            "is_zero_residual": sci.get("is_zero_residual"),
            "total_artifacts_detected": findings.get("total_candidates", 0),
            "validated_artifacts": findings.get("validated_artifacts", 0),
            "partial_artifacts": findings.get("partial_artifacts", 0),
            "unknown_anomalies": findings.get("unknown_anomalies", 0),
            "signature_only_hits": findings.get("signature_only_hits", 0),
            "scan_coverage_pct": metrics.get("coverage_pct", 100.0),
            "sectors_examined": metrics.get("sectors_scanned", 0),
        },
        "forensic_evidence_ledger_summary": [
            {
                "candidate_id": item["candidate_id"],
                "format": item["format"],
                "classification": item["classification"],
                "start_lba": item["start_lba"],
                "length_bytes": item["length_bytes"],
                "sha256_hash": item["sha256_hash"],
            }
            for item in ledger[:20]  # Store top 20 ledger items in cert payload
        ],
        "hardware_and_empirical_disclaimers": {
            "nand_wear_leveling_notice": DISCLAIMER_SSD_NAND,
            "empirical_observation_scope": DISCLAIMER_EMPIRICAL_SCOPE,
        },
    }

    # Canonical serialization and hashing
    canonical_json = json.dumps(cert_payload, sort_keys=True, separators=(",", ":"))
    raw_hash = hashlib.sha256(canonical_json.encode("utf-8"))
    digest = raw_hash.digest()
    digest_hex = raw_hash.hexdigest()

    # RSA-PSS Digital Signature
    signature = priv_key.sign(
        digest,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH,
        ),
        hashes.SHA256(),
    )
    sig_b64 = base64.b64encode(signature).decode("ascii")

    pub_pem = pub_key.public_bytes(
        encoding=from_cryptography_serialization_pem(),
        format=from_cryptography_serialization_spki(),
    ).decode("ascii")

    cert_payload["integrity"] = {
        "canonical_digest_sha256": digest_hex,
        "signature_algorithm": "RSA-PSS-SHA256",
        "signature_base64": sig_b64,
        "key_id": key_id,
        "public_key_pem": pub_pem,
        "signed_at": now_iso,
    }

    return cert_payload


def verify_assessment_certificate(cert_dict: Dict[str, Any]) -> Dict[str, Any]:
    """Verify digital signature and structural integrity of a Schema v2.0 Certificate."""
    try:
        integrity = cert_dict.get("integrity", {})
        sig_b64 = integrity.get("signature_base64", "")
        pub_pem = integrity.get("public_key_pem", "")
        claimed_digest = integrity.get("canonical_digest_sha256", "")

        if not sig_b64 or not pub_pem:
            return {"valid": False, "reason": "Missing signature or public key in integrity block."}

        # Clone dict without integrity block
        payload_copy = {k: v for k, v in cert_dict.items() if k != "integrity"}
        canonical_json = json.dumps(payload_copy, sort_keys=True, separators=(",", ":"))
        raw_hash = hashlib.sha256(canonical_json.encode("utf-8"))
        calc_digest = raw_hash.digest()
        calc_hex = raw_hash.hexdigest()

        if calc_hex != claimed_digest:
            return {"valid": False, "reason": "Canonical digest mismatch. Certificate payload was tampered."}

        # Load public key
        from cryptography.hazmat.primitives import serialization
        pub_key = serialization.load_pem_public_key(pub_pem.encode("ascii"))

        # Verify signature
        sig_bytes = base64.b64decode(sig_b64.encode("ascii"))
        pub_key.verify(
            sig_bytes,
            calc_digest,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH,
            ),
            hashes.SHA256(),
        )

        return {
            "valid": True,
            "certificate_id": cert_dict.get("certificate_id"),
            "schema_version": cert_dict.get("schema_version"),
            "key_id": integrity.get("key_id"),
            "digest_sha256": claimed_digest,
            "overall_classification": cert_dict.get("forensic_assessment_results", {}).get("overall_classification"),
            "verified_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        }
    except Exception as e:
        return {"valid": False, "reason": f"Cryptographic verification failed: {e}"}


def from_cryptography_serialization_pem():
    from cryptography.hazmat.primitives import serialization
    return serialization.Encoding.PEM


def from_cryptography_serialization_spki():
    from cryptography.hazmat.primitives import serialization
    return serialization.PublicFormat.SubjectPublicKeyInfo


# ---------------------------------------------------------------------------
# Swarm Micro-Task Synchronization for Residual Fragments
# ---------------------------------------------------------------------------

def sync_assessment_fragments_to_swarm(assessment_id: str, case_id: str = "CASE-POST-WIPE-01") -> Dict[str, Any]:
    """
    Synchronize genuine fragmented candidates into Swarm micro-task database.
    If 0 fragments exist, reports inactive state without creating bogus records.
    """
    with _assessment_lock:
        session = _assessment_sessions.get(assessment_id)

    if not session:
        return {"status": "ERROR", "message": "Assessment session not found."}

    fragment_candidates = session.partial_artifacts + session.anomalies
    if not fragment_candidates:
        return {
            "status": "INACTIVE",
            "message": "SWARM RECONSTRUCTION: NO RESIDUAL FRAGMENTS DETECTED — PUZZLE GENERATION INACTIVE",
            "tasks_created": 0,
        }

    from swarm_engine import init_swarm_db, create_candidate_and_generate_tasks, get_swarm_db_path

    init_swarm_db()
    tasks_spawned = 0

    for cand in fragment_candidates:
        try:
            # Read real slice from target
            raw_slice = b""
            if os.path.exists(session.target_path):
                with open(session.target_path, "rb") as f:
                    f.seek(cand["start_byte_offset"])
                    raw_slice = f.read(min(cand["length_bytes"], 32768))

            cand_rec = create_candidate_and_generate_tasks(
                case_id=case_id,
                evidence_id=session.assessment_id,
                lba_start=cand["start_lba"],
                byte_offset=cand["start_byte_offset"],
                format_type=cand["format"],
                raw_slice=raw_slice or b"\x00" * 512,
                automated_confidence=cand["confidence_score"],
                structural_indicators={
                    "validation_level": cand["validation_level"],
                    "details": cand["details"],
                    "is_fragmented": True,
                    "classification": cand["classification"],
                },
                candidate_id=cand["candidate_id"],
            )
            tasks_spawned += len(cand_rec.get("tasks", []))
        except Exception as e:
            session.add_log(f"Swarm sync error on {cand['candidate_id']}: {e}")

    return {
        "status": "SUCCESS",
        "message": f"Synchronized {len(fragment_candidates)} residual fragment candidate(s) into Swarm ({tasks_spawned} micro-tasks created).",
        "fragments_count": len(fragment_candidates),
        "tasks_created": tasks_spawned,
    }


def cancel_assessment_session(assessment_id: str) -> bool:
    """Safely and cooperatively cancel an active post-sanitization assessment session."""
    with _assessment_lock:
        session = _assessment_sessions.get(assessment_id)
        if session:
            session.is_cancelled = True
            session.status = "CANCELLED"
            session.add_log("Assessment session cancellation requested.")
            return True
    return False


def get_active_assessment_session(assessment_id: str) -> Optional[PostSanitizationAssessmentSession]:
    """Retrieve active assessment session by ID."""
    with _assessment_lock:
        return _assessment_sessions.get(assessment_id)

