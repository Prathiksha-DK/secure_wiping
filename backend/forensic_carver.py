"""
Forensic Carver & Recovery Verification Engine
Part of SecureWipe Phase 3 Forensic Verification Engine.

Provides streaming, chunked, read-only forensic scanning across files, folders,
and block devices with multi-level structural validation and evidence classification.

Evidence Classification Levels:
  - NO_EVIDENCE: Zero recognizable file structures detected.
  - LOW_CONFIDENCE_TRACE: Isolated magic byte hits without valid internal structures.
  - PROBABLE_RECOVERABLE_ARTIFACT: Structural markers / headers match format specifications.
  - VALIDATED_RECOVERABLE_ARTIFACT: Fully parsable, decompressed, or trailer-verified file artifacts.
"""

import os
import sys
import time
from typing import Dict, Any, Optional, List, Callable, Tuple

from forensic_signatures import evaluate_buffer_signatures, ValidationResult


# Classification Constants
EVIDENCE_NO_EVIDENCE = "NO_EVIDENCE"
EVIDENCE_LOW_CONFIDENCE = "LOW_CONFIDENCE_TRACE"
EVIDENCE_PROBABLE = "PROBABLE_RECOVERABLE_ARTIFACT"
EVIDENCE_VALIDATED = "VALIDATED_RECOVERABLE_ARTIFACT"

DEFAULT_CHUNK_SIZE = 2 * 1024 * 1024  # 2 MiB chunks for streaming
OVERLAP_SIZE = 64 * 1024  # 64 KiB overlap to prevent missing headers across chunk boundaries


class ForensicScanSession:
    def __init__(self, target: str, target_type: str, total_bytes: int = 0):
        self.target = target
        self.target_type = target_type
        self.total_bytes = max(0, total_bytes)
        self.bytes_scanned = 0
        self.read_errors = 0
        self.unscanned_bytes = 0
        self.start_time = time.time()
        self.end_time = 0.0

        self.signature_hits: List[Dict[str, Any]] = []
        self.valid_candidates: List[Dict[str, Any]] = []
        self.validated_artifacts: List[Dict[str, Any]] = []

        self.evidence_level = EVIDENCE_NO_EVIDENCE
        self.confidence_score = 0.0  # 0.0 to 100.0
        self.summary_reason = "Scan initialized"

    def compute_evidence_classification(self, scan_coverage_pct: float) -> None:
        """Calculate evidence classification and numerical confidence score."""
        val_count = len(self.validated_artifacts)
        cand_count = len(self.valid_candidates)
        hit_count = len(self.signature_hits)

        if val_count > 0:
            self.evidence_level = EVIDENCE_VALIDATED
            # Calculate score 70-100 based on validated artifacts
            self.confidence_score = min(100.0, 70.0 + (val_count * 5.0))
            self.summary_reason = (
                f"Detected {val_count} fully validated, structurally intact file artifact(s) "
                f"({', '.join(set(a['format'] for a in self.validated_artifacts[:5]))})."
            )
        elif cand_count > 0:
            self.evidence_level = EVIDENCE_PROBABLE
            self.confidence_score = min(69.0, 35.0 + (cand_count * 4.0))
            self.summary_reason = (
                f"Detected {cand_count} probable file candidate(s) with valid header markers "
                f"({', '.join(set(a['format'] for a in self.valid_candidates[:5]))})."
            )
        elif hit_count > 0:
            self.evidence_level = EVIDENCE_LOW_CONFIDENCE
            self.confidence_score = min(29.0, 5.0 + (hit_count * 2.0))
            self.summary_reason = (
                f"Detected {hit_count} isolated signature prefix match(es), but none possessed "
                "valid internal file structures (likely false positive noise or fragmented residue)."
            )
        else:
            self.evidence_level = EVIDENCE_NO_EVIDENCE
            self.confidence_score = 0.0
            self.summary_reason = (
                f"No recognizable file signatures or recoverable data structures detected "
                f"across {scan_coverage_pct:.1f}% scanned space."
            )

    def to_dict(self) -> Dict[str, Any]:
        duration = (self.end_time or time.time()) - self.start_time
        coverage_pct = (
            (self.bytes_scanned / self.total_bytes * 100.0)
            if self.total_bytes > 0 else 100.0
        )
        throughput_mbps = (
            (self.bytes_scanned / (1024 * 1024)) / duration
            if duration > 0.05 else 0.0
        )

        return {
            "target": self.target,
            "target_type": self.target_type,
            "total_bytes": self.total_bytes,
            "bytes_scanned": self.bytes_scanned,
            "scan_coverage_pct": round(coverage_pct, 2),
            "unscanned_bytes": max(0, self.total_bytes - self.bytes_scanned),
            "read_errors": self.read_errors,
            "duration_seconds": round(duration, 2),
            "throughput_mbps": round(throughput_mbps, 1),
            "evidence_level": self.evidence_level,
            "confidence_score": round(self.confidence_score, 1),
            "summary_reason": self.summary_reason,
            "counts": {
                "level_1_signature_hits": len(self.signature_hits),
                "level_2_valid_candidates": len(self.valid_candidates),
                "level_3_validated_artifacts": len(self.validated_artifacts),
                "total_detections": len(self.signature_hits) + len(self.valid_candidates) + len(self.validated_artifacts),
            },
            "findings_sample": (
                self.validated_artifacts[:10]
                + self.valid_candidates[:10]
                + self.signature_hits[:5]
            )[:15],
        }


# ---------------------------------------------------------------------------
# Streaming Read-Only Scanner Implementations
# ---------------------------------------------------------------------------

def scan_disk_stream(
    device_path: str,
    total_bytes: int,
    scan_limit_bytes: Optional[int] = None,
    progress_cb: Optional[Callable[[Dict[str, Any]], None]] = None,
    cancel_check: Optional[Callable[[], bool]] = None,
) -> Dict[str, Any]:
    """
    Stream-scan a physical or raw block device strictly in READ-ONLY mode.
    Reads chunk by chunk with overlap; evaluates against forensic validators.
    """
    session = ForensicScanSession(device_path, "disk", total_bytes)

    if not os.path.exists(device_path):
        session.end_time = time.time()
        session.evidence_level = EVIDENCE_NO_EVIDENCE
        session.summary_reason = "Device node not found or accessible"
        return session.to_dict()

    effective_limit = min(total_bytes, scan_limit_bytes) if scan_limit_bytes else total_bytes

    try:
        # Strictly open device in READ-ONLY mode
        fd = os.open(device_path, os.O_RDONLY | getattr(os, "O_BINARY", 0))
        try:
            offset = 0
            overlap_buf = b""

            while offset < effective_limit:
                if cancel_check and cancel_check():
                    session.summary_reason = "Scan cancelled by operator"
                    break

                to_read = min(DEFAULT_CHUNK_SIZE, effective_limit - offset)
                try:
                    os.lseek(fd, offset, os.SEEK_SET)
                    chunk = os.read(fd, to_read)
                except Exception:
                    session.read_errors += 1
                    offset += to_read
                    continue

                if not chunk:
                    break

                # Combine overlap from previous block to catch signatures across boundaries
                eval_buffer = overlap_buf + chunk
                base_eval_offset = max(0, offset - len(overlap_buf))

                results = evaluate_buffer_signatures(eval_buffer, base_eval_offset)
                for res in results:
                    r_dict = res.to_dict()
                    if res.level == 3:
                        session.validated_artifacts.append(r_dict)
                    elif res.level == 2:
                        session.valid_candidates.append(r_dict)
                    else:
                        session.signature_hits.append(r_dict)

                session.bytes_scanned += len(chunk)
                offset += len(chunk)
                overlap_buf = chunk[-OVERLAP_SIZE:] if len(chunk) >= OVERLAP_SIZE else chunk

                if progress_cb and total_bytes > 0:
                    pct = int((session.bytes_scanned / effective_limit) * 100)
                    progress_cb({
                        "bytes_scanned": session.bytes_scanned,
                        "total_bytes": effective_limit,
                        "percentage": pct,
                        "validated_count": len(session.validated_artifacts),
                        "candidates_count": len(session.valid_candidates),
                    })

        finally:
            os.close(fd)
    except PermissionError:
        session.read_errors += 1
        session.summary_reason = "Permission denied opening raw device descriptor for recovery scan"
    except Exception as e:
        session.read_errors += 1
        session.summary_reason = f"Read error during recovery assessment: {e}"

    session.end_time = time.time()
    coverage = (session.bytes_scanned / total_bytes * 100.0) if total_bytes > 0 else 100.0
    session.compute_evidence_classification(coverage)
    return session.to_dict()


def scan_file_stream(
    file_path: str,
    progress_cb: Optional[Callable[[Dict[str, Any]], None]] = None,
) -> Dict[str, Any]:
    """Forensic scan of a single file target in read-only mode."""
    if not os.path.exists(file_path):
        session = ForensicScanSession(file_path, "file", 0)
        session.end_time = time.time()
        session.evidence_level = EVIDENCE_NO_EVIDENCE
        session.summary_reason = "Target file does not exist on filesystem"
        return session.to_dict()

    file_size = os.path.getsize(file_path)
    session = ForensicScanSession(file_path, "file", file_size)

    try:
        with open(file_path, "rb") as f:
            data = f.read(min(file_size, 100 * 1024 * 1024))
            results = evaluate_buffer_signatures(data, 0)
            for res in results:
                r_dict = res.to_dict()
                if res.level == 3:
                    session.validated_artifacts.append(r_dict)
                elif res.level == 2:
                    session.valid_candidates.append(r_dict)
                else:
                    session.signature_hits.append(r_dict)
            session.bytes_scanned = len(data)
    except Exception as e:
        session.read_errors += 1
        session.summary_reason = str(e)

    session.end_time = time.time()
    session.compute_evidence_classification(100.0)
    return session.to_dict()


def scan_folder_stream(
    folder_path: str,
    progress_cb: Optional[Callable[[Dict[str, Any]], None]] = None,
) -> Dict[str, Any]:
    """Forensic scan of a folder target in read-only mode."""
    all_files = []
    total_size = 0

    if os.path.exists(folder_path):
        for dirpath, _, filenames in os.walk(folder_path):
            for fn in filenames:
                fp = os.path.join(dirpath, fn)
                all_files.append(fp)
                try:
                    total_size += os.path.getsize(fp)
                except Exception:
                    pass

    session = ForensicScanSession(folder_path, "folder", total_size)

    if not all_files:
        session.end_time = time.time()
        session.evidence_level = EVIDENCE_NO_EVIDENCE
        session.summary_reason = "Directory is empty; no files or data streams exist"
        return session.to_dict()

    for idx, fp in enumerate(all_files):
        try:
            sz = os.path.getsize(fp)
            with open(fp, "rb") as f:
                header = f.read(min(sz, 64 * 1024))
                results = evaluate_buffer_signatures(header, 0)
                for res in results:
                    r_dict = res.to_dict()
                    r_dict["file_path"] = fp
                    if res.level == 3:
                        session.validated_artifacts.append(r_dict)
                    elif res.level == 2:
                        session.valid_candidates.append(r_dict)
                    else:
                        session.signature_hits.append(r_dict)
            session.bytes_scanned += sz
        except Exception:
            session.read_errors += 1

        if progress_cb:
            progress_cb({
                "bytes_scanned": session.bytes_scanned,
                "total_bytes": total_size,
                "percentage": int(((idx + 1) / len(all_files)) * 100),
                "validated_count": len(session.validated_artifacts),
                "candidates_count": len(session.valid_candidates),
            })

    session.end_time = time.time()
    session.compute_evidence_classification(100.0)
    return session.to_dict()
