"""
SecureWipe — Phase 8: SWARM-CARVING Engine
Distributed Human-in-the-Loop Forensic Micro-Triage Engine

Key Architecture Principles:
1. Original evidence remains READ-ONLY + HASH-VERIFIED (SHA-256 / SHA-512).
2. All micro-tasks operate on derived representations (entropy, Hilbert-curve, byte frequencies, tokenized syntax).
3. Human-in-the-Loop triage: Automated -> Human Swarm -> Weighted Consensus -> Confidence Ranking -> Lead Investigator Review.
4. Human triage provides confidence & prioritization; Lead Investigator retains authoritative evidentiary determination.
5. Gamification rewards accuracy and consistency, never guessing. Anti-gaming detects bots, spam, and rapid-clicking.
"""

import os
import sys
import math
import time
import json
import sqlite3
import hashlib
import secrets
import tempfile
from typing import Dict, Any, Optional, List, Tuple

# ---------------------------------------------------------------------------
# Database & Storage Configuration
# ---------------------------------------------------------------------------
def _get_data_dir() -> str:
    data_dir = os.environ.get("SECUREWIPE_DATA_DIR")
    if not data_dir:
        data_dir = os.path.join(os.path.dirname(__file__), "data")
        try:
            os.makedirs(data_dir, exist_ok=True)
            test_file = os.path.join(data_dir, ".write_test_swarm")
            with open(test_file, "w") as f:
                f.write("ok")
            os.remove(test_file)
        except Exception:
            data_dir = os.path.join(tempfile.gettempdir(), "securewipe_data")
            os.makedirs(data_dir, exist_ok=True)
    os.makedirs(data_dir, exist_ok=True)
    return data_dir

def get_swarm_db_path() -> str:
    return os.path.join(_get_data_dir(), "swarm_carving.db")

# ---------------------------------------------------------------------------
# Task Types & Constants
# ---------------------------------------------------------------------------
TASK_TYPE_ANOMALY = "TASK_ANOMALY"
TASK_TYPE_FRAGMENT_CLASSIFICATION = "TASK_FRAGMENT_CLASSIFICATION"
TASK_TYPE_FRAGMENT_MATCH = "TASK_FRAGMENT_MATCH"
TASK_TYPE_STRUCTURE_VALIDATION = "TASK_STRUCTURE_VALIDATION"
TASK_TYPE_PRIORITY = "TASK_PRIORITY"
TASK_TYPE_CORRUPTION = "TASK_CORRUPTION"

ALL_TASK_TYPES = [
    TASK_TYPE_ANOMALY,
    TASK_TYPE_FRAGMENT_CLASSIFICATION,
    TASK_TYPE_FRAGMENT_MATCH,
    TASK_TYPE_STRUCTURE_VALIDATION,
    TASK_TYPE_PRIORITY,
    TASK_TYPE_CORRUPTION,
]

DIFFICULTY_EASY = "EASY"
DIFFICULTY_MEDIUM = "MEDIUM"
DIFFICULTY_HARD = "HARD"
DIFFICULTY_EXPERT = "EXPERT"

CONSENSUS_HIGH_CONFIDENCE = "HIGH_CONFIDENCE_TRIAGE"
CONSENSUS_MODERATE = "MODERATE_CONSENSUS_TRIAGE"
CONSENSUS_AMBIGUOUS = "AMBIGUOUS_SPLIT_REQUIRES_INVESTIGATOR"
CONSENSUS_REJECTED_NOISE = "REJECTED_NOISE"
CONSENSUS_PENDING = "PENDING_MORE_REVIEWS"

INVESTIGATOR_VERDICT_CONFIRMED = "CONFIRMED_EVIDENTIARY_ARTIFACT"
INVESTIGATOR_VERDICT_CORRUPTED = "CORRUPTED_NON_RECOVERABLE"
INVESTIGATOR_VERDICT_NOISE = "INNOCUOUS_NOISE"
INVESTIGATOR_VERDICT_LAB_REQUIRED = "FURTHER_LAB_ANALYSIS_REQUIRED"

# ---------------------------------------------------------------------------
# Database Initialization
# ---------------------------------------------------------------------------
def init_swarm_db():
    """Initialize SQLite tables for Swarm-Carving engine."""
    db_path = get_swarm_db_path()
    conn = sqlite3.connect(db_path)
    try:
        with conn:
            # 1. Evidence registry (Read-only reference)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS swarm_evidence (
                    evidence_id TEXT PRIMARY KEY,
                    case_id TEXT NOT NULL,
                    image_path TEXT NOT NULL,
                    sha256_hash TEXT NOT NULL,
                    sha512_hash TEXT NOT NULL,
                    total_bytes INTEGER NOT NULL,
                    is_read_only INTEGER NOT NULL DEFAULT 1,
                    created_at INTEGER NOT NULL
                )
            """)

            # 2. Carved candidates
            conn.execute("""
                CREATE TABLE IF NOT EXISTS swarm_candidates (
                    candidate_id TEXT PRIMARY KEY,
                    case_id TEXT NOT NULL,
                    evidence_id TEXT NOT NULL,
                    lba_start INTEGER NOT NULL,
                    byte_offset INTEGER NOT NULL,
                    length_bytes INTEGER NOT NULL,
                    format_type TEXT NOT NULL,
                    automated_confidence REAL NOT NULL,
                    entropy REAL NOT NULL,
                    structural_indicators_json TEXT NOT NULL,
                    fragment_relationships_json TEXT NOT NULL,
                    analysis_version TEXT NOT NULL,
                    status TEXT NOT NULL,
                    created_at INTEGER NOT NULL
                )
            """)

            # 3. Micro-tasks
            conn.execute("""
                CREATE TABLE IF NOT EXISTS swarm_tasks (
                    task_id TEXT PRIMARY KEY,
                    candidate_id TEXT NOT NULL,
                    case_id TEXT NOT NULL,
                    evidence_id TEXT NOT NULL,
                    task_type TEXT NOT NULL,
                    difficulty TEXT NOT NULL,
                    difficulty_score REAL NOT NULL,
                    derived_data_json TEXT NOT NULL,
                    is_validation_task INTEGER NOT NULL DEFAULT 0,
                    ground_truth_json TEXT DEFAULT '',
                    target_reviews INTEGER NOT NULL DEFAULT 3,
                    status TEXT NOT NULL DEFAULT 'OPEN',
                    created_at INTEGER NOT NULL
                )
            """)

            # 4. Analyst submissions
            conn.execute("""
                CREATE TABLE IF NOT EXISTS swarm_submissions (
                    submission_id TEXT PRIMARY KEY,
                    task_id TEXT NOT NULL,
                    candidate_id TEXT NOT NULL,
                    analyst_id TEXT NOT NULL,
                    decision TEXT NOT NULL,
                    confidence REAL NOT NULL,
                    time_spent_ms INTEGER NOT NULL,
                    reason TEXT DEFAULT '',
                    flagged_suspicious INTEGER NOT NULL DEFAULT 0,
                    suspicious_reasons_json TEXT DEFAULT '[]',
                    created_at INTEGER NOT NULL
                )
            """)

            # 5. Swarm consensus records
            conn.execute("""
                CREATE TABLE IF NOT EXISTS swarm_consensus (
                    candidate_id TEXT PRIMARY KEY,
                    case_id TEXT NOT NULL,
                    evidence_id TEXT NOT NULL,
                    consensus_status TEXT NOT NULL,
                    dominant_decision TEXT NOT NULL,
                    agreement_ratio REAL NOT NULL,
                    disagreement_entropy REAL NOT NULL,
                    swarm_confidence REAL NOT NULL,
                    total_reviews INTEGER NOT NULL,
                    weighted_votes_json TEXT NOT NULL,
                    updated_at INTEGER NOT NULL
                )
            """)

            # 6. Lead investigator reviews & final determinations
            conn.execute("""
                CREATE TABLE IF NOT EXISTS swarm_investigator_reviews (
                    review_id TEXT PRIMARY KEY,
                    candidate_id TEXT NOT NULL,
                    case_id TEXT NOT NULL,
                    evidence_id TEXT NOT NULL,
                    investigator_id TEXT NOT NULL,
                    final_verdict TEXT NOT NULL,
                    evidentiary_value TEXT NOT NULL,
                    notes TEXT DEFAULT '',
                    digital_signature TEXT NOT NULL,
                    timestamp INTEGER NOT NULL
                )
            """)

            # 7. Analyst profiles & reliability models
            conn.execute("""
                CREATE TABLE IF NOT EXISTS swarm_analysts (
                    analyst_id TEXT PRIMARY KEY,
                    username TEXT NOT NULL UNIQUE,
                    role TEXT NOT NULL DEFAULT 'TRIAGE_ANALYST',
                    reliability_score REAL NOT NULL DEFAULT 0.50,
                    total_tasks_completed INTEGER NOT NULL DEFAULT 0,
                    ground_truth_tested INTEGER NOT NULL DEFAULT 0,
                    ground_truth_matches INTEGER NOT NULL DEFAULT 0,
                    false_positives INTEGER NOT NULL DEFAULT 0,
                    false_negatives INTEGER NOT NULL DEFAULT 0,
                    consistency_score REAL NOT NULL DEFAULT 1.0,
                    avg_response_time_ms REAL NOT NULL DEFAULT 0.0,
                    flagged_suspicious_count INTEGER NOT NULL DEFAULT 0,
                    xp INTEGER NOT NULL DEFAULT 0,
                    level TEXT NOT NULL DEFAULT 'Novice',
                    streak_days INTEGER NOT NULL DEFAULT 1,
                    last_active_date TEXT DEFAULT '',
                    badges_json TEXT NOT NULL DEFAULT '[]',
                    recent_answers_json TEXT NOT NULL DEFAULT '[]'
                )
            """)

            # 8. Chained cryptographic audit trail
            conn.execute("""
                CREATE TABLE IF NOT EXISTS swarm_audit_log (
                    event_id TEXT PRIMARY KEY,
                    prev_hash TEXT NOT NULL,
                    event_hash TEXT NOT NULL,
                    timestamp INTEGER NOT NULL,
                    case_id TEXT NOT NULL,
                    evidence_id TEXT NOT NULL,
                    candidate_id TEXT DEFAULT '',
                    task_id TEXT DEFAULT '',
                    actor_id TEXT NOT NULL,
                    actor_role TEXT NOT NULL,
                    action_type TEXT NOT NULL,
                    payload_digest TEXT NOT NULL,
                    details_json TEXT NOT NULL
                )
            """)
    finally:
        conn.close()

# ---------------------------------------------------------------------------
# Derived Privacy-Preserving Representations
# ---------------------------------------------------------------------------
def compute_shannon_entropy(data: bytes) -> float:
    """Calculate Shannon entropy (0.0 to 8.0) for a byte buffer."""
    if not data:
        return 0.0
    length = len(data)
    counts = {}
    for b in data:
        counts[b] = counts.get(b, 0) + 1
    entropy = 0.0
    for count in counts.values():
        p = count / length
        entropy -= p * math.log2(p)
    return round(entropy, 4)

def compute_entropy_map(data: bytes, bins: int = 16) -> List[Dict[str, Any]]:
    """
    Compute a windowed entropy distribution across the data slice.
    Returns normalized entropy values [0.0 - 1.0] and raw Shannon scores [0.0 - 8.0].
    """
    if not data:
        return []
    length = len(data)
    bin_size = max(1, length // bins)
    result = []
    for i in range(bins):
        start = i * bin_size
        end = min(length, (i + 1) * bin_size) if i < bins - 1 else length
        chunk = data[start:end]
        if not chunk:
            break
        ent = compute_shannon_entropy(chunk)
        result.append({
            "bin_index": i,
            "start_offset": start,
            "end_offset": end,
            "byte_count": len(chunk),
            "entropy": ent,
            "normalized_entropy": round(ent / 8.0, 4)
        })
    return result

def compute_byte_frequency_histogram(data: bytes) -> Dict[str, Any]:
    """
    Compute privacy-preserving byte frequency distribution without exposing raw sensitive content.
    Categorizes bytes into structural classes: Nulls, Control, Printable ASCII, High-Byte (binary/crypto).
    """
    if not data:
        return {
            "total_bytes": 0,
            "null_bytes": 0,
            "null_pct": 0.0,
            "printable_ascii_bytes": 0,
            "printable_ascii_pct": 0.0,
            "control_bytes": 0,
            "control_pct": 0.0,
            "high_bytes": 0,
            "high_bytes_pct": 0.0,
            "unique_byte_count": 0,
            "top_frequencies": []
        }

    total = len(data)
    counts = [0] * 256
    for b in data:
        counts[b] += 1

    null_count = counts[0]
    control_count = sum(counts[1:32]) + counts[127]
    printable_count = sum(counts[32:127])
    high_count = sum(counts[128:256])

    unique_bytes = sum(1 for c in counts if c > 0)

    # Top 8 most frequent byte values
    sorted_bytes = sorted(enumerate(counts), key=lambda x: x[1], reverse=True)[:8]
    top_freqs = [
        {"byte_hex": f"0x{b:02X}", "count": cnt, "pct": round(cnt / total * 100.0, 2)}
        for b, cnt in sorted_bytes if cnt > 0
    ]

    return {
        "total_bytes": total,
        "null_bytes": null_count,
        "null_pct": round(null_count / total * 100.0, 2),
        "printable_ascii_bytes": printable_count,
        "printable_ascii_pct": round(printable_count / total * 100.0, 2),
        "control_bytes": control_count,
        "control_pct": round(control_count / total * 100.0, 2),
        "high_bytes": high_count,
        "high_bytes_pct": round(high_count / total * 100.0, 2),
        "unique_byte_count": unique_bytes,
        "top_frequencies": top_freqs
    }

def _d2xy_hilbert(n: int, d: int) -> Tuple[int, int]:
    """Convert 1D index d to 2D coordinates (x, y) along an n x n Hilbert curve."""
    rx = ry = 0
    t = d
    x = y = 0
    s = 1
    while s < n:
        rx = 1 & (t // 2)
        ry = 1 & (t ^ rx)
        if ry == 0:
            if rx == 1:
                x = s - 1 - x
                y = s - 1 - y
            x, y = y, x
        x += s * rx
        y += s * ry
        t //= 4
        s *= 2
    return x, y

def compute_hilbert_curve_2d(data: bytes, grid_size: int = 8) -> List[List[float]]:
    """
    Project byte density & localized entropy onto a 2D space-filling Hilbert curve (e.g. 8x8 matrix).
    Preserves structural locality for visual pattern triage without disclosing plaintext secrets.
    """
    total_cells = grid_size * grid_size  # 64 cells for 8x8
    grid = [[0.0 for _ in range(grid_size)] for _ in range(grid_size)]

    if not data:
        return grid

    data_len = len(data)
    chunk_size = max(1, data_len // total_cells)

    for cell_idx in range(total_cells):
        start = cell_idx * chunk_size
        end = min(data_len, (cell_idx + 1) * chunk_size) if cell_idx < total_cells - 1 else data_len
        chunk = data[start:end]
        if chunk:
            ent = compute_shannon_entropy(chunk)
            norm_val = round(ent / 8.0, 3)
        else:
            norm_val = 0.0
        x, y = _d2xy_hilbert(grid_size, cell_idx)
        if 0 <= y < grid_size and 0 <= x < grid_size:
            grid[y][x] = norm_val

    return grid

def generate_sanitized_token_preview(data: bytes, format_type: str) -> Dict[str, Any]:
    """
    Generate a sanitized, privacy-preserving structural preview (token tags, offsets, segment headers)
    without rendering unredacted raw personal content.
    """
    tokens = []
    length = len(data)

    if format_type.upper() == "JPEG":
        if length >= 2 and data[:2] == b"\xff\xd8":
            tokens.append({"type": "MARKER", "name": "SOI (Start of Image)", "offset": 0, "status": "VALID"})
        pos = 2
        while pos + 4 < min(length, 1024):
            if data[pos] == 0xff:
                marker = data[pos + 1]
                marker_names = {
                    0xe0: "APP0 (JFIF Header)",
                    0xe1: "APP1 (Exif Metadata)",
                    0xdb: "DQT (Quantization Table)",
                    0xc0: "SOF0 (Baseline Frame)",
                    0xc4: "DHT (Huffman Table)",
                    0xda: "SOS (Start of Scan)",
                    0xd9: "EOI (End of Image)"
                }
                name = marker_names.get(marker, f"MARKER_0xFF{marker:02X}")
                seg_len = (data[pos + 2] << 8) + data[pos + 3] if pos + 4 <= length else 0
                tokens.append({
                    "type": "SEGMENT",
                    "name": name,
                    "offset": pos,
                    "segment_length": seg_len,
                    "status": "VALID" if seg_len > 0 else "PARTIAL"
                })
                pos += max(2, 2 + seg_len)
            else:
                pos += 1
    elif format_type.upper() == "PDF":
        if b"%PDF-" in data[:1024]:
            idx = data.find(b"%PDF-")
            ver = data[idx:idx+8].decode("latin-1", errors="ignore").strip()
            tokens.append({"type": "HEADER", "name": f"PDF Version Header ({ver})", "offset": idx, "status": "VALID"})
        obj_count = data.count(b" obj")
        endobj_count = data.count(b"endobj")
        stream_count = data.count(b"stream")
        tokens.append({"type": "OBJECT_CATALOG", "name": f"{obj_count} Objects / {endobj_count} Endobj / {stream_count} Streams", "offset": 0, "status": "PARSED"})
        if b"%%EOF" in data[-2048:]:
            tokens.append({"type": "TRAILER", "name": "PDF EOF Marker Verified", "offset": length - 6, "status": "VALID"})
    elif format_type.upper() == "PNG":
        if length >= 8 and data[:8] == b"\x89PNG\r\n\x1a\n":
            tokens.append({"type": "SIGNATURE", "name": "PNG Magic Header Verified", "offset": 0, "status": "VALID"})
        chunks = ["IHDR", "IDAT", "PLTE", "IEND", "tEXt", "zTXt", "pHYs"]
        for ch in chunks:
            count = data.count(ch.encode("ascii"))
            if count > 0:
                tokens.append({"type": "CHUNK", "name": f"PNG Chunk '{ch}' ({count}x)", "offset": -1, "status": "VALID"})
    elif format_type.upper() == "SQLITE":
        if length >= 16 and data[:16] == b"SQLite format 3\x00":
            tokens.append({"type": "HEADER", "name": "SQLite v3 Database Header", "offset": 0, "status": "VALID"})
            if length >= 100:
                page_size = int.from_bytes(data[16:18], "big")
                tokens.append({"type": "METADATA", "name": f"Page Size: {page_size} bytes", "offset": 16, "status": "VALID"})
    else:
        tokens.append({"type": "GENERIC_STREAM", "name": f"Raw Fragment ({length} bytes)", "offset": 0, "status": "UNKNOWN"})

    return {
        "format": format_type,
        "total_length": length,
        "token_count": len(tokens),
        "tokens": tokens,
        "summary": f"Identified {len(tokens)} structural elements in {format_type} candidate."
    }

# ---------------------------------------------------------------------------
# Task Difficulty Calculation Model
# ---------------------------------------------------------------------------
def compute_task_difficulty(
    confidence: float,
    entropy: float,
    length_bytes: int,
    is_fragmented: bool,
    structural_completeness: float,
    neighbor_candidates_count: int = 0
) -> Tuple[str, float, Dict[str, Any]]:
    """
    Calculate measurable task difficulty: EASY, MEDIUM, HARD, EXPERT.
    
    Formula:
      Score = w1*(1 - conf) + w2*Ambiguity + w3*(1 - Completeness) + w4*EntropyDispersion + w5*NeighborFactor
    """
    w1, w2, w3, w4, w5 = 0.30, 0.25, 0.20, 0.15, 0.10

    # 1. Inverted confidence factor [0.0 - 1.0]
    conf_factor = max(0.0, min(1.0, 1.0 - confidence))

    # 2. Ambiguity factor based on fragmentation & intermediate entropy
    entropy_ambiguity = 1.0 - abs(entropy - 5.75) / 2.25 if (3.5 <= entropy <= 8.0) else 0.2
    ambiguity_factor = max(0.0, min(1.0, 0.5 * (1.0 if is_fragmented else 0.0) + 0.5 * entropy_ambiguity))

    # 3. Structural completeness [0.0 - 1.0]
    completeness_factor = max(0.0, min(1.0, 1.0 - structural_completeness))

    # 4. Entropy dispersion factor (normalized 0.0 - 1.0)
    entropy_factor = max(0.0, min(1.0, entropy / 8.0))

    # 5. Neighbor candidate complexity factor
    neighbor_factor = max(0.0, min(1.0, neighbor_candidates_count / 5.0))

    difficulty_score = (
        w1 * conf_factor +
        w2 * ambiguity_factor +
        w3 * completeness_factor +
        w4 * entropy_factor +
        w5 * neighbor_factor
    )
    difficulty_score = round(max(0.05, min(0.99, difficulty_score)), 3)

    if difficulty_score < 0.35:
        difficulty_level = DIFFICULTY_EASY
    elif difficulty_score < 0.65:
        difficulty_level = DIFFICULTY_MEDIUM
    elif difficulty_score < 0.85:
        difficulty_level = DIFFICULTY_HARD
    else:
        difficulty_level = DIFFICULTY_EXPERT

    metrics = {
        "difficulty_score": difficulty_score,
        "weights": {"confidence": w1, "ambiguity": w2, "completeness": w3, "entropy": w4, "neighbors": w5},
        "factors": {
            "confidence_inversion": round(conf_factor, 3),
            "ambiguity": round(ambiguity_factor, 3),
            "completeness_inversion": round(completeness_factor, 3),
            "entropy_dispersion": round(entropy_factor, 3),
            "neighbor_complexity": round(neighbor_factor, 3)
        }
    }
    return difficulty_level, difficulty_score, metrics

# ---------------------------------------------------------------------------
# Task Generation Engine
# ---------------------------------------------------------------------------
def register_evidence_source(
    case_id: str,
    image_path: str,
    raw_data: bytes,
    evidence_id: Optional[str] = None
) -> Dict[str, Any]:
    """Register an immutable, read-only forensic evidence image with SHA-256 and SHA-512 hashes."""
    init_swarm_db()
    if not evidence_id:
        evidence_id = f"EV-{secrets.token_hex(6).upper()}"

    sha256_hash = hashlib.sha256(raw_data).hexdigest()
    sha512_hash = hashlib.sha512(raw_data).hexdigest()
    total_bytes = len(raw_data)
    now = int(time.time())

    conn = sqlite3.connect(get_swarm_db_path())
    try:
        with conn:
            conn.execute("""
                INSERT OR REPLACE INTO swarm_evidence
                (evidence_id, case_id, image_path, sha256_hash, sha512_hash, total_bytes, is_read_only, created_at)
                VALUES (?, ?, ?, ?, ?, ?, 1, ?)
            """, (evidence_id, case_id, image_path, sha256_hash, sha512_hash, total_bytes, now))
    finally:
        conn.close()

    record_swarm_audit_event(
        case_id=case_id,
        evidence_id=evidence_id,
        actor_id="SYSTEM",
        actor_role="ADMIN",
        action_type="EVIDENCE_REGISTERED_READ_ONLY",
        payload_digest=sha256_hash,
        details={"image_path": image_path, "bytes": total_bytes, "sha512": sha512_hash}
    )

    return {
        "evidence_id": evidence_id,
        "case_id": case_id,
        "image_path": image_path,
        "sha256_hash": sha256_hash,
        "sha512_hash": sha512_hash,
        "total_bytes": total_bytes,
        "is_read_only": True,
        "created_at": now
    }

def create_candidate_and_generate_tasks(
    case_id: str,
    evidence_id: str,
    lba_start: int,
    byte_offset: int,
    format_type: str,
    raw_slice: bytes,
    automated_confidence: float,
    structural_indicators: Dict[str, Any],
    fragment_relationships: Optional[Dict[str, Any]] = None,
    candidate_id: Optional[str] = None
) -> Dict[str, Any]:
    """
    Ingest a candidate carved artifact, compute derived representations, and generate micro-tasks
    prioritizing low-confidence / ambiguous candidates for human swarm triage.
    """
    init_swarm_db()
    if not candidate_id:
        candidate_id = f"CAND-{secrets.token_hex(5).upper()}"

    now = int(time.time())
    length_bytes = len(raw_slice)
    entropy = compute_shannon_entropy(raw_slice)
    structural_indicators = structural_indicators or {}
    fragment_relationships = fragment_relationships or {}
    analysis_version = "v8.0.4-swarm"

    # Evaluate routing: High confidence skips swarm directly to validated or investigator queue;
    # Low confidence (0.15 <= conf < 0.80) creates swarm micro-tasks.
    if automated_confidence >= 0.80 and structural_indicators.get("is_valid_structure", False):
        candidate_status = "AUTOMATED_HIGH_CONFIDENCE"
    elif automated_confidence < 0.15 and entropy < 1.0:
        candidate_status = "AUTOMATED_NOISE_REJECTED"
    else:
        candidate_status = "QUEUED_FOR_SWARM"

    conn = sqlite3.connect(get_swarm_db_path())
    try:
        with conn:
            conn.execute("""
                INSERT OR REPLACE INTO swarm_candidates
                (candidate_id, case_id, evidence_id, lba_start, byte_offset, length_bytes,
                 format_type, automated_confidence, entropy, structural_indicators_json,
                 fragment_relationships_json, analysis_version, status, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                candidate_id, case_id, evidence_id, lba_start, byte_offset, length_bytes,
                format_type, automated_confidence, entropy, json.dumps(structural_indicators),
                json.dumps(fragment_relationships), analysis_version, candidate_status, now
            ))
    finally:
        conn.close()

    tasks_generated = []

    # If queued for swarm, generate appropriate micro-tasks
    if candidate_status == "QUEUED_FOR_SWARM":
        is_frag = structural_indicators.get("is_fragmented", False)
        completeness = structural_indicators.get("completeness", 0.5)
        neighbor_count = len(fragment_relationships.get("candidate_neighbors", []))

        difficulty, diff_score, diff_metrics = compute_task_difficulty(
            confidence=automated_confidence,
            entropy=entropy,
            length_bytes=length_bytes,
            is_fragmented=is_frag,
            structural_completeness=completeness,
            neighbor_candidates_count=neighbor_count
        )

        entropy_map = compute_entropy_map(raw_slice)
        byte_freq = compute_byte_frequency_histogram(raw_slice)
        hilbert_grid = compute_hilbert_curve_2d(raw_slice, grid_size=8)
        token_preview = generate_sanitized_token_preview(raw_slice, format_type)

        derived_payload = {
            "candidate_id": candidate_id,
            "case_id": case_id,
            "evidence_id": evidence_id,
            "lba_start": lba_start,
            "byte_offset": byte_offset,
            "length_bytes": length_bytes,
            "format_type": format_type,
            "automated_confidence": automated_confidence,
            "entropy": entropy,
            "entropy_map": entropy_map,
            "byte_frequency": byte_freq,
            "hilbert_grid": hilbert_grid,
            "token_preview": token_preview,
            "difficulty_metrics": diff_metrics
        }

        # 1. Structure Validation Task
        task_id_struct = f"TASK-{secrets.token_hex(4).upper()}"
        tasks_generated.append({
            "task_id": task_id_struct,
            "candidate_id": candidate_id,
            "task_type": TASK_TYPE_STRUCTURE_VALIDATION,
            "difficulty": difficulty,
            "difficulty_score": diff_score,
            "derived_data": derived_payload,
            "is_validation_task": 0
        })

        # 2. Visual Anomaly Task (Entropy / Hilbert)
        task_id_anomaly = f"TASK-{secrets.token_hex(4).upper()}"
        tasks_generated.append({
            "task_id": task_id_anomaly,
            "candidate_id": candidate_id,
            "task_type": TASK_TYPE_ANOMALY,
            "difficulty": difficulty,
            "difficulty_score": diff_score,
            "derived_data": derived_payload,
            "is_validation_task": 0
        })

        # 3. Fragment Matching Task (if neighbor fragments exist)
        if neighbor_count > 0 or is_frag:
            task_id_match = f"TASK-{secrets.token_hex(4).upper()}"
            match_payload = dict(derived_payload)
            match_payload["neighbor_relationships"] = fragment_relationships
            tasks_generated.append({
                "task_id": task_id_match,
                "candidate_id": candidate_id,
                "task_type": TASK_TYPE_FRAGMENT_MATCH,
                "difficulty": difficulty,
                "difficulty_score": diff_score,
                "derived_data": match_payload,
                "is_validation_task": 0
            })

        # 4. Rapid Triage Task
        task_id_rapid = f"TASK-{secrets.token_hex(4).upper()}"
        tasks_generated.append({
            "task_id": task_id_rapid,
            "candidate_id": candidate_id,
            "task_type": TASK_TYPE_FRAGMENT_CLASSIFICATION,
            "difficulty": difficulty,
            "difficulty_score": diff_score,
            "derived_data": derived_payload,
            "is_validation_task": 0
        })

        # Save tasks to SQLite
        conn = sqlite3.connect(get_swarm_db_path())
        try:
            with conn:
                for t in tasks_generated:
                    conn.execute("""
                        INSERT OR REPLACE INTO swarm_tasks
                        (task_id, candidate_id, case_id, evidence_id, task_type, difficulty,
                         difficulty_score, derived_data_json, is_validation_task, ground_truth_json,
                         target_reviews, status, created_at)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 3, 'OPEN', ?)
                    """, (
                        t["task_id"], t["candidate_id"], case_id, evidence_id, t["task_type"],
                        t["difficulty"], t["difficulty_score"], json.dumps(t["derived_data"]),
                        t["is_validation_task"], "", now
                    ))
        finally:
            conn.close()

    record_swarm_audit_event(
        case_id=case_id,
        evidence_id=evidence_id,
        candidate_id=candidate_id,
        actor_id="SYSTEM",
        actor_role="SYSTEM_CARVER",
        action_type="CANDIDATE_INGESTED_TASKS_GENERATED",
        payload_digest=hashlib.sha256(raw_slice).hexdigest(),
        details={"status": candidate_status, "tasks_count": len(tasks_generated), "format": format_type}
    )

    return {
        "candidate_id": candidate_id,
        "case_id": case_id,
        "evidence_id": evidence_id,
        "status": candidate_status,
        "automated_confidence": automated_confidence,
        "entropy": entropy,
        "tasks_generated": tasks_generated
    }

# ---------------------------------------------------------------------------
# Hidden Golden Validation Tasks (Anti-Gaming & Quality Control)
# ---------------------------------------------------------------------------
def create_golden_validation_task(
    case_id: str,
    evidence_id: str,
    task_type: str,
    expected_decision: str,
    format_type: str,
    synthetic_slice: bytes,
    difficulty: str = DIFFICULTY_MEDIUM
) -> str:
    """Create a hidden golden calibration task with known expert ground truth for reliability tracking."""
    init_swarm_db()
    task_id = f"GOLDEN-{secrets.token_hex(4).upper()}"
    candidate_id = f"CAND-GT-{secrets.token_hex(4).upper()}"
    now = int(time.time())

    entropy = compute_shannon_entropy(synthetic_slice)
    derived = {
        "candidate_id": candidate_id,
        "case_id": case_id,
        "evidence_id": evidence_id,
        "lba_start": 1000,
        "byte_offset": 512000,
        "length_bytes": len(synthetic_slice),
        "format_type": format_type,
        "automated_confidence": 0.50,
        "entropy": entropy,
        "entropy_map": compute_entropy_map(synthetic_slice),
        "byte_frequency": compute_byte_frequency_histogram(synthetic_slice),
        "hilbert_grid": compute_hilbert_curve_2d(synthetic_slice, grid_size=8),
        "token_preview": generate_sanitized_token_preview(synthetic_slice, format_type),
        "is_golden_ground_truth": True
    }

    ground_truth = {
        "expected_decision": expected_decision,
        "format": format_type,
        "verified_by": "LEAD_INVESTIGATOR_CALIBRATION"
    }

    conn = sqlite3.connect(get_swarm_db_path())
    try:
        with conn:
            conn.execute("""
                INSERT OR REPLACE INTO swarm_tasks
                (task_id, candidate_id, case_id, evidence_id, task_type, difficulty,
                 difficulty_score, derived_data_json, is_validation_task, ground_truth_json,
                 target_reviews, status, created_at)
                VALUES (?, ?, ?, ?, ?, ?, 0.50, ?, 1, ?, 999, 'OPEN', ?)
            """, (
                task_id, candidate_id, case_id, evidence_id, task_type, difficulty,
                json.dumps(derived), json.dumps(ground_truth), now
            ))
    finally:
        conn.close()

    return task_id

# ---------------------------------------------------------------------------
# Task Fetching with Anti-Gaming Distribution & Personalization
# ---------------------------------------------------------------------------
def get_next_task_for_analyst(username: str, role: str = "TRIAGE_ANALYST") -> Optional[Dict[str, Any]]:
    """
    Fetch next personalized micro-task for an analyst.
    Applies:
      1. Blind task ordering.
      2. Injects ~15% hidden golden validation tasks for quality control.
      3. Excludes tasks already reviewed by this analyst.
      4. Never exposes whether a task is a golden validation task.
    """
    init_swarm_db()
    conn = sqlite3.connect(get_swarm_db_path())
    conn.row_factory = sqlite3.Row
    try:
        cursor = conn.cursor()
        reviewed_task_ids = set(
            row["task_id"] for row in cursor.execute(
                "SELECT task_id FROM swarm_submissions WHERE analyst_id = ?", (username,)
            ).fetchall()
        )

        is_golden_eligible = (secrets.randbelow(100) < 18)
        if is_golden_eligible:
            golden_rows = cursor.execute("""
                SELECT * FROM swarm_tasks
                WHERE is_validation_task = 1 AND status = 'OPEN'
                ORDER BY RANDOM() LIMIT 5
            """).fetchall()
            for r in golden_rows:
                if r["task_id"] not in reviewed_task_ids:
                    return _format_task_for_analyst(dict(r))

        rows = cursor.execute("""
            SELECT t.*, COUNT(s.submission_id) as current_reviews
            FROM swarm_tasks t
            LEFT JOIN swarm_submissions s ON t.task_id = s.task_id
            WHERE t.is_validation_task = 0 AND t.status = 'OPEN'
            GROUP BY t.task_id
            HAVING current_reviews < t.target_reviews
            ORDER BY RANDOM() LIMIT 10
        """).fetchall()

        for r in rows:
            if r["task_id"] not in reviewed_task_ids:
                return _format_task_for_analyst(dict(r))

        fallback_rows = cursor.execute("""
            SELECT * FROM swarm_tasks WHERE status = 'OPEN' ORDER BY RANDOM() LIMIT 20
        """).fetchall()
        for r in fallback_rows:
            if r["task_id"] not in reviewed_task_ids:
                return _format_task_for_analyst(dict(r))

        return None
    finally:
        conn.close()

def _format_task_for_analyst(row: Dict[str, Any]) -> Dict[str, Any]:
    """Sanitize task dictionary before returning to client (NEVER reveal is_validation_task or ground_truth)."""
    derived = json.loads(row.get("derived_data_json", "{}"))
    derived.pop("is_golden_ground_truth", None)

    return {
        "task_id": row["task_id"],
        "candidate_id": row["candidate_id"],
        "case_id": row["case_id"],
        "evidence_id": row["evidence_id"],
        "task_type": row["task_type"],
        "difficulty": row["difficulty"],
        "difficulty_score": row["difficulty_score"],
        "derived_data": derived,
        "created_at": row["created_at"]
    }

# ---------------------------------------------------------------------------
# Submission & Anti-Gaming Verification Engine
# ---------------------------------------------------------------------------
def submit_analyst_task(
    task_id: str,
    analyst_id: str,
    decision: str,
    confidence: float,
    time_spent_ms: int,
    reason: str = ""
) -> Dict[str, Any]:
    """
    Process analyst submission, evaluate anti-gaming heuristics (timing, spam patterns),
    update analyst reliability score, update XP/gamification, and trigger consensus evaluation.
    """
    init_swarm_db()
    conn = sqlite3.connect(get_swarm_db_path())
    conn.row_factory = sqlite3.Row
    try:
        task_row = conn.execute("SELECT * FROM swarm_tasks WHERE task_id = ?", (task_id,)).fetchone()
        if not task_row:
            return {"success": False, "error": f"Task {task_id} not found."}

        task = dict(task_row)
        candidate_id = task["candidate_id"]
        case_id = task["case_id"]
        evidence_id = task["evidence_id"]
        is_validation = bool(task.get("is_validation_task", 0))
        ground_truth_json = task.get("ground_truth_json", "")

        # Anti-Gaming Detection
        flagged_suspicious = False
        suspicious_reasons = []

        # 1. Rapid-fire bot / clicking detection (< 1200ms)
        if time_spent_ms < 1200:
            flagged_suspicious = True
            suspicious_reasons.append(f"Sub-human response time ({time_spent_ms} ms)")

        # 2. Check recent answer patterns (Spamming the same choice repeatedly)
        analyst_profile = _get_or_create_analyst_profile(analyst_id)
        recent_answers = json.loads(analyst_profile.get("recent_answers_json", "[]"))
        recent_answers.append(decision)
        if len(recent_answers) > 10:
            recent_answers = recent_answers[-10:]

        if len(recent_answers) >= 6:
            dominant_count = max(recent_answers.count(x) for x in set(recent_answers))
            if dominant_count / len(recent_answers) >= 0.85:
                flagged_suspicious = True
                suspicious_reasons.append("Repetitive pattern / uniform choice spam detected")

        submission_id = f"SUB-{secrets.token_hex(6).upper()}"
        now = int(time.time())

        with conn:
            conn.execute("""
                INSERT OR REPLACE INTO swarm_submissions
                (submission_id, task_id, candidate_id, analyst_id, decision, confidence,
                 time_spent_ms, reason, flagged_suspicious, suspicious_reasons_json, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                submission_id, task_id, candidate_id, analyst_id, decision, confidence,
                time_spent_ms, reason, 1 if flagged_suspicious else 0,
                json.dumps(suspicious_reasons), now
            ))

        # Reliability & Calibration Update
        is_ground_truth_match = None
        if is_validation and ground_truth_json:
            try:
                gt_data = json.loads(ground_truth_json)
                expected = gt_data.get("expected_decision", "")
                is_ground_truth_match = (decision.upper() == expected.upper())
            except Exception:
                is_ground_truth_match = None

        perf_update = _update_analyst_reliability(
            analyst_id=analyst_id,
            decision=decision,
            time_spent_ms=time_spent_ms,
            flagged_suspicious=flagged_suspicious,
            is_ground_truth_tested=is_validation,
            is_ground_truth_match=is_ground_truth_match,
            task_difficulty=task.get("difficulty", DIFFICULTY_MEDIUM),
            recent_answers=recent_answers
        )

        # Update Consensus if Candidate is open
        consensus_result = None
        if not is_validation:
            consensus_result = evaluate_candidate_consensus(candidate_id)

        # Audit Event
        record_swarm_audit_event(
            case_id=case_id,
            evidence_id=evidence_id,
            candidate_id=candidate_id,
            task_id=task_id,
            actor_id=analyst_id,
            actor_role=analyst_profile.get("role", "TRIAGE_ANALYST"),
            action_type="TASK_SUBMISSION",
            payload_digest=hashlib.sha256(f"{submission_id}:{decision}:{confidence}".encode("utf-8")).hexdigest(),
            details={
                "decision": decision,
                "confidence": confidence,
                "time_spent_ms": time_spent_ms,
                "flagged": flagged_suspicious,
                "xp_awarded": perf_update.get("xp_earned", 0)
            }
        )

        return {
            "success": True,
            "submission_id": submission_id,
            "task_id": task_id,
            "candidate_id": candidate_id,
            "flagged_suspicious": flagged_suspicious,
            "suspicious_reasons": suspicious_reasons,
            "gamification": {
                "xp_earned": perf_update.get("xp_earned", 0),
                "total_xp": perf_update.get("total_xp", 0),
                "level": perf_update.get("level", "Novice"),
                "reliability_score": perf_update.get("reliability_score", 0.50),
                "new_badges": perf_update.get("new_badges", [])
            },
            "consensus": consensus_result
        }
    finally:
        conn.close()

# ---------------------------------------------------------------------------
# Reviewer Performance & Reliability Model
# ---------------------------------------------------------------------------
def _get_or_create_analyst_profile(analyst_id: str, role: str = "TRIAGE_ANALYST") -> Dict[str, Any]:
    """Retrieve or register analyst profile."""
    conn = sqlite3.connect(get_swarm_db_path())
    conn.row_factory = sqlite3.Row
    try:
        row = conn.execute("SELECT * FROM swarm_analysts WHERE analyst_id = ? OR username = ?", (analyst_id, analyst_id)).fetchone()
        if row:
            return dict(row)
        with conn:
            conn.execute("""
                INSERT INTO swarm_analysts
                (analyst_id, username, role, reliability_score, total_tasks_completed,
                 ground_truth_tested, ground_truth_matches, false_positives, false_negatives,
                 consistency_score, avg_response_time_ms, flagged_suspicious_count, xp,
                 level, streak_days, last_active_date, badges_json, recent_answers_json)
                VALUES (?, ?, ?, 0.50, 0, 0, 0, 0, 0, 1.0, 0.0, 0, 0, 'Novice', 1, ?, '[]', '[]')
            """, (analyst_id, analyst_id, role, time.strftime("%Y-%m-%d")))
        row = conn.execute("SELECT * FROM swarm_analysts WHERE analyst_id = ?", (analyst_id,)).fetchone()
        return dict(row)
    finally:
        conn.close()

def _update_analyst_reliability(
    analyst_id: str,
    decision: str,
    time_spent_ms: int,
    flagged_suspicious: bool,
    is_ground_truth_tested: bool,
    is_ground_truth_match: Optional[bool],
    task_difficulty: str,
    recent_answers: List[str]
) -> Dict[str, Any]:
    """
    Update analyst reliability score using exponential moving calibration.
    Awards XP scaled strictly by accuracy, reliability, and task difficulty (never guessing).
    """
    conn = sqlite3.connect(get_swarm_db_path())
    conn.row_factory = sqlite3.Row
    try:
        profile = _get_or_create_analyst_profile(analyst_id)
        current_r = profile.get("reliability_score", 0.50)
        total_tasks = profile.get("total_tasks_completed", 0) + 1
        gt_tested = profile.get("ground_truth_tested", 0)
        gt_matches = profile.get("ground_truth_matches", 0)
        fps = profile.get("false_positives", 0)
        fns = profile.get("false_negatives", 0)
        flagged_count = profile.get("flagged_suspicious_count", 0) + (1 if flagged_suspicious else 0)
        current_xp = profile.get("xp", 0)
        badges = json.loads(profile.get("badges_json", "[]"))

        prev_avg = profile.get("avg_response_time_ms", 0.0)
        new_avg_time = (prev_avg * (total_tasks - 1) + time_spent_ms) / total_tasks

        xp_earned = 0
        difficulty_multipliers = {
            DIFFICULTY_EASY: 10,
            DIFFICULTY_MEDIUM: 25,
            DIFFICULTY_HARD: 50,
            DIFFICULTY_EXPERT: 100
        }
        base_xp = difficulty_multipliers.get(task_difficulty, 20)

        if flagged_suspicious:
            new_r = max(0.10, current_r - 0.08)
            xp_earned = 0
        elif is_ground_truth_tested and is_ground_truth_match is not None:
            gt_tested += 1
            if is_ground_truth_match:
                gt_matches += 1
                new_r = min(0.99, current_r * 0.85 + 0.15 * 1.0)
                xp_earned = base_xp + 25
            else:
                if decision.upper() in ("VALID", "MATCH", "HIGH_PRIORITY"):
                    fps += 1
                else:
                    fns += 1
                new_r = max(0.10, current_r * 0.85 + 0.15 * 0.10)
                xp_earned = 0
        else:
            new_r = min(0.95, current_r * 0.98 + 0.02 * current_r)
            xp_earned = int(base_xp * current_r)

        new_r = round(new_r, 4)
        total_xp = current_xp + xp_earned

        if total_xp >= 3000:
            level = "Expert"
        elif total_xp >= 1000:
            level = "Senior Analyst"
        elif total_xp >= 250:
            level = "Analyst"
        else:
            level = "Novice"

        new_badges = []
        if total_tasks >= 20 and new_r >= 0.80 and "Fragment Hunter" not in badges:
            badges.append("Fragment Hunter")
            new_badges.append("Fragment Hunter")
        if gt_matches >= 10 and "Structure Detective" not in badges:
            badges.append("Structure Detective")
            new_badges.append("Structure Detective")
        if new_r >= 0.90 and total_tasks >= 25 and "Consensus Expert" not in badges:
            badges.append("Consensus Expert")
            new_badges.append("Consensus Expert")
        if fps == 0 and gt_tested >= 15 and "Precision Master" not in badges:
            badges.append("Precision Master")
            new_badges.append("Precision Master")
        if total_tasks >= 50 and "Anomaly Finder" not in badges:
            badges.append("Anomaly Finder")
            new_badges.append("Anomaly Finder")

        with conn:
            conn.execute("""
                UPDATE swarm_analysts
                SET reliability_score = ?, total_tasks_completed = ?, ground_truth_tested = ?,
                    ground_truth_matches = ?, false_positives = ?, false_negatives = ?,
                    avg_response_time_ms = ?, flagged_suspicious_count = ?, xp = ?,
                    level = ?, badges_json = ?, recent_answers_json = ?
                WHERE analyst_id = ?
            """, (
                new_r, total_tasks, gt_tested, gt_matches, fps, fns,
                new_avg_time, flagged_count, total_xp, level,
                json.dumps(badges), json.dumps(recent_answers), analyst_id
            ))

        return {
            "reliability_score": new_r,
            "xp_earned": xp_earned,
            "total_xp": total_xp,
            "level": level,
            "total_tasks": total_tasks,
            "new_badges": new_badges
        }
    finally:
        conn.close()

# ---------------------------------------------------------------------------
# Forensic Review Consensus Engine
# ---------------------------------------------------------------------------
def evaluate_candidate_consensus(candidate_id: str) -> Dict[str, Any]:
    """
    Calculate statistical weighted consensus for a candidate artifact across all completed reviews.
    """
    init_swarm_db()
    conn = sqlite3.connect(get_swarm_db_path())
    conn.row_factory = sqlite3.Row
    try:
        cand_row = conn.execute("SELECT * FROM swarm_candidates WHERE candidate_id = ?", (candidate_id,)).fetchone()
        if not cand_row:
            return {"error": f"Candidate {candidate_id} not found."}
        cand = dict(cand_row)

        sub_rows = conn.execute("""
            SELECT s.*, a.reliability_score, a.username
            FROM swarm_submissions s
            JOIN swarm_analysts a ON s.analyst_id = a.analyst_id OR s.analyst_id = a.username
            WHERE s.candidate_id = ? AND s.flagged_suspicious = 0
        """, (candidate_id,)).fetchall()

        total_reviews = len(sub_rows)
        if total_reviews == 0:
            return {
                "candidate_id": candidate_id,
                "consensus_status": CONSENSUS_PENDING,
                "dominant_decision": "PENDING",
                "agreement_ratio": 0.0,
                "disagreement_entropy": 0.0,
                "swarm_confidence": 0.0,
                "total_reviews": 0,
                "weighted_votes": {}
            }

        weighted_votes: Dict[str, float] = {}
        total_weight = 0.0
        reviewers_reliability_sum = 0.0

        for row in sub_rows:
            dec = row["decision"].strip().upper()
            r_score = float(row["reliability_score"])
            c_score = float(row["confidence"])
            weight = r_score * c_score
            weighted_votes[dec] = weighted_votes.get(dec, 0.0) + weight
            total_weight += weight
            reviewers_reliability_sum += r_score

        if total_weight <= 0:
            total_weight = 1.0

        dominant_decision = max(weighted_votes.keys(), key=lambda k: weighted_votes[k])
        dominant_weight = weighted_votes[dominant_decision]
        agreement_ratio = round(dominant_weight / total_weight, 4)

        disagreement_entropy = 0.0
        num_categories = len(weighted_votes)
        if num_categories > 1:
            for w in weighted_votes.values():
                p = w / total_weight
                if p > 0:
                    disagreement_entropy -= p * math.log2(p)
            max_ent = math.log2(num_categories)
            disagreement_entropy = round(disagreement_entropy / max_ent, 4) if max_ent > 0 else 0.0

        quorum_factor = min(1.0, reviewers_reliability_sum / 2.0)
        swarm_confidence = agreement_ratio * quorum_factor * (1.0 - 0.4 * disagreement_entropy) * 100.0
        swarm_confidence = round(max(0.0, min(100.0, swarm_confidence)), 1)

        if total_reviews < 3:
            consensus_status = CONSENSUS_PENDING
        elif agreement_ratio >= 0.85:
            consensus_status = CONSENSUS_HIGH_CONFIDENCE
        elif agreement_ratio >= 0.60:
            consensus_status = CONSENSUS_MODERATE
        elif dominant_decision in ("NOISE", "LIKELY_NOISE", "CORRUPTED"):
            consensus_status = CONSENSUS_REJECTED_NOISE
        else:
            consensus_status = CONSENSUS_AMBIGUOUS

        now = int(time.time())
        with conn:
            conn.execute("""
                INSERT OR REPLACE INTO swarm_consensus
                (candidate_id, case_id, evidence_id, consensus_status, dominant_decision,
                 agreement_ratio, disagreement_entropy, swarm_confidence, total_reviews,
                 weighted_votes_json, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                candidate_id, cand["case_id"], cand["evidence_id"], consensus_status,
                dominant_decision, agreement_ratio, disagreement_entropy, swarm_confidence,
                total_reviews, json.dumps({k: round(v, 3) for k, v in weighted_votes.items()}), now
            ))

            if consensus_status != CONSENSUS_PENDING:
                conn.execute("""
                    UPDATE swarm_candidates SET status = 'SWARM_TRIAGED' WHERE candidate_id = ?
                """, (candidate_id,))

        return {
            "candidate_id": candidate_id,
            "case_id": cand["case_id"],
            "evidence_id": cand["evidence_id"],
            "consensus_status": consensus_status,
            "dominant_decision": dominant_decision,
            "agreement_ratio": agreement_ratio,
            "disagreement_entropy": disagreement_entropy,
            "swarm_confidence": swarm_confidence,
            "total_reviews": total_reviews,
            "weighted_votes": {k: round(v, 3) for k, v in weighted_votes.items()}
        }
    finally:
        conn.close()

# ---------------------------------------------------------------------------
# Investigator Priority Queue
# ---------------------------------------------------------------------------
def compute_investigator_priority_score(
    automated_confidence: float,
    swarm_confidence: float,
    disagreement_entropy: float,
    format_type: str,
    dominant_decision: str
) -> float:
    """Calculate measurable priority score [0.0 - 100.0] for the Lead Investigator's queue."""
    format_weights = {
        "SQLITE": 1.25,
        "PDF": 1.20,
        "JPEG": 1.15,
        "PNG": 1.10,
        "ZIP": 1.10,
        "ELF": 1.05
    }
    fmt_mult = format_weights.get(format_type.upper(), 1.0)

    if dominant_decision.upper() in ("VALID", "VALID_ARTIFACT", "MATCH", "HIGH_PRIORITY"):
        base_score = 0.50 * swarm_confidence + 0.30 * (automated_confidence * 100.0) + 0.20 * 80.0
    elif dominant_decision.upper() in ("AMBIGUOUS", "SPLIT", "UNKNOWN"):
        base_score = 0.40 * swarm_confidence + 0.30 * (disagreement_entropy * 100.0) + 0.30 * 60.0
    else:
        base_score = 0.30 * swarm_confidence + 0.20 * (automated_confidence * 100.0)

    priority_score = min(100.0, base_score * fmt_mult)
    return round(priority_score, 1)

def get_investigator_priority_queue(case_id: Optional[str] = None, limit: int = 50) -> List[Dict[str, Any]]:
    """Retrieve ranked priority evidence queue for Lead Investigator."""
    init_swarm_db()
    conn = sqlite3.connect(get_swarm_db_path())
    conn.row_factory = sqlite3.Row
    try:
        query = """
            SELECT c.*, sc.consensus_status, sc.dominant_decision, sc.agreement_ratio,
                   sc.disagreement_entropy, sc.swarm_confidence, sc.total_reviews,
                   e.image_path, e.sha256_hash as evidence_sha256,
                   ir.final_verdict, ir.investigator_id, ir.timestamp as reviewed_timestamp
            FROM swarm_candidates c
            JOIN swarm_evidence e ON c.evidence_id = e.evidence_id
            LEFT JOIN swarm_consensus sc ON c.candidate_id = sc.candidate_id
            LEFT JOIN swarm_investigator_reviews ir ON c.candidate_id = ir.candidate_id
        """
        params = []
        if case_id:
            query += " WHERE c.case_id = ?"
            params.append(case_id)

        rows = conn.execute(query, params).fetchall()
        results = []

        for r in rows:
            cand = dict(r)
            sc_conf = float(cand.get("swarm_confidence") or 0.0)
            auto_conf = float(cand.get("automated_confidence") or 0.0)
            dis_ent = float(cand.get("disagreement_entropy") or 0.0)
            dom_dec = cand.get("dominant_decision") or "PENDING"
            fmt_type = cand.get("format_type") or "UNKNOWN"

            p_score = compute_investigator_priority_score(
                automated_confidence=auto_conf,
                swarm_confidence=sc_conf,
                disagreement_entropy=dis_ent,
                format_type=fmt_type,
                dominant_decision=dom_dec
            )

            cand["priority_score"] = p_score
            cand["structural_indicators"] = json.loads(cand.get("structural_indicators_json", "{}"))
            cand["fragment_relationships"] = json.loads(cand.get("fragment_relationships_json", "{}"))
            results.append(cand)

        results.sort(key=lambda x: (x.get("final_verdict") is None, x["priority_score"]), reverse=True)
        return results[:limit]
    finally:
        conn.close()

def submit_lead_investigator_verdict(
    candidate_id: str,
    investigator_id: str,
    final_verdict: str,
    evidentiary_value: str,
    notes: str = ""
) -> Dict[str, Any]:
    """Authoritative final determination by Lead Investigator."""
    init_swarm_db()
    conn = sqlite3.connect(get_swarm_db_path())
    conn.row_factory = sqlite3.Row
    try:
        cand_row = conn.execute("SELECT * FROM swarm_candidates WHERE candidate_id = ?", (candidate_id,)).fetchone()
        if not cand_row:
            return {"success": False, "error": f"Candidate {candidate_id} not found."}
        cand = dict(cand_row)

        review_id = f"REV-{secrets.token_hex(6).upper()}"
        now = int(time.time())

        sig_payload = f"{candidate_id}:{cand['evidence_id']}:{final_verdict}:{investigator_id}:{now}"
        digital_sig = hashlib.sha256(sig_payload.encode("utf-8")).hexdigest()

        with conn:
            conn.execute("""
                INSERT OR REPLACE INTO swarm_investigator_reviews
                (review_id, candidate_id, case_id, evidence_id, investigator_id,
                 final_verdict, evidentiary_value, notes, digital_signature, timestamp)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                review_id, candidate_id, cand["case_id"], cand["evidence_id"],
                investigator_id, final_verdict, evidentiary_value, notes,
                digital_sig, now
            ))

            conn.execute("""
                UPDATE swarm_candidates SET status = 'INVESTIGATOR_REVIEWED' WHERE candidate_id = ?
            """, (candidate_id,))

        record_swarm_audit_event(
            case_id=cand["case_id"],
            evidence_id=cand["evidence_id"],
            candidate_id=candidate_id,
            actor_id=investigator_id,
            actor_role="LEAD_INVESTIGATOR",
            action_type="INVESTIGATOR_FINAL_VERDICT",
            payload_digest=digital_sig,
            details={
                "verdict": final_verdict,
                "evidentiary_value": evidentiary_value,
                "notes": notes,
                "signature": digital_sig
            }
        )

        return {
            "success": True,
            "review_id": review_id,
            "candidate_id": candidate_id,
            "final_verdict": final_verdict,
            "evidentiary_value": evidentiary_value,
            "digital_signature": digital_sig,
            "timestamp": now
        }
    finally:
        conn.close()

# ---------------------------------------------------------------------------
# Cryptographic Audit Trail
# ---------------------------------------------------------------------------
def record_swarm_audit_event(
    case_id: str,
    evidence_id: str,
    actor_id: str,
    actor_role: str,
    action_type: str,
    payload_digest: str,
    details: Dict[str, Any],
    candidate_id: str = "",
    task_id: str = ""
) -> str:
    """Append a cryptographically chained audit log entry for swarm operations."""
    init_swarm_db()
    conn = sqlite3.connect(get_swarm_db_path())
    conn.row_factory = sqlite3.Row
    try:
        last_row = conn.execute("SELECT event_hash FROM swarm_audit_log ORDER BY timestamp DESC, ROWID DESC LIMIT 1").fetchone()
        prev_hash = last_row["event_hash"] if last_row else "GENESIS_SWARM_HASH_00000000000000000000000000000000"

        event_id = f"EVT-{secrets.token_hex(6).upper()}"
        now = int(time.time())
        details_json = json.dumps(details, sort_keys=True)

        chain_str = f"{event_id}|{prev_hash}|{now}|{case_id}|{evidence_id}|{candidate_id}|{task_id}|{actor_id}|{actor_role}|{action_type}|{payload_digest}|{details_json}"
        event_hash = hashlib.sha256(chain_str.encode("utf-8")).hexdigest()

        with conn:
            conn.execute("""
                INSERT INTO swarm_audit_log
                (event_id, prev_hash, event_hash, timestamp, case_id, evidence_id,
                 candidate_id, task_id, actor_id, actor_role, action_type, payload_digest, details_json)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                event_id, prev_hash, event_hash, now, case_id, evidence_id,
                candidate_id, task_id, actor_id, actor_role, action_type, payload_digest, details_json
            ))
        return event_id
    finally:
        conn.close()

def verify_swarm_audit_integrity() -> Tuple[bool, str, int]:
    """Verify cryptographic chain integrity of all swarm audit events."""
    init_swarm_db()
    conn = sqlite3.connect(get_swarm_db_path())
    conn.row_factory = sqlite3.Row
    try:
        rows = conn.execute("SELECT * FROM swarm_audit_log ORDER BY timestamp ASC, ROWID ASC").fetchall()
        if not rows:
            return True, "Audit log is empty.", 0

        expected_prev = "GENESIS_SWARM_HASH_00000000000000000000000000000000"
        for idx, r in enumerate(rows):
            if r["prev_hash"] != expected_prev:
                return False, f"Broken chain at event {r['event_id']} (Index {idx}). Prev hash mismatch.", idx

            chain_str = f"{r['event_id']}|{r['prev_hash']}|{r['timestamp']}|{r['case_id']}|{r['evidence_id']}|{r['candidate_id']}|{r['task_id']}|{r['actor_id']}|{r['actor_role']}|{r['action_type']}|{r['payload_digest']}|{r['details_json']}"
            computed_hash = hashlib.sha256(chain_str.encode("utf-8")).hexdigest()

            if computed_hash != r["event_hash"]:
                return False, f"Tampered event digest at event {r['event_id']} (Index {idx}).", idx

            expected_prev = r["event_hash"]

        return True, f"Cryptographic audit chain fully verified across {len(rows)} events.", len(rows)
    finally:
        conn.close()

def get_recent_audit_events(limit: int = 30) -> List[Dict[str, Any]]:
    """Retrieve recent cryptographic audit events for live operations monitoring."""
    init_swarm_db()
    conn = sqlite3.connect(get_swarm_db_path())
    conn.row_factory = sqlite3.Row
    try:
        rows = conn.execute("""
            SELECT event_id, prev_hash, event_hash, timestamp, case_id, evidence_id,
                   candidate_id, task_id, actor_id, actor_role, action_type, payload_digest, details_json
            FROM swarm_audit_log
            ORDER BY timestamp DESC, ROWID DESC
            LIMIT ?
        """, (limit,)).fetchall()
        
        events = []
        for r in rows:
            d = dict(r)
            try:
                d["details"] = json.loads(d.get("details_json", "{}"))
            except Exception:
                d["details"] = {}
            events.append(d)
        return events
    finally:
        conn.close()

# ---------------------------------------------------------------------------
# Dashboard Overview & Leaderboard Aggregations
# ---------------------------------------------------------------------------
def get_swarm_overview_metrics(case_id: Optional[str] = None) -> Dict[str, Any]:
    """Get aggregated metrics for the Swarm Triage Dashboard."""
    init_swarm_db()
    conn = sqlite3.connect(get_swarm_db_path())
    conn.row_factory = sqlite3.Row
    try:
        params = [case_id] if case_id else []
        where_cand = "WHERE case_id = ?" if case_id else ""

        # Evidence Source Metadata
        ev_query = "SELECT * FROM swarm_evidence ORDER BY created_at DESC LIMIT 1"
        ev_row = conn.execute(ev_query).fetchone()
        ev_count = conn.execute("SELECT COUNT(*) as cnt FROM swarm_evidence").fetchone()["cnt"]

        active_case = ev_row["case_id"] if ev_row else (case_id or "NO_CASE_LOADED")
        active_ev_id = ev_row["evidence_id"] if ev_row else "NONE"
        img_path = ev_row["image_path"] if ev_row else ""
        sha256 = ev_row["sha256_hash"] if ev_row else ""
        total_ev_bytes = ev_row["total_bytes"] if ev_row else 0

        total_candidates = conn.execute(f"SELECT COUNT(*) as cnt FROM swarm_candidates {where_cand}", params).fetchone()["cnt"]
        queued_candidates = conn.execute(f"SELECT COUNT(*) as cnt FROM swarm_candidates WHERE status = 'QUEUED_FOR_SWARM' {'AND case_id = ?' if case_id else ''}", params).fetchone()["cnt"]
        auto_classified = conn.execute(f"SELECT COUNT(*) as cnt FROM swarm_candidates WHERE status LIKE 'AUTOMATED_%' {'AND case_id = ?' if case_id else ''}", params).fetchone()["cnt"]
        triaged_candidates = conn.execute(f"SELECT COUNT(*) as cnt FROM swarm_candidates WHERE status = 'SWARM_TRIAGED' {'AND case_id = ?' if case_id else ''}", params).fetchone()["cnt"]
        reviewed_candidates = conn.execute(f"SELECT COUNT(*) as cnt FROM swarm_candidates WHERE status = 'INVESTIGATOR_REVIEWED' {'AND case_id = ?' if case_id else ''}", params).fetchone()["cnt"]

        total_tasks = conn.execute(f"SELECT COUNT(*) as cnt FROM swarm_tasks {where_cand}", params).fetchone()["cnt"]
        completed_submissions = conn.execute("SELECT COUNT(*) as cnt FROM swarm_submissions").fetchone()["cnt"]

        high_priority_count = conn.execute("""
            SELECT COUNT(*) as cnt FROM swarm_consensus
            WHERE consensus_status = 'HIGH_CONFIDENCE_TRIAGE'
        """).fetchone()["cnt"]

        disputed_count = conn.execute("""
            SELECT COUNT(*) as cnt FROM swarm_consensus
            WHERE consensus_status = 'AMBIGUOUS_SPLIT_REQUIRES_INVESTIGATOR'
        """).fetchone()["cnt"]

        return {
            "total_evidence_sources": ev_count,
            "active_case_id": active_case,
            "active_evidence_id": active_ev_id,
            "evidence_image_path": img_path,
            "evidence_sha256": sha256,
            "evidence_total_bytes": total_ev_bytes,
            "total_candidates": total_candidates,
            "auto_classified": auto_classified,
            "queued_for_swarm": queued_candidates,
            "swarm_triaged": triaged_candidates,
            "investigator_reviewed": reviewed_candidates,
            "pending_investigator_review": total_candidates - reviewed_candidates,
            "total_tasks_created": total_tasks,
            "total_submissions": completed_submissions,
            "high_priority_findings": high_priority_count,
            "disputed_findings": disputed_count
        }
    finally:
        conn.close()

def get_swarm_leaderboard(limit: int = 25) -> List[Dict[str, Any]]:
    """Retrieve gamified analyst leaderboard ordered by XP and accuracy."""
    init_swarm_db()
    conn = sqlite3.connect(get_swarm_db_path())
    conn.row_factory = sqlite3.Row
    try:
        rows = conn.execute("""
            SELECT analyst_id, username, role, reliability_score, total_tasks_completed,
                   ground_truth_tested, ground_truth_matches, xp, level, badges_json
            FROM swarm_analysts
            ORDER BY xp DESC, reliability_score DESC, total_tasks_completed DESC
            LIMIT ?
        """, (limit,)).fetchall()

        results = []
        for idx, r in enumerate(rows):
            d = dict(r)
            d["rank"] = idx + 1
            d["badges"] = json.loads(d.get("badges_json", "[]"))
            gt_tested = d.get("ground_truth_tested", 0)
            gt_matches = d.get("ground_truth_matches", 0)
            d["accuracy_pct"] = round((gt_matches / gt_tested * 100.0), 1) if gt_tested > 0 else round(d.get("reliability_score", 0.5) * 100.0, 1)
            results.append(d)
        return results
    finally:
        conn.close()

# ---------------------------------------------------------------------------
# Forensic Report Export
# ---------------------------------------------------------------------------
def generate_swarm_forensic_report(case_id: str) -> Dict[str, Any]:
    """
    Generate comprehensive Phase 8 forensic report clearly distinguishing:
    1. Automated Machine Findings
    2. Human Swarm Triage Consensus
    3. Lead Investigator Authoritative Determinations.
    """
    init_swarm_db()
    conn = sqlite3.connect(get_swarm_db_path())
    conn.row_factory = sqlite3.Row
    try:
        evidence_rows = conn.execute("SELECT * FROM swarm_evidence WHERE case_id = ?", (case_id,)).fetchall()
        candidate_rows = conn.execute("""
            SELECT c.*, sc.consensus_status, sc.dominant_decision, sc.agreement_ratio,
                   sc.swarm_confidence, sc.total_reviews,
                   ir.final_verdict, ir.evidentiary_value, ir.investigator_id, ir.notes as investigator_notes,
                   ir.digital_signature, ir.timestamp as verdict_timestamp
            FROM swarm_candidates c
            LEFT JOIN swarm_consensus sc ON c.candidate_id = sc.candidate_id
            LEFT JOIN swarm_investigator_reviews ir ON c.candidate_id = ir.candidate_id
            WHERE c.case_id = ?
        """, (case_id,)).fetchall()

        audit_ok, audit_msg, audit_count = verify_swarm_audit_integrity()

        report = {
            "report_title": f"SecureWipe Swarm-Carving Forensic Triage Report — Case {case_id}",
            "case_id": case_id,
            "generated_at": int(time.time()),
            "generated_iso": time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime()),
            "evidence_sources": [dict(e) for e in evidence_rows],
            "audit_trail_integrity": {
                "verified": audit_ok,
                "message": audit_msg,
                "event_count": audit_count
            },
            "summary_metrics": get_swarm_overview_metrics(case_id),
            "findings": []
        }

        for cr in candidate_rows:
            c = dict(cr)
            finding = {
                "candidate_id": c["candidate_id"],
                "evidence_id": c["evidence_id"],
                "traceability": {
                    "lba_start": c["lba_start"],
                    "byte_offset": c["byte_offset"],
                    "length_bytes": c["length_bytes"]
                },
                "automated_machine_finding": {
                    "format": c["format_type"],
                    "machine_confidence": c["automated_confidence"],
                    "entropy": c["entropy"],
                    "initial_status": c["status"]
                },
                "human_swarm_triage": {
                    "consensus_status": c.get("consensus_status", "NOT_TRIAGED"),
                    "dominant_decision": c.get("dominant_decision", "N/A"),
                    "agreement_ratio": c.get("agreement_ratio", 0.0),
                    "swarm_confidence": c.get("swarm_confidence", 0.0),
                    "total_reviews": c.get("total_reviews", 0)
                },
                "lead_investigator_determination": {
                    "is_reviewed": c.get("final_verdict") is not None,
                    "final_verdict": c.get("final_verdict", "PENDING_LEAD_INVESTIGATOR"),
                    "evidentiary_value": c.get("evidentiary_value", "UNASSESSED"),
                    "investigator_id": c.get("investigator_id", "N/A"),
                    "notes": c.get("investigator_notes", ""),
                    "digital_signature": c.get("digital_signature", ""),
                    "timestamp": c.get("verdict_timestamp")
                }
            }
            report["findings"].append(finding)

        return report
    finally:
        conn.close()
