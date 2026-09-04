import os
import math
import hashlib
from pathlib import Path
from typing import Dict, List, Any, Optional, Tuple

class FragmentRecoveryEngine:
    """
    Structure & Fragment Recovery Engine.
    Identifies candidate file fragments, analyzes entropy and block continuity,
    and scores fragment compatibility for reassembly.
    """

    def __init__(self, cluster_size: int = 4096):
        self.cluster_size = cluster_size

    @staticmethod
    def calculate_entropy(data: bytes) -> float:
        """
        Calculates Shannon entropy of a byte sequence (0.0 to 8.0).
        """
        if not data:
            return 0.0
        entropy = 0.0
        length = len(data)
        freq = {}
        for b in data:
            freq[b] = freq.get(b, 0) + 1

        for count in freq.values():
            p = count / length
            if p > 0:
                entropy -= p * math.log2(p)
        return entropy

    def analyze_fragment(self, data: bytes, offset: int = 0) -> Dict[str, Any]:
        """
        Extracts forensic features from a data fragment.
        """
        entropy = self.calculate_entropy(data)
        size = len(data)
        has_null_padding = data.endswith(b"\x00" * 64) if size >= 64 else False
        sha256 = hashlib.sha256(data).hexdigest()

        # Detect potential fragment type by content
        fragment_type = "generic_binary"
        if data.startswith(b"SQLite format 3\x00") or (len(data) >= 2 and data[0] in [0x02, 0x05, 0x0A, 0x0D]):
            fragment_type = "sqlite_candidate"
        elif data.startswith(b"\xFF\xD8\xFF") or b"\xFF\xD9" in data:
            fragment_type = "jpeg_candidate"
        elif entropy > 7.5:
            fragment_type = "compressed_or_encrypted"
        elif entropy < 2.0:
            fragment_type = "sparse_or_text"

        return {
            "offset": offset,
            "size": size,
            "entropy": round(entropy, 4),
            "fragment_type": fragment_type,
            "has_null_padding": has_null_padding,
            "sha256": sha256
        }

    def score_fragment_compatibility(self, frag_a: bytes, frag_b: bytes) -> Dict[str, Any]:
        """
        Scores compatibility between two adjacent candidate fragments.
        """
        entropy_a = self.calculate_entropy(frag_a)
        entropy_b = self.calculate_entropy(frag_b)
        entropy_diff = abs(entropy_a - entropy_b)

        # High entropy similarity implies matching compression/encryption or structure
        score = 100.0 - (entropy_diff * 15.0)

        # Penalty if boundary is completely discordant
        if len(frag_a) > 0 and len(frag_b) > 0:
            if frag_a[-1] == 0x00 and frag_b[0] != 0x00:
                score += 5.0  # Common in structured records

        score = max(0.0, min(100.0, score))
        confidence = "HIGH" if score > 75 else ("MEDIUM" if score > 45 else "LOW")

        return {
            "compatibility_score": round(score, 2),
            "confidence": confidence,
            "entropy_a": round(entropy_a, 4),
            "entropy_b": round(entropy_b, 4),
            "entropy_diff": round(entropy_diff, 4),
            "explanation": f"Statistical entropy differential is {round(entropy_diff, 3)} with compatibility score {round(score, 1)}%."
        }

    def reconstruct_fragments(self, fragments: List[bytes], output_path: Path) -> Dict[str, Any]:
        """
        Reconstructs an artifact from ordered compatible fragments and hashes result.
        """
        output_path.parent.mkdir(parents=True, exist_ok=True)
        reconstructed = b"".join(fragments)
        with open(output_path, "wb") as f:
            f.write(reconstructed)

        sha256 = hashlib.sha256(reconstructed).hexdigest()
        return {
            "output_path": str(output_path),
            "fragment_count": len(fragments),
            "total_size": len(reconstructed),
            "sha256": sha256,
            "status": "RECONSTRUCTED"
        }

# Singleton instance
fragment_recovery_engine = FragmentRecoveryEngine()
