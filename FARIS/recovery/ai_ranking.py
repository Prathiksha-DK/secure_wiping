import math
from typing import Dict, List, Any, Optional

class AIFragmentRanker:
    """
    AI/Statistical Fragment Ranking Engine.
    Evaluates and ranks candidate block fragments using deterministic local mathematical & forensic features:
    - Byte frequency distribution (Chi-square deviation)
    - Shannon entropy convergence
    - Structural sequence consistency (e.g. SQLite page headers, JPEG markers)
    - Boundary continuity & null-padding metrics
    Zero cloud dependencies, zero external network calls.
    """

    @staticmethod
    def _compute_chi_square_uniformity(data: bytes) -> float:
        """
        Calculates Chi-Square statistic against uniform distribution (0 = perfectly uniform/random, higher = structured).
        """
        if not data:
            return 0.0
        expected = len(data) / 256.0
        counts = [0] * 256
        for b in data:
            counts[b] += 1
        chi_sq = sum(((c - expected) ** 2) / expected for c in counts)
        return chi_sq

    @staticmethod
    def _calculate_entropy(data: bytes) -> float:
        if not data:
            return 0.0
        length = len(data)
        freq = {}
        for b in data:
            freq[b] = freq.get(b, 0) + 1
        return -sum((c / length) * math.log2(c / length) for c in freq.values() if c > 0)

    def rank_candidate_fragments(
        self,
        anchor_data: bytes,
        candidate_fragments: List[Dict[str, Any]],
        expected_type: str = "generic"
    ) -> List[Dict[str, Any]]:
        """
        Ranks a list of candidate next-fragments against an anchor fragment.
        Returns candidates ordered by descending forensic rank score with detailed explanations.
        """
        anchor_entropy = self._calculate_entropy(anchor_data)
        ranked = []

        for cand in candidate_fragments:
            data = cand.get("data", b"")
            offset = cand.get("offset", 0)
            cand_id = cand.get("id", f"frag_{offset}")

            cand_entropy = self._calculate_entropy(data)
            entropy_delta = abs(anchor_entropy - cand_entropy)

            # Feature 1: Entropy consistency (0 to 30 points)
            entropy_score = max(0.0, 30.0 - (entropy_delta * 10.0))

            # Feature 2: Chi-square structural resemblance (0 to 25 points)
            chi_score = min(25.0, self._compute_chi_square_uniformity(data) / 100.0)

            # Feature 3: Format-specific constraints (0 to 25 points)
            type_score = 10.0
            type_reasons = []

            if expected_type == "sqlite":
                # SQLite leaf page headers: 0x0A (leaf table), 0x0D (leaf index)
                if len(data) >= 8 and data[0] in [0x0A, 0x0D, 0x02, 0x05]:
                    type_score = 25.0
                    type_reasons.append("Valid SQLite B-Tree page flag detected at start of fragment.")
                elif len(data) >= 2 and data[:2] == b"\x00\x00":
                    type_score = 15.0
                    type_reasons.append("Zero-offset header matches interior page padding.")
            elif expected_type == "jpeg":
                if b"\xFF" in data:
                    type_score = 20.0
                    type_reasons.append("JPEG scan data markers found.")
            else:
                type_reasons.append("Generic binary structural heuristic evaluated.")

            # Feature 4: Boundary continuity (0 to 20 points)
            boundary_score = 10.0
            if len(anchor_data) > 0 and len(data) > 0:
                # Disallow sudden large byte jumps if both are text/structure
                if abs(anchor_data[-1] - data[0]) < 32:
                    boundary_score = 20.0

            total_score = min(100.0, entropy_score + chi_score + type_score + boundary_score)

            confidence = "HIGH" if total_score >= 70.0 else ("MEDIUM" if total_score >= 40.0 else "LOW")

            explanation = (
                f"Rank score {round(total_score, 1)}/100. "
                f"Entropy delta: {round(entropy_delta, 3)} (Score: {round(entropy_score, 1)}/30). "
                f"Chi-square structure: {round(chi_score, 1)}/25. "
                f"Boundary continuity: {round(boundary_score, 1)}/20. "
                + " ".join(type_reasons)
            )

            ranked.append({
                "id": cand_id,
                "offset": offset,
                "size": len(data),
                "rank_score": round(total_score, 2),
                "confidence": confidence,
                "entropy": round(cand_entropy, 4),
                "explanation": explanation
            })

        # Sort descending by rank score
        ranked.sort(key=lambda x: x["rank_score"], reverse=True)
        return ranked

# Singleton instance
ai_fragment_ranker = AIFragmentRanker()
