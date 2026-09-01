def correlate_fragments(page_a: dict, page_b: dict) -> tuple:
    """Evaluate structural correlation between two carved SQLite page fragments."""
    score = 0.0
    reasons = []

    # 1. Page Size Alignment (30%)
    if page_a.get("page_size") == page_b.get("page_size"):
        score += 30.0
        reasons.append(f"✓ Identical page size ({page_a.get('page_size')} bytes)")
        
        # Check page offset alignment
        offset_diff = abs(page_b.get("offset", 0) - page_a.get("offset", 0))
        if offset_diff % page_a.get("page_size") == 0:
            score += 20.0
            reasons.append(f"✓ Exact page grid alignment (stride: {offset_diff} bytes = {offset_diff // page_a.get('page_size')} pages)")

    # 2. RowID Continuity (25%)
    max_row_a = page_a.get("max_row_id", 0)
    min_row_b = page_b.get("min_row_id", 0)
    if max_row_a > 0 and min_row_b > 0:
        if page_b.get("offset", 0) > page_a.get("offset", 0) and min_row_b >= max_row_a:
            score += 25.0
            reasons.append(f"✓ Sequential RowID progression (Page A max: {max_row_a} -> Page B min: {min_row_b})")
        elif page_a.get("offset", 0) > page_b.get("offset", 0) and max_row_a >= min_row_b:
            score += 25.0
            reasons.append(f"✓ Sequential RowID progression (Page B -> Page A)")

    # 3. Record Schema Similarity (25%)
    cols_a = page_a.get("schema_signature", [])
    cols_b = page_b.get("schema_signature", [])
    if cols_a and cols_b:
        if cols_a == cols_b:
            score += 25.0
            reasons.append(f"✓ Identical record column signature: ({', '.join(cols_a)})")
        else:
            # Overlap similarity
            set_a, set_b = set(cols_a), set(cols_b)
            intersection = set_a.intersection(set_b)
            if intersection:
                overlap_ratio = len(intersection) / max(len(set_a), len(set_b))
                score += 15.0 * overlap_ratio
                reasons.append(f"✓ Compatible column subset: ({', '.join(list(intersection))})")

    final_score = min(100.0, max(0.0, round(score, 1)))
    return final_score, reasons
