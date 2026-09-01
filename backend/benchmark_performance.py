"""
SecureWipe Phase 3 — Forensic Engine Performance Benchmark
Measures MB/s scanning speed, RAM usage, throughput, and artifact rates.
"""

import os
import time
import tempfile
import resource

from forensic_carver import scan_disk_stream
from sanitization_verifier import verify_disk_sanitization


def run_benchmark():
    with tempfile.NamedTemporaryFile(suffix=".img", delete=False) as f:
        bench_file = f.name
        # Create 100 MiB synthetic drive container
        size_bytes = 100 * 1024 * 1024
        # Write 100MB containing embedded files and zeros
        f.write(b"\x00" * (size_bytes // 2))
        f.write(b"%PDF-1.5\n1 0 obj<</Type/Catalog>>endobj\nxref\n0 2\ntrailer<</Size 2/Root 1 0 R>>\nstartxref\n50\n%%EOF\n")
        f.write(b"\x00" * (size_bytes // 4))
        f.write(b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x02\x00\x00\x00\x02\x08\x06\x00\x00\x00\x1f\x15\xc4\x89\x00\x00\x00\x00IEND\xaeB`\x82")
        f.write(b"\x00" * (size_bytes - f.tell()))

    try:
        t0 = time.perf_counter()
        scan_res = scan_disk_stream(bench_file, size_bytes)
        t_scan = time.perf_counter() - t0

        t0_ver = time.perf_counter()
        ver_res = verify_disk_sanitization(bench_file, size_bytes, strategy="stratified")
        t_ver = time.perf_counter() - t0_ver

        ram_kb = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
        throughput_mbps = (size_bytes / (1024 * 1024)) / t_scan

        print(f"BENCHMARK RESULTS (100 MiB Container):")
        print(f"  - Scanned Bytes:          {scan_res['bytes_scanned'] / (1024*1024):.1f} MiB")
        print(f"  - Full Scan Time:         {t_scan:.3f} s")
        print(f"  - Scan Throughput:        {throughput_mbps:.1f} MB/s")
        print(f"  - Verification Time:      {t_ver:.3f} s (Stratified: {ver_res['verified_coverage_pct']}% coverage)")
        print(f"  - Peak RAM Usage:         {ram_kb / 1024:.1f} MB")
        print(f"  - Validated Artifacts:    {scan_res['counts']['level_3_validated_artifacts']}")
        print(f"  - Candidates Detected:    {scan_res['counts']['level_2_valid_candidates']}")
        print(f"  - Evidence Classification:{scan_res['evidence_level']}")
        print(f"  - Confidence Score:       {scan_res['confidence_score']}%")

    finally:
        if os.path.exists(bench_file):
            os.remove(bench_file)


if __name__ == "__main__":
    run_benchmark()
