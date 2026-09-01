"""
SecureWipe — Storage Inspector & Hex Viewer Test Suite
Verifies read-only safety, LBA address calculations, pattern analysis, and search.
"""

import os
import sys
import tempfile
import unittest

from storage_inspector import (
    read_storage_hex_sector,
    inspect_storage_metadata,
    compare_sector_diff,
    search_storage_stream,
    analyze_sector_patterns,
    calculate_shannon_entropy,
)


class TestStorageInspector(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.mkdtemp(prefix="inspector_test_")
        self.test_img = os.path.join(self.temp_dir, "test_drive.img")

        # Create a 2 MiB synthetic disk container (4096 sectors of 512B)
        self.sector_size = 512
        self.total_sectors = 4096
        self.total_bytes = self.sector_size * self.total_sectors

        with open(self.test_img, "wb") as f:
            # Sector 0: Synthetic MBR with partition type 0x83 and 0x55AA trailer
            mbr = bytearray(512)
            mbr[0:4] = b"\x33\xc0\x8e\xd0"
            mbr[446] = 0x80      # Bootable partition flag
            mbr[446 + 4] = 0x83  # Partition type (Linux native)
            mbr[510:512] = b"\x55\xaa"
            f.write(mbr)

            # Sector 1: GPT Header signature
            gpt = bytearray(512)
            gpt[0:8] = b"EFI PART"
            f.write(gpt)

            # Sector 2 to 2047: Zero-fill
            f.write(b"\x00" * (512 * 2046))

            # Sector 2048: Text message
            msg = b"SECUREWIPE_FORENSIC_INSPECTOR_READONLY_TEST_DATA"
            sec_2048 = msg + b"\x00" * (512 - len(msg))
            f.write(sec_2048)

            # Remaining sectors to 4095: High entropy random data
            f.write(os.urandom(self.total_bytes - f.tell()))

        # Record initial modification time and hash to prove read-only guarantee
        self.initial_mtime = os.path.getmtime(self.test_img)
        with open(self.test_img, "rb") as f:
            import hashlib
            self.initial_sha256 = hashlib.sha256(f.read()).hexdigest()

    def tearDown(self):
        import shutil
        if os.path.exists(self.temp_dir):
            shutil.rmtree(self.temp_dir, ignore_errors=True)

    # 1. Test Sector 0 (MBR) Reading & Formatting
    def test_01_read_sector_zero_mbr(self):
        res = read_storage_hex_sector(self.test_img, lba=0, sector_size=512)
        self.assertEqual(res["status"], "SUCCESS")
        self.assertEqual(res["lba"], 0)
        self.assertEqual(res["byte_offset"], 0)
        self.assertEqual(res["end_byte_offset"], 511)
        self.assertEqual(len(res["rows"]), 32)  # 512 / 16 = 32 rows
        self.assertEqual(res["analysis"]["detected_structure"], "MASTER_BOOT_RECORD (MBR)")

    # 2. Test Sector 1 (GPT Header)
    def test_02_read_sector_one_gpt(self):
        res = read_storage_hex_sector(self.test_img, lba=1, sector_size=512)
        self.assertEqual(res["status"], "SUCCESS")
        self.assertEqual(res["analysis"]["detected_structure"], "GUID_PARTITION_TABLE (GPT Header)")

    # 3. Test Zero-Fill Detection & Entropy
    def test_03_zero_fill_and_entropy_analysis(self):
        res = read_storage_hex_sector(self.test_img, lba=100, sector_size=512)
        self.assertEqual(res["status"], "SUCCESS")
        self.assertEqual(res["analysis"]["zero_percentage"], 100.0)
        self.assertEqual(res["analysis"]["entropy"], 0.0)
        self.assertEqual(res["analysis"]["pattern_type"], "ZERO_FILL")

    # 4. Test Last Addressable Sector
    def test_04_read_last_sector(self):
        last_lba = self.total_sectors - 1
        res = read_storage_hex_sector(self.test_img, lba=last_lba, sector_size=512)
        self.assertEqual(res["status"], "SUCCESS")
        self.assertEqual(res["lba"], last_lba)
        self.assertEqual(res["byte_offset"], last_lba * 512)

    # 5. Test Out-of-Bounds Rejection
    def test_05_out_of_bounds_rejection(self):
        res = read_storage_hex_sector(self.test_img, lba=99999, sector_size=512)
        self.assertIn(res["status"], ("OUT_OF_BOUNDS", "EOF"))

    # 6. Test In-Storage Text & Hex Search
    def test_06_in_storage_search(self):
        res = search_storage_stream(self.test_img, "SECUREWIPE_FORENSIC", query_type="text")
        self.assertEqual(res["status"], "SUCCESS")
        self.assertEqual(res["matches_found"], 1)
        match = res["matches"][0]
        self.assertEqual(match["lba"], 2048)
        self.assertEqual(match["offset"], 2048 * 512)

    # 7. Test Before vs After Sector Comparison
    def test_07_before_after_diff_comparison(self):
        before = "4D 5A 90 01 03 02 03 04 04 05 06 07 FF FF 08 09"
        after = "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00"
        diff = compare_sector_diff(before, after, lba=0, sector_size=512)
        self.assertEqual(diff["status"], "SUCCESS")
        self.assertEqual(diff["percentage_changed"], 100.0)
        self.assertEqual(diff["after"]["pattern_type"], "ZERO_FILL")

    # 8. CRITICAL SAFETY TEST: Verify Strict Read-Only Immutability
    def test_08_strict_read_only_immutability_guarantee(self):
        # Execute extensive inspection operations
        inspect_storage_metadata(self.test_img)
        for sec in [0, 1, 50, 100, 2048, 4095]:
            read_storage_hex_sector(self.test_img, lba=sec, sector_size=512)
        search_storage_stream(self.test_img, "TEST", query_type="text")

        # Verify modification time and SHA-256 hash are 100% identical (unmodified)
        current_mtime = os.path.getmtime(self.test_img)
        with open(self.test_img, "rb") as f:
            import hashlib
            current_sha256 = hashlib.sha256(f.read()).hexdigest()

        self.assertEqual(self.initial_sha256, current_sha256)
        self.assertEqual(self.initial_mtime, current_mtime)


if __name__ == "__main__":
    unittest.main()
