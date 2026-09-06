import os
import sys
import math
import hashlib
import tempfile
import unittest

from storage_inspector import (
    read_storage_hex_sector,
    inspect_storage_metadata,
    compare_sector_diff,
    search_storage_stream,
    search_filesystem_stream,
    unified_storage_search,
    get_file_details,
    analyze_sector_patterns,
    calculate_shannon_entropy,
    resolve_target_path,
    parse_fat32_bpb,
    read_fat32_cluster_chain,
    map_clusters_to_lba_extents,
    parse_fat32_directory_entries,
    get_file_storage_allocation,
    get_folder_storage_allocation,
    direct_fat32_folder_allocation,
)


class TestStorageInspector(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.mkdtemp(prefix="inspector_test_")
        self.test_img = os.path.join(self.temp_dir, "test_drive.img")
        self.fat32_img = os.path.join(self.temp_dir, "fat32_volume.img")

        # Create a 4 MiB synthetic disk container (8192 sectors of 512B)
        self.sector_size = 512
        self.total_sectors = 8192
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

            # Sector 2: NTFS VBR
            ntfs = bytearray(512)
            ntfs[0:3] = b"\xeb\x52\x90"
            ntfs[3:7] = b"NTFS"
            ntfs[510:512] = b"\x55\xaa"
            f.write(ntfs)

            # Sector 3: FAT32 VBR
            fat = bytearray(512)
            fat[0:3] = b"\xeb\x58\x90"
            fat[54:62] = b"FAT32   "
            fat[510:512] = b"\x55\xaa"
            f.write(fat)

            # Sector 4 & 5: Ext4 Superblock (Offset 1024 has 0xEF53 at byte 56)
            ext4_block = bytearray(1024)
            ext4_block[56:58] = b"\x53\xef"
            f.write(ext4_block)

            # Sector 6 to 100: Zero-fill (0x00)
            f.write(b"\x00" * (512 * 95))

            # Sector 101 to 150: One-fill (0xFF)
            f.write(b"\xff" * (512 * 50))

            # Sector 151 to 200: ECE 96-fill (0x96)
            f.write(b"\x96" * (512 * 50))

            # Pad to Sector 2048
            cur = f.tell()
            pad_needed = 2048 * 512 - cur
            if pad_needed > 0:
                f.write(b"\x00" * pad_needed)

            # Sector 2048: Text message
            msg = b"SECUREWIPE_FORENSIC_INSPECTOR_READONLY_TEST_DATA"
            sec_2048 = msg + b"\x00" * (512 - len(msg))
            f.write(sec_2048)

            # Remaining sectors: CSPRNG Random data
            remaining = self.total_bytes - f.tell()
            if remaining > 0:
                f.write(os.urandom(remaining))

        # Build fully functional synthetic FAT32 filesystem volume image
        import struct
        with open(self.fat32_img, "wb") as f:
            # Sector 0: FAT32 BPB Boot Sector
            bpb_raw = bytearray(512)
            bpb_raw[0:3] = b"\xeb\x58\x90"
            bpb_raw[3:11] = b"MSWIN4.1"
            struct.pack_into("<H", bpb_raw, 0x0B, 512)    # bytes per sector
            bpb_raw[0x0D] = 8                             # sectors per cluster (4096 B)
            struct.pack_into("<H", bpb_raw, 0x0E, 32)     # reserved sectors
            bpb_raw[0x10] = 2                             # number of FATs
            struct.pack_into("<H", bpb_raw, 0x11, 0)      # root entries (0 for FAT32)
            struct.pack_into("<H", bpb_raw, 0x13, 0)      # total sectors 16 (0 for FAT32)
            bpb_raw[0x15] = 0xF8                          # media descriptor
            struct.pack_into("<H", bpb_raw, 0x16, 0)      # FAT size 16 (0 for FAT32)
            struct.pack_into("<I", bpb_raw, 0x20, 4096)   # total sectors 32
            struct.pack_into("<I", bpb_raw, 0x24, 32)     # FAT size 32 (32 sectors per FAT)
            struct.pack_into("<I", bpb_raw, 0x2C, 2)      # root cluster (Cluster 2)
            bpb_raw[0x42] = 0x29                          # boot sig
            bpb_raw[0x47:0x52] = b"TESTFAT32  "
            bpb_raw[0x52:0x5A] = b"FAT32   "
            bpb_raw[510:512] = b"\x55\xaa"
            f.write(bpb_raw)

            # Reserved sectors 1..31 (pad to Sector 32)
            f.write(b"\x00" * (512 * 31))

            # FAT1 Table (Sectors 32..63 -> 32 sectors = 16,384 bytes)
            fat_table = bytearray(32 * 512)
            # Cluster 0: Media descriptor
            struct.pack_into("<I", fat_table, 0 * 4, 0x0FFFFFF8)
            # Cluster 1: Clean shutdown bit
            struct.pack_into("<I", fat_table, 1 * 4, 0x0FFFFFFF)
            # Cluster 2 (Root Directory): EOC
            struct.pack_into("<I", fat_table, 2 * 4, 0x0FFFFFFF)
            # Cluster 3 (README.TXT Part 1) -> Cluster 4
            struct.pack_into("<I", fat_table, 3 * 4, 4)
            # Cluster 4 (README.TXT Part 2) -> EOC
            struct.pack_into("<I", fat_table, 4 * 4, 0x0FFFFFFF)
            # Cluster 5 (LOGDATA.BIN Part 1) -> Cluster 7 (Fragmented jump)
            struct.pack_into("<I", fat_table, 5 * 4, 7)
            # Cluster 6 (Free) -> 0
            struct.pack_into("<I", fat_table, 6 * 4, 0)
            # Cluster 7 (LOGDATA.BIN Part 2) -> EOC
            struct.pack_into("<I", fat_table, 7 * 4, 0x0FFFFFFF)

            f.write(fat_table)

            # FAT2 Table (Sectors 64..95 -> Mirror of FAT1)
            f.write(fat_table)

            # Data Area starts at Sector 96 (Cluster 2)
            # Cluster 2 (LBA 96..103, 4096 bytes): Root Directory Entries
            root_dir_data = bytearray(4096)

            # Directory Entry 0: README.TXT (Short 32-byte entry)
            # Name: "README  TXT", attr: 0x20 (Archive), Start Clus: 3, Size: 6000
            root_dir_data[0:11] = b"README  TXT"
            root_dir_data[11] = 0x20
            struct.pack_into("<H", root_dir_data, 0x14, 0)     # FstClusHI = 0
            struct.pack_into("<H", root_dir_data, 0x1A, 3)     # FstClusLO = 3
            struct.pack_into("<I", root_dir_data, 0x1C, 6000)  # FileSize = 6000

            # Directory Entry 1: LOGDATA.BIN (Short 32-byte entry)
            # Name: "LOGDATA BIN", attr: 0x20 (Archive), Start Clus: 5, Size: 5000
            root_dir_data[32:43] = b"LOGDATA BIN"
            root_dir_data[43] = 0x20
            struct.pack_into("<H", root_dir_data, 32 + 0x14, 0)     # FstClusHI = 0
            struct.pack_into("<H", root_dir_data, 32 + 0x1A, 5)     # FstClusLO = 5
            struct.pack_into("<I", root_dir_data, 32 + 0x1C, 5000)  # FileSize = 5000

            f.write(root_dir_data)

            # Cluster 3 (LBA 104..111, 4096 bytes): README.TXT Cluster 1
            clus3_data = b"SECUREWIPE_FAT32_README_PART1_DATA_" + b"A" * (4096 - 35)
            f.write(clus3_data)

            # Cluster 4 (LBA 112..119, 4096 bytes): README.TXT Cluster 2 (remaining 1904 bytes + pad)
            clus4_data = b"SECUREWIPE_FAT32_README_PART2_DATA_" + b"B" * (1904 - 35) + b"\x00" * (4096 - 1904)
            f.write(clus4_data)

            # Cluster 5 (LBA 120..127, 4096 bytes): LOGDATA.BIN Cluster 1
            clus5_data = b"SECUREWIPE_FRAGMENTED_LOG_PART1_DATA" + b"C" * (4096 - 36)
            f.write(clus5_data)

            # Cluster 6 (LBA 128..135, 4096 bytes): Free cluster / gap
            f.write(b"\x00" * 4096)

            # Cluster 7 (LBA 136..143, 4096 bytes): LOGDATA.BIN Cluster 2 (remaining 904 bytes + pad)
            clus7_data = b"SECUREWIPE_FRAGMENTED_LOG_PART2_DATA" + b"D" * (904 - 36) + b"\x00" * (4096 - 904)
            f.write(clus7_data)

            # Pad to 4096 sectors total
            written_bytes = f.tell()
            pad_total = (4096 * 512) - written_bytes
            if pad_total > 0:
                f.write(b"\x00" * pad_total)

        # Record initial modification time and hash to prove read-only guarantee
        self.initial_mtime = os.path.getmtime(self.test_img)
        with open(self.test_img, "rb") as f:
            self.initial_sha256 = hashlib.sha256(f.read()).hexdigest()

        self.fat32_initial_mtime = os.path.getmtime(self.fat32_img)
        with open(self.fat32_img, "rb") as f:
            self.fat32_initial_sha256 = hashlib.sha256(f.read()).hexdigest()

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
        self.assertTrue("sha256" in res)
        self.assertEqual(len(res["sha256"]), 64)

    # 2. Test Sector 1 (GPT Header)
    def test_02_read_sector_one_gpt(self):
        res = read_storage_hex_sector(self.test_img, lba=1, sector_size=512)
        self.assertEqual(res["status"], "SUCCESS")
        self.assertEqual(res["analysis"]["detected_structure"], "GUID_PARTITION_TABLE (GPT Header)")

    # 3. Test Sector 2 (NTFS VBR)
    def test_03_read_sector_ntfs(self):
        res = read_storage_hex_sector(self.test_img, lba=2, sector_size=512)
        self.assertEqual(res["status"], "SUCCESS")
        self.assertEqual(res["analysis"]["detected_structure"], "NTFS_VOLUME_BOOT_RECORD")

    # 4. Test Sector 3 (FAT32 VBR)
    def test_04_read_sector_fat32(self):
        res = read_storage_hex_sector(self.test_img, lba=3, sector_size=512)
        self.assertEqual(res["status"], "SUCCESS")
        self.assertEqual(res["analysis"]["detected_structure"], "FAT_VOLUME_BOOT_RECORD")

    # 5. Test Sector 4 (Ext4 Superblock)
    def test_05_read_sector_ext4(self):
        res = read_storage_hex_sector(self.test_img, lba=4, sector_size=512, sector_count=2)
        self.assertEqual(res["status"], "SUCCESS")
        self.assertEqual(res["analysis"]["detected_structure"], "EXT4_SUPERBLOCK")

    # 6. Test Zero-Fill Detection & Entropy
    def test_06_zero_fill_and_entropy_analysis(self):
        res = read_storage_hex_sector(self.test_img, lba=50, sector_size=512)
        self.assertEqual(res["status"], "SUCCESS")
        self.assertEqual(res["analysis"]["zero_percentage"], 100.0)
        self.assertEqual(res["analysis"]["entropy"], 0.0)
        self.assertEqual(res["analysis"]["pattern_type"], "ZERO_FILL")
        self.assertEqual(res["analysis"]["sanitization_inspection"]["match_percentage"], 100.0)

    # 7. Test One-Fill (0xFF) Detection
    def test_07_one_fill_detection(self):
        res = read_storage_hex_sector(self.test_img, lba=120, sector_size=512)
        self.assertEqual(res["status"], "SUCCESS")
        self.assertEqual(res["analysis"]["ff_percentage"], 100.0)
        self.assertEqual(res["analysis"]["pattern_type"], "ONE_FILL")

    # 8. Test ECE 96-Fill Detection
    def test_08_ece_96_fill_detection(self):
        res = read_storage_hex_sector(self.test_img, lba=160, sector_size=512)
        self.assertEqual(res["status"], "SUCCESS")
        self.assertEqual(res["analysis"]["pattern_type"], "ECE_96_FILL")

    # 9. Test High Entropy CSPRNG Random Sector Detection
    def test_09_high_entropy_random_detection(self):
        res = read_storage_hex_sector(self.test_img, lba=3000, sector_size=512)
        self.assertEqual(res["status"], "SUCCESS")
        self.assertGreaterEqual(res["analysis"]["entropy"], 7.4)
        self.assertEqual(res["analysis"]["pattern_type"], "HIGH_ENTROPY_RANDOM")

    # 10. Test Live Sector SHA-256 Verification
    def test_10_live_sector_sha256(self):
        res = read_storage_hex_sector(self.test_img, lba=2048, sector_size=512)
        self.assertEqual(res["status"], "SUCCESS")
        with open(self.test_img, "rb") as f:
            f.seek(2048 * 512)
            expected_hash = hashlib.sha256(f.read(512)).hexdigest()
        self.assertEqual(res["sha256"], expected_hash)

    # 11. Test Path Resolution on Various Formats
    def test_11_path_resolution(self):
        # File path
        p, name, hints = resolve_target_path(self.test_img)
        self.assertEqual(os.path.abspath(p), os.path.abspath(self.test_img))
        self.assertEqual(hints.get("type"), "file")

        if sys.platform.startswith("win"):
            # Windows drive letter
            p_vol, _, hints_vol = resolve_target_path("E:")
            self.assertEqual(p_vol, r"\\.\E:")
            self.assertEqual(hints_vol.get("type"), "volume")

            # Physical drive
            p_pd, _, hints_pd = resolve_target_path("PhysicalDrive0")
            self.assertEqual(p_pd, r"\\.\PhysicalDrive0")
            self.assertEqual(hints_pd.get("type"), "disk")

            # Linux style device on Windows
            p_sd, _, hints_sd = resolve_target_path("/dev/sda")
            self.assertEqual(p_sd, r"\\.\PhysicalDrive0")

    # 12. Test In-Storage Text & Hex Search
    def test_12_in_storage_search(self):
        res = search_storage_stream(self.test_img, "SECUREWIPE_FORENSIC", query_type="text")
        self.assertEqual(res["status"], "SUCCESS")
        self.assertGreaterEqual(res["matches_found"], 1)
        match = res["matches"][0]
        self.assertEqual(match["lba"], 2048)
        self.assertEqual(match["offset"], 2048 * 512)

        # Hex search
        hex_pattern = b"SECUREWIPE".hex()
        res_hex = search_storage_stream(self.test_img, hex_pattern, query_type="hex")
        self.assertEqual(res_hex["status"], "SUCCESS")
        self.assertGreaterEqual(res_hex["matches_found"], 1)

    # 13. Test Before vs After Sector Comparison
    def test_13_before_after_diff_comparison(self):
        before = "4D 5A 90 01 03 02 03 04 04 05 06 07 FF FF 08 09"
        after = "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00"
        diff = compare_sector_diff(before, after, lba=0, sector_size=512)
        self.assertEqual(diff["status"], "SUCCESS")
        self.assertEqual(diff["percentage_changed"], 100.0)
        self.assertEqual(diff["after"]["pattern_type"], "ZERO_FILL")

    # 14. Test Metadata Inspection Schema & Calculations
    def test_14_metadata_inspection(self):
        meta = inspect_storage_metadata(self.test_img)
        self.assertEqual(meta["exists"], True)
        self.assertEqual(meta["target_type"], "file")
        self.assertEqual(meta["physical_identity"]["total_sectors"], self.total_sectors)
        self.assertEqual(meta["physical_identity"]["capacity_bytes"], self.total_bytes)
    # 15. CRITICAL SAFETY TEST: Verify Strict Read-Only Immutability
    def test_15_strict_read_only_immutability_guarantee(self):
        # Execute extensive inspection operations
        inspect_storage_metadata(self.test_img)
        for sec in [0, 1, 2, 3, 4, 50, 100, 120, 160, 2048, 4095, 8191]:
            read_storage_hex_sector(self.test_img, lba=sec, sector_size=512)
        search_storage_stream(self.test_img, "SECUREWIPE", query_type="text")
        search_storage_stream(self.test_img, "53EF", query_type="hex")

        # Verify modification time and SHA-256 hash are 100% identical (unmodified)
        current_mtime = os.path.getmtime(self.test_img)
        with open(self.test_img, "rb") as f:
            current_sha256 = hashlib.sha256(f.read()).hexdigest()

        self.assertEqual(self.initial_sha256, current_sha256)
        self.assertEqual(self.initial_mtime, current_mtime)

    # 16. Test Entropy Mathematical Edge Cases
    def test_16_entropy_edge_cases(self):
        # 1 symbol: entropy = 0.0
        self.assertEqual(calculate_shannon_entropy(b"\x42" * 512), 0.0)

        # 2 equally likely symbols: entropy = 1.0
        self.assertEqual(calculate_shannon_entropy(b"\x00\xff" * 256), 1.0)

        # 4 equally likely symbols: entropy = 2.0
        self.assertEqual(calculate_shannon_entropy(b"\x00\x01\x02\x03" * 128), 2.0)

        # 256 equally likely unique symbols: entropy = 8.0
        self.assertEqual(calculate_shannon_entropy(bytes(range(256)) * 4), 8.0)

        # 512B random sector entropy >= 7.4
        for _ in range(20):
            ent = calculate_shannon_entropy(os.urandom(512))
            self.assertGreaterEqual(ent, 7.4)

    # 17. Test Forensic Export Certificate Integrity Signature
    def test_17_export_report_schema_and_sha256(self):
        meta = inspect_storage_metadata(self.test_img)
        sec_res = read_storage_hex_sector(self.test_img, lba=0, sector_size=512)

        report_payload = {
            "session_id": "INSPECT-TEST-001",
            "target": self.test_img,
            "metadata": meta,
            "inspected_lba": 0,
            "sector_size": 512,
            "analysis": sec_res["analysis"],
            "read_only_verified": True,
            "disclaimer": "Forensic read-only inspection certificate generated by SecureWipe Storage Inspector.",
        }
        import json
        payload_bytes = json.dumps(report_payload, sort_keys=True).encode()
        sig = hashlib.sha256(payload_bytes).hexdigest()
        self.assertEqual(len(sig), 64)
        report_payload["sha256_digest"] = sig
        self.assertTrue(report_payload["read_only_verified"])

    # 18. Test Friendly Name Resolution on Windows
    def test_18_friendly_name_device_resolution(self):
        if sys.platform.startswith("win"):
            # If real disks exist on the host, test resolution
            from devices import list_devices
            devs = list_devices()
            if devs:
                first_dev = devs[0]
                p, name, hints = resolve_target_path(first_dev["name"])
                self.assertTrue(p.startswith(r"\\.\PhysicalDrive"))
                self.assertEqual(hints.get("type"), "disk")

    # 20. Test Filesystem Search: Folder Name Match
    def test_20_filesystem_search_folder_name(self):
        fs_dir = os.path.join(self.temp_dir, "fs_root")
        secret_dir = os.path.join(fs_dir, "SecretFolder", "NestedSubFolder")
        os.makedirs(secret_dir, exist_ok=True)

        res = search_filesystem_stream(fs_dir, "SecretFolder", search_content=False)
        self.assertEqual(res["status"], "SUCCESS")
        self.assertGreaterEqual(res["matches_found"], 1)
        match = res["matches"][0]
        self.assertEqual(match["type"], "folder")
        self.assertEqual(match["match_type"], "folder_name")
        self.assertEqual(match["name"], "SecretFolder")

        res_nested = search_filesystem_stream(fs_dir, "NestedSubFolder", search_content=False)
        self.assertEqual(res_nested["status"], "SUCCESS")
        self.assertGreaterEqual(res_nested["matches_found"], 1)
        self.assertEqual(res_nested["matches"][0]["name"], "NestedSubFolder")

    # 21. Test Filesystem Search: File Name Match
    def test_21_filesystem_search_file_name(self):
        fs_dir = os.path.join(self.temp_dir, "fs_root_files")
        os.makedirs(fs_dir, exist_ok=True)
        sample_file = os.path.join(fs_dir, "classified_evidence_log.txt")
        with open(sample_file, "w", encoding="utf-8") as f:
            f.write("Just an evidence log.")

        res = search_filesystem_stream(fs_dir, "classified_evidence", search_content=False)
        self.assertEqual(res["status"], "SUCCESS")
        self.assertGreaterEqual(res["matches_found"], 1)
        match = res["matches"][0]
        self.assertEqual(match["type"], "file")
        self.assertEqual(match["match_type"], "file_name")
        self.assertEqual(match["name"], "classified_evidence_log.txt")
        self.assertEqual(match["extension"], ".txt")

    # 22. Test Filesystem Search: Full Path Substring Match
    def test_22_filesystem_search_full_path(self):
        fs_dir = os.path.join(self.temp_dir, "fs_path_test")
        sub_dir = os.path.join(fs_dir, "ProjectAlpha", "SubModule")
        os.makedirs(sub_dir, exist_ok=True)
        fpath = os.path.join(sub_dir, "spec.json")
        with open(fpath, "w", encoding="utf-8") as f:
            f.write("{}")

        res = search_filesystem_stream(fs_dir, "ProjectAlpha", search_content=False)
        self.assertEqual(res["status"], "SUCCESS")
        self.assertGreaterEqual(res["matches_found"], 1)

    # 23. Test Filesystem Search: ASCII Text Content Match with Snippet
    def test_23_filesystem_search_text_content_ascii(self):
        fs_dir = os.path.join(self.temp_dir, "fs_text_content")
        os.makedirs(fs_dir, exist_ok=True)
        doc_path = os.path.join(fs_dir, "clearance.txt")
        with open(doc_path, "w", encoding="utf-8") as f:
            f.write("Line 1: Header\nLine 2: TOP_SECRET_CLEARANCE_KEY_7749\nLine 3: Footer\n")

        res = search_filesystem_stream(fs_dir, "CLEARANCE_KEY_7749", search_content=True)
        self.assertEqual(res["status"], "SUCCESS")
        self.assertGreaterEqual(res["matches_found"], 1)
        content_match = [m for m in res["matches"] if m.get("match_type") == "file_content"]
        self.assertTrue(len(content_match) > 0)
        self.assertEqual(content_match[0]["name"], "clearance.txt")
        self.assertIn("CLEARANCE_KEY_7749", content_match[0]["snippet"])
        self.assertEqual(content_match[0]["line_number"], 2)

    # 24. Test Filesystem Search: UTF-8 International Text Content
    def test_24_filesystem_search_text_content_utf8(self):
        fs_dir = os.path.join(self.temp_dir, "fs_utf8_content")
        os.makedirs(fs_dir, exist_ok=True)
        doc_path = os.path.join(fs_dir, "intl_audit.txt")
        with open(doc_path, "w", encoding="utf-8") as f:
            f.write("Rapport d'effacement sécurisé — 削除レポート — 世界")

        res_fr = search_filesystem_stream(fs_dir, "sécurisé", search_content=True)
        self.assertEqual(res_fr["status"], "SUCCESS")
        self.assertGreaterEqual(res_fr["matches_found"], 1)

        res_jp = search_filesystem_stream(fs_dir, "削除レポート", search_content=True)
        self.assertEqual(res_jp["status"], "SUCCESS")
        self.assertGreaterEqual(res_jp["matches_found"], 1)

    # 25. Test Filesystem Search: Multiple Matches Across Tree
    def test_25_filesystem_search_multiple_matches(self):
        fs_dir = os.path.join(self.temp_dir, "fs_multi")
        os.makedirs(os.path.join(fs_dir, "dir1"), exist_ok=True)
        os.makedirs(os.path.join(fs_dir, "dir2"), exist_ok=True)
        with open(os.path.join(fs_dir, "dir1", "file_alpha.txt"), "w") as f:
            f.write("target_identifier present")
        with open(os.path.join(fs_dir, "dir2", "file_beta.txt"), "w") as f:
            f.write("target_identifier also present")

        res = search_filesystem_stream(fs_dir, "target_identifier", search_content=True)
        self.assertEqual(res["status"], "SUCCESS")
        self.assertGreaterEqual(res["matches_found"], 2)

    # 26. Test Filesystem Search: Binary File Safety
    def test_26_filesystem_search_binary_file_safety(self):
        fs_dir = os.path.join(self.temp_dir, "fs_binary")
        os.makedirs(fs_dir, exist_ok=True)
        bin_path = os.path.join(fs_dir, "binary_blob.dat")
        with open(bin_path, "wb") as f:
            f.write(bytes(range(256)) * 10)

        # Should not crash on binary data, handles gracefully
        res = search_filesystem_stream(fs_dir, "nonexistent_term", search_content=True)
        self.assertEqual(res["status"], "SUCCESS")
        self.assertEqual(res["matches_found"], 0)

    # 27. Test Filesystem Search: Empty Directory
    def test_27_filesystem_search_empty_directory(self):
        empty_dir = os.path.join(self.temp_dir, "empty_dir")
        os.makedirs(empty_dir, exist_ok=True)
        res = search_filesystem_stream(empty_dir, "anything", search_content=True)
        self.assertEqual(res["status"], "SUCCESS")
        self.assertEqual(res["matches_found"], 0)

    # 28. Test Unified Storage Search Modes (both / filesystem / raw)
    def test_28_unified_storage_search_modes(self):
        fs_dir = os.path.join(self.temp_dir, "fs_unified")
        os.makedirs(fs_dir, exist_ok=True)
        test_file = os.path.join(fs_dir, "token.txt")
        with open(test_file, "w", encoding="utf-8") as f:
            f.write("UNIFIED_SEARCH_TOKEN_123")

        # Filesystem only
        res_fs = unified_storage_search(fs_dir, "UNIFIED_SEARCH_TOKEN", search_mode="filesystem")
        self.assertEqual(res_fs["status"], "SUCCESS")
        self.assertGreaterEqual(res_fs["filesystem_matches_count"], 1)
        self.assertEqual(res_fs["raw_matches_count"], 0)

        # Raw only on test_img
        res_raw = unified_storage_search(self.test_img, "SECUREWIPE", search_mode="raw")
        self.assertEqual(res_raw["status"], "SUCCESS")
        self.assertEqual(res_raw["filesystem_matches_count"], 0)
        self.assertGreaterEqual(res_raw["raw_matches_count"], 1)

        # Both mode
        res_both = unified_storage_search(fs_dir, "UNIFIED_SEARCH_TOKEN", search_mode="both")
        self.assertEqual(res_both["status"], "SUCCESS")
        self.assertGreaterEqual(res_both["total_matches"], 1)

    # 29. Test get_file_details: Metadata, Preview and Live SHA-256
    def test_29_get_file_details_metadata_and_sha256(self):
        test_file = os.path.join(self.temp_dir, "details_test.txt")
        file_content = "Read-only forensic inspection details test data."
        with open(test_file, "w", encoding="utf-8") as f:
            f.write(file_content)

        expected_hash = hashlib.sha256(file_content.encode("utf-8")).hexdigest()

        # Without hash
        details = get_file_details(test_file, compute_hash=False)
        self.assertEqual(details["status"], "SUCCESS")
        self.assertEqual(details["name"], "details_test.txt")
        self.assertEqual(details["type"], "file")
        self.assertEqual(details["extension"], ".txt")
        self.assertTrue(details["is_text"])
        self.assertEqual(details["text_preview"], file_content)
        self.assertIsNone(details["sha256"])

        # With on-demand hash
        details_hashed = get_file_details(test_file, compute_hash=True)
        self.assertEqual(details_hashed["sha256"], expected_hash)

        # Directory details
        dir_details = get_file_details(self.temp_dir, compute_hash=False)
        self.assertEqual(dir_details["status"], "SUCCESS")
        self.assertEqual(dir_details["type"], "folder")

    # 30. CRITICAL SAFETY TEST: Filesystem Search Strict Read-Only Immutability
    def test_30_filesystem_strict_read_only_immutability(self):
        fs_dir = os.path.join(self.temp_dir, "fs_safety_test")
        os.makedirs(fs_dir, exist_ok=True)
        test_file = os.path.join(fs_dir, "immutable_doc.txt")
        with open(test_file, "w", encoding="utf-8") as f:
            f.write("Original content that must remain untouched.")

        initial_mtime = os.path.getmtime(test_file)
        with open(test_file, "rb") as f:
            initial_sha = hashlib.sha256(f.read()).hexdigest()

        # Run multiple filesystem search and file-detail operations
        search_filesystem_stream(fs_dir, "immutable", search_content=True)
        search_filesystem_stream(fs_dir, "Original content", search_content=True)
        get_file_details(test_file, compute_hash=True)
        get_file_details(fs_dir, compute_hash=False)
        unified_storage_search(fs_dir, "immutable", search_mode="both")

        # Verify nothing changed
        final_mtime = os.path.getmtime(test_file)
        with open(test_file, "rb") as f:
            final_sha = hashlib.sha256(f.read()).hexdigest()

        self.assertEqual(initial_sha, final_sha)
        self.assertEqual(initial_mtime, final_mtime)

    # 31. Test FAT32 BPB Boot Sector Parser
    def test_31_fat32_bpb_parser(self):
        with open(self.fat32_img, "rb") as f:
            boot_sector = f.read(512)
        bpb = parse_fat32_bpb(boot_sector)
        self.assertIsNotNone(bpb)
        self.assertEqual(bpb["bytes_per_sector"], 512)
        self.assertEqual(bpb["sectors_per_cluster"], 8)
        self.assertEqual(bpb["cluster_size_bytes"], 4096)
        self.assertEqual(bpb["reserved_sectors"], 32)
        self.assertEqual(bpb["num_fats"], 2)
        self.assertEqual(bpb["fat_size_sectors"], 32)
        self.assertEqual(bpb["root_cluster"], 2)
        # First data sector = 32 + (2 * 32) = 96
        self.assertEqual(bpb["first_data_sector"], 96)

    # 32. Test FAT32 Directory Entries Parsing & Starting Cluster Identification
    def test_32_fat32_directory_entries_parsing(self):
        with open(self.fat32_img, "rb") as f:
            boot_sector = f.read(512)
            bpb = parse_fat32_bpb(boot_sector)

            def _read_sec(lba: int, count: int) -> bytes:
                f.seek(lba * bpb["bytes_per_sector"])
                return f.read(count * bpb["bytes_per_sector"])

            entries = parse_fat32_directory_entries(_read_sec, bpb)

        self.assertGreaterEqual(len(entries), 2)
        readme_entry = next((e for e in entries if e["short_name"] == "README.TXT"), None)
        self.assertIsNotNone(readme_entry)
        self.assertEqual(readme_entry["starting_cluster"], 3)
        self.assertEqual(readme_entry["file_size"], 6000)

        log_entry = next((e for e in entries if e["short_name"] == "LOGDATA.BIN"), None)
        self.assertIsNotNone(log_entry)
        self.assertEqual(log_entry["starting_cluster"], 5)
        self.assertEqual(log_entry["file_size"], 5000)

    # 33. Test FAT32 Cluster Chain Traversal in Read-Only Mode
    def test_33_fat32_cluster_chain_traversal(self):
        with open(self.fat32_img, "rb") as f:
            boot_sector = f.read(512)
            bpb = parse_fat32_bpb(boot_sector)

            def _read_sec(lba: int, count: int) -> bytes:
                f.seek(lba * bpb["bytes_per_sector"])
                return f.read(count * bpb["bytes_per_sector"])

            chain_readme = read_fat32_cluster_chain(_read_sec, 3, bpb)
            self.assertEqual(chain_readme, [3, 4])

            chain_log = read_fat32_cluster_chain(_read_sec, 5, bpb)
            self.assertEqual(chain_log, [5, 7])

    # 34. Test FAT32 Cluster-to-LBA Formula & Calculations
    def test_34_fat32_cluster_to_lba_calculation(self):
        with open(self.fat32_img, "rb") as f:
            boot_sector = f.read(512)
            bpb = parse_fat32_bpb(boot_sector)

        # Formula: LBA(C) = first_data_sector + (C - 2) * sectors_per_cluster
        # For Cluster 3: 96 + (3 - 2) * 8 = 104
        # For Cluster 4: 96 + (4 - 2) * 8 = 112 -> Ending LBA = 112 + 8 - 1 = 119
        mapping = map_clusters_to_lba_extents([3, 4], bpb)
        self.assertTrue(mapping["is_allocation_available"])
        self.assertEqual(mapping["starting_cluster"], 3)
        self.assertEqual(mapping["starting_lba"], 104)
        self.assertEqual(mapping["ending_lba"], 119)
        self.assertEqual(mapping["sectors_occupied"], 16)
        self.assertEqual(mapping["clusters_occupied"], 2)
        self.assertFalse(mapping["is_fragmented"])

    # 35. Test FAT32 LBA-to-Byte Offset Calculations
    def test_35_fat32_lba_to_byte_offset_calculation(self):
        with open(self.fat32_img, "rb") as f:
            boot_sector = f.read(512)
            bpb = parse_fat32_bpb(boot_sector)

        mapping = map_clusters_to_lba_extents([3, 4], bpb)
        # Byte offset = 104 * 512 = 53248
        self.assertEqual(mapping["byte_offset"], 53248)
        self.assertEqual(mapping["byte_offset_hex"], "0x0000D000")

    # 36. Test FAT32 File Content Verification Against Raw LBA Sectors
    def test_36_fat32_file_content_matches_raw_lba_bytes(self):
        # Read raw sector at starting LBA 104
        res_sec = read_storage_hex_sector(self.fat32_img, lba=104, sector_size=512)
        self.assertEqual(res_sec["status"], "SUCCESS")
        first_row_ascii = res_sec["rows"][0]["ascii"]
        self.assertIn("SECUREWIPE_FAT32", first_row_ascii)

    # 37. Test FAT32 Fragmented File Multi-Extent Handling
    def test_37_fat32_fragmented_file_handling(self):
        with open(self.fat32_img, "rb") as f:
            boot_sector = f.read(512)
            bpb = parse_fat32_bpb(boot_sector)

        mapping = map_clusters_to_lba_extents([5, 7], bpb)
        self.assertTrue(mapping["is_allocation_available"])
        self.assertTrue(mapping["is_fragmented"])
        self.assertEqual(mapping["starting_cluster"], 5)
        self.assertEqual(mapping["starting_lba"], 120)
        self.assertEqual(mapping["ending_lba"], 143)
        self.assertEqual(len(mapping["extents"]), 2)

        # Extent 1: Cluster 5 -> LBA 120..127 (8 sectors, 4096 B)
        ext1 = mapping["extents"][0]
        self.assertEqual(ext1["start_cluster"], 5)
        self.assertEqual(ext1["end_cluster"], 5)
        self.assertEqual(ext1["start_lba"], 120)
        self.assertEqual(ext1["end_lba"], 127)
        self.assertEqual(ext1["sector_count"], 8)
        self.assertEqual(ext1["start_byte_offset"], 120 * 512)

        # Extent 2: Cluster 7 -> LBA 136..143 (8 sectors, 4096 B)
        ext2 = mapping["extents"][1]
        self.assertEqual(ext2["start_cluster"], 7)
        self.assertEqual(ext2["end_cluster"], 7)
        self.assertEqual(ext2["start_lba"], 136)
        self.assertEqual(ext2["end_lba"], 143)
        self.assertEqual(ext2["sector_count"], 8)
        self.assertEqual(ext2["start_byte_offset"], 136 * 512)

    # 38. Test Unified File Allocation Resolver on Synthetic Volume
    def test_38_unified_file_storage_allocation(self):
        # Contiguous file test
        alloc_readme = get_file_storage_allocation("README.TXT", target_device=self.fat32_img)
        self.assertTrue(alloc_readme["is_allocation_available"])
        self.assertEqual(alloc_readme["starting_cluster"], 3)
        self.assertEqual(alloc_readme["starting_lba"], 104)
        self.assertEqual(alloc_readme["sectors_occupied"], 12)  # ceil(6000 / 512) = 12 sectors
        self.assertEqual(alloc_readme["allocated_sectors_extent"], 16)  # 2 clusters * 8 spc = 16 sectors
        self.assertEqual(alloc_readme["clusters_occupied"], 2)

        # Fragmented file test
        alloc_log = get_file_storage_allocation("LOGDATA.BIN", target_device=self.fat32_img)
        self.assertTrue(alloc_log["is_allocation_available"])
        self.assertEqual(alloc_log["starting_cluster"], 5)
        self.assertEqual(alloc_log["starting_lba"], 120)
        self.assertTrue(alloc_log["is_fragmented"])

    # 39. CRITICAL SAFETY TEST: FAT32 Strict Read-Only Immutability
    def test_39_fat32_strict_read_only_immutability(self):
        # Execute extensive parsing, chain traversal, sector inspection, and allocation calls
        get_file_storage_allocation("README.TXT", target_device=self.fat32_img)
        get_file_storage_allocation("LOGDATA.BIN", target_device=self.fat32_img)
        read_storage_hex_sector(self.fat32_img, lba=0, sector_size=512)
        read_storage_hex_sector(self.fat32_img, lba=96, sector_size=512)
        read_storage_hex_sector(self.fat32_img, lba=104, sector_size=512)
        read_storage_hex_sector(self.fat32_img, lba=120, sector_size=512)
        read_storage_hex_sector(self.fat32_img, lba=136, sector_size=512)

        # Verify image file was NEVER modified (SHA-256 and mtime are 100% untouched)
        current_mtime = os.path.getmtime(self.fat32_img)
        with open(self.fat32_img, "rb") as f:
            current_sha256 = hashlib.sha256(f.read()).hexdigest()

        self.assertEqual(self.fat32_initial_sha256, current_sha256)
        self.assertEqual(self.fat32_initial_mtime, current_mtime)

    # 40. Test File Allocation Unavailable Clean Fallback
    def test_40_file_allocation_unavailable_fallback(self):
        # Unmapped or inaccessible path should return clean fallback without guessing or crashing
        alloc = get_file_storage_allocation("NONEXISTENT_FILE_123.DAT", target_device=None)
        self.assertFalse(alloc["is_allocation_available"])
        self.assertIsNone(alloc["starting_cluster"])
        self.assertIsNone(alloc["starting_lba"])
        self.assertIsNone(alloc["ending_lba"])
        self.assertIsNone(alloc["byte_offset"])
        self.assertEqual(alloc["cluster_chain"], "Unavailable")
        self.assertEqual(alloc["byte_offset_hex"], "Unavailable")
        self.assertEqual(alloc["sectors_occupied"], 0)
        self.assertEqual(alloc["clusters_occupied"], 0)
    # 41. Test Direct FAT32 Directory & LFN Traversal Engine
    def test_41_direct_fat32_lfn_and_subdirectories(self):
        # Create nested directory structure in synthetic image
        alloc = get_file_storage_allocation("README.TXT", target_device=self.fat32_img)
        self.assertTrue(alloc["is_allocation_available"])
        self.assertEqual(alloc["starting_cluster"], 3)
        self.assertEqual(alloc["starting_lba"], 104)
        self.assertEqual(alloc["sectors_occupied"], 12)  # ceil(6000 / 512) = 12 sectors
        self.assertEqual(alloc["clusters_occupied"], 2)  # ceil(6000 / 4096) = 2 clusters
        self.assertEqual(alloc["allocated_sectors_extent"], 16)  # 2 clusters * 8 spc = 16 sectors

    # 42. Test Zero-Byte File FAT32 Handling
    def test_42_direct_fat32_zero_byte_file(self):
        with open(self.fat32_img, "rb") as f:
            boot = f.read(512)
            bpb = parse_fat32_bpb(boot)

        def _read_sec(lba: int, count: int) -> bytes:
            with open(self.fat32_img, "rb") as f:
                f.seek(lba * bpb["bytes_per_sector"])
                return f.read(count * bpb["bytes_per_sector"])

        from storage_inspector import _parse_fat32_file_allocation_engine
        # Test zero-byte file path
        alloc_zero = _parse_fat32_file_allocation_engine(
            read_fn=_read_sec,
            bpb=bpb,
            rel_path="NONEXISTENT.TXT",
            part_start_lba=0,
            full_file_path="NONEXISTENT.TXT"
        )
        self.assertIsNone(alloc_zero)

    # 43. Test Invalid FAT32 Metadata Boundary Validation
    def test_43_invalid_fat32_metadata_boundary_validation(self):
        # Corrupted BPB with reserved_sectors = 0
        corrupt_bpb = {
            "bytes_per_sector": 512,
            "sectors_per_cluster": 8,
            "reserved_sectors": 0,  # Invalid!
            "num_fats": 2,
            "fat_size_32": 32,
            "root_cluster": 2,
            "first_data_sector": 64
        }
        from storage_inspector import _parse_fat32_file_allocation_engine
        alloc = _parse_fat32_file_allocation_engine(
            read_fn=lambda lba, count: b"\x00" * 512,
            bpb=corrupt_bpb,
            rel_path="test.txt",
            part_start_lba=0,
            full_file_path="test.txt"
        )
        self.assertFalse(alloc["is_allocation_available"])
        self.assertEqual(alloc["allocation_disclaimer"], "UNAVAILABLE (INVALID FAT32 METADATA)")

    # 44. Test Real USB evidence.txt Storage Allocation (when E: is connected)
    def test_44_real_usb_evidence_txt_allocation(self):
        real_usb_file = r"E:\SecureWipe_Test\evidence.txt"
        if os.path.exists(real_usb_file):
            alloc = get_file_storage_allocation(real_usb_file)
            self.assertTrue(alloc["is_allocation_available"])
            self.assertEqual(alloc["filesystem"], "FAT32")
            self.assertEqual(alloc["starting_cluster"], 7)
            self.assertEqual(alloc["starting_lba"], 34856)
            self.assertEqual(alloc["ending_lba"], 34863)
            self.assertEqual(alloc["byte_offset"], 17846272)
            self.assertEqual(alloc["byte_offset_hex"], "0x01105000")
            self.assertEqual(alloc["sectors_occupied"], 1)
            self.assertEqual(alloc["clusters_occupied"], 1)
            self.assertEqual(alloc["mapping_layer"], "Device Logical LBA")
            self.assertEqual(alloc["raw_lba_verification"], "PASS")

    # 46. Test Direct FAT32 Folder Allocation (Directory Table + Child Files + Combined Map)
    def test_46_fat32_folder_allocation_directory_and_children(self):
        f_alloc = direct_fat32_folder_allocation("", target_device=self.fat32_img)
        self.assertIsNotNone(f_alloc)
        self.assertTrue(f_alloc["is_allocation_available"])
        self.assertEqual(f_alloc["filesystem"], "FAT32")

        # Check Directory Table Allocation
        dir_alloc = f_alloc["directory_allocation"]
        self.assertEqual(dir_alloc["starting_cluster"], 2)
        self.assertEqual(dir_alloc["starting_lba"], 96)
        self.assertEqual(dir_alloc["sectors_occupied"], 8)
        self.assertEqual(dir_alloc["clusters_occupied"], 1)

        # Check Child Files Allocation
        child_files = f_alloc["child_files"]
        self.assertEqual(len(child_files), 2)
        readme = next((cf for cf in child_files if "README" in cf["name"]), None)
        logdata = next((cf for cf in child_files if "LOGDATA" in cf["name"]), None)
        self.assertIsNotNone(readme)
        self.assertIsNotNone(logdata)
        self.assertEqual(readme["starting_cluster"], 3)
        self.assertEqual(readme["starting_lba"], 104)
        self.assertEqual(logdata["starting_cluster"], 5)
        self.assertEqual(logdata["starting_lba"], 120)

        # Check Combined Folder Storage Map (Deduplicated & Merged)
        combined = f_alloc["combined_storage_map"]
        self.assertEqual(combined["starting_lba"], 96)
        self.assertGreaterEqual(combined["total_sectors"], 8 + 16 + 16)  # Dir (8) + Readme (16) + Logdata (16)
        self.assertTrue(len(combined["extents"]) >= 1)

    # 47. Test Mode B: Filesystem Object Hex Reader for Files
    def test_47_mode_b_file_hex_sector_reader(self):
        sec_res = read_storage_hex_sector(
            "README.TXT",
            target_device=self.fat32_img,
            mode="file",
            extent_index=0,
            relative_sector=0
        )
        self.assertEqual(sec_res["status"], "SUCCESS")
        self.assertEqual(sec_res["mode"], "file")
        self.assertEqual(sec_res["lba"], 104)
        self.assertEqual(len(sec_res["rows"]), 32)
        self.assertTrue("sha256" in sec_res)
        self.assertEqual(len(sec_res["sha256"]), 64)
        self.assertEqual(sec_res["current_extent_index"], 0)
        self.assertEqual(sec_res["relative_sector_in_extent"], 0)

    # 48. Test Mode B: Filesystem Object Hex Reader for Folders (Directory Subview)
    def test_48_mode_b_folder_hex_sector_reader_directory_subview(self):
        sec_res = read_storage_hex_sector(
            "",
            target_device=self.fat32_img,
            mode="folder",
            sub_view="directory",
            extent_index=0,
            relative_sector=0
        )
        self.assertEqual(sec_res["status"], "SUCCESS")
        self.assertEqual(sec_res["mode"], "folder")
        self.assertEqual(sec_res["sub_view"], "directory")
        self.assertEqual(sec_res["lba"], 96)
        self.assertEqual(len(sec_res["rows"]), 32)
        # Check that directory entries for README and LOGDATA appear in rows ascii
        combined_ascii = "".join(r["ascii"] for r in sec_res["rows"])
        self.assertIn("README", combined_ascii)

    # 49. Test Mode B: Filesystem Object Hex Reader for Folders (Child Files Subview)
    def test_49_mode_b_folder_hex_sector_reader_child_files_subview(self):
        sec_res = read_storage_hex_sector(
            "",
            target_device=self.fat32_img,
            mode="folder",
            sub_view="child_files",
            child_file_path="README.TXT",
            extent_index=0,
            relative_sector=0
        )
        self.assertEqual(sec_res["status"], "SUCCESS")
        self.assertEqual(sec_res["mode"], "folder")
        self.assertEqual(sec_res["sub_view"], "child_files")
        self.assertEqual(sec_res["lba"], 104)

    # 50. Test Mode B: Filesystem Object Hex Reader for Folders (Combined Subview)
    def test_50_mode_b_folder_hex_sector_reader_combined_subview(self):
        sec_res = read_storage_hex_sector(
            "",
            target_device=self.fat32_img,
            mode="folder",
            sub_view="combined",
            extent_index=0,
            relative_sector=0
        )
        self.assertEqual(sec_res["status"], "SUCCESS")
        self.assertEqual(sec_res["mode"], "folder")
        self.assertEqual(sec_res["sub_view"], "combined")
        self.assertEqual(sec_res["lba"], 96)

    # 51. Test Folder Allocation Unavailable Fallback
    def test_51_folder_allocation_unavailable_fallback(self):
        f_alloc = get_folder_storage_allocation("NONEXISTENT_FOLDER_XYZ", target_device=None)
        self.assertFalse(f_alloc["is_allocation_available"])
        self.assertEqual(f_alloc["child_files_count"], 0)
        self.assertEqual(f_alloc["directory_allocation"]["sectors_occupied"], 0)

    # 52. Test Real USB Folder Storage Allocation (when E:\SecureWipe_Test is connected)
    def test_52_real_usb_folder_allocation(self):
        real_usb_folder = r"E:\SecureWipe_Test"
        if os.path.exists(real_usb_folder) and os.path.isdir(real_usb_folder):
            f_alloc = get_folder_storage_allocation(real_usb_folder)
            self.assertTrue(f_alloc["is_allocation_available"])
            self.assertEqual(f_alloc["filesystem"], "FAT32")
            self.assertGreaterEqual(f_alloc["directory_allocation"]["sectors_occupied"], 1)
            self.assertIsNotNone(f_alloc["directory_allocation"]["starting_cluster"])
            self.assertIsNotNone(f_alloc["directory_allocation"]["starting_lba"])
            evidence = next((cf for cf in f_alloc["child_files"] if "evidence" in cf["name"].lower()), None)
            if evidence:
                self.assertEqual(evidence["starting_cluster"], 7)
                self.assertEqual(evidence["starting_lba"], 34856)


if __name__ == "__main__":
    unittest.main()



