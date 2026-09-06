"""
Unit and Integration Tests for Central Device Registry
Part of NTRO Adaptive Sanitization & Forensic Recovery Platform.
"""

import os
import sys
import unittest
import tempfile
import sqlite3

# Adjust paths
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from central_device_registry import (
    compute_device_fingerprint,
    generate_securewipe_device_id,
    init_device_registry_db,
    register_device,
    get_registered_device_by_id,
    get_registered_device_by_fingerprint,
    get_all_registered_devices,
    get_current_devices_status,
)
from auth import init_platform_db


class TestCentralDeviceRegistry(unittest.TestCase):
    def setUp(self):
        init_platform_db()
        init_device_registry_db()

    def test_fingerprint_determinism(self):
        """Verify that identical device specs produce the exact same fingerprint and ID."""
        fp1 = compute_device_fingerprint("HP", "v236w", "C3A7A27F307B920A", 7903117312, "USB")
        fp2 = compute_device_fingerprint("hp", "V236W", "c3a7a27f307b920a", 7903117312, "usb")
        self.assertEqual(fp1, fp2)

        id1 = generate_securewipe_device_id(fp1)
        id2 = generate_securewipe_device_id(fp2)
        self.assertEqual(id1, id2)
        self.assertTrue(id1.startswith("SW-DEV-"))
        self.assertEqual(len(id1), 15)  # "SW-DEV-" (7) + 8 hex chars = 15

    def test_different_devices_different_fingerprints(self):
        """Verify that different devices produce distinct fingerprints and IDs."""
        fp_hp = compute_device_fingerprint("HP", "v236w", "C3A7A27F307B920A", 7903117312, "USB")
        fp_sandisk = compute_device_fingerprint("SanDisk", "Ultra Fit", "4C530001150212117282", 32000000000, "USB")
        
        self.assertNotEqual(fp_hp, fp_sandisk)
        id_hp = generate_securewipe_device_id(fp_hp)
        id_sandisk = generate_securewipe_device_id(fp_sandisk)
        self.assertNotEqual(id_hp, id_sandisk)

    def test_device_registration_and_retrieval(self):
        """Verify registering a new device stores and returns all metadata properly."""
        dev_info = {
            "manufacturer": "Kingston",
            "model": "DataTraveler 3.0",
            "serial_number": "0014D118BC58B9C1B7200010",
            "capacity": 15800000000,
            "interface": "USB",
            "device_type": "USB Storage"
        }
        ok, msg, record = register_device(dev_info, created_by="citizen_user")
        self.assertTrue(ok)
        self.assertTrue(record["device_id"].startswith("SW-DEV-"))
        self.assertEqual(record["registration_status"], "REGISTERED")
        self.assertEqual(record["created_by"], "citizen_user")

        # Lookup by ID
        fetched = get_registered_device_by_id(record["device_id"])
        self.assertIsNotNone(fetched)
        self.assertEqual(fetched["device_id"], record["device_id"])
        self.assertEqual(fetched["model"], "DataTraveler 3.0")

    def test_duplicate_registration_idempotency(self):
        """Verify registering the exact same physical device returns existing record with no duplicate ID."""
        dev_info = {
            "manufacturer": "Samsung",
            "model": "FIT Plus",
            "serial_number": "0373819070001294",
            "capacity": 64000000000,
            "interface": "USB",
            "device_type": "USB Storage"
        }
        ok1, msg1, rec1 = register_device(dev_info, created_by="citizen_user")
        self.assertTrue(ok1)
        id1 = rec1["device_id"]

        # Register same device from another login/operator
        ok2, msg2, rec2 = register_device(dev_info, created_by="gov_officer")
        self.assertTrue(ok2)
        id2 = rec2["device_id"]

        # IDs must be identical
        self.assertEqual(id1, id2)
        self.assertIn("already registered", msg2.lower())

    def test_all_registered_devices_listing(self):
        """Verify all registered devices can be listed."""
        # Ensure at least one registered device exists
        dev_info = {
            "manufacturer": "Toshiba",
            "model": "TransMemory",
            "serial_number": "TOSHIBA-TM-9981",
            "capacity": 8000000000,
            "interface": "USB",
            "device_type": "USB Storage"
        }
        register_device(dev_info, created_by="citizen_user")
        all_devs = get_all_registered_devices()
        self.assertIsInstance(all_devs, list)
        self.assertGreaterEqual(len(all_devs), 1)

    def test_current_devices_status(self):
        """Verify scanning current devices returns proper registration structure."""
        status = get_current_devices_status()
        self.assertEqual(status["status"], "success")
        self.assertIn("connected_devices", status)
        self.assertIn("registered_count", status)


if __name__ == "__main__":
    unittest.main()
