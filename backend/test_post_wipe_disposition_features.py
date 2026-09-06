"""
Unit and integration tests for post-wipe lifecycle disposition matrix and government forward auction/buy-back features.
"""

import unittest
import json
import os
import sys

sys.path.insert(0, os.path.dirname(__file__))

from app import app
from auth import init_platform_db, get_db
from health_valuation import (
    record_device_disposition,
    get_disposition_records,
    list_government_auction,
    get_government_auctions,
    place_government_bid,
    create_government_buyback_claim,
    get_government_buybacks
)

class TestPostWipeDispositionFeatures(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        init_platform_db()
        cls.client = app.test_client()

    def test_01_marketplace_requires_full_disk(self):
        """Test that private marketplace listing fails if target_type is not 'disk'."""
        ok, msg, res = record_device_disposition(
            device_name="Confidential_Report.pdf",
            serial_number="",
            certificate_id="CERT-TEST-FILE-001",
            target_type="file",
            disposition="MARKETPLACE_LIST",
            health_score=95,
            is_reusable=True,
            actor_username="citizen_user"
        )
        self.assertFalse(ok)
        self.assertIn("entire physical device was wiped", msg)
        self.assertIsNone(res)

        # Folder test
        ok_folder, msg_folder, _ = record_device_disposition(
            device_name="D:\\Documents\\Financials",
            serial_number="",
            certificate_id="CERT-TEST-DIR-002",
            target_type="folder",
            disposition="MARKETPLACE_LIST",
            health_score=95,
            is_reusable=True,
            actor_username="citizen_user"
        )
        self.assertFalse(ok_folder)
        self.assertIn("entire physical device was wiped", msg_folder)

    def test_02_marketplace_succeeds_for_full_disk(self):
        """Test that private marketplace listing succeeds when target_type is 'disk' and reusable."""
        ok, msg, res = record_device_disposition(
            device_name="Samsung 980 Pro 1TB",
            serial_number="S980-PRO-4819",
            certificate_id="CERT-TEST-DISK-003",
            target_type="disk",
            disposition="MARKETPLACE_LIST",
            health_score=98,
            is_reusable=True,
            actor_username="citizen_user"
        )
        self.assertTrue(ok)
        self.assertIsNotNone(res)
        self.assertEqual(res["disposition"], "MARKETPLACE_LIST")
        self.assertEqual(res["target_type"], "disk")

    def test_03_keep_self_disposition(self):
        """Test keeping reusable device for self-retention."""
        ok, msg, res = record_device_disposition(
            device_name="SanDisk Ultra USB 64GB",
            serial_number="SD-ULTRA-092",
            certificate_id="CERT-TEST-USB-004",
            target_type="disk",
            disposition="KEEP_SELF",
            health_score=90,
            is_reusable=True,
            actor_username="citizen_user"
        )
        self.assertTrue(ok)
        self.assertEqual(res["disposition"], "KEEP_SELF")

    def test_04_non_reusable_device_e_waste(self):
        """Test routing damaged / non-reusable device to E-Waste."""
        # Trying to keep or list degraded device fails
        ok_bad_list, _, _ = record_device_disposition(
            device_name="Damaged Seagate 500GB",
            serial_number="SG-BAD-001",
            certificate_id="CERT-TEST-FAIL-005",
            target_type="disk",
            disposition="MARKETPLACE_LIST",
            health_score=40,
            is_reusable=False,
            actor_username="citizen_user"
        )
        self.assertFalse(ok_bad_list)

        # Route to E-Waste succeeds
        ok_ewaste, msg_ewaste, res_ewaste = record_device_disposition(
            device_name="Damaged Seagate 500GB",
            serial_number="SG-BAD-001",
            certificate_id="CERT-TEST-FAIL-005",
            target_type="disk",
            disposition="E_WASTE",
            health_score=40,
            is_reusable=False,
            actor_username="citizen_user"
        )
        self.assertTrue(ok_ewaste)
        self.assertEqual(res_ewaste["disposition"], "E_WASTE")

    def test_05_government_forward_auction_lifecycle(self):
        """Test creating an auction lot, retrieving items, and placing bids."""
        ok, msg, lot = list_government_auction(
            lot_number="GA-TEST-LOT-99",
            title="10x Intel Optane SSD Fleet (NIST 800-88 Purged)",
            device_name="Intel Optane 905P",
            media_type="SSD",
            capacity_gb=9600.0,
            certificate_id="CERT-GOV-OPTANE-001",
            agency_name="National Technical Research Org",
            reserve_price_inr=50000,
            duration_days=5
        )
        self.assertTrue(ok)
        self.assertEqual(lot["lot_number"], "GA-TEST-LOT-99")

        # Fetch auction items
        items = get_government_auctions()
        found = any(i["lot_number"] == "GA-TEST-LOT-99" for i in items)
        self.assertTrue(found)

        # Place competitive bid
        bid_ok, bid_msg, bid_res = place_government_bid(
            auction_id="GA-TEST-LOT-99",
            bidder_name="Authorized Recycler Consortium",
            bid_amount_inr=55000
        )
        self.assertTrue(bid_ok)
        self.assertEqual(bid_res["bid_amount_inr"], 55000)

    def test_06_government_oem_buyback_claim(self):
        """Test initiating government OEM buy-back claim and voucher generation."""
        ok, msg, claim = create_government_buyback_claim(
            device_name="Dell Precision 5820 NVMe 2TB",
            serial_number="DEL-PREC-8891",
            media_type="NVME",
            capacity_gb=2000.0,
            certificate_id="CERT-GOV-DELL-002",
            agency_name="National Technical Research Org",
            vendor_name="Dell Technologies OEM Trade-In",
            credit_value_inr=7500
        )
        self.assertTrue(ok)
        self.assertIn("voucher_code", claim)
        self.assertEqual(claim["credit_value_inr"], 7500)

        # Fetch claims
        claims = get_government_buybacks()
        found = any(c["voucher_code"] == claim["voucher_code"] for c in claims)
        self.assertTrue(found)

    def test_07_api_endpoints_integration(self):
        """Test HTTP API endpoints via test client."""
        # 1. Disposition Endpoint
        res1 = self.client.post("/api/lifecycle/disposition/decide", json={
            "device_name": "Kingston A400 240GB",
            "serial_number": "KGT-240-881",
            "certificate_id": "CERT-API-001",
            "target_type": "disk",
            "disposition": "KEEP_SELF",
            "health_score": 95,
            "is_reusable": True
        })
        self.assertEqual(res1.status_code, 200)

        # 2. Government Auction List Endpoint
        res2 = self.client.get("/api/lifecycle/government/auction/items")
        self.assertEqual(res2.status_code, 200)
        lots = res2.get_json()
        self.assertIsInstance(lots, list)
        self.assertGreater(len(lots), 0)

        # 3. Government Buy-Back Claims Endpoint
        res3 = self.client.get("/api/lifecycle/government/buyback/claims")
        self.assertEqual(res3.status_code, 200)
        claims = res3.get_json()
        self.assertIsInstance(claims, list)
        self.assertGreater(len(claims), 0)

if __name__ == "__main__":
    unittest.main()
