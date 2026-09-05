"""
SecureWipe — Phase 7 Automated Marketplace & Lifecycle Test Suite
Exhaustive automated verification of:
1. Privacy-Preserving Device Registration & Identifier Generation
2. Server-Side Listing Eligibility Evaluation
3. Verified Marketplace Listing Creation & Filter Subsystem
4. Measurable Trust Score Calculation
5. Secure Ownership Transfer Lifecycle (Seller -> Sanitized -> Listed -> Sold -> Buyer)
6. Certificate Revocation & Automated Listing Delisting
7. Privacy Protection & Public Certificate Verification
8. Unauthorized Access & Tampering Prevention
"""

import os
import sys
import json
import time
import unittest
import tempfile
import shutil

os.environ["SECUREWIPE_ENV"] = "TEST"
os.environ["SECUREWIPE_SECRET_KEY"] = "test-secret-key-for-phase7-validation-112233445566778899"

from security_config import init_auth_db
from audit_log import init_audit_db
from marketplace_engine import (
    init_marketplace_db,
    register_device,
    get_user_devices,
    get_device_by_id,
    evaluate_marketplace_eligibility,
    create_marketplace_listing,
    get_marketplace_listings,
    get_listing_detail,
    initiate_device_purchase,
    complete_ownership_transfer,
    register_marketplace_certificate,
    revoke_certificate,
    get_public_certificate_verification,
    mask_serial_number,
    compute_device_trust_score,
    get_admin_marketplace_overview
)


class TestPhase7MarketplaceSuite(unittest.TestCase):

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp(prefix="securewipe_phase7_")
        os.environ["SECUREWIPE_DATA_DIR"] = self.temp_dir
        init_auth_db()
        init_audit_db()
        init_marketplace_db()

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    # -----------------------------------------------------------------------
    # 1. Device Registration & Privacy Masking
    # -----------------------------------------------------------------------
    def test_01_device_registration_privacy(self):
        """Verify registration assigns SW-DEV-ID and masks raw serial number."""
        raw_serial = "WDC-WD10EZEX-75M2NA0"
        dev = register_device(
            owner_username="AliceSeller",
            manufacturer="Western Digital",
            model="WD Blue 1TB Desktop HDD",
            capacity_bytes=1000204886016,
            interface="SATA 6Gb/s",
            device_type="HDD",
            raw_serial=raw_serial,
            health_status="Healthy",
            smart_data={"power_on_hours": 1200, "reallocated_sectors": 0}
        )
        self.assertTrue(dev["device_id"].startswith("SW-DEV-"))
        self.assertEqual(dev["owner_username"], "AliceSeller")
        self.assertEqual(dev["status"], "REGISTERED")
        self.assertNotEqual(dev["masked_serial"], raw_serial)
        self.assertIn("****", dev["masked_serial"])

        # Check retrieval by user
        alice_devs = get_user_devices("AliceSeller")
        self.assertEqual(len(alice_devs), 1)
        self.assertEqual(alice_devs[0]["device_id"], dev["device_id"])

    # -----------------------------------------------------------------------
    # 2. Server-Side Marketplace Eligibility Engine
    # -----------------------------------------------------------------------
    def test_02_listing_eligibility_enforcement(self):
        """Verify unverified or failed devices are rejected for marketplace listing."""
        # 1. Unwiped / Registered device (MUST BE INELIGIBLE)
        dev = register_device(
            owner_username="BobOwner",
            manufacturer="Crucial",
            model="P3 Plus 1TB NVMe",
            capacity_bytes=1000000000000,
            interface="NVMe PCIe 4.0",
            device_type="NVMe",
            raw_serial="CT1000P3SSD8-9988",
            health_status="Healthy"
        )
        el1 = evaluate_marketplace_eligibility(dev["device_id"], "BobOwner")
        self.assertFalse(el1["eligible"])
        self.assertIn("must complete sanitization", el1["reason"])

        # 2. Unauthorized user trying to check or list another person's device
        el2 = evaluate_marketplace_eligibility(dev["device_id"], "EveAttacker")
        self.assertFalse(el2["eligible"])
        self.assertIn("ownership", el2["reason"])

        # 3. Verified device with active certificate (MUST BE ELIGIBLE)
        dummy_cert = {
            "certificate_id": "CERT-TEST-EL-001",
            "device_id": dev["device_id"],
            "assurance_status": "SANITIZED_REUSABLE",
            "operation": {"method": "NIST SP 800-88 Purge", "completed_at": "2026-09-02T12:00:00Z"},
            "device": {"model": dev["model"], "masked_serial": dev["masked_serial"]}
        }
        register_marketplace_certificate(dummy_cert, dev["device_id"])

        el3 = evaluate_marketplace_eligibility(dev["device_id"], "BobOwner")
        self.assertTrue(el3["eligible"])

    # -----------------------------------------------------------------------
    # 3. Marketplace Listing Creation & Filtering
    # -----------------------------------------------------------------------
    def test_03_create_and_filter_marketplace_listing(self):
        """Verify listing creation attaches certificate and filters work accurately."""
        dev = register_device(
            owner_username="Charlie",
            manufacturer="Samsung",
            model="970 EVO Plus 2TB",
            capacity_bytes=2000000000000,
            interface="NVMe PCIe Gen 3",
            device_type="NVMe",
            raw_serial="S4EVON00123",
            health_status="Healthy",
            smart_data={"wear_level": 97}
        )
        dummy_cert = {
            "certificate_id": "CERT-CHARLIE-001",
            "device_id": dev["device_id"],
            "assurance_status": "SANITIZED_REUSABLE",
            "operation": {"method": "DoD 5220.22-M 3-Pass", "completed_at": "2026-09-02T12:00:00Z"},
            "device": {"model": dev["model"], "masked_serial": dev["masked_serial"]}
        }
        register_marketplace_certificate(dummy_cert, dev["device_id"])

        # Create Listing
        ok, msg, res = create_marketplace_listing(
            seller_username="Charlie",
            device_id=dev["device_id"],
            title="Samsung 970 EVO Plus 2TB NVMe M.2 SSD",
            description="Sanitized and verified. Great condition.",
            price_usd=110.00,
            condition="Used - Excellent",
            shipping_options="Free US Shipping",
            location="Austin, TX",
            warranty_terms="30-Day Money Back Guarantee"
        )
        self.assertTrue(ok)
        self.assertTrue(res["is_verified"])
        listing_id = res["listing_id"]

        # Filter by NVMe category
        nvme_listings = get_marketplace_listings(category="NVMe")
        self.assertTrue(any(l["listing_id"] == listing_id for l in nvme_listings))

        # Filter by price
        cheap_listings = get_marketplace_listings(max_price=50.00)
        self.assertFalse(any(l["listing_id"] == listing_id for l in cheap_listings))

    # -----------------------------------------------------------------------
    # 4. Ownership Transfer Lifecycle (Buy -> Transfer -> Sold)
    # -----------------------------------------------------------------------
    def test_04_ownership_transfer_lifecycle(self):
        """Verify full lifecycle: Listed -> Purchased -> Ownership Transferred to Buyer."""
        # Setup seller device and listing
        dev = register_device(
            owner_username="SellerDave",
            manufacturer="Seagate",
            model="IronWolf 4TB NAS HDD",
            capacity_bytes=4000000000000,
            interface="SATA 6Gb/s",
            device_type="HDD",
            raw_serial="ST4000VN008-2233",
            health_status="Healthy"
        )
        dummy_cert = {
            "certificate_id": "CERT-SEAGATE-001",
            "device_id": dev["device_id"],
            "assurance_status": "SANITIZED_REUSABLE",
            "operation": {"method": "NIST SP 800-88 Clear", "completed_at": "2026-09-02T12:00:00Z"},
            "device": {"model": dev["model"], "masked_serial": dev["masked_serial"]}
        }
        register_marketplace_certificate(dummy_cert, dev["device_id"])

        ok_l, _, l_res = create_marketplace_listing(
            seller_username="SellerDave",
            device_id=dev["device_id"],
            title="Seagate IronWolf 4TB NAS Hard Drive",
            description="Perfect for Synology or QNAP.",
            price_usd=65.00,
            condition="Used - Like New",
            shipping_options="Standard Shipping"
        )
        self.assertTrue(ok_l)
        listing_id = l_res["listing_id"]

        # Buyer attempts to purchase
        ok_buy, _, buy_res = initiate_device_purchase(
            listing_id=listing_id,
            buyer_username="BuyerFrank",
            transfer_notes="Ship via FedEx Ground."
        )
        self.assertTrue(ok_buy)
        transfer_id = buy_res["transfer_id"]

        # Verify listing state is PENDING_TRANSFER
        detail = get_listing_detail(listing_id)
        self.assertEqual(detail["listing_status"], "PENDING_TRANSFER")

        # Finalize ownership transfer
        ok_done, _ = complete_ownership_transfer(transfer_id, "SystemAdmin")
        self.assertTrue(ok_done)

        # Verify new device owner is BuyerFrank
        updated_dev = get_device_by_id(dev["device_id"])
        self.assertEqual(updated_dev["owner_username"], "BuyerFrank")
        self.assertEqual(updated_dev["status"], "TRANSFERRED")

    # -----------------------------------------------------------------------
    # 5. Certificate Revocation & Automated Listing Delisting
    # -----------------------------------------------------------------------
    def test_05_certificate_revocation_delisting(self):
        """Verify revoking a certificate immediately delists the marketplace listing."""
        dev = register_device(
            owner_username="Grace",
            manufacturer="Intel",
            model="Optane SSD 905P 960GB",
            capacity_bytes=960000000000,
            interface="PCIe NVMe",
            device_type="NVMe",
            raw_serial="INTEL-OPT-0099",
            health_status="Healthy"
        )
        cert_id = "CERT-OPTANE-REVOKE-001"
        dummy_cert = {
            "certificate_id": cert_id,
            "device_id": dev["device_id"],
            "assurance_status": "SANITIZED_REUSABLE",
            "operation": {"method": "DoD 5220.22-M", "completed_at": "2026-09-02T12:00:00Z"},
            "device": {"model": dev["model"], "masked_serial": dev["masked_serial"]}
        }
        register_marketplace_certificate(dummy_cert, dev["device_id"])

        ok_l, _, l_res = create_marketplace_listing(
            seller_username="Grace",
            device_id=dev["device_id"],
            title="Intel Optane 905P 960GB",
            description="Ultra low latency drive.",
            price_usd=250.00,
            condition="Used - Excellent",
            shipping_options="Free Shipping"
        )
        self.assertTrue(ok_l)
        listing_id = l_res["listing_id"]

        # Admin revokes certificate
        ok_rev, _ = revoke_certificate(cert_id, "Firmware read error detected post-audit.", "AdminUser")
        self.assertTrue(ok_rev)

        # Verify listing is now DELISTED and badge stripped
        updated_listing = get_listing_detail(listing_id)
        self.assertEqual(updated_listing["listing_status"], "DELISTED")
        self.assertEqual(updated_listing["is_verified"], 0)

        # Verify public certificate verification reflects revocation
        pub_ver = get_public_certificate_verification(cert_id)
        self.assertFalse(pub_ver["valid"])
        self.assertEqual(pub_ver["status"], "REVOKED")
        self.assertIn("Firmware read error", pub_ver["revocation_reason"])

    # -----------------------------------------------------------------------
    # 6. Trust Score Calculation Accuracy
    # -----------------------------------------------------------------------
    def test_06_trust_score_calculation(self):
        """Verify trust score evaluates verifiable signals without arbitrary fabrication."""
        dev_high = {
            "certificate_id": "CERT-123",
            "status": "VERIFIED",
            "health_status": "Healthy",
            "owner_username": "ValidOwner",
            "smart_data_json": '{"wear_level": 99}'
        }
        score_high = compute_device_trust_score(dev_high, cert_active=True)
        self.assertEqual(score_high, 100)

        dev_unverified = {
            "certificate_id": "",
            "status": "REGISTERED",
            "health_status": "Unknown",
            "owner_username": "NewUser",
            "smart_data_json": "{}"
        }
        score_low = compute_device_trust_score(dev_unverified, cert_active=False)
        self.assertEqual(score_low, 10)


if __name__ == "__main__":
    unittest.main()
