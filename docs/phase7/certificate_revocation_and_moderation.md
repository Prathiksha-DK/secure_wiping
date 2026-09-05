# SecureWipe — Certificate Revocation, Moderation & Anti-Fraud Specification

## 1. Certificate Revocation Protocol

If a certificate is found to be compromised, erroneous, or associated with a hardware failure detected post-audit, a platform administrator can execute an immediate revocation.

---

## 2. Revocation Cascading Effects

When `revoke_certificate(certificate_id, reason, admin_username)` is invoked:

1. **Certificate Registry Update**:
   * Status transitions from `ACTIVE` to `REVOKED`.
   * Revocation reason and timestamp are recorded in the public ledger.
2. **Device State Downgrade**:
   * Linked `registered_devices` status transitions to `NOT_VERIFIABLE`.
3. **Automated Marketplace Delisting**:
   * Any active marketplace listing linked to the device is immediately updated:
     * `is_verified` $\longrightarrow 0$
     * `listing_status` $\longrightarrow \text{"DELISTED"}$
4. **Public Verification Response**:
   * Any future queries to `GET /api/marketplace/verify/<cert_id>` or QR scans return `valid: false` and explicitly display the official revocation reason.
5. **Cryptographic Audit Event**:
   * Appends a `CERTIFICATE_REVOKED` event to the SHA-256 tamper-evident audit log.

---

## 3. Anti-Fraud & Market Protection

* **No Unverified Badges**: The "SecureWipe Verified" badge is computed dynamically by the backend; sellers cannot add or manipulate badges through frontend payloads.
* **Duplicate Device Detection**: `raw_serial_hash` prevents malicious actors from registering the same physical disk under multiple simultaneous seller accounts.
* **Self-Purchase Prevention**: Sellers cannot buy their own listings to fabricate transaction volume.
