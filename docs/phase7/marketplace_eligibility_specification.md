# SecureWipe — Marketplace Listing Eligibility & Trust Badge Engine

## 1. Objective

To preserve market integrity, the SecureWipe platform enforces that **only verified devices with active, authentic certificates can receive the "✓ SecureWipe Verified" badge**.

Users cannot bypass this requirement through client-side state manipulation; eligibility is validated **server-side** by `marketplace_engine.evaluate_marketplace_eligibility()`.

---

## 2. Server-Side Eligibility Rules

A device is marked **`LISTING ELIGIBLE`** if and only if all of the following conditions evaluate to `True`:

1. **Ownership Authenticity**:
   * The authenticated user must be the recorded `owner_username` of the target `device_id`.
2. **Sanitization Status**:
   * The device's recorded lifecycle status must be `VERIFIED` or `SANITIZED`.
   * Unwiped (`REGISTERED`), in-progress (`WIPING`), failed (`FAILED`), or non-verifiable (`NOT_VERIFIABLE`) devices are strictly rejected.
3. **Certificate Registry Validity**:
   * A valid `certificate_id` must be bound to the device.
   * The certificate record in `certificate_registry` must have `status == 'ACTIVE'`.
   * Revoked (`REVOKED`) or superseded certificates result in immediate rejection.
4. **No Active Disputes / Transfers**:
   * Device must not be locked in a pending transfer order (`ORDERED`, `PAYMENT_PENDING`, `HANDOVER_IN_PROGRESS`).

---

## 3. Marketplace Trust Badge Display Logic

```
               [Device Query]
                     │
                     v
  [Check 'is_verified == 1' & 'status == ACTIVE']
        │                             │
       Yes                            No
        │                             │
        v                             v
[Render: ✓ SecureWipe Verified]  [Render: Unverified Listing]
        │
        v
[Clickable: Opens Public Certificate Modal]
```
