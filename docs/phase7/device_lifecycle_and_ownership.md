# SecureWipe — Device Lifecycle & Ownership Transfer Specification

## 1. Lifecycle State Machine

A registered storage device transitions through deterministic lifecycle states:

$$\begin{aligned}
\text{REGISTERED} &\longrightarrow \text{WIPING} \longrightarrow \text{VERIFIED} \longrightarrow \text{LISTED} \\
&\longrightarrow \text{PENDING\_TRANSFER} \longrightarrow \text{TRANSFERRED / SOLD}
\end{aligned}$$

---

## 2. Platform Device ID & Privacy Architecture

* **Physical Serial Privacy**:
  * Raw physical serials (e.g., `WDC-WD10EZEX-75M2NA0`) are never displayed publicly.
  * Public presentation uses privacy-masked strings: `mask_serial_number()` $\rightarrow$ `WDC****2NA0`.
  * Collision and duplicate detection uses `raw_serial_hash = SHA256(raw_serial)`.
* **Platform Device ID**:
  * Every device is assigned an independent identifier: `SW-DEV-<8-HEX>` (e.g., `SW-DEV-8F92A1B0`).
  * All marketplace listings, purchase orders, and transfer records reference `SW-DEV-ID`.

---

## 3. Ownership Transfer Protocol

1. **Buyer Purchase Initiation**:
   * Buyer executes `POST /api/marketplace/listings/<id>/buy`.
   * Listing state changes from `ACTIVE` to `PENDING_TRANSFER`.
   * Transfer record created: `TRF-<8-HEX>` in `ORDERED` state.
2. **Physical Handover & Verification**:
   * Hardware is delivered via carrier or local pickup. Buyer can inspect the physical device against the public certificate.
3. **Transfer Finalization**:
   * Execution of `POST /api/marketplace/transfers/<id>/complete`.
   * Device `owner_username` updated to `Buyer`.
   * Device status updated to `TRANSFERRED`.
   * Listing status updated to `SOLD`.
   * Immutable event appended to `device_lifecycle` and cryptographic audit log.
