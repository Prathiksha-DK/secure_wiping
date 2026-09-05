# SecureWipe — Phase 7 Commercial Platform Architecture

## 1. Executive Product Direction

SecureWipe v7.0 is an **independent commercial platform** engineered around the circular technology model:

$$\textbf{WIPE} \longrightarrow \textbf{VERIFY} \longrightarrow \textbf{CERTIFY} \longrightarrow \textbf{LIST} \longrightarrow \textbf{TRANSFER}$$

The platform connects permanent data sanitization with verified hardware reuse, creating digital trust for buyers and sellers without generating electronic waste.

---

## 2. High-Level Subsystem Architecture

```
                    +------------------------------------------+
                    |        SECUREWIPE COMMERCIAL PLATFORM     |
                    |           (Public Web & SaaS API)        |
                    +------------------------------------------+
                                         │
                 ┌───────────────────────┴───────────────────────┐
                 │                                               │
   +-----------------------------+               +-----------------------------+
   |      PUBLIC WEB PLATFORM     |               |      SECURE PLATFORM API    |
   | - Commercial Landing Page   |               | - PBKDF2 Server Auth & RBAC |
   | - Verified Marketplace      |               | - Eligibility Engine        |
   | - Public Certificate Lookup |               | - Ownership Transfer Ledger |
   | - User Dashboard & Portal   |               | - Certificate Revocation CA |
   +-----------------------------+               +-----------------------------+
                 │                                               │
                 └───────────────────────┬───────────────────────┘
                                         │ Cryptographic Result
                                         │ Payload & HMAC Token
                                         v
                         +-------------------------------+
                         |   SECUREWIPE LOCAL AGENT      |
                         |   (Privileged Sanitization)   |
                         +-------------------------------+
                                         │
                                         v
                         +-------------------------------+
                         |    PHYSICAL STORAGE DEVICE    |
                         |    (NVMe, SSD, HDD, USB)      |
                         +-------------------------------+
```

---

## 3. Core Operational Lifecycle Stages

1. **Stage 1: Register Device**:
   * User onboards device; platform generates an anonymous **Platform Device ID** (`SW-DEV-<8-HEX>`) separate from physical serial numbers.
   * Raw serial is hashed via SHA-256 for collision prevention and masked for public presentation (`WD-****-9988`).
2. **Stage 2: Secure Sanitization**:
   * Multi-pass overwrite (NIST SP 800-88 Clear/Purge, DoD 5220.22-M 3-Pass, or IEEE 2883 Crypto Erase).
   * Exclusive hardware locking prevents concurrent race conditions.
3. **Stage 3: Stratified Verification & Forensic Carving**:
   * Multi-region sector sampling and 3-level deep file signature carving confirm complete data eradication.
4. **Stage 4: Certificate Generation & RSA-PSS Signing**:
   * Schema v1.0 certificate issued with canonical JSON SHA-256 digest and RSA-2048/4096 PSS digital signature.
5. **Stage 5: Marketplace Listing & Verified Trust Badge**:
   * Backend eligibility validator checks certificate status; verified devices receive the **✓ SecureWipe Verified** badge.
6. **Stage 6: Purchase & Ownership Transfer**:
   * Buyer inspects certificate and initiates order; device lifecycle ledger updates from Owner A to Owner B.
