# SecureWipe — Certificate Security, Digital Signatures & Verification Guide

## 1. Schema v1.0 Overview

SecureWipe v6.0 produces **cryptographically signed, tamper-evident Sanitization Certificates** compliant with the formal Schema v1.0 specification.

---

## 2. Integrity Architecture

Every Schema v1.0 certificate contains an `integrity` block:

```json
"integrity": {
  "algorithm": "SHA-256",
  "digest": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
  "digest_input_fields": [
    "assurance_status", "certificate_id", "device", "generated_at",
    "lifecycle_decision", "operation", "operation_id", "operator",
    "policy", "recovery_assessment", "schema_version", "verification"
  ],
  "signature": "MIIB...==",
  "signature_algorithm": "RSA-PSS-SHA256",
  "signing_key_id": "SECUREWIPE-CA-9A7B3E"
}
```

---

## 3. Asymmetric Digital Signature Specification

* **Key Pair**: RSA-2048 or RSA-4096.
* **Signature Algorithm**: RSA-PSS (Probabilistic Signature Scheme) with SHA-256 and `MGF1(SHA-256)` mask generation.
* **Canonical Serialization**: Deterministic JSON serialization (sorted keys, compact `,` and `:` separators, UTF-8 encoding).
* **Digest Computation**: SHA-256 digest computed over all certificate fields except the `integrity` block itself.

---

## 4. Verification Workflow

```
[Import Certificate JSON]
          |
          v
[1. Check 'integrity' block presence] --------> FAIL -> [Invalid Certificate]
          |
          v
[2. Extract stored digest & signature]
          |
          v
[3. Re-serialize canonical JSON & compute SHA-256]
          |
          v
[4. Compare computed digest == stored digest] --> FAIL -> [TAMPERING DETECTED: Data Altered]
          |
          v
[5. Verify RSA-PSS signature against Public CA Key] -> FAIL -> [SIGNATURE FORGERY / INVALID]
          |
          v
[Certificate Authenticity & Integrity VERIFIED: PASS]
```

---

## 5. Assurance Status Classifications

SecureWipe assigns one of three technical assurance classifications:

1. `SANITIZED_REUSABLE`:
   * Verified complete eradication of all logical sectors on magnetic hard disk drives (HDDs). Zero residual carver artifacts detected. Device is safe for redeployment or resale.
2. `SANITIZATION_NOT_VERIFIABLE`:
   * Applied to **SSDs, NVMe drives, USB flash sticks, and NAND media**.
   * **Technical Honesty Statement**: Due to internal flash translation layers (FTL), wear leveling, over-provisioning, and bad-block retirement, logical overwriting cannot physically guarantee that data in unmapped flash blocks has been destroyed.
3. `SANITIZATION_FAILED`:
   * Verification failed, or significant validated data artifacts were recovered by the forensic carver.
