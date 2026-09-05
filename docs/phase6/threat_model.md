# SecureWipe — Phase 6 Formal Threat Model

## 1. Executive Summary

This document establishes the formal threat model for **SecureWipe v6.0**, a security-hardened data sanitization and forensic verification platform. The model follows standard STRIDE and NIST SP 800-30 risk assessment methodologies, identifying critical assets, threat actors, attack vectors, defensive controls, and residual risks.

---

## 2. Protected Assets

| Asset ID | Asset Name | Description | Confidentiality | Integrity | Availability |
|---|---|---|---|---|---|
| **AST-01** | Host Operating System & Boot Disks | The host OS kernel, root filesystem (`/`, `C:\`), EFI system partition, and application files. | Medium | **Critical** | **Critical** |
| **AST-02** | Connected Non-Target Storage | Non-selected internal hard drives, system SSDs, corporate network mounts, and removable media not queued for wipe. | **Critical** | **Critical** | **Critical** |
| **AST-03** | Target Data Under Sanitization | Residual confidential, proprietary, or classified data on the target storage medium. | **Critical** | **Critical** | High |
| **AST-04** | Audit Log & Event Stream | Forensic audit trail of all security, sanitization, and administrative actions. | Medium | **Critical** | High |
| **AST-05** | Sanitization Certificates | Schema v1.0 certificates declaring data destruction assurance and lifecycle decisions. | Medium | **Critical** | Medium |
| **AST-06** | Cryptographic Keys & Secrets | CA private signing keys (RSA-2048/4096), HMAC secrets, ephemeral AES keys, and user hashes. | **Critical** | **Critical** | High |

---

## 3. Threat Actors & Capabilities

| Threat Actor | Motivation | Skill Level | Access Level |
|---|---|---|---|
| **Accidental / Untrained Operator** | Human error, lack of training, distraction, misidentification of storage drive. | Low | Local UI / Operator interface |
| **Malicious Insider / Rogue Operator** | Sabotage (wiping system/root), fraud (forging sanitization certificates without erasing media), data theft. | Moderate to High | Operator / Local Terminal |
| **Network Attacker (Adjacent/Remote)** | Unauthorized remote sanitization, command injection, denial of service, certificate forgery. | Moderate to High | Network access to API port |
| **Forensic Adversary (Data Recovery Attacker)** | Recovering sensitive residual data from discarded or recycled storage devices. | High (Laboratory capabilities) | Physical possession of sanitized media |
| **Audit Tamperer** | Modifying SQLite logs or certificates to conceal unperformed wipes or altered records. | Moderate | Local filesystem or DB access |

---

## 4. Threat Analysis & Mitigations (STRIDE Matrix)

```
+-----------------------------------------------------------------------------------------------+
|                                    STRIDE THREAT MATRIX                                      |
+-------------------+----------------------------------------+----------------------------------+
| Threat Category   | Specific Risk Scenario                 | SecureWipe Mitigation Control    |
+-------------------+----------------------------------------+----------------------------------+
| Spoofing          | Unauthenticated API calls triggering   | - Signed HMAC-SHA256 tokens      |
|                   | destructive wipes or forged certs      | - PBKDF2 user authentication     |
|                   |                                        | - RSA-PSS asymmetric signing     |
+-------------------+----------------------------------------+----------------------------------+
| Tampering         | - Modifying audit log to hide failure  | - Cryptographic hash chaining    |
|                   | - Altering certificate fields          | - Canonical SHA-256 digests      |
|                   | - Device path swap (/dev/sdX change)   | - Hardware identity fingerprint  |
+-------------------+----------------------------------------+----------------------------------+
| Repudiation       | Operator denies executing destructive  | - Immutable audit trail          |
|                   | wipe or generating invalid certificate | - Operator ID in hash chain      |
+-------------------+----------------------------------------+----------------------------------+
| Information       | - Sensitive data retained in memory    | - In-memory key zeroization      |
| Disclosure        | - Cleartext credentials in code        | - Elimination of hardcoded secrets|
|                   | - Excessive error stack traces in API  | - Sanitized production errors    |
+-------------------+----------------------------------------+----------------------------------+
| Denial of Service | - Concurrency race on same disk        | - Exclusive Device Lock Manager  |
|                   | - Destructive wipe targeting root OS   | - Multi-layer fail-closed safety |
|                   | - Rate-limiting brute force attempts   | - IP lockout on failed auth      |
+-------------------+----------------------------------------+----------------------------------+
| Elevation of      | - UI low-privilege invoking shell cmd  | - Zero shell=True execution      |
| Privilege         | - Parameter injection in format tools  | - Fixed argument arrays          |
|                   | - Role-based authorization bypass      | - Server-side RBAC decorators    |
+-------------------+----------------------------------------+----------------------------------+
```

---

## 5. High-Risk Misuse Path Analysis

### 5.1 Misuse Path 1: System / Root Disk Destruction
* **Threat**: Operator selects `/dev/sda` or `C:` intending to wipe a USB drive, but accidentally queues the OS root.
* **Defensive Controls**:
  1. Multi-layer storage safety validator (`validate_storage_safety`) evaluates root `/`, `/boot`, `/boot/efi`, `/etc`, `/usr`, `/var`, `/home`, workspace directory, and Windows boot partitions.
  2. Fail-closed rejection: If safe evaluation fails or target is unresolved, operation aborts with `SAFETY_REJECTED`.
  3. Two-stage confirmation forces explicit hardware summary review and typing `CONFIRM-WIPE-<SERIAL>`.

### 5.2 Misuse Path 2: Device Re-Enumeration / Anti-Misdirection (Device Swap)
* **Threat**: Operator selects `/dev/sdb` (USB), disconnects it, and reconnects a corporate hard drive that receives the same `/dev/sdb` node.
* **Defensive Controls**:
  1. Stage 1 captures a SHA-256 hardware identity fingerprint `(Serial, Model, Size, BusType)`.
  2. Stage 2 re-computes the target's live hardware fingerprint before write lock acquisition. If mismatched, operation immediately aborts with `ANTI-MISDIRECTION ABORT`.

### 5.3 Misuse Path 3: Certificate Forgery & False Certification
* **Threat**: An operator generates a valid-looking certificate for an unwiped SSD to claim compliance.
* **Defensive Controls**:
  1. Certificates are signed with RSA-PSS using a secured private key.
  2. The integrity block contains a canonical SHA-256 digest of all fields.
  3. SSDs and NAND flash devices are technically and honestly classified as `SANITIZATION_NOT_VERIFIABLE` per NIST SP 800-88 Rev.1 guidelines.

---

## 6. Residual Risk Assessment & Technical Honesty

| Risk ID | Residual Risk Description | Impact | Likelihood | Residual Mitigation / Operator Responsibility |
|---|---|---|---|---|
| **RR-01** | **NAND Flash Wear-Leveling / Over-Provisioning**: Logical block overwriting cannot guarantee physical erasure of retired flash blocks or wear-leveling spare area on SSDs. | High | Inherent | **Classified as `SANITIZATION_NOT_VERIFIABLE`**. Operator must use ATA Secure Erase, NVMe Sanitize, or physical shredding for top-secret classification. |
| **RR-02** | **Root / Kernel Compromise**: An adversary with root/SYSTEM level kernel access can bypass OS-level locks or modify SQLite files directly. | Critical | Low | Deploy on dedicated, isolated sanitization kiosk appliances with WORM log export. |
| **RR-03** | **Host Re-imaging / Volatile Data Loss**: Testing software in dev environment. | Medium | Low | Strict isolation between DEV, TEST, and PROD configurations. |
