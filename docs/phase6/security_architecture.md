# SecureWipe — Phase 6 Security Architecture Specification

## 1. Architectural Overview

SecureWipe v6.0 implements a **defense-in-depth, fail-closed security architecture** designed to guarantee storage safety, non-repudiation, tamper evidence, and forensic rigor across all data lifecycle phases.

```
+-----------------------------------------------------------------------------------------+
|                                    SECUREWIPE ARCHITECTURE                              |
|                                                                                         |
|   +-------------------+    HTTPS / Signed Token    +--------------------------------+   |
|   | Next.js Frontend  | -------------------------> | Flask Security-Hardened API    |   |
|   | (Low-Privilege UI)|                            | (Port 9758, Localhost Binding) |   |
|   +-------------------+                            +--------------------------------+   |
|                                                                    |                    |
|                +---------------------------------------------------+                    |
|                |                                                                        |
|   +------------------------+  +------------------------+  +-------------------------+  |
|   | Storage Safety Engine  |  | Two-Stage Confirmation |  | Server-Side RBAC & Auth |  |
|   | - Root/Boot Detection  |  | - Single-Use Nonce     |  | - PBKDF2 (600k iter)    |  |
|   | - Fail-Closed Validator|  | - Phrase Match Check   |  | - HMAC-SHA256 Tokens    |  |
|   | - Hardware Lock Mgr    |  | - Hardware Re-verify   |  | - Administrator/Operator|  |
|   +------------------------+  +------------------------+  +-------------------------+  |
|                |                                                                        |
|   +---------------------------------------------------------------------------------+  |
|   |                     Adaptive Sanitization & Forensic Pipeline                   |  |
|   |  [Target Lock] -> [Multi-Pass Overwrite] -> [Stratified Verify] -> [Carver]    |  |
|   +---------------------------------------------------------------------------------+  |
|                |                                                   |                    |
|   +----------------------------+                     +------------------------------+  |
|   | Tamper-Evident Audit Log   |                     | Certificate Engine v1.0      |  |
|   | - SHA-256 Hash Chaining    |                     | - Canonical JSON Digest      |  |
|   | - Automated Tamper Detect  |                     | - RSA-PSS Digital Signatures |  |
|   +----------------------------+                     +------------------------------+  |
|                                                                                         |
|   +---------------------------------------------------------------------------------+  |
|   | Storage Inspector (Strictly Read-Only: O_RDONLY, Bounded Reads, Zero Mutation)   |  |
|   +---------------------------------------------------------------------------------+  |
+-----------------------------------------------------------------------------------------+
```

---

## 2. Core Security Subsystems

### 2.1 Storage Safety & Anti-Misdirection Subsystem (`storage_safety.py`)
* **Fail-Closed Principle**: If a storage target cannot be positively verified as a non-system storage object, the operation is rejected immediately (`SAFETY_REJECTED`).
* **Root & Boot Protection**:
  * **POSIX / Linux**: Uses `lsblk` and `psutil` to inspect the block device tree, identifying any mountpoint matching `/`, `/boot`, `/boot/efi`, `/etc`, `/usr`, `/var`, `/home`, or the running application workspace.
  * **Windows**: Queries `Get-Partition` to detect `IsBoot`, `IsSystem`, and `DriveLetter == 'C'`, preventing access to `PhysicalDriveX` hosting Windows.
* **Anti-Misdirection (Hardware Fingerprint)**:
  * Computes `Fingerprint = SHA256(Serial || Model || CapacityBytes || BusType || TargetType)`.
  * The fingerprint generated during Stage 1 confirmation is re-verified immediately prior to write lock acquisition in Stage 2.
* **Device Concurrency Lock Manager**:
  * Exclusive mutex per canonical storage target ID (`DISK:<SERIAL>` or `FILE:<PATH>`).
  * Prevents concurrent wipe jobs, race conditions, or simultaneous overwrite processes.

### 2.2 Two-Stage Destructive Confirmation Subsystem (`two_stage_confirmation.py`)
* **Stage 1 (Inspection & Token Issue)**:
  * Generates a signed, single-use token containing target metadata, operator identity, client IP, 300-second expiration, and a unique 128-bit cryptographic nonce.
  * Computes the required confirmation phrase: `CONFIRM-WIPE-<SERIAL>`.
* **Stage 2 (Validation & Execution)**:
  * Verifies HMAC-SHA256 token signature.
  * Validates token has not expired (`exp < now`).
  * Validates single-use nonce (rejection of replay attempts).
  * Enforces exact phrase match (`typed_phrase == confirmation_phrase`).
  * Re-executes `validate_storage_safety` and hardware fingerprint match.

### 2.3 Cryptographic Authentication & RBAC Subsystem (`security_config.py`)
* **Password Hashing**: PBKDF2-HMAC-SHA256 with 600,000 iterations and 16-byte cryptographically secure random salt (`os.urandom(16)`).
* **Signed Session Tokens**: HMAC-SHA256 signed payload containing username, role, expiration, and random nonce.
* **Role Separation**:
  * `ADMINISTRATOR`: Full system access, configuration, user management, and security dashboard review.
  * `OPERATOR`: Device listing, storage inspection, sanitization execution, certificate generation.
  * `AUDITOR`: Read-only access to audit logs, certificates, integrity verification, and compliance statistics.
  * `VIEWER`: Read-only summary stats and history.

### 2.4 Cryptographic Tamper-Evident Audit Subsystem (`audit_log.py`)
* Every security-relevant event appends to an immutable SQLite audit log.
* **Cryptographic Hash Chaining**:
  $$\text{EventHash}_i = \text{SHA256}(\text{EventID}_i \,||\, \text{Timestamp}_i \,||\, \text{EventType}_i \,||\, \text{Operator}_i \,||\, \text{Target}_i \,||\, \text{PayloadJSON}_i \,||\, \text{EventHash}_{i-1})$$
  $$\text{EventHash}_0 = \text{"GENESIS\_00000000000000000000000000000000000000000000000000000000"}$$
* **Verification Engine**: Traverses the chain and mathematically detects payload modification, event deletion (broken chain), and insertion.

### 2.5 Schema v1.0 Certificate Engine & Digital Signatures (`certificate_engine.py`)
* Implements Schema v1.0 standard.
* **Integrity Block**:
  * Canonical JSON serialization (sorted keys, compact separators).
  * SHA-256 canonical digest.
  * RSA-2048/4096 PSS digital signature (`RSA-PSS-SHA256`).
* **Assurance Status Classification**:
  * `SANITIZED_REUSABLE`: Zero residual data detected on HDD / magnetic storage.
  * `SANITIZATION_NOT_VERIFIABLE`: SSD, NVMe, USB Flash (honest technical recognition of wear-leveling limits).
  * `SANITIZATION_FAILED`: Verification failure or residual carver artifacts.

### 2.6 Storage Inspector Read-Only Isolation (`storage_inspector.py`)
* Strictly opens devices with `O_RDONLY` / `rb` modes.
* Bounded reads (maximum 64KB per sector request, bounded streaming pattern searches).
* Never requests or opens write descriptors.
