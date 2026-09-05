# SecureWipe — Tamper-Evident Audit Log Specification

## 1. Purpose & Forensic Scope

The SecureWipe Audit Subsystem provides an immutable, forensically sound, and cryptographically chained event log for all security-sensitive operations.

---

## 2. Event Types & Taxonomy

SecureWipe records the following standardized event taxonomy:

| Event Type | Trigger | Required Payload Fields |
|---|---|---|
| `LOGIN` | User successfully authenticates | `role`, `client_ip` |
| `LOGIN_FAILED` | Failed authentication attempt | `reason`, `client_ip` |
| `LOGOUT` | User session termination | `operator` |
| `DEVICE_DETECTED` | Storage device enumerated | `target`, `model`, `serial`, `size_bytes` |
| `SAFETY_VALIDATED` | Target passed storage safety check | `target`, `target_type`, `canonical_id` |
| `SAFETY_REJECTED` | Target rejected due to safety risk | `target`, `reasons`, `session_id` |
| `CONFIRMATION_REQUESTED` | Stage 1 confirmation initiated | `target`, `method`, `token_nonce` |
| `CONFIRMATION_REJECTED` | Stage 2 confirmation failed | `target`, `reason` |
| `SANITIZATION_STARTED` | Destructive wipe pass initiated | `session_id`, `method`, `canonical_id` |
| `SANITIZATION_COMPLETED` | All sanitization passes completed | `session_id`, `final_state`, `total_iterations`, `tamper_hash` |
| `SANITIZATION_FAILED` | Sanitization failed or aborted | `session_id`, `errors`, `final_state` |
| `CERTIFICATE_GENERATED` | Schema v1.0 certificate signed | `certificate_id`, `assurance_status`, `digest` |
| `CERTIFICATE_VERIFIED` | Certificate signature verified | `certificate_id`, `valid`, `digest_valid`, `signature_valid` |
| `SYSTEM_STARTUP` | Backend service initialized | `version`, `environment` |

---

## 3. Cryptographic Chaining Algorithm

Each event in the SQLite database `audit.db` is linked to its predecessor via SHA-256:

$$\text{CurrentHash} = \text{SHA256}(\text{EventID} \,||\, \text{Timestamp} \,||\, \text{EventType} \,||\, \text{Operator} \,||\, \text{Target} \,||\, \text{PayloadJSON} \,||\, \text{PreviousHash})$$

### Genesis Hash:
The initial event in the audit trail links to the fixed Genesis Hash:
```
GENESIS_00000000000000000000000000000000000000000000000000000000
```

---

## 4. Verification Procedure

The verification engine (`verify_audit_log_integrity()`) performs linear validation across all recorded sequence numbers:

1. **Step 1 — Link Verification**: Compares each event's `previous_hash` against the preceding event's `event_hash`.
2. **Step 2 — Payload Integrity Re-computation**: Reconstructs the canonical string representation and computes SHA-256. Compares with stored `event_hash`.
3. **Step 3 — Anomaly Detection**:
   * If `stored_previous_hash != calculated_previous_hash`: Reports `BROKEN_CHAIN_LINK` (indicates deleted or inserted record).
   * If `recalculated_hash != stored_event_hash`: Reports `MODIFIED_EVENT_DATA` (indicates payload tampering).

---

## 5. Practical Security Guarantees & Boundaries

* **What it guarantees**: Detects any alteration, tampering, deletion, or insertion of audit records within the SQLite database.
* **Boundaries**: If an adversary has write access to the host disk, they could theoretically recalculate the entire chain from the point of tampering forward.
* **Production Recommendation**: Export audit records to an external WORM (Write Once, Read Many) log aggregation service (e.g. Syslog, Splunk, AWS CloudWatch, S3 Object Lock) in enterprise deployments.
