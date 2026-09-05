# SecureWipe — Security Operations & Incident Response Guide

## 1. Routine Security Operations

### 1.1 Daily Audit Trail Verification
Automated cron or administrator check:
```bash
curl -s http://127.0.0.1:9758/api/security/audit-verify | jq .
```
Expected Output:
```json
{
  "status": "PASS",
  "chain_valid": true,
  "total_events": 1420,
  "verified_events": 1420
}
```

### 1.2 System Security Diagnostic Inspection
```bash
curl -s http://127.0.0.1:9758/api/security/status | jq .
```
Expected: `overall_security: "PASS"`, `production_readiness: "READY"`.

---

## 2. Certificate Verification for Compliance Auditors

To independently verify a sanitization certificate:
```bash
curl -X POST http://127.0.0.1:9758/api/compliance/certificates/<CERT_ID>/verify | jq .
```
Expected Output:
```json
{
  "valid": true,
  "digest_valid": true,
  "signature_valid": true,
  "signing_key_id": "SECUREWIPE-CA-9A7B3E"
}
```

---

## 3. Incident Response Procedures

### 3.1 Incident 1: Audit Log Tampering Detected (`BROKEN_CHAIN_LINK` / `MODIFIED_EVENT_DATA`)
1. **Immediate Isolation**: Stop the sanitization service to prevent further log writes.
2. **Identify Compromised Sequence**: The verification response provides the exact `compromised_sequence` and `compromised_event_id`.
3. **Forensic Database Inspection**: Compare `audit.db` against the external WORM log or daily backup to determine what record was altered or removed.
4. **Invalidate Affected Certificates**: Any certificates generated around the timestamp of the tampered event must be marked for review.

### 3.2 Incident 2: Anti-Misdirection Triggered (`ANTI-MISDIRECTION ABORT`)
1. **Root Cause Analysis**: Device was replaced or re-enumerated between Stage 1 confirmation and Stage 2 execution.
2. **Audit Event**: Check event `SAFETY_REJECTED` in audit log for serial numbers involved.
3. **Physical Inspection**: Inspect physical storage connection to verify drive was not unintentionally swapped.

### 3.3 Incident 3: CA Private Key Compromise
1. **Revoke CA Public Key**: Distribute key revocation notice to downstream auditors and asset management platforms.
2. **Regenerate Signing Keypair**:
   ```bash
   rm /var/lib/securewipe/data/keys/ca_private_key.pem
   rm /var/lib/securewipe/data/keys/ca_public_key.pem
   # Restarting service automatically creates a new keypair and unique key ID
   ```
3. **Re-sign Active Certificates**: Re-issue valid certificates using the new CA key.
