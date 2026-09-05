# SecureWipe — Two-Stage Destructive Confirmation Flow

## 1. Objective

To prevent accidental, inadvertent, or automated data destruction, all destructive sanitization operations in SecureWipe require an **explicit, two-stage cryptographic confirmation protocol**.

---

## 2. Confirmation Protocol Sequence

```
Operator/UI                                Backend Server                            Target Device
    |                                             |                                        |
    | 1. POST /api/sanitization/confirm-stage1    |                                        |
    |    { target: "/dev/sdb", method: "dod" }   |                                        |
    | ------------------------------------------> |                                        |
    |                                             | Validate Safety & Extract Metadata     |
    |                                             | Compute Hardware Fingerprint           |
    |                                             | Generate Signed Token + Nonce          |
    | 2. Response 200 OK                          |                                        |
    |    { status: "CONFIRMATION_REQUIRED",       |                                        |
    |      device_summary: {...},                 |                                        |
    |      confirmation_token: "...",             |                                        |
    |      required_phrase: "CONFIRM-WIPE-SN123" }|                                        |
    | <------------------------------------------ |                                        |
    |                                             |                                        |
    | [Operator reviews hardware summary &        |                                        |
    |  types required confirmation phrase]        |                                        |
    |                                             |                                        |
    | 3. POST /api/sanitization/start             |                                        |
    |    { target, method, confirmation_token,    |                                        |
    |      typed_phrase: "CONFIRM-WIPE-SN123" }   |                                        |
    | ------------------------------------------> |                                        |
    |                                             | 1. Verify HMAC Token Signature         |
    |                                             | 2. Verify Token Expiration (<300s)     |
    |                                             | 3. Verify Single-Use Nonce (Anti-Replay|
    |                                             | 4. Match Typed Phrase                  |
    |                                             | 5. Re-Verify Hardware Fingerprint      |
    |                                             | 6. Acquire Device Lock                 |
    |                                             |                                        |
    | 4. Response 200 OK { session_id: "..." }    |                                        |
    | <------------------------------------------ |                                        |
    |                                             | 5. Execute Multi-Pass Overwrite -----> | Destructive I/O
```

---

## 3. Cryptographic Confirmation Token Structure

The Stage 1 Confirmation Token is an HMAC-SHA256 signed JWT-style token containing:

```json
{
  "target": "/dev/sdb",
  "canonical_id": "DISK:SN-WD12345678",
  "target_type": "disk",
  "method": "dod-3pass",
  "operator": "Madhan",
  "fingerprint": "a3f89e81b6728c...",
  "confirmation_phrase": "CONFIRM-WIPE-SN-WD12345678",
  "client_ip": "127.0.0.1",
  "iat": 1772620000,
  "exp": 1772620300,
  "nonce": "7c88b901e38944fa"
}
```

---

## 4. Security Assertions & Guarantees

1. **Explicit Intent**: Sanitization cannot be triggered by a single button click or CSRF attack.
2. **Replay Protection**: The unique `nonce` is marked as consumed immediately upon first validation. Replay attempts are rejected with `REPLAY_ATTACK_DETECTED`.
3. **Time-Bounded**: Tokens expire after 300 seconds (5 minutes). Stale tokens are rejected.
4. **Anti-Misdirection**: The live hardware fingerprint of the connected storage must match the token's embedded fingerprint.
