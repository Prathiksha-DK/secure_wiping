# SecureWipe — Device Trust Score & Hardware Health Specification

## 1. Verifiable Trust Score Methodology

The SecureWipe Trust Score (0–100) is **derived exclusively from objective, measurable signals**. The platform rejects arbitrary or fabricated ratings.

---

## 2. Mathematical Scoring Model

$$\text{Trust Score} = \min\left(100, \, S_{\text{cert}} + S_{\text{wipe}} + S_{\text{health}} + S_{\text{owner}} + S_{\text{telemetry}}\right)$$

| Signal Component | Verifiable Criteria | Max Points |
|---|---|---|
| **$S_{\text{cert}}$: Active Certificate** | Cryptographically signed Schema v1.0 certificate exists and has `ACTIVE` status in the ledger. | **40 Points** |
| **$S_{\text{wipe}}$: Verified Sanitization** | Device passed stratified multi-region verifier and 3-level forensic carver. | **25 Points** |
| **$S_{\text{health}}$: Hardware Health** | Hardware SMART telemetry reports overall status as `Healthy` with zero bad/reallocated sectors. | **15 Points** |
| **$S_{\text{owner}}$: Ownership Chain** | Verified single-owner chain with complete onboarding metadata. | **10 Points** |
| **$S_{\text{telemetry}}$: SMART Attributes** | Real SMART telemetry (power-on hours, wear level, operating temperature) is available. | **10 Points** |
| **TOTAL SCORE** | | **100 Points** |

---

## 3. Hardware Health & Telemetry Handling

* **Non-Fabrication Rule**: Telemetry fields (`power_on_hours`, `wear_level`, `temperature_c`, `reallocated_sectors`) are presented only when exposed by real hardware drivers. If unavailable, they are marked as `Unknown` rather than fabricating simulated numbers.
