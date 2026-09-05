# SecureWipe Phase 5 — Compliance & Device Lifecycle Architecture

**Document Version:** 1.0  
**Date:** 2026-09-02  
**Status:** Phase 5 — Implemented (Core), Architecture Ready (Integrations)

---

## Table of Contents

1. [Executive Summary](#executive-summary)
2. [Lifecycle Overview](#lifecycle-overview)
3. [Architecture Components](#architecture-components)
4. [Data Flow](#data-flow)
5. [Database Schema Overview](#database-schema-overview)
6. [Security Design](#security-design)
7. [Offline-First Behavior](#offline-first-behavior)
8. [API Architecture](#api-architecture)

---

## Executive Summary

SecureWipe Phase 5 introduces a structured Compliance & Device Lifecycle subsystem that extends the core sanitization engine with:

- **Compliance Certificate Engine** — generates structured, integrity-hashed sanitization certificates for completed wipe operations
- **Lifecycle Decision Engine** — policy-driven assessment of whether a device should be reused, resold, or disposed of securely
- **Audit Trail Architecture** — append-only, integrity-hashed event log for all lifecycle events
- **Integration Adapter Layer** — defined interfaces for e-waste recycler APIs, GRC platforms, and government portals

> **Scope Boundary:** Phase 5 delivers the core certificate and decision engines as fully implemented features. External integrations (e-waste APIs, GRC platforms, GeM) are architecture-ready interfaces awaiting real API specifications and credentials from external organizations. No government certifications or third-party approvals are claimed.

---

## Lifecycle Overview

The complete SecureWipe device lifecycle flows from initial detection through sanitization verification, adaptive decision, and finally compliance record generation — covering both reuse and secure disposal pathways.

```
Device Detection
     ↓
Storage Inspection
     ↓
Sanitization (Engine: NIST/DoD/AES)
     ↓
Verification (Multi-mode)
     ↓
Recovery Assessment (Forensic Carver)
     ↓
Adaptive Decision Engine
     ↓
┌─────────────────────────────────────────┐
│     Compliance Service (Phase 5)         │
│  Certificate Engine  Decision Engine     │
│  Audit Trail        Integration Layer    │
└─────────────────────────────────────────┘
     ↓                    ↓
Reuse / Resale       Disposal Workflow
     ↓                    ↓
Compliance Record    Recycler Handover
                         ↓
                 Disposal Evidence
```

### Lifecycle States

| State | Trigger | Next Action |
|-------|---------|-------------|
| `SANITIZED_REUSABLE` | Wipe verified, no residual data detected | Issue certificate, mark for reuse/resale |
| `SANITIZATION_NOT_VERIFIABLE` | SSD/NVMe/Flash where physical NAND erasure cannot be confirmed | Recommend alternate method or physical destruction |
| `SANITIZATION_FAILED` | Verification detected residual data or errors | Mandatory secure disposal |
| `DISPOSAL_REQUIRED` | Policy or hardware condition requires disposal | Initiate disposal workflow, recycler handover |

---

## Architecture Components

### Compliance Certificate Engine

**Status: IMPLEMENTED**

The Certificate Engine generates structured sanitization certificates upon completion of a verified wipe operation. Each certificate captures:

- Device identity (serial, model, manufacturer, storage class, capacity)
- Operation identity (operation ID, timestamp, duration)
- Sanitization method applied (NIST 800-88 Clear/Purge, DoD 5220.22-M, AES Crypto-Erase, Gutmann)
- Verification results (mode, samples checked, residual data detected)
- Recovery assessment results (forensic recovery score)
- Assurance status (one of four defined states)
- Operator identity and organizational context
- Integrity digest (SHA-256, computed over all certificate fields)

**Integrity Mechanism:**  
Each certificate has a SHA-256 digest computed deterministically over all certificate fields. This digest detects tampering (integrity). It does **not** provide cryptographic authenticity — it does not prove who generated the certificate. Digital signature infrastructure (Ed25519/RSA via HSM) is architecture-ready but not yet deployed.

**Certificate lifecycle:**

```
Operation Completed
       ↓
CertificateEngine.generate()
       ↓
Assurance Status Assigned
       ↓
SHA-256 Digest Computed
       ↓
Certificate Stored (compliance.db)
       ↓
Audit Event Logged
       ↓
Certificate Available for Export / UI / API
```

---

### Lifecycle Decision Engine

**Status: IMPLEMENTED (DEFAULT, GOVERNMENT, ENTERPRISE profiles core logic)**  
**Status: ARCHITECTURE READY (CORPORATE_IT, RESEARCH profiles)**

The Decision Engine is policy-driven. Each policy profile defines thresholds and rules that determine the lifecycle recommendation for a device.

#### Policy Profiles

| Profile | Description | Status |
|---------|-------------|--------|
| `DEFAULT` | Standard thresholds for general use | IMPLEMENTED |
| `GOVERNMENT` | Stricter thresholds; disposal biased for unverifiable SSDs | IMPLEMENTED (core) |
| `ENTERPRISE` | Enterprise reuse/resale oriented, moderate verification requirements | IMPLEMENTED (core) |
| `CORPORATE_IT` | Corporate IT asset management integration hooks | ARCHITECTURE READY |
| `RESEARCH` | Research/lab context — maximum verification requirements | ARCHITECTURE READY |

#### Decision Logic Inputs

- Assurance status from Certificate Engine
- Verification confidence score
- Recovery assessment score (forensic carver output)
- Device storage class (HDD, SSD, NVMe, Flash, Hybrid)
- Device age and condition metadata
- Active policy profile

#### Decision Outputs

- `lifecycle_recommendation`: REUSE | RESALE | DISPOSE | ADDITIONAL_VERIFICATION_REQUIRED
- `confidence_score`: 0.0 – 1.0
- `rationale`: Human-readable explanation
- `policy_profile_applied`: Name of active profile
- `disposal_method_recommended`: (if applicable) Physical Destruction | Authorized Recycler | Degaussing

---

### Audit Trail Architecture

**Status: IMPLEMENTED**

The Audit Trail is an append-only, integrity-hashed event log. Every significant lifecycle event is recorded.

**Design principles:**

- **Append-only:** No update or delete operations on audit events in the database schema
- **Integrity hashing:** Each event includes a SHA-256 hash of its own content fields, plus a chain hash linking to the previous event's hash (hash chain)
- **Tamper evidence:** Verification procedure re-computes hashes and checks chain continuity; any gap or mismatch is flagged
- **Completeness:** Events cover certificate generation, lifecycle decisions, integration attempts, handover records, and errors

**Event categories:**

| Category | Examples |
|----------|---------|
| `CERTIFICATE` | Generated, verified, exported |
| `LIFECYCLE` | Decision made, recommendation issued |
| `DISPOSAL` | Handover initiated, recycler assigned, evidence received |
| `INTEGRATION` | Adapter invoked, submission status, failure |
| `SYSTEM` | Engine initialized, policy profile changed |

---

### Integration Adapter Layer

**Status: ARCHITECTURE READY — Interfaces IMPLEMENTED, Integrations NOT IMPLEMENTED**

The Integration Adapter Layer defines abstract interfaces for connecting SecureWipe to external systems. No live external integrations are active.

#### Defined Adapter Interfaces

| Adapter | Interface | Current Implementation | External Requirement |
|---------|-----------|----------------------|---------------------|
| E-Waste Recycler | `EwasteAdapter` | `UnimplementedEwasteAdapter` (NOT_CONFIGURED) | Authorized recycler API specification |
| GRC Platform | `GRCAdapter` | `UnimplementedGRCAdapter` (NOT_CONFIGURED) | GRC vendor API credentials |
| Government Portal | `GovPortalAdapter` | Not implemented | GeM/government portal API specification |

> **Important:** No CPCB (Central Pollution Control Board) endpoint is implemented or claimed. The e-waste adapter interface is a defined contract only.

---

## Data Flow

```
[Sanitization Engine] ──> [Compliance Service]
                                   │
                    ┌──────────────┼──────────────┐
                    ↓              ↓               ↓
           [Certificate     [Decision         [Audit Trail
            Engine]          Engine]           Writer]
                    │              │               │
                    └──────────────┴───────────────┘
                                   │
                    ┌──────────────┼──────────────┐
                    ↓              ↓               ↓
              [REST API]    [UI Dashboard]   [Integration
                                              Adapter Layer]
                                                    │
                                        ┌───────────┼───────────┐
                                        ↓           ↓           ↓
                                  [E-Waste]    [GRC]     [Gov Portal]
                                  (NOT IMPL)  (NOT IMPL) (NOT IMPL)
```

---

## Database Schema Overview

**Database:** `compliance.db` (SQLite, local, offline-capable)  
**Tables:** 7

| Table | Purpose | Notes |
|-------|---------|-------|
| `certificates` | Sanitization certificate records | Includes SHA-256 digest field |
| `lifecycle_decisions` | Decision engine outputs per operation | Linked to certificate |
| `audit_events` | Append-only audit trail | Chain hash per event |
| `disposal_handovers` | Recycler handover records | Linked to lifecycle decision |
| `recycler_registry` | Known/registered recycler entities | Admin-managed |
| `integration_submissions` | Outbound integration attempt log | Status tracked per submission |
| `assessment_checklists` | Readiness assessment records | Point-in-time snapshots |

All tables use auto-incrementing integer primary keys and store timestamps in ISO 8601 UTC format.

---

## Security Design

| Concern | Approach | Status |
|---------|----------|--------|
| Certificate tamper detection | SHA-256 digest over all fields | IMPLEMENTED |
| Certificate authenticity | Ed25519/RSA digital signature via HSM | ARCHITECTURE READY |
| Audit trail tamper detection | Per-event hash + chain hash | IMPLEMENTED |
| Database integrity | Local SQLite with application-layer integrity | IMPLEMENTED |
| API authentication | Currently local-only, no auth required | NOT IMPLEMENTED |
| Role-based access control | Planned for Phase 6 | NOT IMPLEMENTED |
| Certificate transport security | HTTPS assumed for any future API exposure | EXTERNAL DEPENDENCY |

> **Known Limitation:** SHA-256 digest alone does not provide cryptographic authenticity. It detects whether the certificate was altered after generation, but does not prove who generated it or that it was generated by an authorized instance of SecureWipe. Digital signatures require PKI/HSM infrastructure not yet deployed.

---

## Offline-First Behavior

SecureWipe Phase 5 is designed to operate fully offline. All core compliance functions — certificate generation, lifecycle decisions, audit trail writing, and local database storage — require no network connectivity.

**Offline-capable operations:**

- Generate sanitization certificates
- Record lifecycle decisions
- Write audit events
- Create disposal handover records
- Run assessment readiness checklists

**Network-required operations (when implemented):**

- Submitting records to external GRC platforms
- Submitting handover records to e-waste recycler APIs
- Government portal submissions

An **Offline Event Queue** (architecture-ready, not yet implemented) will buffer integration submissions when connectivity is unavailable and retry when the network becomes available.

---

## API Architecture

**Status: IMPLEMENTED (15+ endpoints, local only, no authentication)**

Phase 5 exposes a REST API for all compliance operations. All endpoints are currently local-only (no authentication layer implemented).

### Endpoint Groups

| Group | Base Path | Description |
|-------|-----------|-------------|
| Certificates | `/api/v1/compliance/certificates/` | CRUD + verify + export |
| Lifecycle Decisions | `/api/v1/compliance/decisions/` | Get decisions, history |
| Audit Trail | `/api/v1/compliance/audit/` | Query events, verify chain |
| Disposal | `/api/v1/compliance/disposal/` | Handover records, recyclers |
| Integration | `/api/v1/compliance/integration/` | Adapter status, submissions |
| Readiness | `/api/v1/compliance/readiness/` | Assessment checklists |
| Dashboard | `/api/v1/compliance/dashboard/` | Aggregated lifecycle metrics |

> **Phase 6 Requirement:** Role-based access control and API authentication must be implemented before exposing these endpoints over any network interface.

---

*Document generated: 2026-09-02 | SecureWipe Phase 5*
