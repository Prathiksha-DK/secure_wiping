# SecureWipe Phase 5 — Integration Architecture

**Document Version:** 1.0  
**Date:** 2026-09-02  
**Status:** Interfaces IMPLEMENTED — External Integrations NOT IMPLEMENTED

---

## Table of Contents

1. [Design Philosophy](#design-philosophy)
2. [Integration Status Model](#integration-status-model)
3. [E-Waste Integration Adapter](#e-waste-integration-adapter)
4. [GRC Integration Adapter](#grc-integration-adapter)
5. [Government/Procurement Adapter](#governmentprocurement-adapter)
6. [Offline Queue Architecture](#offline-queue-architecture)
7. [Security Requirements for Integrations](#security-requirements-for-integrations)

---

## Design Philosophy

SecureWipe Phase 5 integrations are built on three foundational principles:

### Adapter Pattern

All external integrations are implemented through a defined abstract interface (adapter contract). The core compliance engine communicates only with the adapter interface — never directly with external APIs. This means:

- External API changes require only a new adapter implementation, not changes to the core engine
- The adapter interface can be tested and documented without requiring external API access
- The `UnimplementedAdapter` base class provides a safe fallback that returns `NOT_CONFIGURED` status instead of failing

### Offline-First

SecureWipe does not require network connectivity for any core compliance function. Certificates are generated locally, lifecycle decisions are computed locally, and audit events are written to a local database. Integration with external systems is an optional, additive layer.

When an integration is invoked and the network is unavailable (or the adapter is not configured), the event is recorded in the local audit trail with status `OFFLINE_QUEUED` or `NOT_CONFIGURED`. No data is lost.

### Explicit Status

Every integration attempt results in an explicit, recorded status. The integration layer never silently fails. All outcomes — success, failure, not configured, offline, error — are recorded in `integration_submissions` and the audit trail.

---

## Integration Status Model

Every integration submission record carries one of the following seven status values:

| Status | Value | Description |
|--------|-------|-------------|
| `NOT_CONFIGURED` | 0 | Adapter is defined but no external endpoint has been configured. The `UnimplementedAdapter` returns this status. No network call is made. |
| `PENDING` | 1 | A submission has been queued but not yet attempted. |
| `IN_PROGRESS` | 2 | A submission attempt is currently in progress (network call outstanding). |
| `SUBMITTED` | 3 | The submission was accepted by the external system. A reference ID from the external system is recorded. |
| `CONFIRMED` | 4 | The external system has confirmed receipt and processing of the submission. |
| `FAILED` | 5 | The submission attempt failed (network error, API rejection, invalid credentials). Error details are recorded. |
| `OFFLINE_QUEUED` | 6 | The system was offline when submission was attempted. The record is queued for retry when connectivity is restored. |

> **Implementation note:** Only `NOT_CONFIGURED` and `FAILED` statuses are currently reachable in practice, since no live external adapters are implemented. `SUBMITTED`, `CONFIRMED`, and `OFFLINE_QUEUED` will become reachable once live adapters are deployed.

---

## E-Waste Integration Adapter

### Purpose

The E-Waste adapter enables SecureWipe to submit disposal handover records to authorized e-waste recycler portals. A disposal handover record includes the device identity, sanitization certificate reference, assurance status, and handover metadata.

### Interface Specification

The `EwasteAdapter` abstract interface defines the following contract:

```python
class EwasteAdapter(ABC):

    @abstractmethod
    def get_adapter_name(self) -> str:
        """Return a human-readable name for this adapter."""
        ...

    @abstractmethod
    def get_integration_status(self) -> IntegrationStatus:
        """Return current configuration/connectivity status."""
        ...

    @abstractmethod
    def submit_handover(
        self,
        handover_record: DisposalHandoverRecord,
        certificate: SanitizationCertificate,
    ) -> IntegrationSubmissionResult:
        """
        Submit a disposal handover record to the recycler portal.

        Returns an IntegrationSubmissionResult with:
          - status: IntegrationStatus
          - external_reference_id: str | None
          - submitted_at: datetime | None
          - error_message: str | None
          - raw_response: dict | None
        """
        ...

    @abstractmethod
    def check_submission_status(
        self, external_reference_id: str
    ) -> IntegrationSubmissionResult:
        """Check the status of a previously submitted handover record."""
        ...

    @abstractmethod
    def get_registered_recyclers(self) -> list[RecyclerInfo]:
        """Return list of recyclers accessible through this adapter."""
        ...
```

### Current Implementation: `UnimplementedEwasteAdapter`

**Status: NOT_CONFIGURED**

The `UnimplementedEwasteAdapter` is the default implementation provided with Phase 5. Its behavior:

- `get_integration_status()` returns `IntegrationStatus.NOT_CONFIGURED`
- `submit_handover()` records the attempt as `NOT_CONFIGURED`, returns without network call
- `check_submission_status()` returns `NOT_CONFIGURED`
- `get_registered_recyclers()` returns empty list

This ensures the compliance engine operates safely without crashing when no recycler API is configured.

### What Is Needed to Implement a Live Adapter

To implement a functional e-waste recycler adapter, the following are required:

1. **Recycler API specification** — endpoint URLs, authentication method (API key, OAuth2, mutual TLS), request schema, response schema, error codes
2. **Verified recycler authorization** — confirmation that the recycler is authorized under applicable regulations (in India: CPCB authorization under E-Waste Management Rules)
3. **Test environment credentials** — sandbox API credentials for development and testing
4. **Production credentials** — securely stored API credentials for production use
5. **Data agreement** — formal data sharing agreement defining what device and operator data can be transmitted

> **IMPORTANT: No CPCB (Central Pollution Control Board) API endpoint is implemented or claimed.**
>
> The CPCB manages authorization of e-waste recyclers in India under the E-Waste (Management) Rules. SecureWipe does not have an integration with any CPCB system, portal, or API. The adapter interface is a technical contract only. Actual integration requires engagement with a CPCB-authorized recycler who exposes an API — which is an external organizational dependency.

---

## GRC Integration Adapter

### Purpose

The GRC (Governance, Risk & Compliance) adapter enables SecureWipe to submit sanitization certificates and lifecycle events to enterprise GRC platforms. This supports audit evidence collection for standards such as ISO 27001, SOC 2, and similar frameworks.

### Interface Specification

```python
class GRCAdapter(ABC):

    @abstractmethod
    def get_adapter_name(self) -> str:
        """Return a human-readable name for this adapter."""
        ...

    @abstractmethod
    def get_integration_status(self) -> IntegrationStatus:
        """Return current configuration/connectivity status."""
        ...

    @abstractmethod
    def submit_certificate(
        self,
        certificate: SanitizationCertificate,
        evidence_context: EvidenceContext,
    ) -> IntegrationSubmissionResult:
        """
        Submit a sanitization certificate as evidence to the GRC platform.

        evidence_context carries:
          - control_id: str     — the GRC control being evidenced
          - audit_period: str   — audit period identifier
          - evidence_type: str  — category label for this evidence
          - notes: str | None
        """
        ...

    @abstractmethod
    def submit_audit_events(
        self,
        events: list[AuditEvent],
        context: EvidenceContext,
    ) -> IntegrationSubmissionResult:
        """Submit audit trail events as evidence."""
        ...

    @abstractmethod
    def check_submission_status(
        self, external_reference_id: str
    ) -> IntegrationSubmissionResult:
        """Check status of a prior submission."""
        ...
```

### Current Implementation

**Status: NOT_CONFIGURED — `UnimplementedGRCAdapter` only**

No live GRC adapter is implemented. The `UnimplementedGRCAdapter` follows the same pattern as the e-waste adapter: all methods return `NOT_CONFIGURED` without making any network calls.

### Supported Future Platforms (Conceptual Only — NOT IMPLEMENTED)

The following platforms are named as targets for future adapter implementations. **These are conceptual plans only. No integration with any of these platforms is currently active.**

| Platform | Type | Status |
|----------|------|--------|
| ServiceNow GRC | Enterprise GRC | CONCEPTUAL ONLY |
| Archer RSA | Enterprise GRC | CONCEPTUAL ONLY |
| MetricStream | Enterprise GRC | CONCEPTUAL ONLY |
| OneTrust | Privacy/GRC | CONCEPTUAL ONLY |
| Vanta | SOC 2 automation | CONCEPTUAL ONLY |
| Drata | Compliance automation | CONCEPTUAL ONLY |

### What Is Needed to Implement a Live GRC Adapter

1. **GRC platform API specification** — REST or GraphQL endpoint, authentication method, evidence submission schema
2. **GRC vendor API credentials** — organization-specific API keys or service account credentials
3. **Control mapping** — mapping of SecureWipe lifecycle events to the GRC platform's control framework
4. **Evidence format requirements** — how the GRC platform expects evidence structured (e.g., attachment format, metadata fields)
5. **Test environment** — sandbox GRC instance for integration testing

---

## Government/Procurement Adapter

### GeM Context

GeM (Government e-Marketplace) is India's public procurement platform operated by the Ministry of Commerce and Industry. It is a **procurement and distribution channel** — a marketplace where government buyers discover and purchase products and services from registered sellers.

**GeM is not a software feature of SecureWipe.** Listing on GeM is an organizational/commercial process:

1. The selling organization registers on GeM as a seller
2. The organization creates a product/service listing
3. Government buyers discover and purchase through the GeM portal
4. Transactions and fulfillment occur outside SecureWipe's software

> **WARNING: SecureWipe is not listed on GeM. This is not claimed.**
>
> No `GovPortalAdapter` for GeM is implemented. Any future GeM-related integration would be an API for submitting procurement documentation or compliance certificates as part of a tender response — not a feature that makes SecureWipe "GeM-ready" by itself.

### Government Adapter Interface (NOT IMPLEMENTED)

A `GovPortalAdapter` interface is identified for future design but has not been specified or implemented in Phase 5. The requirements are:

- Government portal API specification (not publicly available; requires engagement with relevant ministry/agency)
- Organizational registration and authentication credentials
- Formal procurement documentation

---

## Offline Queue Architecture

**Status: CONCEPTUAL — Not Implemented**

The Offline Queue is designed to buffer integration submissions when connectivity is unavailable and automatically retry when the network becomes reachable.

### Conceptual Design

```
Integration Attempt
       ↓
Network Available?
   Yes → Submit directly → Record result
   No  → Write to OfflineQueue (local DB)
              ↓
       Connectivity Monitor
              ↓ (network restored)
       Queue Processor
              ↓
       Retry submission(s)
              ↓
       Update submission record
              ↓
       Write audit event
```

### Queue Record Fields (Planned Schema)

| Field | Type | Description |
|-------|------|-------------|
| `queue_id` | UUID | Unique queue entry identifier |
| `adapter_type` | enum | `EWASTE`, `GRC`, `GOV_PORTAL` |
| `payload` | JSON | Serialized submission payload |
| `created_at` | datetime | When the queue entry was created |
| `retry_count` | integer | Number of retry attempts made |
| `last_retry_at` | datetime | Timestamp of most recent retry attempt |
| `next_retry_at` | datetime | Scheduled time for next retry attempt |
| `max_retries` | integer | Maximum allowed retry attempts |
| `status` | enum | `QUEUED`, `RETRYING`, `SUBMITTED`, `FAILED_PERMANENT` |
| `error_history` | JSON array | List of error messages from each failed attempt |

### Retry Policy (Planned)

- Exponential backoff starting at 60 seconds
- Maximum retry interval: 24 hours
- Maximum retry count: configurable (default: 10)
- Permanent failure after max retries exceeded — alert generated, manual intervention required

---

## Security Requirements for Integrations

The following security controls are required before any live external integration is enabled:

| Requirement | Description | Status |
|-------------|-------------|--------|
| Transport encryption | All API calls must use TLS 1.2 or higher | REQUIRED — not validated (no live integrations) |
| Certificate validation | TLS certificates must be validated; no self-signed cert acceptance in production | REQUIRED |
| Credential storage | API keys/secrets must not be stored in plaintext in configuration files or source code | REQUIRED |
| Credential rotation | Support for API key rotation without downtime | REQUIRED |
| Data minimization | Only transmit data fields required by the receiving system | REQUIRED |
| Audit logging | Every integration attempt (success and failure) must be logged in the audit trail | IMPLEMENTED (for local audit) |
| Error handling | Integration failures must not propagate exceptions that crash the core compliance engine | IMPLEMENTED (adapter isolation) |
| Input validation | Responses from external APIs must be validated before processing | REQUIRED |
| Rate limiting | Implement backoff and rate limiting to respect external API limits | REQUIRED |
| Authentication | API authentication must use the method required by each external system | EXTERNAL DEPENDENCY |

> **CAUTION: Do not expose SecureWipe's Phase 5 REST API over a network interface without first implementing authentication and role-based access control.** The current implementation is designed for local/localhost use only.

---

*Document generated: 2026-09-02 | SecureWipe Phase 5*
