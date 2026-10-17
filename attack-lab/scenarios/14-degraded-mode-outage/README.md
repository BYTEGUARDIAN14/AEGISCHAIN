# Scenario 14: Upstream Outage & Degraded Mode Handling

## Real-World Incident Context
Mirrors distributed denial of service (DDoS) or network outages impacting upstream dependencies (e.g. OCI registry failure, Rekor transparency log downtime, or internal risk scorer network timeout).

## Attack Vector / Evaluation
The platform tests failure behavior under simulated service outages:
1. **Enforce Mode (Fail-Closed)**: When an upstream dependency fails and verification cannot be completed, the admission controller strictly fails closed (`failurePolicy: Fail`), denying unverified workloads.
2. **Audit Mode (Observable)**: In non-production/staging namespaces configured with `mode: audit`, the failure is logged to the ledger and admitted with an explicit degraded-mode warning annotation.

## Expected Verdict
- **Enforce Mode**: `DENY` (Fail-Closed: Circuit breaker active, unverified workload rejected)
- **Audit Mode**: `ALLOW_WITH_AUDIT_WARNING` (Observable fallback logged to metrics and ledger)
- **Remediation**: `Check network connectivity to OCI registry and dependency risk scorer; use signed Break-Glass token if emergency bypass required`
