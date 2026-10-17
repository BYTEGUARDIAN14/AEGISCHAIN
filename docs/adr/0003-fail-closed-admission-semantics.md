# ADR-0003: Fail-Closed Admission Semantics and Break-Glass Protocol

- Status: Accepted
- Date: 2026-10-17
- Deciders: AegisChain Architecture Team
- Consulted: Security Operations, Platform Reliability

## Context and Problem Statement

Kubernetes ValidatingWebhookConfigurations configure `failurePolicy: Fail` (fail-closed) or `failurePolicy: Ignore` (fail-open). If the admission webhook becomes unreachable or experiences backend timeout, `Fail` blocks all pod mutations, while `Ignore` permits unverified images to run in production.

We must define the operational model for AegisChain in production enterprise clusters.

## Decision Drivers

- Zero unauthorized or tampered software reaching protected production namespaces.
- SRE survivability during catastrophic control-plane or webhook outages.
- Clear distinction between `audit` mode (non-blocking monitoring) and `enforce` mode (strict blocking).
- Fully logged, tamper-evident emergency override capability (Break-Glass).

## Considered Options

1. **Option 1: Hard Fail-Closed (`failurePolicy: Fail`) with Cryptographic Break-Glass**
2. **Option 2: Fail-Open (`failurePolicy: Ignore`) with Asynchronous Alerting**
3. **Option 3: Dynamic Fallback based on registry ping status**

## Decision Outcome

Chosen option: **Option 1 (Fail-Closed with Cryptographic Break-Glass)**.

### Policy Rules

1. Protected namespaces (e.g., `prod`, `finance`, `payment`) enforce `failurePolicy: Fail`.
2. Staging and development namespaces operate under `audit` mode where policy violations emit warnings, audit logs, and `PolicyReport` objects, but allow pod scheduling.
3. System namespaces (`kube-system`, `aegischain-system`) are excluded via `namespaceSelector` to prevent circular deadlocks during cluster bootstrap.
4. **Break-Glass Mechanism**: An emergency pod annotation (`aegischain.dev/break-glass-token`) permits deployment if signed by a designated emergency authorization key with a mandatory, non-extendable expiration timestamp (maximum 2 hours). Break-glass activations are immediately recorded to the tamper-evident ledger and trigger a critical P1 alert.

### Positive Consequences

- Prevents attacker evasion via denial-of-service against the admission controller.
- Ensures non-bypassable guarantees in compliance-regulated environments.
- Emergency procedures are auditable and time-bounded.

### Negative Consequences and Tradeoffs

- A total outage of the admission webhook will prevent new pod creation in protected namespaces until resolved or break-glass is invoked.

## Pros and Cons of the Options

### Option 1: Fail-Closed with Break-Glass

- Good, because strictly guarantees zero unvetted code execution.
- Good, because break-glass actions generate immutable audit evidence.
- Bad, because webhook bugs can block deployments if not properly mitigated by high-availability replicas and circuit-breaking.

### Option 2: Fail-Open

- Good, because avoids production deployment blockage during webhook failure.
- Bad, because attackers can intentionally DoS the webhook to bypass all verification gates.

## Compliance and Standards Mapping

- **NIST SP 800-53**: AC-3 (Access Enforcement), AU-2 (Audit Events).
- **PCI DSS v4.0**: Requirement 6.4.1 (Protecting software integrity).
