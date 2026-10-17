# ADR-0002: Embedded OPA Policy Decision Point Over External Sidecar

- Status: Accepted
- Date: 2026-10-17
- Deciders: AegisChain Architecture Team
- Consulted: Platform SRE, Performance Engineering

## Context and Problem Statement

Kubernetes admission webhooks must evaluate incoming Pod requests against complex security policies under strict latency constraints. The Kubernetes API server default webhook timeout is 10 seconds, but production latency budgets demand sub-300ms p95 response times.

We must decide whether to evaluate Rego v1 policies using:
1. In-process embedded Open Policy Agent (OPA) Go library.
2. An external OPA daemon running as a sidecar or dedicated cluster service accessed over HTTP/gRPC.

## Decision Drivers

- Target admission path p95 latency under 300ms with warm cache.
- Reliability under network partition or high request concurrency.
- Zero inter-process network overhead and reduced failure domains.
- Ability to hot-reload signed policy bundles from memory or local cache.

## Considered Options

1. **Option 1: Embedded OPA as a Go Library (`github.com/open-policy-agent/opa/rego`)**
2. **Option 2: OPA daemon as a Kubernetes Sidecar (HTTP REST /v1/data)**
3. **Option 3: External Cluster-Wide Gatekeeper / OPA Deployment**

## Decision Outcome

Chosen option: **Option 1 (Embedded OPA)**.

### Positive Consequences

- Direct in-memory query execution eliminates TCP socket handshakes, serialization, and context switches.
- Evaluation latency drops to single-digit milliseconds (<10ms).
- Atomic hot-reloading of policy bundles via memory swap without restarting the admission controller.
- Fewer container processes per Pod, simplifying resource allocation and eliminating sidecar crashloop cascading failures.

### Negative Consequences and Tradeoffs

- Go binary size increases by ~30MB due to embedded Rego compiler and runtime dependencies.
- Memory consumption of the webhook process is proportional to the size of policy datasets and bundles cached in memory.

## Pros and Cons of the Options

### Option 1: Embedded OPA

- Good, because zero network latency and maximum deterministic execution.
- Good, because unified logging, telemetry, and decision hashing occur in one process.
- Bad, because policy evaluation cannot be scaled independently of the webhook binary.

### Option 2: Sidecar OPA

- Good, because leverages stock upstream OPA container images.
- Bad, because adds localhost HTTP roundtrip (5-15ms) and double JSON serialization overhead.

### Option 3: External Gatekeeper Service

- Good, because centralized management across disparate platforms.
- Bad, because network jitter, cross-node hops, and admission controller timeouts lead to degraded cluster availability.

## Compliance and Standards Mapping

- **NIST SP 800-218**: PW.8.1 (Reviewing software against security requirements).
- **SLSA v1.0**: Verifier policy engine encapsulation.
