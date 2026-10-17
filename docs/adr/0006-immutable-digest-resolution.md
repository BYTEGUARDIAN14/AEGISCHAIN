# ADR-0006: Immutable Digest Resolution Before Any Decision Making

- Status: Accepted
- Date: 2026-10-17
- Deciders: AegisChain Architecture Team
- Consulted: Platform Engineering, Kubernetes Operators

## Context and Problem Statement

OCI container image tags (such as `:latest`, `:v1.2.0`, `:staging`) are mutable pointers. An attacker with registry access can overwrite an approved tag with a malicious payload after a signature check has passed (Time-of-Check to Time-of-Use / TOCTOU vulnerability, also known as tag retargeting).

Furthermore, multi-platform images contain an OCI Image Index (manifest list) pointing to architecture-specific manifests.

## Decision Drivers

- Absolute prevention of tag retargeting / TOCTOU attacks.
- Exact reproducibility between verification time and node runtime pull.
- Transparent rewriting via mutating webhook (when enabled) to pin workload specs to digests.

## Considered Options

1. **Option 1: Mandatory Tag-to-Digest Resolution Before Evaluation + Optional Mutating Rewriting**
2. **Option 2: Allow Tag References if Signature on Tag Manifest is Valid**
3. **Option 3: Require Developers to Hardcode Digests in Helm Charts and Kubernetes Manifests**

## Decision Outcome

Chosen option: **Option 1**.

### Architectural Invariants

1. **Early Resolution**: The Trust Engine resolves any incoming image reference (`name:tag`) to its canonical SHA-256 digest (`name@sha256:...`) against the registry before performing any signature, attestation, or policy evaluation.
2. **Multi-Architecture Handling**: When resolving an Image Index, AegisChain verifies both the index manifest digest and the architecture-specific child manifest (matching the target Kubernetes cluster node architecture).
3. **Mutating Webhook**: When `mutateImageDigests: true` is configured in `TrustPolicy`, the admission webhook mutates the Pod spec, rewriting mutable tags to immutable digests and annotating the Pod with the resolved digest and decision ID.

## Compliance and Standards Mapping

- **CIS Kubernetes Benchmark**: Section 5.5 (Ensure image vulnerability scanning and digest pinning).
- **SLSA v1.0**: Requirement that software artifacts are identified by cryptographic digest.
