# Scenario 02: Unsigned Container Image

## Real-World Incident Context
Mirrors unauthorized ad-hoc production deployments and Shadow IT rollouts where developers bypass CI/CD gates to push images directly from personal laptops to Kubernetes clusters.

## Attack Vector / Evaluation
An attacker attempts to deploy a standard public registry image (`registry:2` or custom build) that has zero cryptographic signatures and zero Sigstore attestations.

## Expected Verdict
- **Verdict**: `DENY`
- **Trust Score**: `50 / 100` (or lower)
- **Failing Rule**: `signature_required`
- **Reason**: `Artifact has zero valid cryptographic signatures`
- **Remediation**: `Configure hardened GitHub Actions CI pipeline to sign release images using Cosign keyless identity`
