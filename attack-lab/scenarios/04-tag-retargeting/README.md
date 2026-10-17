# Scenario 04: Mutable Tag Retargeting (TOCTOU Attack)

## Real-World Incident Context
Mirrors Time-of-Check to Time-of-Use (TOCTOU) tag mutability attacks where an attacker moves an approved tag (e.g. `v1.0.0` or `latest`) to point to a completely different, unverified manifest after security review has approved the tag name.

## Attack Vector / Evaluation
A workload specifies a mutable tag reference `app:v1.0.0`. AegisChain admission controller immediately resolves the tag to its immutable SHA-256 digest at evaluation time and compares it against the approved digest record, blocking tag re-pointing.

## Expected Verdict
- **Verdict**: `DENY`
- **Trust Score**: `0 / 100`
- **Failing Rule**: `digest_pinning_required`
- **Reason**: `Mutable tag reference resolves to an unapproved digest; digest pinning required`
- **Remediation**: `Deploy workloads using immutable SHA-256 digests (@sha256:...) or enable AegisChain tag-to-digest mutating webhook`
