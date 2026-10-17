# AegisChain Policy Guide and Risk Scoring Weights

## 1. Production Rego v1 Policies

AegisChain evaluates eight core security policies on every admission request:

### Policy 1: `signature_required`
- **Objective**: Ensure the container image carries a valid cryptographic signature issued by a trusted identity.
- **Rule**:
  ```rego
  default allow = false
  allow if {
      input.signature.valid == true
      input.signature.issuer == data.trusted.oidc_issuer
      regex.match(data.trusted.identity_regex, input.signature.identity)
      input.signature.rekor_verified == true
  }
  ```

### Policy 2: `provenance_required`
- **Objective**: Verify that the image was built by an approved builder (e.g., GitHub Actions SLSA generator) from the authoritative source repository and branch.
- **Rule**:
  - `predicateType == "https://slsa.dev/provenance/v1"`
  - `builder.id == data.trusted.builder_id`
  - `source.repository == expected_repo`
  - `source.ref == "refs/heads/main"` or approved release tag
  - `subject.digest == input.subject.digest`

### Policy 3: `sbom_required`
- **Objective**: Guarantee that a machine-readable SBOM (CycloneDX or SPDX) is cryptographically attested to the image digest.
- **Rule**:
  - SBOM attestation present and uncorrupted.
  - Component count within expected boundaries (e.g., > 5 components).

### Policy 4: `vulnerability_gate`
- **Objective**: Block images containing critical vulnerabilities or actively exploited CVEs.
- **Rule**:
  - Zero un-waived Critical vulnerabilities.
  - High vulnerabilities must not exceed configured namespace threshold (default: 5).
  - CISA Known Exploited Vulnerabilities (KEV) membership unconditionally blocks unless accompanied by a cryptographically signed OpenVEX `not_affected` statement.

### Policy 5: `base_image_allowlist`
- **Objective**: Ensure container images derive exclusively from audited, minimal base distributions (e.g., Distroless, Chainguard, Alpine minimal).
- **Rule**: Base image layer digest matches an entry in `policies/data/base_images.json`.

### Policy 6: `dependency_risk_gate`
- **Objective**: Intercept packages exhibiting supply chain attack indicators (typosquatting, dependency confusion, install script exfiltration).
- **Rule**: Dependency composite risk score must not exceed the namespace threshold (default: 65). Any package classified as `known_malicious` or `confirmed_typosquat` results in an immediate hard block.

### Policy 7: `freshness`
- **Objective**: Prevent rollback attacks where an older, signed image with unpatched vulnerabilities is redeployed.
- **Rule**: Image build timestamp must be within maximum age policy (default: 30 days) and build timestamp must not be older than the currently running workload image.

### Policy 8: `privileged_workload_extra_scrutiny`
- **Objective**: Impose heightened restrictions on workloads requesting elevated cluster capabilities.
- **Rule**: Pods requesting `privileged: true`, `hostNetwork: true`, or `hostPath` mounts require explicit security committee approval attestation and a risk score under 20.

## 2. Dependency Risk Scoring Weights

The composite risk score $S \in [0, 100]$ is computed as:

$$S = \min\left(100, \, \sum_{i} w_i \cdot s_i\right)$$

| Signal ($i$) | Weight ($w_i$) | Evaluation Mechanism | Hard Gate Trigger |
| --- | --- | --- | --- |
| **Known Malicious Advisory** | 100 | Match against OSV malicious package database | Yes (Score set to 100) |
| **Confirmed Typosquat** | 80 | Damerau-Levenshtein distance $\le 2$ or homoglyph against top 10k packages | Yes if combined with install hook |
| **Malicious Install-Time Script** | 50 | AST static analysis detecting network socket creation, process spawning, or base64 decoding in `preinstall` / `setup.py` | High priority investigation |
| **Dependency Confusion** | 40 | Package matching internal namespace exists on public npm/PyPI registry | Yes if public version > internal |
| **Sudden Maintainer Churn** | 20 | Maintainer changed within last 14 days following > 180 days dormancy | Warning flag |
| **Anomalous Release Cadence** | 15 | Version jump > 3 major versions or multiple releases within 1 hour | Informational |
| **Low Repository Health** | 15 | OpenSSF Scorecard score < 4.0 | Contributes to score |

## 3. Policy Exemptions Architecture

Exemptions are structured data artifacts stored in `policies/data/exemptions.json`:
```json
{
  "exemptions": [
    {
      "id": "EX-2026-001",
      "cve": "CVE-2026-9999",
      "owner": "sec-ops@byteaegis.in",
      "reason": "Vulnerable function not reachable in production code path",
      "expires_at": "2026-12-31T23:59:59Z",
      "scope": {
        "namespace": "staging",
        "image": "registry.byteaegis.in/billing-service"
      }
    }
  ]
}
```
Exemptions must have a non-empty owner, technical justification, bounded scope, and explicit expiration date. Any expired exemption automatically fails CI test suites (`aegischain policy test`).
