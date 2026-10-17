# AegisChain Threat Model and Security Architecture

## 1. System Assets and Protected Resources

AegisChain safeguards the following critical assets:

| Asset ID | Description | Impact of Compromise |
| --- | --- | --- |
| **A-1** | Production Kubernetes Workloads | Critical: Remote code execution, data exfiltration, lateral movement |
| **A-2** | Admission Decision Ledger | High: Tampering with audit trail prevents forensics and compliance |
| **A-3** | OPA Security Policies and Exemptions | Critical: Policy weakening allows unauthorized code admission |
| **A-4** | Signing Keys and OIDC Workload Identities | Critical: Forged signatures on unapproved containers |
| **A-5** | Registry Artifacts and Manifests | High: Tag alteration, image layer poisoning |
| **A-6** | Webhook CA Certificates and Private Keys | Critical: Man-in-the-middle bypass of Kubernetes admission control |

## 2. Trust Boundaries and Data Flow

```
[ Developer Workstation ]
          | (git push)
          v
======================= TRUST BOUNDARY 1: SOURCE CONTROL =======================
[ GitHub Repository / Pull Request ]
          | (GitHub OIDC Token / Fulcio ephemeral certificate)
          v
======================= TRUST BOUNDARY 2: BUILD RUNNER ========================
[ Hardened CI Pipeline (Hermetic Build, Syft, Grype/Trivy, SLSA L3 Generator) ]
          |
          +---> [ Cosign Signatures & Attestations ]
          |
          v
======================= TRUST BOUNDARY 3: OCI REGISTRY =======================
[ Container Registry (Images, Cosign Signatures, In-Toto Attestations) ]
          |
          | (image pull / manifest resolve)
          v
======================= TRUST BOUNDARY 4: K8S CONTROL PLANE ===================
[ K8s API Server ] <---(TLS / Mutual Auth)---> [ AegisChain Admission Controller ]
                                                        |
                                                        v
                                          [ AegisChain Trust Engine ]
                                          - Resolver (Digest Pinning)
                                          - Verifier (Sigstore / Rekor)
                                          - Vulnerability & VEX Evaluator
                                          - Embedded OPA Policy Engine
                                          - Hash-Chained Decision Ledger
                                                        |
                                                        v
======================= TRUST BOUNDARY 5: CLUSTER RUNTIME =====================
[ Kubelet Worker Nodes ] ---> Spawns Verified Pod Only
```

## 3. STRIDE Threat Analysis

| Threat ID | STRIDE Category | Target Asset | Attack Description | AegisChain Mitigating Control | Proving Test / Attack-Lab Scenario |
| --- | --- | --- | --- | --- | --- |
| **T-1** | Spoofing | Workload Identity (A-4) | Attacker signs image using their own personal GitHub repository or fork | Keyless identity verification checking exact `certificate-identity` and `certificate-oidc-issuer` | Scenario 5: Wrong Signer |
| **T-2** | Tampering | Container Image (A-5) | Attacker replaces image layer after signing or redirects tag to another digest | Immutable digest resolution + cryptographic layer hash verification | Scenario 3: Tampered Image; Scenario 4: Tag Retargeting |
| **T-3** | Repudiation | Decision Ledger (A-2) | Malicious insider modifies admission database to hide an unauthorized deployment | Hash-chained append-only ledger with periodic signed root checkpoints | Scenario 13: Ledger Tampering (`aegischain ledger verify`) |
| **T-4** | Information Disclosure | Vulnerability Data (A-1) | Unauthenticated user queries unpublished zero-day CVE findings | REST API OIDC authentication with role-based access control (RBAC) | API Auth Unit & Integration Tests |
| **T-5** | Denial of Service | Admission Webhook (A-1) | Attacker floods admission webhook or takes down registry to force fail-open | Fail-closed policy for protected namespaces, circuit breakers, timeout bounds | Scenario 14: Registry & Scorer Outage |
| **T-6** | Elevation of Privilege | Workload Execution (A-1) | Attacker deploys privileged container with hostPath mounts | `privileged_workload_extra_scrutiny` Rego policy and Pod Security restricted rules | Policy Rule 8 Unit Tests |
| **T-7** | Tampering | Build Environment (A-1) | Attacker injects malware during build via poisoned dependency cache | Hermetic builds, cache restore disabled on releases, SLSA L3 provenance checks | Scenario 6: Untrusted Builder |
| **T-8** | Tampering | Dependencies (A-1) | Attacker publishes typosquatted package with obfuscated postinstall payload | Static dependency risk scoring analyzing AST, entropy, and Levenshtein distance | Scenario 9: Malicious Dependency |
| **T-9** | Tampering | Base Image (A-5) | Attacker substitutes unauthorized base image containing backdoors | `base_image_allowlist` policy checking cryptographically pinned base image digest | Scenario 11: Base Image Swap |
| **T-10** | Tampering | Rollback Attack (A-1) | Attacker redeploys an older, legitimately signed image with known exploitable CVEs | Anti-rollback freshness policy rejecting builds older than current version or TTL | Scenario 12: Rollback Attack |

## 4. Attack Trees for the Three Highest-Impact Threats

### Threat Tree 1: Attacker Bypasses Admission Gate to Execute Malicious Image (T-2, T-5)

```
[ Compromise Cluster Runtime via Malicious Image ]
     |
     +--> 1. Circumvent Admission Webhook
     |         |
     |         +--> 1.1 DoS Webhook to trigger Fail-Open
     |         |         Mitigation: Webhook configured with failurePolicy: Fail in protected namespaces.
     |         |
     |         +--> 1.2 Forge Webhook TLS Certificate
     |         |         Mitigation: cert-manager auto-rotates CA and injects CA bundle via API server.
     |         |
     |         +--> 1.3 Deploy to Excluded Namespace
     |                   Mitigation: Exclusions restricted strictly to kube-system and aegischain-system.
     |
     +--> 2. Deceive Policy Decision Point
               |
               +--> 2.1 Mutate tag after verification (TOCTOU)
               |         Mitigation: Mandatory tag-to-digest resolution before evaluation.
               |
               +--> 2.2 Replay older signed image with critical CVE
               |         Mitigation: Anti-rollback freshness gate and minimum version tracking.
               |
               +--> 2.3 Fake signed VEX statement
                         Mitigation: Cryptographic verification of VEX author identity and Rekor entry.
```

### Threat Tree 2: Attacker Forges Build Pipeline Provenance (T-1, T-7)

```
[ Forge Provenance to Fake Approved Release ]
     |
     +--> 1. Sign Artifact with Illegitimate Workflow
     |         |
     |         +--> 1.1 Use Attacker GitHub Actions Runner
     |                   Mitigation: Policy enforces exact certificate SAN (repo:org/trusted-app).
     |
     +--> 2. Compromise Build Runner
     |         |
     |         +--> 2.1 Exfiltrate signing credentials
     |         |         Mitigation: Keyless Sigstore (Fulcio); no private keys exist to steal.
     |         |
     |         +--> 2.2 Poison build cache
     |                   Mitigation: Release builds run without cache restoration; hermetic network.
     |
     +--> 3. Forge SLSA Provenance Predicate
               |
               +--> 3.1 Tamper with subject digest
                         Mitigation: Verifier checks provenance subject digest equals artifact digest.
```

### Threat Tree 3: Attacker Covers Tracks by Tampering with Decision Ledger (T-3)

```
[ Modify Historical Admission Decision from DENY to ALLOW ]
     |
     +--> 1. Direct Database Modification
     |         |
     |         +--> 1.1 SQL UPDATE on decision row
     |                   Mitigation: Hash chain verification detects hash mismatch at index N.
     |
     +--> 2. Delete Historical Decision Rows
     |         |
     |         +--> 2.1 SQL DELETE on denied record
     |                   Mitigation: Broken sequence index and previous hash chain pointer mismatch.
     |
     +--> 3. Recompute Entire Hash Chain
               |
               +--> 3.1 Recalculate all subsequent hashes
                         Mitigation: Periodic signed checkpoints published to external Rekor log.
```

## 5. Security Frameworks Mapping

| Framework | Control Identifier | Control Description | AegisChain Implementation |
| --- | --- | --- | --- |
| **SLSA v1.0** | Build Level 3 | Hermetic, isolated build with non-forgeable provenance | Validated via `internal/verify` checking builder identity, external params, and subject digest. |
| **NIST SSDF (SP 800-218)** | PO.3.2 | Check integrity of third-party software | Dependency risk scorer static AST analysis and typosquat distance checks. |
| **NIST SSDF (SP 800-218)** | PS.1.1 | Store software releases securely | Digest pinning, immutable OCI artifacts, and Sigstore Rekor inclusion verification. |
| **NIST SSDF (SP 800-218)** | PW.4.1 | Secure and harden the build pipeline | GitHub Actions with pinned SHAs, `permissions: {}`, step-security harden-runner. |
| **NIST SSDF (SP 800-218)** | PW.7.1 | Vulnerability monitoring and remediation | Multi-scanner normalization (Grype, Trivy, OSV) and signed OpenVEX suppression. |
| **OpenSSF S2C2F** | Ingestion L3 | Automated signature and provenance verification | Embedded OPA Rego policy evaluating keyless signatures and SLSA attestations. |
| **OpenSSF S2C2F** | Ingestion L4 | Deep dependency static analysis | AST static checks for obfuscated install hooks (`preinstall`, `setup.py`). |

## 6. Honest Limitations and Residual Risks

AegisChain provides mathematically sound supply chain integrity verification, but the following residual risks must be acknowledged:

1. **Reachability Analysis Limits**: While symbol-level reachability in Go via `govulncheck` is compiler-backed, reachability for Python and Node.js relies on import-graph heuristics. Dynamic runtime imports (`__import__`, `eval()`, `require(variable)`) cannot be statically determined with 100% precision.
2. **First-Day Vulnerabilities (0-Days)**: Vulnerability gates can only catch known CVEs indexed in OSV/NVD/GitHub Security Advisories. Dependency risk scoring mitigates this by flagging anomalies, but cannot guarantee detection of clean-looking 0-day code logic.
3. **Upstream OIDC Identity Provider Compromise**: If GitHub Actions' internal OIDC issuer or Sigstore's Fulcio CA root were compromised, false identities could theoretically be certified until revoked in TUF root metadata.
4. **Non-Containerized Host Binaries**: AegisChain secures Kubernetes admission and container images. Host-level binaries (kubelet, systemd, containerd) must be secured by host OS integrity mechanisms.
