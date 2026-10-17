# AegisChain Architecture and Core Systems Design

## System Overview

AegisChain is a software supply chain trust platform that enforces policy decisions across the entire software delivery lifecycle, from CI commit to Kubernetes runtime admission.

## Core Architectural Components

### 1. Hardened CI Pipeline
Constructs container images inside an isolated GitHub Actions runner using hermetic build constraints. Produces:
- Cryptographically signed container image layers.
- CycloneDX and SPDX Software Bill of Materials (SBOM) generated via Syft.
- Normalized vulnerability assessments synthesized from Grype, Trivy, and OSV.
- SLSA Build Level 3 provenance via `slsa-framework/slsa-github-generator`.
- OpenVEX vulnerability assertions for false-positive suppression.
- Keyless signatures and attestations pushed to the OCI registry and recorded in the Rekor transparency log.

### 2. Trust Engine (`internal/`)
The central policy decision point (PDP) shared across the admission webhook, CLI, and CI gate:
- **Resolver (`internal/resolver`)**: Resolves mutable image tags to immutable cryptographic SHA-256 digests. Caches resolved digests with negative caching and TTL.
- **Verifier (`internal/verify`)**: Validates Sigstore keyless signatures, Rekor inclusion proofs, Fulcio certificate identity and OIDC issuer, and in-toto attestations (SLSA provenance v1, SBOM, scan results, OpenVEX).
- **Vulnerability Engine (`internal/vuln`)**: Ingests multi-scanner reports, flags scanner disagreements, resolves reachability precision (`symbol`, `package`, `unknown`), and evaluates signed OpenVEX waivers.
- **Policy Engine (`internal/policy`)**: Embeds Open Policy Agent (OPA) with hot-reloading Rego v1 bundles.
- **Append-Only Ledger (`internal/ledger`)**: Computes SHA-256 hash chains over every admission decision, creating an immutable audit trail with periodic signed root checkpoints.
- **Risk Client (`internal/risk`)**: Communicates with the decoupled Python Risk Scorer via circuit breakers.

### 3. Kubernetes Admission Controller (`cmd/admission-webhook`)
Validates incoming Pod creations, Deployments, StatefulSets, DaemonSets, and Jobs:
- Handles init containers, ephemeral containers, and multi-architecture manifests.
- Evaluates per-namespace `TrustPolicy` CRDs (`audit` or `enforce`).
- Excludes system namespaces while verifying platform images at install time.
- Emits Kubernetes Events and `PolicyReport` CRDs.
- Supports emergency cryptographic break-glass overrides with automated expiry.

### 4. Dependency Risk Scorer (`risk-scorer/`)
A high-throughput Python FastAPI service analyzing SBOM packages:
- Static AST inspection of install hooks (`preinstall`, `setup.py`).
- Typosquatting detection via Damerau-Levenshtein distance and homoglyphs against top-downloaded packages.
- Dependency confusion analysis for internal package namespaces.
- Maintainer velocity, ownership change, and package age signals.

### 5. Control Dashboard (`dashboard/`)
A responsive React TypeScript application featuring:
- Live provenance graph visualizer tracing Git Commit -> Workflow -> Builder -> Image Digest -> Kubernetes Deployment.
- Decision explorer with rule-by-rule explainability and remediation guidance.
- Ledger integrity badge confirming unbroken hash chain verification.
- Dependency risk breakdown with install-script static analysis snippets.
