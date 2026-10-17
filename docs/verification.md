# AegisChain Release Verification Guide

This guide provides copy-paste verification commands allowing any operator, platform security engineer, or auditor to cryptographically verify the authenticity, SLSA Build Level 3 provenance, and software bill of materials (SBOM) of official AegisChain releases.

---

## 1. Trust Anchors

Official release artifacts are signed using Sigstore keyless workflow identity anchored to GitHub Actions OIDC:

| Attribute | Expected Value |
|---|---|
| **OIDC Issuer** | `https://token.actions.githubusercontent.com` |
| **Certificate Identity** | `https://github.com/BYTEGUARDIAN14/aegischain/.github/workflows/release-slsa3.yml@refs/tags/v*` |
| **SLSA Builder ID** | `https://github.com/slsa-framework/slsa-github-generator/.github/workflows/generator_generic_slsa3.yml@refs/tags/v2.0.0` |
| **Source Repository** | `https://github.com/BYTEGUARDIAN14/aegischain` |

---

## 2. Verifying Release Binaries

### Step 2.1: Download Release Artifacts
Download the binary, cryptographic bundle, and provenance attestation from GitHub Releases:

```bash
VERSION="v1.0.0"
curl -sLO "https://github.com/BYTEGUARDIAN14/aegischain/releases/download/${VERSION}/aegischain-linux-amd64"
curl -sLO "https://github.com/BYTEGUARDIAN14/aegischain/releases/download/${VERSION}/aegischain-linux-amd64.bundle"
curl -sLO "https://github.com/BYTEGUARDIAN14/aegischain/releases/download/${VERSION}/attestation.intoto.jsonl"
```

### Step 2.2: Verify Cryptographic Signature with Cosign
Verify the binary using Cosign with strict identity enforcement:

```bash
cosign verify-blob \
  --bundle "aegischain-linux-amd64.bundle" \
  --certificate-identity-regexp "^https://github.com/BYTEGUARDIAN14/aegischain/.github/workflows/.*" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  aegischain-linux-amd64
```

Expected output:
```text
Verified OK
Certificate subject: https://github.com/BYTEGUARDIAN14/aegischain/.github/workflows/release-slsa3.yml@refs/tags/v1.0.0
Certificate issuer: https://token.actions.githubusercontent.com
```

### Step 2.3: Verify SLSA Build Level 3 Provenance
Verify that the binary was built by the isolated SLSA generator from the exact tagged commit:

```bash
slsa-verifier verify-artifact \
  --provenance-path "attestation.intoto.jsonl" \
  --source-uri "github.com/BYTEGUARDIAN14/aegischain" \
  --source-tag "${VERSION}" \
  --builder-id "https://github.com/slsa-framework/slsa-github-generator/.github/workflows/generator_generic_slsa3.yml@refs/tags/v2.0.0" \
  aegischain-linux-amd64
```

Expected output:
```text
PASSED: Verified SLSA provenance
  Source: github.com/BYTEGUARDIAN14/aegischain
  Tag: v1.0.0
  Builder: https://github.com/slsa-framework/slsa-github-generator/.github/workflows/generator_generic_slsa3.yml@refs/tags/v2.0.0
```

---

## 3. Verifying Container Images

### Step 3.1: Verify Image Signature
Verify the admission webhook and trust engine container images published to Docker Hub (`mohamed1410/aegischain-*`):

```bash
IMAGE="mohamed1410/aegischain-admission-webhook@sha256:52242b9363649daf33fecab71ff1a41988547a97a966b5b127ca91c186d3023b"

cosign verify \
  --certificate-identity-regexp "^https://github.com/BYTEGUARDIAN14/aegischain/.github/workflows/.*" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  "${IMAGE}"
```

### Step 3.2: Verify In-Toto Attestations

#### Verify SLSA Provenance Attestation
```bash
cosign verify-attestation \
  --type "https://slsa.dev/provenance/v1" \
  --certificate-identity-regexp "^https://github.com/BYTEGUARDIAN14/aegischain/.*" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  "${IMAGE}"
```

#### Verify CycloneDX Software Bill of Materials (SBOM)
```bash
cosign verify-attestation \
  --type "https://cyclonedx.org/schema" \
  --certificate-identity-regexp "^https://github.com/BYTEGUARDIAN14/aegischain/.*" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  "${IMAGE}"
```

#### Verify Vulnerability Scan and OpenVEX
```bash
cosign verify-attestation \
  --type "https://openvex.dev/ns/v0.2.0" \
  --certificate-identity-regexp "^https://github.com/BYTEGUARDIAN14/aegischain/.*" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  "${IMAGE}"
```

---

## 4. Air-Gapped Key-Based Verification (Secondary Mode)

For air-gapped environments disconnected from public Rekor and Fulcio, AegisChain release assets can be verified using the platform's public key:

```bash
cosign verify-blob \
  --key deploy/keys/cosign.pub \
  --signature aegischain-linux-amd64.sig \
  aegischain-linux-amd64
```

---

## 5. Verifying Decision Ledger Cryptographic Integrity

To independently audit the append-only decision ledger in a cluster or offline backup:

```bash
aegischain ledger verify --ledger /var/log/aegischain/ledger.jsonl
```

Expected output:
```text
Cryptographic hash chain validated successfully across N decision records.
Genesis Hash: 0000000000000000000000000000000000000000000000000000000000000000
Merkle Head Hash: a89f...
Integrity: PASS (Zero modifications or deletions detected)
```
