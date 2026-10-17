# Verifying AegisChain Releases

Every official release of AegisChain (binaries, Helm charts, and container images) is cryptographically signed using Sigstore keyless signing and accompanied by SLSA Build Level 3 provenance and CycloneDX SBOMs.

Anyone can independently verify release authenticity and integrity using the copy-paste instructions below.

## 1. Verifying Container Images with Cosign

Verify the container image signature against Sigstore Fulcio and Rekor with the exact expected workflow identity:

```bash
# Set release tag and expected identity
export IMAGE="ghcr.io/byteaegis/aegischain:v1.0.0"
export EXPECTED_IDENTITY="https://github.com/BYTEGUARDIAN14/aegischain/.github/workflows/release.yml@refs/tags/v1.0.0"
export EXPECTED_ISSUER="https://token.actions.githubusercontent.com"

# Verify cryptographic signature
cosign verify \
  --certificate-identity "${EXPECTED_IDENTITY}" \
  --certificate-oidc-issuer "${EXPECTED_ISSUER}" \
  "${IMAGE}"
```

## 2. Verifying SLSA Build Level 3 Provenance

Verify that the artifact was built by the official GitHub Actions SLSA generator from the authentic source repository:

```bash
# Verify SLSA Build L3 provenance attestation
cosign verify-attestation \
  --type https://slsa.dev/provenance/v1 \
  --certificate-identity "${EXPECTED_IDENTITY}" \
  --certificate-oidc-issuer "${EXPECTED_ISSUER}" \
  "${IMAGE}" | jq -r '.payload' | base64 -d | jq .
```

Alternatively, use `slsa-verifier`:
```bash
slsa-verifier verify-image "${IMAGE}" \
  --source-uri "github.com/BYTEGUARDIAN14/aegischain" \
  --source-tag "v1.0.0"
```

## 3. Verifying the Software Bill of Materials (SBOM)

Verify the CycloneDX SBOM attestation:

```bash
# Verify CycloneDX SBOM attestation
cosign verify-attestation \
  --type https://cyclonedx.org/schema \
  --certificate-identity "${EXPECTED_IDENTITY}" \
  --certificate-oidc-issuer "${EXPECTED_ISSUER}" \
  "${IMAGE}" | jq -r '.payload' | base64 -d | jq .predicate
```

## 4. Verifying Release Binaries

For standalone CLI binaries downloaded from GitHub Releases:

```bash
# Verify binary checksum with signed SHA256SUMS
sha256sum --check SHA256SUMS

# Verify the SHA256SUMS file signature
cosign verify-blob \
  --certificate-identity "${EXPECTED_IDENTITY}" \
  --certificate-oidc-issuer "${EXPECTED_ISSUER}" \
  --bundle SHA256SUMS.sigstore.json \
  SHA256SUMS
```
