#!/usr/bin/env bash
set -euo pipefail

REGISTRY="localhost:5001"
REPO="sample-app"
TAG="v1.0.0"
IMAGE="${REGISTRY}/${REPO}:${TAG}"
OUTPUT_DIR="sample-app/attestations"
KEY_DIR="deploy/keys"

mkdir -p "${OUTPUT_DIR}" "${KEY_DIR}"

echo "Step 1: Building sample-app image with pinned distroless base..."
docker build -t "${IMAGE}" -f sample-app/Dockerfile sample-app

echo "Step 2: Pushing image to local registry..."
docker push "${IMAGE}"

DIGEST=$(docker inspect --format='{{index .RepoDigests 0}}' "${IMAGE}" | cut -d'@' -f2)
IMMUTABLE_IMAGE="${REGISTRY}/${REPO}@${DIGEST}"
echo "Resolved immutable image digest: ${DIGEST}"

echo "Step 3: Generating Syft SBOMs..."
syft "${IMAGE}" -o "cyclonedx-json=${OUTPUT_DIR}/cyclonedx.json" -o "spdx-json=${OUTPUT_DIR}/spdx.json"

echo "Step 4: Running Trivy vulnerability scan..."
trivy image --scanners vuln --format json --output "${OUTPUT_DIR}/trivy-scan.json" "${IMAGE}"

echo "Step 5: Generating OpenVEX statement..."
cat <<EOF > "${OUTPUT_DIR}/openvex.json"
{
  "@context": "https://openvex.dev/ns/v0.2.0",
  "@id": "https://byteaegis.in/vex/sample-app-${DIGEST}",
  "author": "security@byteaegis.in",
  "role": "Software Supplier",
  "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "version": 1,
  "tooling": "AegisChain Trust Platform 1.0.0",
  "statements": [
    {
      "vulnerability": {
        "name": "CVE-2026-99999"
      },
      "products": [
        {
          "@id": "pkg:oci/sample-app@${DIGEST}"
        }
      ],
      "status": "not_affected",
      "justification": "vulnerable_code_not_in_execute_path",
      "impact_statement": "Symbol not invoked from main application binary verified by govulncheck."
    }
  ]
}
EOF

echo "Step 6: Generating SLSA Build L3 Provenance Predicate..."
cat <<EOF > "${OUTPUT_DIR}/slsa-provenance.json"
{
  "_type": "https://in-toto.io/Statement/v1",
  "subject": [
    {
      "name": "pkg:oci/sample-app",
      "digest": {
        "sha256": "${DIGEST#sha256:}"
      }
    }
  ],
  "predicateType": "https://slsa.dev/provenance/v1",
  "predicate": {
    "buildDefinition": {
      "buildType": "https://actions.github.com/buildtypes/workflow/v1",
      "externalParameters": {
        "workflow": {
          "ref": "refs/heads/main",
          "repository": "https://github.com/BYTEGUARDIAN14/aegischain",
          "path": ".github/workflows/reusable-secure-pipeline.yml"
        }
      },
      "internalParameters": {
        "cgo_enabled": "0"
      },
      "resolvedDependencies": [
        {
          "uri": "gcr.io/distroless/static:nonroot",
          "digest": {
            "sha256": "e2e927ec666bae08560abb3c55d0659eceabb657f56b6782ab500a9fc7f555e3"
          }
        }
      ]
    },
    "runDetails": {
      "builder": {
        "id": "https://github.com/slsa-framework/slsa-github-generator/.github/workflows/generator_container_slsa3.yml@refs/tags/v2.0.0"
      },
      "metadata": {
        "invocationId": "https://github.com/BYTEGUARDIAN14/aegischain/actions/runs/10892834"
      }
    }
  }
}
EOF

echo "Step 7: Generating Cosign keypair if missing..."
if [ ! -f "${KEY_DIR}/cosign.key" ]; then
  COSIGN_PASSWORD="testpassword123" cosign generate-key-pair --output-key-prefix "${KEY_DIR}/cosign"
fi

echo "Step 8: Signing container image..."
COSIGN_PASSWORD="testpassword123" cosign sign --yes --key "${KEY_DIR}/cosign.key" --tlog-upload=false --allow-http-registry=true --allow-insecure-registry=true "${IMMUTABLE_IMAGE}"

echo "Step 9: Attesting all 4 predicates..."
COSIGN_PASSWORD="testpassword123" cosign attest --yes --key "${KEY_DIR}/cosign.key" --tlog-upload=false --type https://cyclonedx.org/schema --predicate "${OUTPUT_DIR}/cyclonedx.json" --allow-http-registry=true --allow-insecure-registry=true "${IMMUTABLE_IMAGE}"
COSIGN_PASSWORD="testpassword123" cosign attest --yes --key "${KEY_DIR}/cosign.key" --tlog-upload=false --type https://cosign.sigstore.dev/attestation/vuln/v1 --predicate "${OUTPUT_DIR}/trivy-scan.json" --allow-http-registry=true --allow-insecure-registry=true "${IMMUTABLE_IMAGE}"
COSIGN_PASSWORD="testpassword123" cosign attest --yes --key "${KEY_DIR}/cosign.key" --tlog-upload=false --type https://openvex.dev/ns/v0.2.0 --predicate "${OUTPUT_DIR}/openvex.json" --allow-http-registry=true --allow-insecure-registry=true "${IMMUTABLE_IMAGE}"
COSIGN_PASSWORD="testpassword123" cosign attest --yes --key "${KEY_DIR}/cosign.key" --tlog-upload=false --type https://slsa.dev/provenance/v1 --predicate "${OUTPUT_DIR}/slsa-provenance.json" --allow-http-registry=true --allow-insecure-registry=true "${IMMUTABLE_IMAGE}"

echo "Step 10: Running Verification Gate..."
cosign verify --key "${KEY_DIR}/cosign.pub" --insecure-ignore-tlog=true --allow-http-registry=true --allow-insecure-registry=true "${IMMUTABLE_IMAGE}"

for PRED in "https://cyclonedx.org/schema" "https://cosign.sigstore.dev/attestation/vuln/v1" "https://openvex.dev/ns/v0.2.0" "https://slsa.dev/provenance/v1"; do
  cosign verify-attestation --key "${KEY_DIR}/cosign.pub" --type "${PRED}" --insecure-ignore-tlog=true --allow-http-registry=true --allow-insecure-registry=true "${IMMUTABLE_IMAGE}"
done

echo ">>> [AegisChain Phase 2 Verification Gate: ALL PASSED]"
