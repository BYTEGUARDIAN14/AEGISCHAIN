# Scenario 01: Clean Verified Workload (False-Positive Control)

## Real-World Incident Context
Mirrors the baseline gold standard established after the **SolarWinds (SUNBURST)** compromise: workloads entering production must possess a verified chain of custody proving they originated from audited source code, were compiled by an isolated builder, and were attested before deployment.

## Attack Vector / Evaluation
A legitimate container image built by the trusted GitHub Actions pipeline (`BYTEGUARDIAN14/aegischain`), signed using Sigstore keyless workflow identity, accompanied by SLSA Build Level 3 provenance, Syft CycloneDX SBOM, Trivy vulnerability scan, and OpenVEX metadata.

## Expected Verdict
- **Verdict**: `ALLOW`
- **Trust Score**: `100 / 100`
- **Policy Mode**: `enforce`
- **Rule Results**: All 8 OPA Rego v1 rules pass.
