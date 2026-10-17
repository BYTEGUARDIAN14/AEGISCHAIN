# Scenario 10: Dependency Confusion Attack

## Real-World Incident Context
Mirrors Alex Birsan's seminal 2021 research uncovering dependency confusion across Apple, Microsoft, and PayPal: package managers (npm, pip) configured with public registries prioritize higher semver version numbers from public registries over internal private repositories.

## Attack Vector / Evaluation
The project's dependency manifest contains an internal package named `byteaegis-auth`. An adversary registers the identical name on public npm with version `99.0.0`. AegisChain's Dependency Risk Scorer inspects internal naming patterns and version distribution, detects the confusion collision, and blocks deployment.

## Expected Verdict
- **Verdict**: `DENY`
- **Trust Score**: `10 / 100`
- **Failing Rule**: `dependency_risk_gate`
- **Reason**: `Dependency confusion detected: internal package name published to public registry with inflated version (99.0.0)`
- **Remediation**: `Scope internal packages under approved organization prefix (@byteaegis/) and configure registry resolution scoping`
