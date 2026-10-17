# Scenario 06: Untrusted Build Platform / Compromised Runner

## Real-World Incident Context
Mirrors the **Codecov** and **SolarWinds** attacks where the build platform itself was compromised or unauthorized unhardened builders were used to compile software.

## Attack Vector / Evaluation
The artifact carries an in-toto SLSA provenance predicate, but the builder ID indicates an unapproved self-hosted builder (`https://github.com/attacker/untrusted-builder@v1.0.0`) instead of the official SLSA Build Level 3 generator (`slsa-framework/slsa-github-generator`).

## Expected Verdict
- **Verdict**: `DENY`
- **Trust Score**: `40 / 100`
- **Failing Rule**: `provenance_required`
- **Reason**: `SLSA provenance builder is not on the trusted allowlist`
- **Remediation**: `Migrate container build step to slsa-framework/slsa-github-generator generator_container_slsa3.yml`
