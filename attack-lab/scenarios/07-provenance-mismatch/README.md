# Scenario 07: Provenance Subject Digest Mismatch (Attestation Replay)

## Real-World Incident Context
Mirrors attestation replay and metadata substitution attacks where an adversary captures a valid SLSA Build Level 3 provenance statement generated for an approved image and attaches it to an entirely different backdoored container image.

## Attack Vector / Evaluation
The artifact is accompanied by a genuine SLSA provenance document signed by a trusted builder, but the in-toto `subject[0].digest.sha256` in the provenance statement points to digest `A`, while the image being admitted is digest `B`.

## Expected Verdict
- **Verdict**: `DENY`
- **Trust Score**: `40 / 100`
- **Failing Rule**: `provenance_required`
- **Reason**: `Provenance subject digest does not match container image digest`
- **Remediation**: `Regenerate SLSA provenance for the specific image digest being deployed`
