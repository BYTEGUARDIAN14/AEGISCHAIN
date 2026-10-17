# Scenario 05: Wrong Signer Identity (Forked CI Workflow Attack)

## Real-World Incident Context
Mirrors attacks where an adversary forks a legitimate open-source repository and uses their own GitHub Actions runner to sign an image with a valid Fulcio OIDC certificate issued by `token.actions.githubusercontent.com`, hoping keyless verification only checks certificate validity rather than the workflow identity claims.

## Attack Vector / Evaluation
The container image is signed with a valid Sigstore keyless certificate from `https://token.actions.githubusercontent.com`, but the certificate SAN identity is `https://github.com/attacker-org/forked-repo/...` rather than the approved `BYTEGUARDIAN14` repository.

## Expected Verdict
- **Verdict**: `DENY`
- **Trust Score**: `40 / 100`
- **Failing Rule**: `signature_required`
- **Reason**: `Signature identity does not match allowed policy pattern: attacker-org not permitted`
- **Remediation**: `Enforce exact certificate-identity pattern in TrustPolicy matching approved repository owner and workflow`
