# ADR-0001: Adopt Keyless Sigstore Over Long-Lived Asymmetric Keys

- Status: Accepted
- Date: 2026-10-17
- Deciders: AegisChain Architecture Team
- Consulted: Platform Security, DevSecOps

## Context and Problem Statement

Supply chain signing historically relies on static asymmetric key pairs (e.g., GPG, RSA/ECDSA key pairs stored in CI secrets or KMS). In CI/CD pipelines, long-lived private keys introduce significant attack surfaces:
1. Exposure via build script exfiltration or compromised runner environments.
2. Inadequate key rotation cadences and complex revocation lists.
3. Lack of cryptographic binding between the signer and the exact execution identity (repository, workflow ref, commit SHA, runner runner_id).

We must choose how AegisChain verifies artifact provenance and signatures in enterprise Kubernetes environments.

## Decision Drivers

- Elimination of static private key leakage risks in automated pipelines.
- Verifiable cryptographic binding to workload identity (OIDC issuer and certificate identity).
- Tamper-evident transparency log auditing (Rekor).
- Support for air-gapped / offline enterprise clusters as an explicit secondary fallback.

## Considered Options

1. **Option 1: Sigstore Keyless (Fulcio ephemeral X.509 + Rekor transparency log)**
2. **Option 2: Cloud KMS Asymmetric Keys (AWS KMS, GCP Cloud KMS, Azure Key Vault)**
3. **Option 3: Static Pinned Public Keys (GPG / Cosign private-key secret in CI)**

## Decision Outcome

Chosen option: **Option 1 (Sigstore Keyless)** as the primary verification mechanism, with **Option 3** supported as a documented secondary mode for air-gapped environments.

### Positive Consequences

- Signatures are tied to short-lived (10-minute) X.509 certificates issued by Fulcio upon validating OpenID Connect (OIDC) identity tokens.
- No private keys are stored on disk or in CI secrets, nullifying key theft threats.
- Certificates embed SAN extensions containing the exact source repository, workflow filename, and triggering ref.
- Rekor provides non-repudiable proof of timestamp and inclusion.

### Negative Consequences and Tradeoffs

- Requires external connectivity to Fulcio, Rekor, and OIDC providers unless an internal private Sigstore scaffold is deployed.
- Verifier must evaluate transparency log inclusion proofs and certificate validity at the recorded timestamp rather than current clock time.

## Pros and Cons of the Options

### Option 1: Sigstore Keyless

- Good, because identity-based verification prevents unauthorized builds from foreign forks.
- Good, because transparency log entries are append-only and universally auditable.
- Bad, because private deployments require managing Fulcio, Rekor, and TUF root services.

### Option 2: Cloud KMS

- Good, because private keys never leave Hardware Security Modules (HSMs).
- Bad, because verification requires cloud provider IAM permissions and introduces cross-cloud credential complexities in Kubernetes webhooks.

### Option 3: Static Pinned Keys

- Good, because works fully offline with no external dependencies.
- Bad, because keys do not inherently prove build pipeline provenance and are prone to compromise.

## Compliance and Standards Mapping

- **SLSA v1.0**: Build Level 3 requirement for non-forgeable provenance and isolated build environments.
- **NIST SP 800-218 (SSDF)**: PO.3.2, PS.1.1, PW.4.1 (Verifying integrity and authenticity of software releases).
- **OpenSSF S2C2F**: Ingestion Track Level 3 (Cryptographic verification of producer identities).
