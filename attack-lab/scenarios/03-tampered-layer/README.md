# Scenario 03: Cryptographically Tampered Layer Injection

## Real-World Incident Context
Mirrors container registry poisoning and Man-in-the-Middle (MitM) registry attacks where an adversary modifies an intermediate container filesystem layer after signing has completed.

## Attack Vector / Evaluation
An adversary takes a validly signed container manifest and swaps one of the root filesystem layers with a modified backdoor layer. When the image digest is recalculated by the resolver, the hash does not match the cryptographic signature envelope.

## Expected Verdict
- **Verdict**: `DENY`
- **Trust Score**: `0 / 100`
- **Failing Rule**: `signature_required`
- **Reason**: `Cryptographic signature verification failed: digest mismatch on modified layer`
- **Remediation**: `Purge compromised registry cache and rebuild immutable image layers from trusted source`
