# Security Policy

## Supported Versions

AegisChain provides security updates for the following release branches:

| Version | Supported          |
| ------- | ------------------ |
| 1.0.x   | Yes                |
| < 1.0   | No                 |

## Reporting a Vulnerability

The AegisChain engineering team takes the security of supply chain infrastructure seriously. If you discover a vulnerability or potential security flaw within AegisChain, do not open a public issue.

Submit reports via encrypted email or GitHub Private Vulnerability Reporting:
- Contact: security@byteaegis.in
- PGP Fingerprint: Available upon request from security@byteaegis.in
- Platform: GitHub Security Advisory (Private Disclosure)

Include the following details in your report:
1. Impacted component (Admission Webhook, Trust Engine, Verifier, Ledger, Scorer, or CLI).
2. Reproduction steps and minimal test artifacts.
3. Proof-of-concept exploit if available.
4. Proposed mitigation or patch if developed.

## Response Timetable

- Acknowledgment: Within 24 hours of receipt.
- Initial Assessment and Severity Classification: Within 48 hours.
- Fix Development and Remediation Target: Within 14 calendar days for High/Critical advisories.
- Public Disclosure: Coordinated after downstream patches have been tagged and signed.

## Self-Securing Architecture

AegisChain implements strict self-defense controls:
- Releases are built using SLSA Build Level 3 generator workflows.
- Binaries and container images are signed keylessly via Sigstore Fulcio and recorded on Rekor.
- All dependencies are pinned by cryptographic digests.
- Container runtimes execute as non-root on read-only root filesystems under Kubernetes restricted Pod Security standards.
