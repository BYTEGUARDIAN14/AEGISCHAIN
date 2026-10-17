# Scenario 12: Rollback Downgrade Attack

## Real-World Incident Context
Mirrors rollback attacks where an adversary or misconfigured CD deployment rolls back production workloads to an older, historically signed and valid container release that contains severe vulnerabilities that were patched in recent releases.

## Attack Vector / Evaluation
A release built 90 days ago with a valid signature is submitted for deployment to overwrite a workload whose currently active deployment has a more recent build timestamp. AegisChain anti-rollback engine compares build timestamps and image age against policy limits.

## Expected Verdict
- **Verdict**: `DENY`
- **Trust Score**: `40 / 100`
- **Failing Rule**: `freshness`
- **Reason**: `Rollback detected: image build timestamp is older than deployed version or exceeds 30-day limit`
- **Remediation**: `Deploy the latest approved patch release; rollback requires approved Break-Glass emergency token`
