# Scenario 13: Decision Ledger Tampering

## Real-World Incident Context
Mirrors insider threat scenarios and post-exploitation actions where an adversary with database access alters past security audit records to disguise unauthorized deployments or retroactive approvals.

## Attack Vector / Evaluation
An adversary directly edits a stored JSONL decision record on the file system/database, changing a `deny` verdict to `allow`. `aegischain ledger verify` traverses the append-only cryptographic hash chain (`prev_hash` -> `hash`) to validate Merkle continuity.

## Expected Verdict
- **Verdict**: `TAMPER_DETECTED`
- **Result**: `Exit code 1 (Non-zero)`
- **Assertion**: `Tamper detected at record index 1; hash chain verification failed`
- **Remediation**: `Investigate storage layer access logs and restore ledger from latest cryptographically signed checkpoint`
