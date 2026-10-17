# ADR-0004: Hash-Chained Append-Only Ledger for Admission Decisions

- Status: Accepted
- Date: 2026-10-17
- Deciders: AegisChain Architecture Team
- Consulted: Compliance Engineering, Incident Response

## Context and Problem Statement

When an image is admitted or denied by AegisChain, platform engineers and auditors need verifiable, tamper-evident proof of:
1. The exact policy evaluated and its active cryptographic checksum.
2. The evidence examined (Rekor log ID, signatures, SBOM hash, scan timestamps).
3. The precise timestamp and decision verdict.

Standard relational databases (PostgreSQL/SQLite) or system logs (slog/syslog) can be altered, truncated, or forged by an adversary with database access.

## Decision Drivers

- Tamper evidence: Any modification, deletion, or reordering of historical decisions must be cryptographically detectable.
- Offline and independent verifiability via the `aegischain ledger verify` command.
- Low write latency: Appending a decision record must not degrade webhook response times.
- Periodic anchoring: Checkpointing the chain root to Rekor or signing with Cosign.

## Considered Options

1. **Option 1: Cryptographic Hash-Chained Append-Only Log with Periodic Root Checkpoints**
2. **Option 2: Immutable External Ledger Service (Amazon QLDB / Immudb)**
3. **Option 3: Standard PostgreSQL / SQLite table with application-level write-only permissions**

## Decision Outcome

Chosen option: **Option 1 (Hash-Chained Append-Only Log with Root Checkpoints)**.

### Data Model and Cryptography

Each decision $E_i$ computes:
$$H_i = \text{SHA-256}(H_{i-1} \,||\, \text{CanonicalJSON}(E_i))$$
where $H_0 = \text{SHA-256}(\text{"AEGISCHAIN_GENESIS_ROOT"})$.

Every entry records:
- `decision_id` (UUIDv4)
- `index` (monotonically increasing uint64)
- `timestamp` (RFC3339 UTC)
- `subject` (image reference, resolved digest, target namespace, pod name)
- `verdict` (`allow` | `deny`)
- `mode` (`audit` | `enforce`)
- `policy_version` (git commit SHA or bundle digest)
- `rules` (array of evaluated rule IDs, verdicts, and evidence hashes)
- `trust_score` (0-100)
- `prev_hash` ($H_{i-1}$)
- `hash` ($H_i$)

### Positive Consequences

- Anyone with access to the ledger can verify integrity with `aegischain ledger verify`.
- If an attacker tampers with a historical row (e.g., changing a `deny` to `allow`), the hash chain breaks from that index onward.
- Fully portable across SQLite in lightweight/local mode and PostgreSQL in enterprise clusters.

### Negative Consequences and Tradeoffs

- Rebuilding or pruning the ledger is prohibited without publishing a signed truncation checkpoint.

## Compliance and Standards Mapping

- **NIST SP 800-218 (SSDF)**: PO.3.3 (Maintaining records of all software integrity evaluations).
- **SOC 2 Type II**: Trust Services Criteria CC6.1, CC6.6, CC7.2 (Audit logging and tamper evidence).
