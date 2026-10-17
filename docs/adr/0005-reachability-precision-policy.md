# ADR-0005: Multi-Language Vulnerability Reachability and Precision Taxonomy

- Status: Accepted
- Date: 2026-10-17
- Deciders: AegisChain Architecture Team
- Consulted: Security Research, Vulnerability Management

## Context and Problem Statement

Container vulnerability scanning frequently reports hundreds of vulnerabilities in transitively included third-party libraries. Many CVEs reside in code paths that are never invoked by the application entrypoint.

Treating all vulnerabilities equally causes alert fatigue and delays critical deployments. Conversely, falsely claiming a vulnerability is "unreachable" introduces catastrophic supply chain vulnerabilities.

We must define how AegisChain measures, reports, and acts upon reachability across different runtime ecosystems.

## Decision Drivers

- Transparent precision reporting: Avoid presenting heuristics or best-effort guesses as cryptographic or compiler certainty.
- Language-specific analysis fidelity (Go vs. Python vs. Node.js).
- Clear policy controls: Unwaived KEV (Known Exploited Vulnerabilities) must always block regardless of reachability claims.

## Considered Options

1. **Option 1: Tiered Precision Taxonomy with Ecosystem-Specific Analyzers**
2. **Option 2: Binary reachable/unreachable boolean based purely on file imports**
3. **Option 3: Ignore reachability entirely and enforce solely on CVSS severity thresholds**

## Decision Outcome

Chosen option: **Option 1 (Tiered Precision Taxonomy)**.

### Precision Taxonomy

Every vulnerability evaluated by AegisChain carries an explicit `precision` attribute:

| Level | Value | Mechanism | Supported Ecosystems | Confidence |
| --- | --- | --- | --- | --- |
| 1 | `symbol` | Call-graph static analysis (`govulncheck`) verifying symbol call path from `main()` | Go | High (Compiler verified) |
| 2 | `package` | Import graph analysis verifying package resolution in dependency AST | Python, Node.js | Medium (Best-effort heuristic) |
| 3 | `unknown` | Vulnerability exists in installed package but call graph cannot be statically resolved | C/C++, Rust, Dynamic bindings | Low |

### Non-Negotiable Safety Invariants

1. **CISA KEV Override**: Any vulnerability listed in the CISA Known Exploited Vulnerabilities catalog **always blocks** in enforce mode, regardless of reachability status, unless suppressed by a cryptographically signed VEX statement.
2. **Conservative Defaults**: If an analyzer fails or encounters dynamic reflection/metaprogramming, precision downgrades to `unknown`, and the vulnerability is treated as reachable.

## Compliance and Standards Mapping

- **CISA**: Managing Vulnerabilities in Software (Known Exploited Vulnerabilities Catalog).
- **OpenVEX Specification**: Status justifications (`vulnerable_code_not_in_execute_path`, `vulnerable_code_cannot_be_controlled_by_adversary`).
