# ADR-0008: Decoupled Python FastAPI Microservice for Deep Dependency Risk Scoring

- Status: Accepted
- Date: 2026-10-17
- Deciders: AegisChain Architecture Team
- Consulted: Data Science, Platform Security

## Context and Problem Statement

Modern software supply chain attacks frequently target dependencies via typosquatting, dependency confusion, malicious install-time scripts (`preinstall`, `setup.py`), and rapid ownership takeovers before public CVEs are assigned.

Analyzing these threats requires string similarity algorithms (Damerau-Levenshtein, homoglyphs), static AST parsing for obfuscated payload execution, and ecosystem metadata analysis (PyPI, npm, Go). Implementing and updating these complex heuristics inside a low-level Go admission controller creates maintenance friction and potential memory/CPU contention.

## Decision Drivers

- Isolation of complex string matching and AST parsing from the core Go webhook admission loop.
- Rapid iteration on risk heuristics, weights, and ML/heuristic scoring models.
- Graceful degradation: If the risk scorer service is unreachable, the admission controller falls back to cached results or enters configured degraded mode according to namespace policy.
- Deterministic offline evaluation against labeled corpora.

## Considered Options

1. **Option 1: Decoupled Python FastAPI Microservice with Local Caching in Go Engine**
2. **Option 2: Native Go Implementation of all package analytics directly in engine**
3. **Option 3: Reliance exclusively on external SaaS risk APIs**

## Decision Outcome

Chosen option: **Option 1 (Decoupled Python FastAPI Microservice)**.

### Architecture and Interconnect

1. **Service Interface**: `risk-scorer/` exposes a high-performance REST endpoint (`POST /v1/score`) receiving SBOM component inventories and returning granular risk signals (0-100 composite score, typosquat flags, install-time static flags).
2. **Circuit Breaker**: The Go engine wraps the risk client in a circuit breaker with a 150ms timeout and in-memory TTL caching.
3. **Deterministic Fixtures**: All external registry lookups (deps.dev, PyPI, npm) use local versioned dataset snapshots for offline tests and predictable benchmark repeatability.

## Compliance and Standards Mapping

- **OpenSSF S2C2F**: Ingestion Track Level 4 (Comprehensive analysis of dependency integrity and package metadata).
- **NIST SP 800-218 (SSDF)**: PO.1.3, PS.1.1 (Mitigating third-party software risks).
