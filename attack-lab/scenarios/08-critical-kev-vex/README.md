# Scenario 08: Critical KEV Vulnerability and Signed OpenVEX Waiver

## Real-World Incident Context
Mirrors high-impact zero-day vulnerabilities cataloged in CISA's Known Exploited Vulnerabilities (KEV) catalog (such as **Log4Shell - CVE-2021-44228** or **Spring4Shell - CVE-2022-22965**). Workloads containing active KEV criticals must be halted immediately unless a verifiable, cryptographically signed Vulnerability Exploitability eXchange (OpenVEX) statement proves non-exploitability in the target execution environment.

## Attack Vector / Evaluation
1. **Phase A (Blocked)**: Workload image contains an unwaived KEV critical vulnerability (`CVE-2026-3199`). AegisChain blocks admission with a `vulnerability_gate` violation.
2. **Phase B (Admitted)**: Security team issues a signed OpenVEX statement with status `not_affected` and impact justification `vulnerable_code_cannot_be_controlled_by_adversary`. The exact same image is re-evaluated and admitted cleanly.

## Expected Verdict
- **Phase A**: `DENY` (`vulnerability_gate`: Unwaived critical KEV vulnerability)
- **Phase B**: `ALLOW` (`vulnerability_gate`: Waived via signed OpenVEX statement)
- **Remediation**: `Apply security patch or publish cryptographically signed OpenVEX waiver`
