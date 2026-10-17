# Scenario 09: Malicious Dependency Injection & Postinstall Script

## Real-World Incident Context
Mirrors notorious open-source software supply chain compromises such as **event-stream** (flatmap-stream bitcoin wallet stealer) and **cross-env** typosquatting, where malicious actors hijack dependencies or register lookalike package names to execute arbitrary JavaScript/Python during package installation.

## Attack Vector / Evaluation
The dependency set inside the CycloneDX SBOM includes `crossenv` (a typosquat of `cross-env`) which contains a postinstall lifecycle script inspecting environment variables for `AWS_SECRET_ACCESS_KEY` and spawning a background curl exfiltration process. The AegisChain Dependency Risk Scorer AST analyzer inspects the package and assigns a risk score of 100/100.

## Expected Verdict
- **Verdict**: `DENY`
- **Trust Score**: `0 / 100`
- **Failing Rule**: `dependency_risk_gate`
- **Reason**: `Dependency risk score (100) exceeds threshold (65); malicious postinstall script detected`
- **Remediation**: `Remove flagged typosquatted dependency crossenv and pin canonical cross-env package`
