from __future__ import annotations
import ast
import math
import re
from typing import List, Optional
from .models import InstallScripts, RiskFactor

SUSPICIOUS_COMMANDS = [
    (r"\b(curl|wget)\b.*http|require\(['\"]https?['\"]\)|urllib\.request|requests\.", "outbound_network_download", 50, "Direct network download via curl/wget or http module in install script"),
    (r"(nc|ncat|netcat)\s+-[el]", "reverse_shell_indicator", 95, "Reverse shell invocation (netcat) in install hook"),
    (r"powershell(\.exe)?\s+(-(enc|encodedcommand)|-(nop|noprofile))", "obfuscated_powershell", 90, "Obfuscated PowerShell execution in install script"),
    (r"child_process\.(exec|execSync|spawn|spawnSync)", "process_spawning", 40, "Execution of external system binaries in install hook"),
    (r"os\.system\(|subprocess\.(Popen|call|run|check_output)", "python_process_execution", 45, "Execution of system commands during package setup"),
    (r"(process\.env|os\.environ)(\.|\[?['\"]?)(AWS_|GITHUB_|TOKEN|KEY|PASS|SECRET)", "credential_exfiltration_attempt", 90, "Access and access-pattern to sensitive environmental credentials/tokens"),
    (r"Buffer\.from\([^)]*['\"]base64['\"]\)", "base64_payload_execution", 60, "Execution of decoded base64 payload during installation"),
    (r"base64\.b64decode\(", "python_base64_decode", 60, "Dynamic base64 decoding during package build/install"),
    (r"eval\(|Function\(", "dynamic_code_evaluation", 65, "Arbitrary dynamic code execution (eval) during package installation"),
]


def shannon_entropy(data: str) -> float:
    """Calculate Shannon entropy to flag high-entropy obfuscated strings."""
    if not data:
        return 0.0
    entropy = 0.0
    length = len(data)
    counts = {}
    for char in data:
        counts[char] = counts.get(char, 0) + 1
    for count in counts.values():
        p = count / length
        entropy -= p * math.log2(p)
    return entropy


class ScriptStaticAnalyzer:
    def analyze(self, scripts: Optional[InstallScripts]) -> List[RiskFactor]:
        if not scripts:
            return []

        factors: List[RiskFactor] = []
        script_dict = scripts.model_dump(exclude_none=True)

        for script_name, content in script_dict.items():
            if not content:
                continue

            # 1. Regex heuristics on script content
            for pattern, rule_name, score, desc in SUSPICIOUS_COMMANDS:
                if re.search(pattern, content, re.IGNORECASE):
                    severity = "CRITICAL" if score >= 80 else ("HIGH" if score >= 50 else "MEDIUM")
                    snippet = content[:120].strip().replace("\n", " ")
                    factors.append(RiskFactor(
                        category="static_analysis",
                        name=f"{script_name}_{rule_name}",
                        score_delta=score,
                        severity=severity,
                        evidence=f"Suspicious pattern in {script_name}: {desc} (Snippet: {snippet})",
                        remediation=f"Inspect and remove suspicious execution hooks in {script_name}",
                    ))

            # 2. Entropy check for obfuscated blobs (tokens or base64 code)
            tokens = re.findall(r"[A-Za-z0-9+/=]{40,}", content)
            for tok in tokens:
                entropy = shannon_entropy(tok)
                if entropy > 4.5:
                    factors.append(RiskFactor(
                        category="static_analysis",
                        name=f"{script_name}_high_entropy_blob",
                        score_delta=70,
                        severity="HIGH",
                        evidence=f"High-entropy obfuscated string detected in {script_name} (entropy: {entropy:.2f}, length: {len(tok)})",
                        remediation="Ensure all dependencies are distributed as plain, readable source code without packed binary blobs",
                    ))
                    break

            # 3. Python AST analysis if setup_py
            if script_name == "setup_py":
                factors.extend(self._analyze_python_ast(content))

        return factors

    def _analyze_python_ast(self, code: str) -> List[RiskFactor]:
        factors: List[RiskFactor] = []
        try:
            tree = ast.parse(code)
            for node in ast.walk(tree):
                # Check for socket, urllib, httpx, requests imports in setup.py
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        if alias.name in ["socket", "urllib.request", "http.client"]:
                            factors.append(RiskFactor(
                                category="static_analysis",
                                name="setup_py_network_import",
                                score_delta=50,
                                severity="HIGH",
                                evidence=f"Network module '{alias.name}' imported in setup.py",
                                remediation="Network requests during package installation are considered high risk",
                            ))
        except SyntaxError:
            pass
        return factors
