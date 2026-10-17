from __future__ import annotations
import re
from typing import List, Optional
from .models import RiskFactor

# Common internal prefix conventions targeted in dependency confusion attacks
INTERNAL_PATTERNS = [
    r"^@?(byteaegis|byteguardian|internal|corp|private|enterprise|secops)[-_/]",
    r"[-_](internal|corp|private|secret|infra|auth)$",
]

SUSPICIOUS_VERSIONS = [
    r"^9[0-9]\.",       # 90.x.x, 99.x.x
    r"^[1-9][0-9]{2,}\.", # 100.x.x, 999.x.x
    r"^9000\.",
]


class DependencyConfusionDetector:
    def __init__(self, internal_namespaces: Optional[List[str]] = None):
        self.internal_namespaces = internal_namespaces or [
            "byteaegis", "byteguardian", "corp", "internal", "private"
        ]

    def analyze(self, name: str, version: Optional[str] = "1.0.0", ecosystem: str = "npm") -> List[RiskFactor]:
        factors: List[RiskFactor] = []
        lower_name = name.lower()

        # 1. Internal prefix matching
        for pattern in INTERNAL_PATTERNS:
            if re.search(pattern, lower_name):
                factors.append(RiskFactor(
                    category="confusion",
                    name="internal_naming_pattern",
                    score_delta=50,
                    severity="HIGH",
                    evidence=f"Package name '{name}' matches internal corporate naming pattern ({pattern})",
                    remediation="Verify registry scope configuration (.npmrc / pip.conf) to prevent public resolution of internal packages",
                ))
                break

        # 2. Suspicious inflated version number anomaly (Dependency Confusion weaponization)
        if version:
            for v_pattern in SUSPICIOUS_VERSIONS:
                if re.search(v_pattern, version):
                    factors.append(RiskFactor(
                        category="confusion",
                        name="inflated_version_number",
                        score_delta=40,
                        severity="HIGH",
                        evidence=f"Anomalously high package version '{version}' typical of public dependency confusion override attacks",
                        remediation="Pin exact internal versions or configure package scoping to internal feed only",
                    ))
                    break

        return factors
