from __future__ import annotations
import json
import os
from typing import Dict, List, Optional
from .models import (
    PackageQuery,
    PackageRiskScore,
    RiskFactor,
    SBOMScoreRequest,
    SBOMScoreResponse,
)
from .typosquat import TyposquatDetector
from .confusion import DependencyConfusionDetector
from .static_analysis import ScriptStaticAnalyzer


class DependencyRiskEngine:
    def __init__(self, data_dir: Optional[str] = None):
        if not data_dir:
            base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            data_dir = os.path.join(base_dir, "data")

        self.typosquat = TyposquatDetector(os.path.join(data_dir, "top_packages.json"))
        self.confusion = DependencyConfusionDetector()
        self.analyzer = ScriptStaticAnalyzer()

        # Load known malicious database
        malicious_path = os.path.join(data_dir, "known_malicious.json")
        self.known_malicious: Dict[str, Dict] = {}
        if os.path.exists(malicious_path):
            with open(malicious_path, "r", encoding="utf-8") as f:
                data = json.load(f)
                for item in data.get("malicious_packages", []):
                    key = f"{item['ecosystem'].lower()}:{item['name'].lower()}"
                    self.known_malicious[key] = item

    def score_package(self, pkg: PackageQuery) -> PackageRiskScore:
        factors: List[RiskFactor] = []
        is_malicious = False
        hard_gate = False
        ecosystem = pkg.ecosystem.lower()
        name_lower = pkg.name.lower()

        # 1. Known malicious check (Immediate Hard Gate)
        mal_key = f"{ecosystem}:{name_lower}"
        if mal_key in self.known_malicious:
            entry = self.known_malicious[mal_key]
            factors.append(RiskFactor(
                category="known_malicious",
                name="osv_malicious_advisory",
                score_delta=100,
                severity="CRITICAL",
                evidence=f"Confirmed malicious package listed in security advisory {entry.get('advisory')}: {entry.get('reason')}",
                remediation="Remove dependency immediately and audit compromised environment",
            ))
            is_malicious = True
            hard_gate = True

        # 2. Typosquatting Analysis
        typo_factors = self.typosquat.analyze(pkg.name, ecosystem)
        factors.extend(typo_factors)
        for f in typo_factors:
            if f.name in ["separator_trick", "damerau_levenshtein_distance_1", "homoglyph_substitution"]:
                hard_gate = True

        # 3. Dependency Confusion Analysis
        confusion_factors = self.confusion.analyze(pkg.name, pkg.version, ecosystem)
        factors.extend(confusion_factors)

        # 4. Install-time Static Script Analysis
        script_factors = self.analyzer.analyze(pkg.scripts)
        factors.extend(script_factors)
        for f in script_factors:
            if "credential_exfiltration" in f.name or "reverse_shell" in f.name:
                is_malicious = True
                hard_gate = True

        # 5. Score aggregation with dampening
        raw_score = sum(f.score_delta for f in factors)
        computed_score = min(100, raw_score)

        if hard_gate:
            computed_score = max(computed_score, 85)
        if is_malicious:
            computed_score = 100

        # Determine qualitative risk level
        if computed_score >= 80:
            level = "CRITICAL"
        elif computed_score >= 50:
            level = "HIGH"
        elif computed_score >= 25:
            level = "MEDIUM"
        else:
            level = "LOW"

        return PackageRiskScore(
            name=pkg.name,
            ecosystem=pkg.ecosystem,
            version=pkg.version,
            score=computed_score,
            risk_level=level,
            is_malicious=is_malicious,
            hard_gate_triggered=hard_gate,
            factors=factors,
        )

    def score_sbom(self, request: SBOMScoreRequest) -> SBOMScoreResponse:
        evaluated: List[PackageRiskScore] = []
        flagged: List[PackageRiskScore] = []
        max_score = 0
        has_malicious = False

        for comp in request.components:
            score_res = self.score_package(comp)
            evaluated.append(score_res)

            if score_res.score > max_score:
                max_score = score_res.score

            if score_res.is_malicious:
                has_malicious = True

            if score_res.score >= request.risk_threshold or score_res.hard_gate_triggered:
                flagged.append(score_res)

        verdict = "allow"
        if has_malicious or max_score > request.risk_threshold:
            verdict = "deny"

        return SBOMScoreResponse(
            overall_risk_score=max_score,
            risk_threshold=request.risk_threshold,
            has_malicious_packages=has_malicious,
            verdict=verdict,
            component_count=len(request.components),
            flagged_packages_count=len(flagged),
            flagged_packages=flagged,
            evaluated_packages=evaluated,
        )
