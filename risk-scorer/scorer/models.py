from __future__ import annotations
from typing import Dict, List, Optional
from pydantic import BaseModel, Field


class InstallScripts(BaseModel):
    preinstall: Optional[str] = None
    install: Optional[str] = None
    postinstall: Optional[str] = None
    setup_py: Optional[str] = None


class PackageQuery(BaseModel):
    name: str = Field(..., description="Package name")
    ecosystem: str = Field(default="npm", description="Package ecosystem: npm, pypi, or go")
    version: Optional[str] = Field(default="latest", description="Package version")
    scripts: Optional[InstallScripts] = Field(default=None, description="Install-time script contents")


class RiskFactor(BaseModel):
    category: str = Field(..., description="Signal category: typosquatting, static_analysis, confusion, etc.")
    name: str = Field(..., description="Name of the specific detection rule")
    score_delta: int = Field(..., description="Contribution to the 0-100 risk score")
    severity: str = Field(..., description="INFO, LOW, MEDIUM, HIGH, CRITICAL")
    evidence: str = Field(..., description="Human-readable concrete evidence")
    remediation: Optional[str] = None


class PackageRiskScore(BaseModel):
    name: str
    ecosystem: str
    version: Optional[str] = "latest"
    score: int = Field(..., ge=0, le=100, description="Overall risk score (0=clean, 100=highest risk)")
    risk_level: str = Field(..., description="LOW, MEDIUM, HIGH, CRITICAL")
    is_malicious: bool = False
    hard_gate_triggered: bool = False
    factors: List[RiskFactor] = []


class SBOMScoreRequest(BaseModel):
    components: List[PackageQuery]
    namespace: Optional[str] = "prod"
    risk_threshold: Optional[int] = 65


class SBOMScoreResponse(BaseModel):
    overall_risk_score: int
    risk_threshold: int
    has_malicious_packages: bool
    verdict: str  # allow | deny
    component_count: int
    flagged_packages_count: int
    flagged_packages: List[PackageRiskScore]
    evaluated_packages: List[PackageRiskScore]
