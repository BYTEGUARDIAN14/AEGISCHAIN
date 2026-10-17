from __future__ import annotations
import os
import sys
from fastapi import FastAPI, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware

# Ensure risk-scorer root is in python path
current_dir = os.path.dirname(os.path.abspath(__file__))
parent_dir = os.path.dirname(current_dir)
if parent_dir not in sys.path:
    sys.path.insert(0, parent_dir)

from scorer.engine import DependencyRiskEngine
from scorer.models import (
    PackageQuery,
    PackageRiskScore,
    SBOMScoreRequest,
    SBOMScoreResponse,
)

app = FastAPI(
    title="AegisChain Dependency Risk Scorer",
    description="Microservice providing real-time package typosquatting, dependency confusion, and static AST analysis",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

engine = DependencyRiskEngine()


@app.get("/healthz", status_code=status.HTTP_200_OK)
def healthz():
    return {"status": "healthy", "service": "aegischain-risk-scorer", "version": "1.0.0"}


@app.get("/readyz", status_code=status.HTTP_200_OK)
def readyz():
    return {"status": "ready", "service": "aegischain-risk-scorer"}


@app.post("/score/package", response_model=PackageRiskScore)
def score_single_package(query: PackageQuery):
    try:
        return engine.score_package(query)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/score/sbom", response_model=SBOMScoreResponse)
def score_sbom(request: SBOMScoreRequest):
    try:
        return engine.score_sbom(request)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("api.main:app", host="0.0.0.0", port=8088, reload=False)
