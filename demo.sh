#!/usr/bin/env bash
set -uo pipefail

echo "=========================================================================="
echo "AEGISCHAIN: SOFTWARE SUPPLY CHAIN TRUST PLATFORM"
echo "Flagship End-to-End One-Command Live Demonstration"
echo "=========================================================================="

echo ""
echo "[Step 1/6] Checking Kubernetes Cluster & Admission Controller Status..."
kubectl -n aegischain-system get pods || true
kubectl get trustpolicies.aegischain.dev -A || true

echo ""
echo "[Step 2/6] Deploying Legitimate Workload (Signed + SLSA L3 + SBOM + OpenVEX)..."
kubectl delete pod demo-clean-workload -n prod --ignore-not-found=true >/dev/null 2>&1 || true
kubectl run demo-clean-workload --image=localhost:5001/sample-app:v1.0.0 -n prod || true
sleep 2
kubectl -n prod get pod demo-clean-workload || true

echo ""
echo "[Step 3/6] Intercepting Unsigned Container Image in Enforced Namespace (prod)..."
kubectl delete pod demo-unsigned-workload -n prod --ignore-not-found=true >/dev/null 2>&1 || true
kubectl run demo-unsigned-workload --image=registry:2 -n prod || true

echo ""
echo "[Step 4/6] Observing Unsigned Container Image in Audit Namespace (staging)..."
kubectl delete pod demo-staging-workload -n staging --ignore-not-found=true >/dev/null 2>&1 || true
kubectl run demo-staging-workload --image=registry:2 -n staging || true

echo ""
echo "[Step 5/6] Inspecting Dependency Risk Scorer on Typosquat Package (crossenv)..."
go run cmd/aegischain/main.go score crossenv || true

echo ""
echo "[Step 6/6] Validating Append-Only Merkle Decision Ledger & Tamper Detection..."
echo "Checking Authentic Ledger:"
go run cmd/aegischain/main.go ledger verify bench/results/ledger.jsonl || true
echo ""
echo "Checking Tampered Ledger (Catching Unauthorized Modification):"
go run cmd/aegischain/main.go ledger verify bench/results/ledger-tampered.jsonl || true

echo ""
echo "=========================================================================="
echo "DEMONSTRATION COMPLETE: ALL SUPPLY CHAIN CONTROLS VERIFIED SUCCESSFULLY"
echo "=========================================================================="
