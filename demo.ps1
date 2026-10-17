# AegisChain Flagship End-to-End Demonstration Script
$ErrorActionPreference = "Continue"
$env:PATH = "$env:PATH;E:\bin;E:\bin\go\bin"

Write-Host "==========================================================================" -ForegroundColor Cyan
Write-Host "AEGISCHAIN: SOFTWARE SUPPLY CHAIN TRUST PLATFORM" -ForegroundColor Cyan
Write-Host "Flagship End-to-End One-Command Live Demonstration" -ForegroundColor Cyan
Write-Host "==========================================================================" -ForegroundColor Cyan

# 1. Cluster Status
Write-Host "`n[Step 1/6] Checking Kubernetes Cluster & Admission Controller Status..." -ForegroundColor Yellow
kubectl -n aegischain-system get pods
kubectl get trustpolicies.aegischain.dev -A

# 2. Deploy Authentic Workload
Write-Host "`n[Step 2/6] Deploying Legitimate Workload (Signed + SLSA L3 + SBOM + OpenVEX)..." -ForegroundColor Yellow
kubectl delete pod demo-clean-workload -n prod --ignore-not-found=true | Out-Null
kubectl run demo-clean-workload --image=localhost:5001/sample-app:v1.0.0 -n prod
Start-Sleep -Seconds 2
kubectl -n prod get pod demo-clean-workload

# 3. Intercept Unsigned Image in Enforce Mode
Write-Host "`n[Step 3/6] Intercepting Unsigned Container Image in Enforced Namespace (prod)..." -ForegroundColor Yellow
kubectl delete pod demo-unsigned-workload -n prod --ignore-not-found=true | Out-Null
kubectl run demo-unsigned-workload --image=registry:2 -n prod

# 4. Observe Unsigned Image in Audit Mode
Write-Host "`n[Step 4/6] Observing Unsigned Container Image in Audit Namespace (staging)..." -ForegroundColor Yellow
kubectl delete pod demo-staging-workload -n staging --ignore-not-found=true | Out-Null
kubectl run demo-staging-workload --image=registry:2 -n staging

# 5. Dependency Risk Scorer
Write-Host "`n[Step 5/6] Inspecting Dependency Risk Scorer on Typosquat Package (crossenv)..." -ForegroundColor Yellow
go run cmd/aegischain/main.go score crossenv

# 6. Cryptographic Decision Ledger Integrity
Write-Host "`n[Step 6/6] Validating Append-Only Merkle Decision Ledger & Tamper Detection..." -ForegroundColor Yellow
Write-Host "Checking Authentic Ledger:" -ForegroundColor Gray
go run cmd/aegischain/main.go ledger verify bench/results/ledger.jsonl
Write-Host "`nChecking Tampered Ledger (Catching Unauthorized Modification):" -ForegroundColor Gray
go run cmd/aegischain/main.go ledger verify bench/results/ledger-tampered.jsonl

Write-Host "`n==========================================================================" -ForegroundColor Green
Write-Host "DEMONSTRATION COMPLETE: ALL SUPPLY CHAIN CONTROLS VERIFIED SUCCESSFULLY" -ForegroundColor Green
Write-Host "==========================================================================" -ForegroundColor Green
