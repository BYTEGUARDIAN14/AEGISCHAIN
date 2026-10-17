# AegisChain Attack Lab Execution Script
$ErrorActionPreference = "Stop"
$env:PATH = "$env:PATH;E:\bin;E:\bin\go\bin"

Write-Host "Executing AegisChain Attack Lab Suite..." -ForegroundColor Cyan
go run attack-lab/runner.go
if ($LASTEXITCODE -ne 0) {
    Write-Error "Attack Lab execution failed with exit code $LASTEXITCODE"
    exit $LASTEXITCODE
}
Write-Host "All 14 attack scenarios verified successfully!" -ForegroundColor Green
