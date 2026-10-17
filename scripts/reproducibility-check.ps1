# AegisChain Reproducible Build Verification Script
$ErrorActionPreference = "Stop"
$env:PATH = "$env:PATH;E:\bin;E:\bin\go\bin"

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "AEGISCHAIN REPRODUCIBLE BUILD VERIFICATION" -ForegroundColor Cyan
Write-Host "Compiling Go binary in two isolated passes (-trimpath)..." -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan

$buildDirA = "dist/repro-a"
$buildDirB = "dist/repro-b"

if (Test-Path $buildDirA) { Remove-Item -Recurse -Force $buildDirA }
if (Test-Path $buildDirB) { Remove-Item -Recurse -Force $buildDirB }

New-Item -ItemType Directory -Force -Path $buildDirA | Out-Null
New-Item -ItemType Directory -Force -Path $buildDirB | Out-Null

$binaryName = "aegischain.exe"

# Pass 1
Write-Host "[Pass 1/2] Compiling $binaryName into $buildDirA..." -ForegroundColor Yellow
$env:CGO_ENABLED = "0"
go build -trimpath -ldflags="-s -w -buildid=" -o "$buildDirA/$binaryName" ./cmd/aegischain

# Pass 2
Write-Host "[Pass 2/2] Compiling $binaryName into $buildDirB..." -ForegroundColor Yellow
go build -trimpath -ldflags="-s -w -buildid=" -o "$buildDirB/$binaryName" ./cmd/aegischain

# Calculate SHA-256 Hashes
$hashA = (Get-FileHash "$buildDirA/$binaryName" -Algorithm SHA256).Hash
$hashB = (Get-FileHash "$buildDirB/$binaryName" -Algorithm SHA256).Hash

Write-Host "`nBuild A SHA-256: $hashA" -ForegroundColor Gray
Write-Host "Build B SHA-256: $hashB" -ForegroundColor Gray

if ($hashA -eq $hashB) {
    Write-Host "`nREPRODUCIBLE BUILD RESULT: PASS" -ForegroundColor Green
    Write-Host "Bit-for-bit identical binary artifact produced across independent builds." -ForegroundColor Green
    exit 0
} else {
    Write-Host "`nREPRODUCIBLE BUILD RESULT: FAIL" -ForegroundColor Red
    Write-Host "Binary hash mismatch between Pass 1 and Pass 2." -ForegroundColor Red
    exit 1
}
