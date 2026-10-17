#!/usr/bin/env bash
set -euo pipefail

echo "Executing AegisChain Attack Lab Suite..."
go run attack-lab/runner.go
echo "All 14 attack scenarios verified successfully!"
