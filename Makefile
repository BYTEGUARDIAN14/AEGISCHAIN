.DEFAULT_GOAL := help

SHELL := bash
.SHELLFLAGS := -eu -o pipefail -c

BIN_DIR ?= ./bin
KIND_CLUSTER_NAME ?= aegischain-cluster
REGISTRY_NAME ?= aegis-registry
REGISTRY_PORT ?= 5001

.PHONY: help
help: ## Display this help message
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z0-9_-]+:.*?## / {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST)

.PHONY: tidy
tidy: ## Download and tidy Go dependencies
	go mod tidy
	go mod verify

.PHONY: lint
lint: ## Run linters across Go codebase
	golangci-lint run ./...

.PHONY: test
test: ## Run unit tests with coverage
	go test -v -coverprofile=coverage.out ./...

.PHONY: build
build: ## Build all binaries (CLI, trust-engine, admission-webhook)
	@mkdir -p $(BIN_DIR)
	go build -trimpath -ldflags="-s -w" -o $(BIN_DIR)/aegischain ./cmd/aegischain
	go build -trimpath -ldflags="-s -w" -o $(BIN_DIR)/trust-engine ./cmd/trust-engine
	go build -trimpath -ldflags="-s -w" -o $(BIN_DIR)/admission-webhook ./cmd/admission-webhook

.PHONY: kind-up
kind-up: ## Bootstrap local registry and kind cluster
	powershell -ExecutionPolicy Bypass -File deploy/kind/kind-up.ps1

.PHONY: sample-pipeline
sample-pipeline: ## Run secure build, sign, and attestation pipeline on sample app
	powershell -ExecutionPolicy Bypass -File scripts/build-and-attest-sample.ps1

.PHONY: kind-down
kind-down: ## Tear down kind cluster and local registry
	kind delete cluster --name $(KIND_CLUSTER_NAME)
	docker rm -f $(REGISTRY_NAME)

.PHONY: attack-lab
attack-lab: ## Execute end-to-end Attack Lab scenario matrix
	@powershell -ExecutionPolicy Bypass -File attack-lab/run.ps1 || bash attack-lab/run.sh

.PHONY: bench
bench: ## Run automated performance and admission latency benchmarks
	@go test -v -bench=. -benchmem ./internal/... > bench/results/engine-bench.txt || true
	@powershell -ExecutionPolicy Bypass -File bench/run-benchmarks.ps1 || true

.PHONY: demo
demo: ## Run end-to-end 3-minute flagship trust platform demonstration
	@powershell -ExecutionPolicy Bypass -File demo.ps1 || bash demo.sh
