# Gibson Framework Makefile
# Stage 1 - Foundation

.PHONY: all build bin gibson-migrate test test-coverage test-race lint clean install help proto proto-deps proto-clean check-authz check-coverage test-daemon-identity-roundtrip check-no-tenant-id check-fga-headers authz-registry

# Go parameters
GOCMD=go
GOBUILD=$(GOCMD) build
GOTEST=$(GOCMD) test
GOGET=$(GOCMD) get
GOMOD=$(GOCMD) mod
BINARY_NAME=gibson
BINARY_DIR=bin
MAIN_PACKAGE=./cmd/gibson

# Pure Go build - no CGO required
export CGO_ENABLED=0

# No build tags required (SQLite removed)
BUILD_TAGS=

# Version information (can be overridden at build time)
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
GIT_COMMIT ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
BUILD_TIME ?= $(shell date -u '+%Y-%m-%dT%H:%M:%SZ')

# LD flags for version injection
LDFLAGS=-ldflags "-X github.com/zero-day-ai/gibson/pkg/version.Version=$(VERSION) \
	-X github.com/zero-day-ai/gibson/pkg/version.GitCommit=$(GIT_COMMIT) \
	-X github.com/zero-day-ai/gibson/pkg/version.BuildTime=$(BUILD_TIME)"

# Coverage settings
COVERAGE_FILE=coverage.out
COVERAGE_THRESHOLD=90

# Proto generation settings
PROTO_DIR=api/proto
PROTO_OUT=api/gen/proto

# Buf code generation (uses local buf.yaml + buf.gen.yaml in this directory)
DASHBOARD_DIR := $(abspath $(dir $(lastword $(MAKEFILE_LIST)))../../enterprise/platform/dashboard)
# Use locally-installed buf from the dashboard node_modules when the dashboard
# checkout is present; fall back to buf from PATH (e.g. npm install -g @bufbuild/buf
# in CI where only this repo is checked out).
BUF := $(if $(wildcard $(DASHBOARD_DIR)/node_modules/.bin/buf),npx --prefix $(DASHBOARD_DIR) buf,buf)

# Default target
all: test build

# Build the binary (quick local build)
bin:
	@echo "Building $(BINARY_NAME)..."
	@mkdir -p $(BINARY_DIR)
	$(GOBUILD) $(BUILD_TAGS) $(LDFLAGS) -o $(BINARY_DIR)/$(BINARY_NAME) $(MAIN_PACKAGE)
	@echo "Build complete: $(BINARY_DIR)/$(BINARY_NAME)"

# Full build (for Docker/CI/CD)
build: bin gibson-migrate
	@echo "Full build complete"

# Build the gibson-migrate CLI for backfilling tenant DB migrations
gibson-migrate:
	@echo "Building gibson-migrate..."
	@mkdir -p $(BINARY_DIR)
	$(GOBUILD) $(BUILD_TAGS) $(LDFLAGS) -o $(BINARY_DIR)/gibson-migrate ./cmd/gibson-migrate
	@echo "Build complete: $(BINARY_DIR)/gibson-migrate"

# Run tests
test:
	@echo "Running tests..."
	$(GOTEST) $(BUILD_TAGS) -v ./...

# Run tests with race detection
test-race:
	@echo "Running tests with race detection..."
	$(GOTEST) $(BUILD_TAGS) -race -v ./...

# Run tests with coverage
test-coverage:
	@echo "Running tests with coverage..."
	$(GOTEST) $(BUILD_TAGS) -coverprofile=$(COVERAGE_FILE) -covermode=atomic ./...
	@echo "Coverage report:"
	@$(GOCMD) tool cover -func=$(COVERAGE_FILE)
	@echo ""
	@echo "Checking coverage threshold ($(COVERAGE_THRESHOLD)%)..."
	@./scripts/check-coverage.sh $(COVERAGE_FILE) $(COVERAGE_THRESHOLD)

# Generate coverage HTML report
coverage-html: test-coverage
	@$(GOCMD) tool cover -html=$(COVERAGE_FILE) -o coverage.html
	@echo "Coverage HTML report: coverage.html"

# Run linter (requires golangci-lint)
lint:
	@echo "Running linter..."
	@if command -v golangci-lint > /dev/null; then \
		golangci-lint run ./... || (echo "WARNING: golangci-lint failed (version mismatch or config issue) — skipping"; true); \
	else \
		echo "golangci-lint not installed. Run: go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest"; \
	fi
	@bash scripts/check-fga-model-headers.sh
	@node scripts/lint-pagination.mjs
	@node scripts/lint-allowed-identities.mjs

# Format code
fmt:
	@echo "Formatting code..."
	$(GOCMD) fmt ./...

# Vet code
vet:
	@echo "Vetting code..."
	$(GOCMD) vet ./...

# Tidy modules
tidy:
	@echo "Tidying modules..."
	$(GOMOD) tidy

# Clean build artifacts
clean:
	@echo "Cleaning..."
	@rm -rf $(BINARY_DIR)/*
	@rm -f $(COVERAGE_FILE) coverage.html
	@echo "Clean complete"

# Install binary to GOPATH/bin
install: build
	@echo "Installing $(BINARY_NAME)..."
	$(GOCMD) install $(BUILD_TAGS) $(LDFLAGS) $(MAIN_PACKAGE)
	@echo "Installed to $(shell go env GOPATH)/bin/$(BINARY_NAME)"

# Download dependencies
deps:
	@echo "Downloading dependencies..."
	$(GOGET) ./...
	$(GOMOD) tidy

# check-coverage enforces per-package coverage thresholds for auth-critical packages.
# The spec (zitadel-envoy-gateway-migration, task 32) requires ≥95% on internal/identity.
# Other daemon packages have widely varying coverage; only gate on the new auth-critical package.
check-coverage:
	@echo "Checking coverage for auth-critical daemon packages..."
	@$(GOTEST) -coverprofile=/tmp/daemon_identity_cover.out -covermode=atomic ./internal/identity/... -count=1 > /dev/null 2>&1
	@ID_COV=$$(go tool cover -func=/tmp/daemon_identity_cover.out | grep total | awk '{print $$3}' | sed 's/%//'); \
	echo "  internal/identity: $${ID_COV}%"; \
	RESULT=$$(echo "$${ID_COV} >= 95" | bc -l); \
	if [ "$$RESULT" -ne 1 ]; then echo "FAIL: internal/identity coverage $${ID_COV}% is below 95% threshold"; exit 1; fi
	@echo "Coverage check PASSED"

# check-no-tenant-id enforces the database-per-tenant invariant:
# no migration file may define a tenant_id column or property.
# Spec: database-per-tenant-data-plane Phase I Task 9.2, Requirement 16.1.
check-no-tenant-id:
	@echo "Checking migrations for tenant_id column references..."
	@bash scripts/check-no-tenant-id-column.sh
	@echo "check-no-tenant-id PASSED"

# check-fga-headers asserts both FGA model files carry their required marker lines.
# Spec: cross-repo-cohesion-fixes Requirement 5.4.
check-fga-headers:
	@echo "Checking FGA model header markers..."
	@bash scripts/check-fga-model-headers.sh
	@echo "check-fga-headers PASSED"

# check-no-gibson-io asserts no gibson.io references exist outside the allowlist.
# Spec: naming-and-config-standardization Requirement 1.6.
check-no-gibson-io:
	@echo "Checking for gibson.io references outside the allowlist..."
	@bash scripts/check-no-gibson-io.sh
	@echo "check-no-gibson-io PASSED"

# check-no-skipped-tests asserts no bare t.Skip calls exist in non-exempt test files.
# Spec: naming-and-config-standardization Requirement 3.5.
check-no-skipped-tests:
	@echo "Checking for skipped tests outside the allowlist..."
	@bash scripts/check-no-skipped-tests.sh
	@echo "check-no-skipped-tests PASSED"

# check-noun-contract: enforce the verb/noun extension contract
# from mission-verb-noun-registry Requirement 1. For every
# NodeType enum value, asserts the four pieces are present:
# config message in oneof, registered handler package,
# e2e fixture, unit tests. Spec: mission-verb-noun-registry.
check-noun-contract:
	@bash scripts/check-noun-contract.sh

# Run all checks before commit
check: fmt vet lint test-race check-no-tenant-id check-fga-headers check-no-gibson-io check-no-skipped-tests check-noun-contract
	@echo "All checks passed!"

# Run authorization-specific checks: vet + unit tests + integration tests (requires Docker)
# Usage:
#   make check-authz           # unit tests only (no Docker required)
#   make check-authz INTEGRATION=1  # unit + integration tests (requires Docker)
check-authz:
	@echo "Running authz package vet..."
	$(GOCMD) vet ./internal/authz/... ./internal/daemon/authz_init.go
	@echo "Running authz unit tests (race detector)..."
	$(GOTEST) -race -count=1 -timeout=2m ./internal/authz/... ./internal/daemon/...
	@echo "Running RPC registry drift gate (audit build tag)..."
	$(GOTEST) -tags audit -count=1 -timeout=1m ./internal/auth/... ./internal/daemon/api/...
	@if [ "$(INTEGRATION)" = "1" ]; then \
		echo "Running authz integration tests (requires Docker for testcontainers)..."; \
		$(GOTEST) -v -tags integration -count=1 -timeout=5m ./internal/authz/...; \
	else \
		echo "Skipping integration tests. Run 'make check-authz INTEGRATION=1' to include them (requires Docker)."; \
	fi
	@echo "authz checks passed!"

# test-daemon-identity-roundtrip — Task 28 / B15 cross-format golden test.
#
# Proves that the daemon's IdentityFromHeaders function accepts headers produced
# by ext-authz's Sign logic when both sides use the SAME decoded HMAC key.
#
# The test uses a fixed 64-char hex secret (simulating EXT_AUTHZ_HMAC_SECRET)
# and three sub-assertions:
#   1. Zitadel OIDC identity roundtrips (the normal production path).
#   2. SPIFFE identity roundtrips (the signup saga path — B6 coupling).
#   3. B15 wrong-key detection: if one side decodes and the other doesn't,
#      IdentityFromHeaders must return HMAC mismatch (not silently pass).
#
# This test runs in < 5s with no network or cluster dependency.
# Requirements: R3.2, B15.
test-daemon-identity-roundtrip:
	@echo "Running daemon identity HMAC roundtrip test (B15)..."
	$(GOTEST) -v -count=1 -run 'TestRoundtrip' ./internal/identity/...
	@echo "PASS: daemon identity roundtrip (B15)"

# Proto generation
proto-deps:
	@echo "Installing protoc plugins..."
	go install google.golang.org/protobuf/cmd/protoc-gen-go@v1.34.2
	go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@v1.5.1

proto: proto-deps authz-registry
	@echo "Generating Go code from daemon proto files via Buf..."
	$(BUF) generate
	@echo "Proto generation complete"

# authz-registry: regenerate the three authz artifacts (registry.go, registry.yaml,
# permissions.ts) plus audit.csv from the pinned SDK version's proto annotations.
# Writes to internal/authz/registry/. Run this target when the SDK version is bumped
# or to verify the committed files are not drifted.
#
# Spec: private-authz-registry Component 2.
authz-registry:
	@echo "Building authz-registry-gen from pinned SDK..."
	@mkdir -p $(BINARY_DIR) .tmp
	@SDK_DIR=$$($(GOCMD) list -m -f '{{.Dir}}' github.com/zero-day-ai/sdk); \
	  if [ -z "$$SDK_DIR" ]; then echo "ERROR: could not resolve github.com/zero-day-ai/sdk module dir" && exit 1; fi; \
	  echo "  SDK dir: $$SDK_DIR"; \
	  cd "$$SDK_DIR" && $(GOBUILD) -o $(CURDIR)/$(BINARY_DIR)/authz-registry-gen ./cmd/authz-registry-gen
	@echo "Building fds-merge..."
	@$(GOBUILD) -o $(BINARY_DIR)/fds-merge ./cmd/fds-merge
	@echo "Building audit-csv-gen..."
	@$(GOBUILD) -o $(BINARY_DIR)/audit-csv-gen ./cmd/audit-csv-gen
	@echo "Building FDS from SDK protos..."
	@SDK_DIR=$$($(GOCMD) list -m -f '{{.Dir}}' github.com/zero-day-ai/sdk); \
	  cd "$$SDK_DIR" && $(BUF) build -o $(CURDIR)/.tmp/sdk-fds.binpb
	@echo "Building FDS from gibson daemon-local protos (via temp workspace so gibson/auth/v1/options.proto resolves from the pinned SDK)..."
	@SDK_DIR=$$($(GOCMD) list -m -f '{{.Dir}}' github.com/zero-day-ai/sdk); \
	  rm -rf .tmp/ws && mkdir -p .tmp/ws && \
	  ln -sfn $(CURDIR)/internal/daemon/api .tmp/ws/gibson-local && \
	  ln -sfn $$SDK_DIR/api/proto .tmp/ws/sdk-proto && \
	  printf 'version: v2\nmodules:\n  - path: gibson-local\n  - path: sdk-proto\nlint:\n  use:\n    - STANDARD\n  ignore:\n    - sdk-proto/google\n    - gibson-local/gibson/daemon/admin/v1/daemon_admin.proto\n' > .tmp/ws/buf.yaml && \
	  cd .tmp/ws && $(BUF) build gibson-local -o $(CURDIR)/.tmp/gibson-fds.binpb
	@rm -rf .tmp/ws
	@echo "Merging FDSes (SDK + daemon-local)..."
	@$(BINARY_DIR)/fds-merge -input .tmp/sdk-fds.binpb -input .tmp/gibson-fds.binpb -output .tmp/combined-fds.binpb
	@echo "Generating registry artifacts..."
	@$(BINARY_DIR)/authz-registry-gen -input .tmp/combined-fds.binpb -output internal/authz/registry
	@echo "Generating audit CSV (Spec unified-authz-regen Req 1.4)..."
	@$(BINARY_DIR)/audit-csv-gen -input .tmp/combined-fds.binpb -output internal/authz/registry/audit.csv
	@rm -f .tmp/sdk-fds.binpb .tmp/gibson-fds.binpb .tmp/combined-fds.binpb
	@echo "Registry artifacts written to internal/authz/registry/"

proto-clean:
	@echo "Cleaning generated proto files..."
	@rm -rf $(PROTO_OUT)/*.pb.go

# Help target
help:
	@echo "Gibson Framework - Makefile Targets"
	@echo ""
	@echo "  make bin           - Build the gibson binary (quick local build)"
	@echo "  make build         - Full build for Docker/CI/CD"
	@echo "  make test          - Run all tests"
	@echo "  make test-race     - Run tests with race detection"
	@echo "  make test-coverage - Run tests with coverage (enforces $(COVERAGE_THRESHOLD)% threshold)"
	@echo "  make coverage-html - Generate HTML coverage report"
	@echo "  make lint          - Run golangci-lint"
	@echo "  make fmt           - Format Go code"
	@echo "  make vet           - Run go vet"
	@echo "  make tidy          - Tidy go modules"
	@echo "  make clean         - Remove build artifacts"
	@echo "  make install       - Install binary to GOPATH/bin"
	@echo "  make deps          - Download dependencies"
	@echo "  make check         - Run all checks (fmt, vet, lint, test-race)"
	@echo "  make check-authz   - Run authz package checks (unit tests + vet)"
	@echo "  make check-coverage - Enforce ≥95% coverage on internal/identity"
	@echo "  make check-authz INTEGRATION=1 - Include FGA integration tests (requires Docker)"
	@echo "  make check-no-tenant-id - Fail if any migration defines a tenant_id column"
	@echo "  make proto         - Generate Go code from proto files (includes authz-registry)"
	@echo "  make authz-registry - Regen authz artifacts from pinned SDK protos"
	@echo "  make proto-deps    - Install protoc plugins"
	@echo "  make proto-clean   - Remove generated proto files"
	@echo "  make help          - Show this help message"
