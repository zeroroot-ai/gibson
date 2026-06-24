# Gibson Framework Makefile
# Stage 1 - Foundation

.PHONY: all build bin gibson-migrate sandbox-eviction-handler test test-coverage test-race lint lint-all lint-deadcode lint-deadcode-baseline clean install help proto proto-deps proto-clean check-authz check-coverage test-daemon-identity-roundtrip check-no-tenant-id check-fga-headers check-rpc-test-walker coverage-profile check-coverage-floor check-diff-coverage check-coverage-gates check-critical-paths test-integration authz-registry

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
LDFLAGS=-ldflags "-X github.com/zeroroot-ai/gibson/pkg/version.Version=$(VERSION) \
	-X github.com/zeroroot-ai/gibson/pkg/version.GitCommit=$(GIT_COMMIT) \
	-X github.com/zeroroot-ai/gibson/pkg/version.BuildTime=$(BUILD_TIME)"

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
build: bin gibson-migrate sandbox-eviction-handler
	@echo "Full build complete"

# Build the gibson-migrate CLI for backfilling tenant DB migrations
gibson-migrate:
	@echo "Building gibson-migrate..."
	@mkdir -p $(BINARY_DIR)
	$(GOBUILD) $(BUILD_TAGS) $(LDFLAGS) -o $(BINARY_DIR)/gibson-migrate ./cmd/gibson-migrate
	@echo "Build complete: $(BINARY_DIR)/gibson-migrate"

# Build the sandbox-eviction-handler sidecar binary. Runs as a sidecar in
# the sandbox-host DaemonSet per ADR-0023 + gibson#211 (Option B): watches
# the aws-node-termination-handler notice file and cordons its own node so
# no new sandbox pods land on a node about to be terminated. The daemon
# itself stays K8s-API-free; this binary is the one place node-cordon
# logic lives.
sandbox-eviction-handler:
	@echo "Building sandbox-eviction-handler..."
	@mkdir -p $(BINARY_DIR)
	$(GOBUILD) $(BUILD_TAGS) $(LDFLAGS) -o $(BINARY_DIR)/sandbox-eviction-handler ./cmd/sandbox-eviction-handler
	@echo "Build complete: $(BINARY_DIR)/sandbox-eviction-handler"

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

# golangci-lint version — pinned for reproducible lint output (gibson#778).
# v2 schema (.golangci.yml `version: "2"`). Built from source with the repo's
# own Go toolchain (GOTOOLCHAIN below) so its embedded Go version is never lower
# than go.mod's `go 1.26.4` target — golangci v2 refuses to load a newer target,
# the known v2 trap that bit sdk#355 / adk#154.
GOLANGCI_LINT_VERSION := v2.4.0

# Pin the toolchain used to BUILD golangci-lint to this repo's Go. golangci's
# own go.mod declares an older `go` directive, so with GOTOOLCHAIN=auto Go may
# download and build it with that older compiler (→ embedded go < 1.26.4 → load
# refusal). GOTOOLCHAIN=go1.26.4 forces the host compiler. Keep in lockstep with
# go.mod's `go` directive.
GOLANGCI_BUILD_TOOLCHAIN := go1.26.4

# golangci-lint binary, pinned + repo-local (under bin/tools/, gitignored).
GOLANGCI_LINT := bin/tools/golangci-lint

$(GOLANGCI_LINT):
	@echo "Installing golangci-lint $(GOLANGCI_LINT_VERSION) to $(CURDIR)/bin/tools (toolchain $(GOLANGCI_BUILD_TOOLCHAIN))..."
	@mkdir -p $(CURDIR)/bin/tools
	@GOTOOLCHAIN=$(GOLANGCI_BUILD_TOOLCHAIN) GOBIN=$(CURDIR)/bin/tools GOFLAGS=-mod=mod \
		$(GOCMD) install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@$(GOLANGCI_LINT_VERSION)

# x/tools whole-program deadcode binary (separate from golangci; used by the
# blocking dead-code gate, which golangci's `unused` does not cover — `unused`
# is per-package, `deadcode` is whole-program reachability from the cmd mains).
DEADCODE := bin/tools/deadcode

$(DEADCODE):
	@echo "Installing deadcode to $(CURDIR)/bin/tools (toolchain $(GOLANGCI_BUILD_TOOLCHAIN))..."
	@mkdir -p $(CURDIR)/bin/tools
	@GOTOOLCHAIN=$(GOLANGCI_BUILD_TOOLCHAIN) GOBIN=$(CURDIR)/bin/tools GOFLAGS=-mod=mod \
		$(GOCMD) install golang.org/x/tools/cmd/deadcode@v0.44.0

# Baseline revision for the incremental lint gate. PRs lint against the
# merge-base with origin/main; override for local branches as needed.
LINT_BASE ?= origin/main

# lint — the BLOCKING gate (gibson#778, QUALITY-BARS §3). NO `|| true` swallow.
# Runs the full golangci-lint suite (incl. `unused` + `depguard`) but reports
# only NEW issues since LINT_BASE, so the pre-existing backlog (burndown tracked
# in gibson#918) is baselined while any NEW violation fails. This is the same
# invocation the CI `lint` job uses.
lint: $(GOLANGCI_LINT)
	@echo "Running linter (blocking; new since $(LINT_BASE))..."
	$(GOLANGCI_LINT) run --new-from-merge-base=$(LINT_BASE) ./...
	@bash scripts/check-fga-model-headers.sh
	@node scripts/lint-pagination.mjs
	@node scripts/lint-allowed-identities.mjs

# lint-all — full-tree, non-baselined. Surfaces the entire backlog for the
# gibson#918 burndown. Not wired into `check` until the backlog is cleared.
.PHONY: lint-all
lint-all: $(GOLANGCI_LINT)
	@echo "Running linter (full tree; informational — surfaces the gibson#918 backlog)..."
	$(GOLANGCI_LINT) run ./...

# lint-deadcode — BLOCKING whole-program dead-code gate (gibson#778). Fails on
# NEW unreachable code vs .deadcode-baseline (deadcode has no diff-scoping).
.PHONY: lint-deadcode
lint-deadcode: $(DEADCODE)
	@bash scripts/check-deadcode.sh

# lint-deadcode-baseline — regenerate .deadcode-baseline (run after a deliberate
# keep, or after burning down dead code in gibson#918).
.PHONY: lint-deadcode-baseline
lint-deadcode-baseline: $(DEADCODE)
	@echo "Regenerating .deadcode-baseline..."
	@$(DEADCODE) -test=false ./cmd/... ./operators/... 2>/dev/null \
		| sed -E 's/^([^:]+):[0-9]+:[0-9]+: unreachable func: (.+)$$/\1\t\2/' \
		| sort -u > .deadcode-baseline
	@echo "Wrote .deadcode-baseline ($$(wc -l < .deadcode-baseline | tr -d ' ') entries)"

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
	@$(GOTEST) -coverprofile=/tmp/daemon_identity_cover.out -covermode=atomic ./internal/platform/identity/... -count=1 > /dev/null 2>&1
	@ID_COV=$$(go tool cover -func=/tmp/daemon_identity_cover.out | grep total | awk '{print $$3}' | sed 's/%//'); \
	echo "  internal/identity: $${ID_COV}%"; \
	RESULT=$$(echo "$${ID_COV} >= 95" | bc -l); \
	if [ "$$RESULT" -ne 1 ]; then echo "FAIL: internal/identity coverage $${ID_COV}% is below 95% threshold"; exit 1; fi
	@echo "Coverage check PASSED"

# coverage-profile generates the repo-wide atomic coverage profile the two
# quality gates (floor + diff) consume. CI runs this once with the envtest
# binaries on PATH (see .github/workflows/coverage.yml) so operator suites
# count. Spec: gibson#794 (E3 / QUALITY-BARS §4).
coverage-profile:
	@echo "Generating repo-wide coverage profile -> $(COVERAGE_FILE)..."
	$(GOTEST) $(BUILD_TAGS) -coverprofile=$(COVERAGE_FILE) -covermode=atomic ./...

# check-coverage-floor enforces the absolute total-coverage floor (ratcheting
# toward 80%). Reads .coverage-floor. Requires an existing profile.
check-coverage-floor:
	@bash scripts/check-coverage-floor.sh $(COVERAGE_FILE) .coverage-floor

# check-diff-coverage enforces 85% coverage on lines changed vs the base ref.
# Override the base with DIFF_COVERAGE_BASE (default origin/main).
DIFF_COVERAGE_BASE ?= origin/main
check-diff-coverage:
	@echo "Checking diff coverage (>=85% of changed statement lines) vs $(DIFF_COVERAGE_BASE)..."
	@$(GOBUILD) -o $(BINARY_DIR)/diff-coverage ./cmd/diff-coverage
	@$(BINARY_DIR)/diff-coverage -profile $(COVERAGE_FILE) -base $(DIFF_COVERAGE_BASE) -threshold 85

# check-coverage-gates runs both #794 gates against an existing profile.
check-coverage-gates: check-coverage-floor check-diff-coverage
	@echo "Coverage gates PASSED"

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

# check-rpc-test-walker: per-RPC test gate (gibson#793, E3 / QUALITY-BARS §4).
# Fails if any registered gRPC RPC is not authz-enforceable, or lacks a handler
# test and is not in the shrinking baseline. Pure unit test — no infra needed.
check-rpc-test-walker:
	@echo "Running per-RPC test walker (authz-deny + handler-test coverage)..."
	$(GOTEST) -count=1 -run 'TestEveryRegisteredRPC' ./internal/platform/authz/registry/
	@echo "check-rpc-test-walker PASSED"

# check-critical-paths: pure-unit guard that every named Tier-3 critical-path
# test (gibson#795) still exists. No Docker/infra. Runs in the fast lane so a
# deleted critical-path test fails CI even when the container-backed integration
# lane does not run.
check-critical-paths:
	@echo "Running critical-path manifest guard..."
	$(GOTEST) -count=1 ./tests/criticalpath/
	@echo "check-critical-paths PASSED"

# test-integration: the integration lane (gibson#795, E3 / QUALITY-BARS §4
# Tier 3). Runs the `integration`-tagged suite — testcontainers spins up
# Postgres/Neo4j/Redis/OpenFGA per test, and operator envtest suites run when
# KUBEBUILDER_ASSETS is set. Requires Docker; CI provides it
# (.github/workflows/integration.yml).
#
# INTEGRATION_PKG is scoped to the packages that carry the five Tier-3 critical
# paths and currently COMPILE under -tags integration:
#   - tests/integration/...           per-tenant isolation, mission-run, handler authz
#   - internal/platform/authz/...     FGA model (auth-chain decision)
#   - internal/server/extauthz/...    ext-authz check (auth-chain)
#   - operators/...                   tenant-provision saga + operator envtest
#   - internal/platform/audit/...     audit Writer/Query against real Postgres (gibson#953)
#   - internal/infra/secrets/gcpsm/... GCP Secret Manager provider contract (gibson#953)
#   - internal/engine/graphrag/ingest/... DiscoveryProcessor → Neo4j hierarchy (gibson#953)
#   - internal/engine/graphrag/loader/... GraphLoader → Neo4j nodes/edges (gibson#953)
#   - internal/engine/mission/...     checkpoint capture/restore via miniredis (gibson#953)
# It still excludes server/daemon{,/api} (integration tests bit-rotted against
# current APIs) and engine/harness — the latter now COMPILES under -tags
# integration but two of its integration tests fail at RUNTIME and are NOT yet
# gated: TestCallbackServiceWithProtoResolver_Integration (missing tenant in
# context) and TestE2ERemoteToolExecution (proto "descriptor mismatch" panic in
# CallToolProto). Tracked in gibson#953; widen INTEGRATION_PKG as each is fixed.
# Run everything once fixed: make test-integration INTEGRATION_PKG=./...
INTEGRATION_PKG ?= ./tests/integration/... ./internal/platform/authz/... ./internal/server/extauthz/... ./operators/... ./internal/platform/audit/... ./internal/infra/secrets/gcpsm/... ./internal/engine/graphrag/ingest/... ./internal/engine/graphrag/loader/... ./internal/engine/mission/...
INTEGRATION_TIMEOUT ?= 30m
test-integration:
	@echo "Running integration lane (-tags integration) over $(INTEGRATION_PKG)..."
	$(GOTEST) -tags integration -count=1 -timeout=$(INTEGRATION_TIMEOUT) $(INTEGRATION_PKG)

# Run all checks before commit
check: fmt vet lint lint-deadcode test-race check-no-tenant-id check-fga-headers check-no-gibson-io check-no-skipped-tests check-noun-contract check-rpc-test-walker check-critical-paths
	@echo "All checks passed!"

# Run authorization-specific checks: vet + unit tests + integration tests (requires Docker)
# Usage:
#   make check-authz           # unit tests only (no Docker required)
#   make check-authz INTEGRATION=1  # unit + integration tests (requires Docker)
check-authz:
	@echo "Running authz package vet..."
	$(GOCMD) vet ./internal/platform/authz/... ./internal/server/daemon/authz_init.go
	@echo "Running authz unit tests (race detector)..."
	$(GOTEST) -race -count=1 -timeout=2m ./internal/platform/authz/... ./internal/server/daemon/...
	@echo "Running RPC registry drift gate (audit build tag)..."
	$(GOTEST) -tags audit -count=1 -timeout=1m ./internal/platform/auth/... ./internal/server/daemon/api/...
	@if [ "$(INTEGRATION)" = "1" ]; then \
		echo "Running authz integration tests (requires Docker for testcontainers)..."; \
		$(GOTEST) -v -tags integration -count=1 -timeout=5m ./internal/platform/authz/...; \
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
	$(GOTEST) -v -count=1 -run 'TestRoundtrip' ./internal/platform/identity/...
	@echo "PASS: daemon identity roundtrip (B15)"

# Proto generation
proto-deps:
	@echo "Installing protoc plugins..."
	go install google.golang.org/protobuf/cmd/protoc-gen-go@v1.34.2
	go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@v1.6.0

proto: proto-deps authz-registry
	@echo "Generating Go code from daemon proto files via Buf..."
	@# Synthesise a workspace so `gibson/auth/v1/options.proto` (lives in
	@# the pinned SDK) resolves while generating daemon-local pb.go.
	@# Mirrors the authz-registry recipe above; without this, a standalone
	@# `buf generate` fails with "import gibson/auth/v1/options.proto:
	@# file does not exist". The workspace lists both proto trees as
	@# modules so cross-tree imports resolve, but the buf.gen.yaml's
	@# `inputs: directory: gibson-local` restricts codegen to the
	@# daemon-local tree — Go bindings for the SDK already ship as a
	@# published Go module. gibson#122.
	@$(GOCMD) mod download github.com/zeroroot-ai/sdk
	@SDK_DIR=$$($(GOCMD) list -m -f '{{.Dir}}' github.com/zeroroot-ai/sdk); \
	  if [ -z "$$SDK_DIR" ]; then echo "ERROR: could not resolve github.com/zeroroot-ai/sdk module dir" && exit 1; fi; \
	  rm -rf .tmp/proto-ws && mkdir -p .tmp/proto-ws/out && \
	  ln -sfn $(CURDIR)/internal/server/daemon/api .tmp/proto-ws/gibson-local && \
	  ln -sfn $$SDK_DIR/api/proto .tmp/proto-ws/sdk-proto && \
	  printf 'version: v2\nmodules:\n  - path: gibson-local\n  - path: sdk-proto\n    excludes:\n      - sdk-proto/google\nlint:\n  use:\n    - STANDARD\n  ignore:\n    - gibson-local/gibson/daemon/admin/v1/daemon_admin.proto\n' > .tmp/proto-ws/buf.yaml && \
	  printf 'version: v2\nmanaged:\n  enabled: true\n  disable:\n    - file_option: go_package\nplugins:\n  - local: protoc-gen-go\n    out: out\n    opt:\n      - module=github.com/zeroroot-ai/gibson\n      - Mgoogle/protobuf/descriptor.proto=google.golang.org/protobuf/types/descriptorpb\n  - local: protoc-gen-go-grpc\n    out: out\n    opt:\n      - module=github.com/zeroroot-ai/gibson\n      - Mgoogle/protobuf/descriptor.proto=google.golang.org/protobuf/types/descriptorpb\ninputs:\n  - directory: gibson-local\n' > .tmp/proto-ws/buf.gen.yaml && \
	  cd .tmp/proto-ws && $(BUF) generate
	@# rsync the generated *.pb.go files back into the daemon tree. buf's
	@# `module=` opt emits paths rooted at the Go module, so the layout
	@# under .tmp/proto-ws/out/ matches internal/server/daemon/api/... already.
	@rsync -a --include='*/' --include='*.pb.go' --exclude='*' \
	  .tmp/proto-ws/out/internal/server/daemon/api/ internal/server/daemon/api/
	@rm -rf .tmp/proto-ws
	@echo "Proto generation complete"

# authz-registry: regenerate the three authz artifacts (registry.go, registry.yaml,
# permissions.ts) plus audit.csv from the pinned SDK version's proto annotations.
# Writes to internal/platform/authz/registry/. Run this target when the SDK version is bumped
# or to verify the committed files are not drifted.
#
# Spec: private-authz-registry Component 2.
authz-registry:
	@echo "Building authz-registry-gen from pinned SDK..."
	@mkdir -p $(BINARY_DIR) .tmp
	@$(GOCMD) mod download github.com/zeroroot-ai/sdk
	@SDK_DIR=$$($(GOCMD) list -m -f '{{.Dir}}' github.com/zeroroot-ai/sdk); \
	  if [ -z "$$SDK_DIR" ]; then echo "ERROR: could not resolve github.com/zeroroot-ai/sdk module dir" && exit 1; fi; \
	  echo "  SDK dir: $$SDK_DIR"; \
	  cd "$$SDK_DIR" && $(GOBUILD) -o $(CURDIR)/$(BINARY_DIR)/authz-registry-gen ./cmd/authz-registry-gen
	@echo "Building fds-merge..."
	@$(GOBUILD) -o $(BINARY_DIR)/fds-merge ./cmd/fds-merge
	@echo "Building audit-csv-gen..."
	@$(GOBUILD) -o $(BINARY_DIR)/audit-csv-gen ./cmd/audit-csv-gen
	@echo "Building FDS from SDK protos (local workspace — avoids BSR fetch for renamed org buf.build/zeroroot-ai-platform)..."
	@SDK_DIR=$$($(GOCMD) list -m -f '{{.Dir}}' github.com/zeroroot-ai/sdk); \
	  rm -rf .tmp/sdk-ws && mkdir -p .tmp/sdk-ws && \
	  ln -sfn "$$SDK_DIR/api/proto" .tmp/sdk-ws/sdk-proto && \
	  printf 'version: v2\nmodules:\n  - path: sdk-proto\n    excludes:\n      - sdk-proto/google\ndeps:\n  - buf.build/bufbuild/protovalidate\n' > .tmp/sdk-ws/buf.yaml && \
	  printf '# Generated by buf. DO NOT EDIT.\nversion: v2\ndeps:\n  - name: buf.build/bufbuild/protovalidate\n    commit: 50325440f8f24053b047484a6bf60b76\n    digest: b5:74cb6f5c0853c3c10aafc701614194bbd63326bdb8ef4068214454b8894b03ba4113e04b3a33a8321cdf05336e37db4dc14a5e2495db8462566914f36086ba31\n' > .tmp/sdk-ws/buf.lock && \
	  cd .tmp/sdk-ws && $(BUF) build sdk-proto -o $(CURDIR)/.tmp/sdk-fds.binpb
	@rm -rf .tmp/sdk-ws
	@echo "Building FDS from gibson daemon-local protos (via temp workspace so gibson/auth/v1/options.proto resolves from the pinned SDK)..."
	@SDK_DIR=$$($(GOCMD) list -m -f '{{.Dir}}' github.com/zeroroot-ai/sdk); \
	  rm -rf .tmp/ws && mkdir -p .tmp/ws && \
	  ln -sfn $(CURDIR)/internal/server/daemon/api .tmp/ws/gibson-local && \
	  ln -sfn $$SDK_DIR/api/proto .tmp/ws/sdk-proto && \
	  printf 'version: v2\nmodules:\n  - path: gibson-local\n  - path: sdk-proto\nlint:\n  use:\n    - STANDARD\n  ignore:\n    - sdk-proto/google\n    - gibson-local/gibson/daemon/admin/v1/daemon_admin.proto\n' > .tmp/ws/buf.yaml && \
	  cd .tmp/ws && $(BUF) build gibson-local -o $(CURDIR)/.tmp/gibson-fds.binpb
	@rm -rf .tmp/ws
	@echo "Merging FDSes (SDK + daemon-local)..."
	@$(BINARY_DIR)/fds-merge -input .tmp/sdk-fds.binpb -input .tmp/gibson-fds.binpb -output .tmp/combined-fds.binpb
	@echo "Generating registry artifacts..."
	@$(BINARY_DIR)/authz-registry-gen -input .tmp/combined-fds.binpb -output internal/platform/authz/registry
	@echo "Generating audit CSV (Spec unified-authz-regen Req 1.4)..."
	@$(BINARY_DIR)/audit-csv-gen -input .tmp/combined-fds.binpb -output internal/platform/authz/registry/audit.csv
	@rm -f .tmp/sdk-fds.binpb .tmp/gibson-fds.binpb .tmp/combined-fds.binpb
	@echo "Registry artifacts written to internal/platform/authz/registry/"

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
	@echo "  make check-coverage - Enforce ≥95% coverage on internal/platform/identity"
	@echo "  make check-authz INTEGRATION=1 - Include FGA integration tests (requires Docker)"
	@echo "  make check-no-tenant-id - Fail if any migration defines a tenant_id column"
	@echo "  make proto         - Generate Go code from proto files (includes authz-registry)"
	@echo "  make authz-registry - Regen authz artifacts from pinned SDK protos"
	@echo "  make proto-deps    - Install protoc plugins"
	@echo "  make proto-clean   - Remove generated proto files"
	@echo "  make help          - Show this help message"
