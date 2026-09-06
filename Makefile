# Gibson Framework Makefile
# Stage 1 - Foundation

.PHONY: check-no-tracked-binaries
.PHONY: all build bin gibson-migrate sandbox-eviction-handler test test-coverage test-race lint lint-all lint-deadcode lint-deadcode-baseline clean install help proto proto-deps proto-clean check-authz check-coverage test-daemon-identity-roundtrip check-no-tenant-id check-fga-headers check-oss-boundary check-airgap-build check-rpc-test-walker coverage-profile check-coverage-floor check-diff-coverage check-coverage-gates check-critical-paths check-ci-lane-parity check-build-tags check-queue-gate vet-e2e vet-tags test-integration test-openbao test-merge-queue test-setec-roundtrip authz-registry tool-manifests tool-catalog-capture

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

# Build tags for the default lane. Deliberately empty: the default build needs
# none (SQLite removed).
#
# ⚠ This is why `make test` / `make test-race` / `make coverage-profile` compile
# ONLY untagged files. Every `//go:build <tag>` suite is invisible to them —
# that is how the 34-file tests/e2e suite went months without ever being built
# (gibson#1280). Tagged suites are selected explicitly instead:
#
#   -tags integration        make test-integration
#   -tags setec_integration  make test-setec-roundtrip
#   -tags e2e                make vet-e2e (compile-only; the cluster-bound part
#                            still has no runner — gibson#1293)
#   every declared tag       make vet-tags, and the `vet-tags` matrix in
#                            .github/workflows/go-ci.yml, on BOTH CI lanes
#
# `make check-build-tags` fails the build if a tag exists that no lane selects,
# so this cannot silently recur.
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
#
# CGO_ENABLED=1 is set inline (not exported) because `-race` requires cgo,
# while the module-wide `export CGO_ENABLED=0` above keeps the default build
# pure Go. The inline assignment overrides the export for this recipe only.
test-race:
	@echo "Running tests with race detection..."
	CGO_ENABLED=1 $(GOTEST) $(BUILD_TAGS) -race -v ./...

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
# than go.mod's `go` target — golangci v2 refuses to load a newer target,
# the known v2 trap that bit sdk#355 / adk#154.
GOLANGCI_LINT_VERSION := v2.4.0

# Toolchain used to BUILD golangci-lint (and deadcode), derived from go.mod's
# `go` directive so it can never drift when go.mod bumps (gibson#1234 — a
# hardcoded pin here went stale). golangci's own go.mod declares an older `go`
# directive, so with GOTOOLCHAIN=auto Go builds it with that older compiler
# (→ embedded go < go.mod's target → the opaque "Go language version … is lower
# than the targeted Go version" load refusal). This is also why a bare
# `go install …/golangci-lint@vX` NEVER works here: only `make lint` /
# `make $(GOLANGCI_LINT)` sets GOTOOLCHAIN explicitly.
GOLANGCI_BUILD_TOOLCHAIN := go$(shell awk '$$1 == "go" {print $$2; exit}' go.mod)

# golangci-lint binary, pinned + repo-local (under bin/tools/, gitignored).
# make ALWAYS invokes this path — a system golangci-lint from PATH is never
# used, so a stale system binary cannot poison `make lint` (gibson#1234).
GOLANGCI_LINT := bin/tools/golangci-lint

# Stamp recording which version+toolchain the installed binary was built with.
# When either pin moves (go.mod bump, GOLANGCI_LINT_VERSION bump), or the
# binary predates the stamp scheme / was hand-installed, the stamp mismatch
# deletes the stale binary and triggers a rebuild — instead of golangci
# surfacing its opaque version-refusal config error at `run` time.
GOLANGCI_LINT_STAMP := bin/tools/.golangci-lint-$(GOLANGCI_LINT_VERSION)-$(GOLANGCI_BUILD_TOOLCHAIN).stamp

$(GOLANGCI_LINT_STAMP):
	@mkdir -p $(CURDIR)/bin/tools
	@rm -f bin/tools/.golangci-lint-*.stamp $(GOLANGCI_LINT)
	@touch $@

$(GOLANGCI_LINT): $(GOLANGCI_LINT_STAMP)
	@echo "Installing golangci-lint $(GOLANGCI_LINT_VERSION) to $(CURDIR)/bin/tools (toolchain $(GOLANGCI_BUILD_TOOLCHAIN))..."
	@mkdir -p $(CURDIR)/bin/tools
	@GOTOOLCHAIN=$(GOLANGCI_BUILD_TOOLCHAIN) GOBIN=$(CURDIR)/bin/tools GOFLAGS=-mod=mod \
		$(GOCMD) install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@$(GOLANGCI_LINT_VERSION)
	@$(GOLANGCI_LINT) version 2>/dev/null | grep -q "built with $(GOLANGCI_BUILD_TOOLCHAIN) " || { \
		echo "ERROR: $(GOLANGCI_LINT) was not built with $(GOLANGCI_BUILD_TOOLCHAIN) (go.mod's toolchain)."; \
		echo "       Its embedded Go version would make golangci-lint refuse this repo's config."; \
		echo "       Rebuild it: rm -f $(GOLANGCI_LINT) && make $(GOLANGCI_LINT)"; \
		$(GOLANGCI_LINT) version; \
		exit 1; }

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

# Fail on gofmt drift instead of silently rewriting it. `make fmt` (and its
# slot in `make check`) WRITES fixes, so nothing ever failed on unformatted
# code and drift landed on main unnoticed (gibson#1415: 2 files flagged, 6 by
# the time the gate was added). CI runs this in go-ci.yml's `critical-paths`
# job on both lanes. Uses the go.mod-selected toolchain's gofmt so local and
# CI agree; excludes .tmp/ (synthesized proto workspaces) and bin/ (built
# tools), which exist only in local working trees.
check-fmt:
	@echo "Checking gofmt cleanliness..."
	@drift="$$("$$($(GOCMD) env GOROOT)/bin/gofmt" -l . 2>/dev/null | grep -v -e '^\.tmp/' -e '^bin/' || true)"; \
	if [ -n "$$drift" ]; then \
		echo "gofmt drift in:"; echo "$$drift"; \
		echo "Run 'make fmt' and commit the result."; \
		exit 1; \
	fi

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
# binaries on PATH (see the `coverage` job in .github/workflows/go-ci.yml) so
# operator suites
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

# check-no-tracked-binaries asserts no compiled binary (ELF, Mach-O, PE) is
# tracked in git. Keyed by file magic, never by path. Self-test proves it fails.
check-no-tracked-binaries:
	@bash scripts/check-no-tracked-binaries.sh --selftest
	@bash scripts/check-no-tracked-binaries.sh

# check-oss-boundary asserts the open-core boundary (gibson#817, ADR-0050/0054):
# the Apache layer (sdk/adk/setec/gibson-executor) links zero ELv2/closed code,
# and gibson's go.mod never requires the closed billing repo. Clones the public
# OSS repos (network) unless OSS_BOUNDARY_REPOS_DIR points at existing checkouts.
# CI: .github/workflows/oss-boundary.yml (path-filtered PRs + weekly sweep).
check-oss-boundary:
	@echo "Checking open-core boundary (Apache layer vs ELv2/closed)..."
	@bash scripts/check-oss-boundary.sh
	@echo "check-oss-boundary PASSED"

# check-airgap-build asserts the clean-room air-gap promise (gibson#818,
# ADR-0050): fresh anonymous clones of the OSS stack (sdk/adk/setec/
# gibson-executor) build + test-compile with zero external fetch after a
# single public-proxy module-cache warm-up. Needs network for phases 0/1.
# CI: .github/workflows/airgap-build.yml (path-filtered PRs + weekly sweep).
check-airgap-build:
	@echo "Checking air-gapped clean-room build of the OSS stack..."
	@bash scripts/check-airgap-build.sh
	@echo "check-airgap-build PASSED"

# check-no-skipped-tests asserts no test is skipped unconditionally — a skip
# that is not inside a conditional runs in no lane at all, so the test body is
# dead. Conditional skips (-short, GOOS, env-var, infra-probe) are allowed.
# Spec: naming-and-config-standardization Requirement 3.5. gibson#1294.
# The self-test runs first: a guard is only worth its green line if it has just
# demonstrated it can go red.
check-no-skipped-tests:
	@echo "Checking for unconditionally skipped tests..."
	@bash scripts/check-no-skipped-tests.sh --selftest
	@bash scripts/check-no-skipped-tests.sh
	@echo "check-no-skipped-tests PASSED"

# check-no-mcp-bridge asserts the legacy connector-launcher path stays removed
# (ADR-0065, gibson#1524): MCP lives only in the connector domain via ToolHive
# (ADR-0014); the plugin domain has no MCP. The guard script names the exact
# tokens it forbids. Self-test first so a broken guard cannot pass by finding
# nothing.
check-no-mcp-bridge:
	@echo "Checking the mcp-bridge path stays removed..."
	@SELFTEST=1 bash scripts/check-no-mcp-bridge.sh
	@bash scripts/check-no-mcp-bridge.sh
	@echo "check-no-mcp-bridge PASSED"

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
# KUBEBUILDER_ASSETS is set. Requires Docker; CI provides it via the
# `integration` job in .github/workflows/go-ci.yml (merge_group tier).
#
# INTEGRATION_PKG is scoped to the packages that carry the five Tier-3 critical
# paths and currently COMPILE under -tags integration:
#   - tests/integration/...           per-tenant isolation, mission-run, handler authz
#   - internal/platform/authz/...     FGA model (auth-chain decision)
#   - internal/server/extauthz/...    ext-authz check (auth-chain)
#   - operators/...                   tenant-provision saga + operator envtest
#   - internal/platform/audit/...     audit Writer/Query against real Postgres (gibson#953)
#   - internal/engine/graphrag/ingest/... DiscoveryProcessor → Neo4j hierarchy (gibson#953)
#   - internal/engine/mission/...     checkpoint capture/restore via miniredis (gibson#953)
#   - internal/server/daemon/         event-streaming + daemon handlers, miniredis (gibson#953)
#   - internal/server/daemon/api/     tenant RPC smoke + entitlements-audit (gibson#953)
#   - internal/engine/harness/...     proto-resolver + remote-tool round trip (gibson#963)
# All packages that previously failed to compile under -tags integration are now
# fixed (gibson#953/#963); the rotted set is empty. The default is NOT yet ./...
# because other integration-tagged packages need live cloud/infra that does not
# run-or-skip cleanly in the lane yet (e.g. internal/infra/reconciler,
# internal/platform/secrets/providers/postgres).
# Confirm those skip-or-pass before flipping the default to ./....
INTEGRATION_PKG ?= ./tests/integration/... ./internal/platform/authz/... ./internal/server/extauthz/... ./operators/... ./internal/platform/audit/... ./internal/engine/graphrag/ingest/... ./internal/engine/mission/... ./internal/server/daemon/ ./internal/server/daemon/api/ ./internal/engine/harness/...
INTEGRATION_TIMEOUT ?= 30m
test-integration:
	@echo "Running integration lane (-tags integration) over $(INTEGRATION_PKG)..."
	$(GOTEST) -tags integration -count=1 -timeout=$(INTEGRATION_TIMEOUT) $(INTEGRATION_PKG)

# test-openbao: the OpenBao secrets-backend suites (gibson#1293). These carry
# their OWN build tags (openbao_smoke, openbao_integration) — distinct from the
# `integration` tag above and deliberately kept separate (the tag-isolated test
# trees define their own constants, e.g. openbaoTestMount vs intTestMount, so
# mixing the tags in one `go test` invocation would collide). Each test stands
# up its own `openbao/openbao:2.5.3` container via testcontainers-go and
# fails-skip when Docker is unavailable, so this needs only Docker — no live
# service container and no envtest. CI runs it via the `openbao` job in
# .github/workflows/go-ci.yml on BOTH lanes (~45s; hermetic).
#
#   openbao_smoke        stands the container up + asserts /v1/sys/health.
#   openbao_integration  exercises the SDK provider + operator AdminClient
#                        end-to-end (KV v2, token/AppRole/JWT auth, namespaces).
OPENBAO_PKG ?= ./internal/infra/secrets/vault/... ./operators/tenant/internal/clients/vault/...
test-openbao:
	@echo "Running OpenBao suites (-tags 'openbao_smoke openbao_integration') over $(OPENBAO_PKG)..."
	$(GOTEST) -tags 'openbao_smoke openbao_integration' -count=1 -timeout=$(INTEGRATION_TIMEOUT) $(OPENBAO_PKG)

# test-setec-roundtrip: the E10 / gibson#999 execution round-trip (E3). Runs the
# `setec_integration`-tagged harness suite that proves an UNTRUSTED tool executes
# ONLY via a real setec microVM round-trip and is denied (typed error, no
# in-process fallback) otherwise. Hardware-gated: requires KVM + a reachable
# setec frontend. The tests self-skip unless SETEC_ROUNDTRIP_ADDR (+ mTLS cert
# paths) is set, so this target is a safe no-op off the KVM runner. CI wiring:
# .github/workflows/e2e-setec-roundtrip.yml (self-hosted `setec-bare-metal`).
SETEC_ROUNDTRIP_TIMEOUT ?= 15m
test-setec-roundtrip:
	@echo "Running setec execution round-trip (-tags setec_integration)..."
	$(GOTEST) -tags setec_integration -count=1 -timeout=$(SETEC_ROUNDTRIP_TIMEOUT) -run TestSetecRoundTrip ./internal/engine/harness/...


# ---------------------------------------------------------------------------
# CI lane parity + build-tag selection (gibson#1236 / #1233 / #1280)
# ---------------------------------------------------------------------------
# check-ci-lane-parity: no gate may run only in the merge queue without saying
# so. A queue-only gate evicts PRs while they still report CLEAN with no failing
# check, which is undebuggable from the PR (gibson#1233).
check-ci-lane-parity:
	@bash scripts/check-ci-lane-parity.sh --selftest
	@bash scripts/check-ci-lane-parity.sh

# check-build-tags: every `//go:build <tag>` in the module must be selected by a
# leg of the vet-tags matrix in .github/workflows/go-ci.yml, so no suite can sit
# there uncompiled the way tests/e2e did (gibson#1280).
check-build-tags:
	@bash scripts/check-build-tags-selected.sh --selftest
	@bash scripts/check-build-tags-selected.sh

# check-queue-gate: `queue-gate` is the ONE context the merge queue requires
# from go-ci.yml, so every other job in that file is only as blocking as its
# `needs:` list says. It shipped naming five of nine -- `fast`, `lint` and
# `critical-paths` ran and gated nothing, `critical-paths` being the job that
# runs the two targets directly above. Guards that could not be enforced.
check-queue-gate:
	@bash scripts/check-queue-gate-coverage.sh --selftest
	@bash scripts/queue-gate-eval.sh --selftest
	@bash scripts/check-queue-gate-coverage.sh .github/workflows/go-ci.yml

# vet-e2e: compile-only signal for the `e2e` suite (tests/e2e/... plus
# operators/tenant/test/e2e). What is left under the tag needs a live kind
# cluster, GIBSON_TEST_FIXTURES_ENABLED=true and an admin JWT to RUN, which is a
# separate question (gibson#1280/#1293); this at least catches drift where a
# test references an RPC or symbol that no longer exists. The cluster-free files
# that used to sit under the tag were untagged in gibson#1293 and are covered by
# plain `make test` — see docs/testing/ci-lanes.md.
vet-e2e:
	$(GOCMD) vet -tags e2e ./...

# ---------------------------------------------------------------------------
# Cluster-bound e2e suites (gibson#1394). Each target runs one tests/e2e suite
# against a LIVE kind cluster (`make deploy-local` in enterprise/deploy) and
# requires the env its suite documents; the suites fail loud on missing env,
# so these targets validate up front only what the suite cannot self-check.
# The four targets restore what the suite doc-comments have referenced since
# they were written ("run via `make test-login-e2e`", …) — the targets never
# existed, so the documented invocation path was a 404 (gibson#1394). Where
# they RUN in CI is gibson#1396 (venue decision pending); locally they run
# against your kind cluster today.
# ---------------------------------------------------------------------------
E2E_TIMEOUT ?= 10m

define require_env
	@if [ -z "$${$(1)}" ]; then echo "ERROR: $(1) is required for this target (see tests/e2e/$(2))"; exit 1; fi
endef

.PHONY: test-signup-e2e
test-signup-e2e: ## Run the signup full-chain e2e suite against a live kind cluster
	$(call require_env,SIGNUP_SLUG,signup_full_chain_test.go)
	$(call require_env,SIGNUP_EMAIL,signup_full_chain_test.go)
	$(GOCMD) test -tags=e2e -run 'TestSignup' -v -timeout $(E2E_TIMEOUT) ./tests/e2e/...

.PHONY: test-login-e2e
test-login-e2e: ## Run the login full-chain e2e suite against a live kind cluster
	$(call require_env,SIGNUP_SLUG,login_full_chain_test.go)
	$(call require_env,SIGNUP_EMAIL,login_full_chain_test.go)
	$(GOCMD) test -tags=e2e -run 'TestLogin' -v -timeout $(E2E_TIMEOUT) ./tests/e2e/...

.PHONY: test-dashboard-smoke-e2e
test-dashboard-smoke-e2e: ## Run the dashboard smoke e2e suite (two tenants) against a live kind cluster
	$(call require_env,SIGNUP_SLUG_A,dashboard_smoke_test.go)
	$(call require_env,SIGNUP_EMAIL_A,dashboard_smoke_test.go)
	$(call require_env,SIGNUP_SLUG_B,dashboard_smoke_test.go)
	$(call require_env,SIGNUP_EMAIL_B,dashboard_smoke_test.go)
	$(GOCMD) test -tags=e2e -run 'TestDashboard' -v -timeout $(E2E_TIMEOUT) ./tests/e2e/...

.PHONY: test-mission-run-e2e
test-mission-run-e2e: ## Run the mission-run e2e suite against a live kind cluster (fixtures-enabled)
	$(call require_env,SIGNUP_SLUG,mission_run_test.go)
	$(call require_env,SIGNUP_EMAIL,mission_run_test.go)
	GIBSON_TEST_FIXTURES_ENABLED=true $(GOCMD) test -tags=e2e -run 'TestMission_Run' -v -timeout $(E2E_TIMEOUT) ./tests/e2e/...

# vet-tags: the local equivalent of the CI `vet-tags` matrix — type-checks the
# module once per declared build-tag variant. Roughly a minute per leg.
# `default` is the sentinel for the untagged leg; every other word is passed
# through to -tags verbatim (commas combine tags within one leg).
VET_TAG_LEGS ?= default setec_integration integration e2e test_fixtures openbao_integration,openbao_smoke,llm_integration,integration_spire
vet-tags:
	@for leg in $(VET_TAG_LEGS); do \
		if [ "$$leg" = "default" ]; then \
			echo "==> go vet ./...  (untagged)"; $(GOCMD) vet ./... || exit 1; \
		else \
			echo "==> go vet -tags $$leg ./..."; $(GOCMD) vet -tags "$$leg" ./... || exit 1; \
		fi; \
	done
	@echo "vet-tags PASSED"

# test-merge-queue: everything the merge_group lane runs that the pull_request
# lane does not (gibson#1236). After the lane-parity fix that is just the heavy
# tier — module-wide `go test -race` per build-tag variant. Run it before
# enqueueing a change that touches concurrency.
#
# ⚠ EXPENSIVE. Two module-wide race passes; several GB resident and most of the
# machine for minutes. Do not run it concurrently with `make lint` or another
# agent's build.
test-merge-queue:
	@echo "Running the merge_group-only lane (heavy tier)..."
	CGO_ENABLED=1 $(GOTEST) -race -count=1 ./...
	CGO_ENABLED=1 $(GOTEST) -tags setec_integration -race -count=1 ./...
	@echo "test-merge-queue PASSED (govulncheck is CI-only — see .github/workflows/security.yaml)"

# Run all checks before commit.
#
# golangci-lint is deliberately NOT here. `make lint` type-checks the whole
# module — ~3 GB resident and a full core for minutes — and `lint-deadcode`
# repeats the analysis. Two of those in parallel take this workspace to a load
# average near 40 on 8 cores, which is what happened on 2026-08-06 when two
# agents ran `make check` concurrently.
#
# CI runs both directly (`.github/workflows/go-ci.yml` calls `make lint
# LINT_BASE=…` and `make lint-deadcode`), so nothing is lost by keeping them out
# of the local aggregate. Run `make lint` by hand when you actually want it.
check: fmt check-fmt vet test-race check-no-tenant-id check-fga-headers check-no-gibson-io check-no-tracked-binaries check-no-skipped-tests check-no-mcp-bridge check-noun-contract check-rpc-test-walker check-critical-paths check-ci-lane-parity check-build-tags check-queue-gate
	@echo "All checks passed! (golangci-lint not included — run 'make lint' separately)"

# Run authorization-specific checks: vet + unit tests + integration tests (requires Docker)
# Usage:
#   make check-authz           # unit tests only (no Docker required)
#   make check-authz INTEGRATION=1  # unit + integration tests (requires Docker)
check-authz:
	@echo "Running authz package vet..."
	$(GOCMD) vet ./internal/platform/authz/...
	$(GOCMD) vet ./internal/server/daemon/
	@echo "Running authz unit tests (race detector)..."
	CGO_ENABLED=1 $(GOTEST) -race -count=1 -timeout=2m ./internal/platform/authz/... ./internal/server/daemon/...
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
	  printf 'version: v2\nmodules:\n  - path: gibson-local\n  - path: sdk-proto\n    excludes:\n      - sdk-proto/google\ndeps:\n  - buf.build/bufbuild/protovalidate\nlint:\n  use:\n    - STANDARD\n  ignore:\n    - gibson-local/gibson/daemon/admin/v1/daemon_admin.proto\n' > .tmp/proto-ws/buf.yaml && \
	  printf '# Generated by buf. DO NOT EDIT.\nversion: v2\ndeps:\n  - name: buf.build/bufbuild/protovalidate\n    commit: 50325440f8f24053b047484a6bf60b76\n    digest: b5:74cb6f5c0853c3c10aafc701614194bbd63326bdb8ef4068214454b8894b03ba4113e04b3a33a8321cdf05336e37db4dc14a5e2495db8462566914f36086ba31\n' > .tmp/proto-ws/buf.lock && \
	  printf 'version: v2\nmanaged:\n  enabled: true\n  disable:\n    - file_option: go_package\nplugins:\n  - local: protoc-gen-go\n    out: out\n    opt:\n      - module=github.com/zeroroot-ai/gibson\n      - Mgoogle/protobuf/descriptor.proto=google.golang.org/protobuf/types/descriptorpb\n  - local: protoc-gen-go-grpc\n    out: out\n    opt:\n      - module=github.com/zeroroot-ai/gibson\n      - Mgoogle/protobuf/descriptor.proto=google.golang.org/protobuf/types/descriptorpb\ninputs:\n  - directory: gibson-local\n' > .tmp/proto-ws/buf.gen.yaml && \
	  cd .tmp/proto-ws && $(BUF) generate
	@# rsync the generated *.pb.go files back into the daemon tree. buf's
	@# `module=` opt emits paths rooted at the Go module, so the layout
	@# under .tmp/proto-ws/out/ matches internal/server/daemon/api/... already.
	@rsync -a --include='*/' --include='*.pb.go' --exclude='*' \
	  .tmp/proto-ws/out/internal/server/daemon/api/ internal/server/daemon/api/
	@rm -rf .tmp/proto-ws
	@echo "Generating Go code from pkg/billing/entitlements/v1 proto files via Buf..."
	@# The entitlements proto has no cross-tree imports (it does NOT import
	@# gibson/auth/v1/options.proto — this RPC is daemon→billing SPIFFE mTLS,
	@# not Envoy-routed, so no authz annotation is needed). A standalone
	@# workspace suffices; no SDK symlink is required. The generated stubs
	@# land under pkg/ so the external billing module can import them without
	@# violating Go's internal/ restriction (gibson#1027).
	@rm -rf .tmp/ent-ws && mkdir -p .tmp/ent-ws/out && \
	  ln -sfn $(CURDIR)/pkg/billing/entitlements/v1 .tmp/ent-ws/entitlements-proto && \
	  printf 'version: v2\nmodules:\n  - path: entitlements-proto\nlint:\n  use:\n    - STANDARD\n' > .tmp/ent-ws/buf.yaml && \
	  printf 'version: v2\nmanaged:\n  enabled: true\n  disable:\n    - file_option: go_package\nplugins:\n  - local: protoc-gen-go\n    out: out\n    opt:\n      - module=github.com/zeroroot-ai/gibson\n  - local: protoc-gen-go-grpc\n    out: out\n    opt:\n      - module=github.com/zeroroot-ai/gibson\ninputs:\n  - directory: entitlements-proto\n' > .tmp/ent-ws/buf.gen.yaml && \
	  cd .tmp/ent-ws && $(BUF) generate
	@rsync -a --include='*/' --include='*.pb.go' --exclude='*' \
	  .tmp/ent-ws/out/pkg/billing/entitlements/v1/ pkg/billing/entitlements/v1/
	@rm -rf .tmp/ent-ws
	@echo "Proto generation complete"

# tool-manifests: regenerate the kind:tool catalog manifests from the captured
# executor catalog (ADR-0017). Reads internal/platform/componentcatalog/
# executor-catalog.json — the verbatim `gibson-runner --list-tools` output of one
# digest-pinned executor image — and writes one manifest per tool. CI drift-gates
# the result, so a manifest can never disagree with the image it names.
tool-manifests:
	@echo "Generating kind:tool manifests from the captured executor catalog..."
	@$(GOCMD) run ./cmd/tool-manifest-gen

# tool-catalog-capture: re-capture the executor catalog from a NEW executor image,
# then regenerate the manifests. Run this when gibson-executor publishes a
# release; commit both the JSON and the regenerated manifests.
#
#   make tool-catalog-capture IMAGE=ghcr.io/zeroroot-ai/gibson-executor@sha256:...
#
# The image MUST be digest-pinned: a captured tool list is only meaningful for the
# exact image it came from, and a tag would make "which tools does this cluster
# have" a question with no reproducible answer. The generator enforces this too.
tool-catalog-capture:
	@if [ -z "$(IMAGE)" ]; then \
		echo "ERROR: IMAGE is required, e.g."; \
		echo "  make tool-catalog-capture IMAGE=ghcr.io/zeroroot-ai/gibson-executor@sha256:<digest>"; \
		exit 1; \
	fi
	@echo "Capturing --list-tools from $(IMAGE)..."
	@tmp=$$(mktemp); \
	docker run --rm --entrypoint gibson-runner "$(IMAGE)" --list-tools > "$$tmp" && \
	$(GOCMD) run ./cmd/tool-manifest-gen -capture-image "$(IMAGE)" -capture-tools "$$tmp"; \
	rc=$$?; rm -f "$$tmp"; exit $$rc

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
	  printf 'version: v2\nmodules:\n  - path: gibson-local\n  - path: sdk-proto\ndeps:\n  - buf.build/bufbuild/protovalidate\nlint:\n  use:\n    - STANDARD\n  ignore:\n    - sdk-proto/google\n    - gibson-local/gibson/daemon/admin/v1/daemon_admin.proto\n' > .tmp/ws/buf.yaml && \
	  printf '# Generated by buf. DO NOT EDIT.\nversion: v2\ndeps:\n  - name: buf.build/bufbuild/protovalidate\n    commit: 50325440f8f24053b047484a6bf60b76\n    digest: b5:74cb6f5c0853c3c10aafc701614194bbd63326bdb8ef4068214454b8894b03ba4113e04b3a33a8321cdf05336e37db4dc14a5e2495db8462566914f36086ba31\n' > .tmp/ws/buf.lock && \
	  cd .tmp/ws && $(BUF) build gibson-local -o $(CURDIR)/.tmp/gibson-fds.binpb
	@rm -rf .tmp/ws
	@echo "Merging FDSes (SDK + daemon-local)..."
	@$(BINARY_DIR)/fds-merge -input .tmp/sdk-fds.binpb -input .tmp/gibson-fds.binpb -output .tmp/combined-fds.binpb
	@echo "Generating registry artifacts..."
	@$(BINARY_DIR)/authz-registry-gen -input .tmp/combined-fds.binpb -output internal/platform/authz/registry
	@# authz-registry-gen emits non-gofmt const alignment (gibson#1157); normalise
	@# so the committed artifact and the drift gate's regeneration are both gofmt-clean.
	@gofmt -w internal/platform/authz/registry/registry.go
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
