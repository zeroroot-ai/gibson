# Gibson Framework Makefile
# Stage 1 - Foundation

.PHONY: all build bin test test-coverage test-race lint clean install help proto proto-deps proto-clean

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

# Buf code generation (delegates to the repo root workspace)
# Resolve repo root relative to this Makefile's location (core/gibson → root is ../..)
ROOT_DIR := $(abspath $(dir $(lastword $(MAKEFILE_LIST)))../..)
BUF := npx --prefix $(ROOT_DIR)/enterprise/dashboard buf

# Default target
all: test build

# Build the binary (quick local build)
bin:
	@echo "Building $(BINARY_NAME)..."
	@mkdir -p $(BINARY_DIR)
	$(GOBUILD) $(BUILD_TAGS) $(LDFLAGS) -o $(BINARY_DIR)/$(BINARY_NAME) $(MAIN_PACKAGE)
	@echo "Build complete: $(BINARY_DIR)/$(BINARY_NAME)"

# Full build (for Docker/CI/CD)
build: bin
	@echo "Full build complete"

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
		golangci-lint run ./...; \
	else \
		echo "golangci-lint not installed. Run: go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest"; \
	fi

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

# Run all checks before commit
check: fmt vet lint test-race
	@echo "All checks passed!"

# Proto generation
proto-deps:
	@echo "Installing protoc plugins..."
	go install google.golang.org/protobuf/cmd/protoc-gen-go@v1.34.2
	go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@v1.5.1

proto: proto-deps
	@echo "Generating Go code from daemon proto files via Buf..."
	cd $(ROOT_DIR) && $(BUF) generate --template buf.gen.yaml --path core/gibson/internal/daemon/api
	@echo "Proto generation complete"

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
	@echo "  make proto         - Generate Go code from proto files"
	@echo "  make proto-deps    - Install protoc plugins"
	@echo "  make proto-clean   - Remove generated proto files"
	@echo "  make help          - Show this help message"
