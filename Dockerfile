# ============================================================================
# Gibson Core Multi-Stage Dockerfile
# ============================================================================
# Production-ready container using Go module cache.
# Pure Go build with CGO disabled for static binary compilation.
#
# Build from gibson directory:
#   docker build -t ghcr.io/zero-day-ai/gibson:latest .
# ============================================================================

# ============================================================================
# Stage 1: Builder - Pure Go compilation (no CGO)
# ============================================================================
FROM golang:1.25-alpine AS builder

# Install git and ca-certificates for dependency fetching
RUN apk add --no-cache git ca-certificates

WORKDIR /workspace

# Optional Go build tags. Leave empty for the default daemon; set to
# `setec_integration` (or a comma-separated list) to compile in the Setec
# gRPC adapter for sandboxed tool dispatch.
ARG BUILD_TAGS=""

# Copy dependency manifests first for better layer caching
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download

# Copy source code
COPY . .

# Build static binary with CGO disabled
ENV CGO_ENABLED=0

RUN if [ -n "$BUILD_TAGS" ]; then \
        go build -tags="$BUILD_TAGS" -ldflags="-s -w" -o /out/gibson ./cmd/gibson; \
    else \
        go build -ldflags="-s -w" -o /out/gibson ./cmd/gibson; \
    fi

# ============================================================================
# Stage 2: Runtime - Minimal Alpine
# ============================================================================
FROM alpine:3.21 AS runtime

# Install ca-certificates for HTTPS connections
RUN apk add --no-cache ca-certificates

# Copy gibson binary from builder
COPY --from=builder /out/gibson /usr/local/bin/gibson

# Create gibson home directory
RUN mkdir -p /root/.gibson && chmod -R 755 /root/.gibson

# Copy pre-cached HuggingFace model files for native embedder
# These files are required by GraphRAG and must exist to avoid network calls at startup
# The model directory must be copied from the build context (models/huggingface/)
COPY models/huggingface/ /root/.cache/huggingface/

# Set environment variables
ENV GIBSON_CONFIG=/etc/gibson/gibson.yaml
ENV GIBSON_HOME=/root/.gibson

# Expose ports
# 50001: Callback server (agent communication)
# 50002: gRPC API server (daemon)
# 9090:  Prometheus metrics
EXPOSE 50001 50002 9090

# Health check via the daemon's HTTP health endpoint.
# The daemon binds /healthz on :8080 (internal/daemon/health_state.go).
# Alpine 3.21 ships wget in busybox, so no extra package is needed.
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
    CMD wget -qO- http://localhost:8080/healthz || exit 1

WORKDIR /root/.gibson

ENTRYPOINT ["/usr/local/bin/gibson"]
# No subcommand: the binary reads GIBSON_CONFIG (or ~/.gibson/config.yaml) and
# starts the daemon directly, matching the Mat Ryer entry-point pattern.
CMD []
