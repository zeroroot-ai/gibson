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

# Copy dependency manifests first for better layer caching
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download

# Copy source code
COPY . .

# Build static binary with CGO disabled
ENV CGO_ENABLED=0

RUN go build \
    -ldflags="-s -w" \
    -o /out/gibson \
    ./cmd/gibson

# ============================================================================
# Stage 2: Runtime - Minimal Alpine
# ============================================================================
FROM alpine:3.21 AS runtime

# Install ca-certificates for HTTPS connections
RUN apk add --no-cache ca-certificates

# Copy gibson binary from builder
COPY --from=builder /out/gibson /usr/local/bin/gibson

# Copy default configuration
COPY --from=builder /workspace/configs/gibson.yaml /etc/gibson/gibson.yaml

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

# Health check using daemon status command
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD gibson daemon status || exit 1

WORKDIR /root/.gibson

ENTRYPOINT ["/usr/local/bin/gibson"]
CMD ["daemon", "start"]
