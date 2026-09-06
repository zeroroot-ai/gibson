# ============================================================================
# Gibson Core Multi-Stage Dockerfile (Redis-only)
# ============================================================================
# Production-ready container WITHOUT SQLite/CGO dependencies.
# Significantly smaller and simpler build.
#
# Build from repository root with SDK available:
#   docker build -f core/gibson/build/Dockerfile -t ghcr.io/zeroroot-ai/gibson:latest .
# ============================================================================

# ============================================================================
# Stage 1: Builder - Pure Go compilation (no CGO)
# ============================================================================
FROM golang:1.26.4-alpine AS builder

# Install git for private repo access
RUN apk add --no-cache git ca-certificates

WORKDIR /workspace

# Copy SDK first (it's a dependency via replace directive)
COPY core/sdk /workspace/sdk

# Copy gibson source
COPY core/gibson /workspace/gibson

WORKDIR /workspace/gibson

# NO CGO - pure Go build
ENV CGO_ENABLED=0

# Build the gibson binary
RUN go build \
    -ldflags="-s -w" \
    -o /out/gibson \
    ./cmd/gibson

# ============================================================================
# Stage 2: Runtime - Minimal Alpine, non-root (uid 65532)
# ============================================================================
FROM alpine:3.19 AS runtime

# Install only ca-certificates for HTTPS
RUN apk add --no-cache ca-certificates

# Create non-root user uid 65532 (matches chart's runAsUser per
# security-hardening:R3 + first-deploy:R3 chart values)
RUN addgroup -S -g 65532 nonroot && \
    adduser -S -D -u 65532 -G nonroot -h /var/lib/gibson -s /sbin/nologin nonroot && \
    mkdir -p /var/lib/gibson/.gibson && \
    chown -R 65532:65532 /var/lib/gibson

# Copy gibson binary
COPY --from=builder /out/gibson /usr/local/bin/gibson

# Copy default configuration
COPY --from=builder /workspace/gibson/configs/gibson.yaml /etc/gibson/gibson.yaml

# Set environment variables
ENV GIBSON_CONFIG=/etc/gibson/gibson.yaml
ENV GIBSON_HOME=/var/lib/gibson/.gibson
ENV HOME=/var/lib/gibson

# Expose ports
# 50001: Callback server (agent communication, SPIFFE-mTLS-only)
# 50002: gRPC API server (daemon, SPIFFE-mTLS-only)
# 9090:  Prometheus metrics (TLS-only)
EXPOSE 50001 50002 9090

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD gibson daemon status || exit 1

WORKDIR /var/lib/gibson/.gibson

USER 65532:65532

ENTRYPOINT ["/usr/local/bin/gibson"]
CMD ["daemon", "start"]
