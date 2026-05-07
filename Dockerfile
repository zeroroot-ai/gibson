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
FROM golang:1.25-alpine@sha256:5caaf1cca9dc351e13deafbc3879fd4754801acba8653fa9540cea125d01a71f AS builder

# Install git and ca-certificates for dependency fetching
RUN apk add --no-cache git ca-certificates

WORKDIR /workspace

# Optional Go build tags. Leave empty for the default daemon; set to
# `setec_integration` (or a comma-separated list) to compile in the Setec
# gRPC adapter for sandboxed tool dispatch.
ARG BUILD_TAGS=""

# Copy dependency manifests first for better layer caching
COPY go.mod go.sum ./

# Download dependencies. Private github.com/zero-day-ai/* modules
# require auth — supplied via the optional `ghtoken` BuildKit secret
# (a file containing a GitHub PAT or `gh auth token` output). When the
# secret is absent (e.g. CI on a public-only build), this step still
# runs but a private-module fetch will fail at build time with a
# missing-auth error.
ENV GOPRIVATE=github.com/zero-day-ai
RUN --mount=type=secret,id=ghtoken,target=/run/secrets/ghtoken,required=false \
    if [ -s /run/secrets/ghtoken ]; then \
      git config --global url."https://x-access-token:$(cat /run/secrets/ghtoken)@github.com/".insteadOf "https://github.com/"; \
    fi && \
    go mod download && \
    git config --global --unset-all url."https://x-access-token:$(cat /run/secrets/ghtoken 2>/dev/null)@github.com/".insteadOf 2>/dev/null || true

# Copy source code
COPY . .

# Build static binary with CGO disabled
ENV CGO_ENABLED=0

RUN if [ -n "$BUILD_TAGS" ]; then \
        go build -tags="$BUILD_TAGS" -ldflags="-s -w" -o /out/gibson ./cmd/gibson; \
    else \
        go build -ldflags="-s -w" -o /out/gibson ./cmd/gibson; \
    fi

# Build the auxiliary one-shot tools shipped alongside the daemon.
# Spec auth-resolution-hardening (R4): lowercase-tenant-owner runs as a
# Helm post-install/post-upgrade Hook Job to lowercase any pre-existing
# Tenant.spec.owner values. Idempotent.
RUN go build -ldflags="-s -w" -o /out/lowercase-tenant-owner ./cmd/lowercase-tenant-owner

# Spec tenant-role-taxonomy (Req 5.1–5.4): tenant-owner-backfill seeds the
# FGA owner tuple for the founding user of each existing tenant. Runs as a
# regular Kubernetes Job (no Helm hook) on helm upgrade to v0.27.0+. Idempotent.
RUN go build -ldflags="-s -w" -o /out/tenant-owner-backfill ./cmd/tenant-owner-backfill

# Spec gibson-postgres-migrations (Req 4): the chart's pre-upgrade
# platform-db-migrate Job runs `gibson-migrate platform up` from this
# image to apply embedded dashboard-DB migrations before the daemon
# StatefulSet rolls. Same image as the daemon — the binary is invoked
# via explicit Job command override.
RUN go build -ldflags="-s -w" -o /out/gibson-migrate ./cmd/gibson-migrate

# ============================================================================
# Stage 2: Runtime - Minimal Alpine
# ============================================================================
FROM alpine:3.21@sha256:48b0309ca019d89d40f670aa1bc06e426dc0931948452e8491e3d65087abc07d AS runtime

# Install ca-certificates for HTTPS connections
RUN apk add --no-cache ca-certificates

# Copy gibson binary + auxiliary tools from builder
COPY --from=builder /out/gibson /usr/local/bin/gibson
COPY --from=builder /out/lowercase-tenant-owner /usr/local/bin/lowercase-tenant-owner
COPY --from=builder /out/tenant-owner-backfill /usr/local/bin/tenant-owner-backfill
COPY --from=builder /out/gibson-migrate /usr/local/bin/gibson-migrate

# Create gibson home directory and HF model-cache mount point.
# In production, /root/.cache/huggingface/ is mounted from EFS via the
# gibson.hfModelCache values path and seeded by a pre-install Job that
# syncs from s3://<artifacts>/huggingface/. In Kind / local dev without
# EFS, the daemon downloads models from HuggingFace on first use.
RUN mkdir -p /root/.gibson /root/.cache/huggingface \
    && chmod -R 755 /root/.gibson /root/.cache/huggingface

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
