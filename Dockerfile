# ============================================================================
# Gibson Core Multi-Stage Dockerfile
# ============================================================================
# Production-ready container using Go module cache.
# Pure Go build with CGO disabled for static binary compilation.
#
# Build from gibson directory:
#   docker build -t ghcr.io/zeroroot-ai/gibson:latest .
# ============================================================================

# ============================================================================
# Stage 1: Builder - Pure Go compilation (no CGO)
# ============================================================================
FROM ghcr.io/zeroroot-ai/mirror/golang:1.25-alpine AS builder

# Install git and ca-certificates for dependency fetching
RUN apk add --no-cache git ca-certificates

WORKDIR /workspace

# Go build tags. Default is `setec_integration` so every published image
# compiles in the Setec gRPC adapter for sandboxed tool dispatch — this is
# the production-default path per spec setec-sandbox-prod-default (R1.1).
#
# Override to `""` (empty) to build the SDK-only / dev stub variant; that
# binary fails the daemon's production self-check at startup (refuses to
# run with `GIBSON_MODE=saas`) so it cannot be shipped to production by
# accident. CI exercises both variants via a build-tags matrix.
#
# Comma-separated tag lists are supported (e.g. `setec_integration,test_fixtures`).
ARG BUILD_TAGS="setec_integration"

# Git commit SHA and build timestamp — injected by CI via --build-arg.
# Default to "unknown" so local `docker build` without args still works;
# the daemon logs these at startup for operator diagnostics.
ARG COMMIT="unknown"
ARG BUILD_TIME="unknown"

# Copy dependency manifests first for better layer caching
COPY go.mod go.sum ./

# Download dependencies. Private github.com/zeroroot-ai/* modules
# require auth — supplied via the optional `ghtoken` BuildKit secret
# (a file containing a GitHub PAT or `gh auth token` output). When the
# secret is absent (e.g. CI on a public-only build), this step still
# runs but a private-module fetch will fail at build time with a
# missing-auth error.
ENV GOPRIVATE=github.com/zeroroot-ai

# Allow the Go toolchain to auto-fetch the version specified in go.mod when
# the base image ships an older patch. The base FROM is SHA-pinned to a
# specific golang:1.25-alpine digest; Docker Hub re-tagging that alias for
# new patch releases lags by hours-to-days, so without GOTOOLCHAIN=auto a
# fresh go.mod toolchain bump fails the build with "go.mod requires go
# >= 1.X.Y (running go 1.X.Z; GOTOOLCHAIN=local)". This keeps reproducible
# base-image pinning while letting go.mod choose the toolchain.
ENV GOTOOLCHAIN=auto

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

RUN LDFLAGS="-s -w \
      -X github.com/zeroroot-ai/gibson/pkg/version.GitCommit=${COMMIT} \
      -X github.com/zeroroot-ai/gibson/pkg/version.BuildTime=${BUILD_TIME}"; \
    if [ -n "$BUILD_TAGS" ]; then \
        go build -tags="$BUILD_TAGS" -ldflags="$LDFLAGS" -o /out/gibson ./cmd/gibson; \
    else \
        go build -ldflags="$LDFLAGS" -o /out/gibson ./cmd/gibson; \
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

# Spec setec-sandbox-prod-default §C7 / ADR-0023 / gibson#211: the chart's
# sandbox-host DaemonSet runs `sandbox-eviction-handler` as a sidecar/peer
# pod on each sandbox-host node. The binary watches the
# aws-node-termination-handler notice file (/var/run/aws/spot-interruption-notice)
# and cordons its own Kubernetes node on appearance. Daemon never imports
# this binary's code — they share only the image. Same image as the daemon;
# the binary is invoked via explicit DaemonSet command override.
RUN go build -ldflags="-s -w" -o /out/sandbox-eviction-handler ./cmd/sandbox-eviction-handler

# ============================================================================
# Stage 2: Runtime - Minimal Alpine
# ============================================================================
FROM ghcr.io/zeroroot-ai/mirror/alpine:3.21 AS runtime

# Install ca-certificates for HTTPS connections
RUN apk add --no-cache ca-certificates

# Copy gibson binary + auxiliary tools from builder
COPY --from=builder /out/gibson /usr/local/bin/gibson
COPY --from=builder /out/lowercase-tenant-owner /usr/local/bin/lowercase-tenant-owner
COPY --from=builder /out/tenant-owner-backfill /usr/local/bin/tenant-owner-backfill
COPY --from=builder /out/gibson-migrate /usr/local/bin/gibson-migrate
COPY --from=builder /out/sandbox-eviction-handler /usr/local/bin/sandbox-eviction-handler

# Create gibson home directory.
# The bundled ONNX embedder (and its HuggingFace model cache) was removed in
# docs ADR-0059 — embedding is now a BYO provider, so no model artifacts ship
# in the image and no HF cache mount is needed.
RUN mkdir -p /root/.gibson \
    && chmod -R 755 /root/.gibson

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
