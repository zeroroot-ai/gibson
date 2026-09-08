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
FROM ghcr.io/zeroroot-ai/mirror/golang:1.26.8-alpine@sha256:ce864e7223ac17b1775e6fd0b4c0db580c2eb50e7953a427916379e4b92a1628 AS builder

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

# Download dependencies. Every first-party module is public and comes from
# the public Go proxy. No credential is needed to build this image.

# The builder image carries exactly the Go that go.mod names, and the org
# guard (check-go-toolchain.sh, .github#22) fails a PR where they differ.
# GOTOOLCHAIN=local makes a mismatch fail the build instead of downloading a
# toolchain, so the pinned base is the toolchain that built the binary.
ARG GOTOOLCHAIN=local
ENV GOTOOLCHAIN=${GOTOOLCHAIN}

# Go cache mounts. The builder image keeps its build cache at
# /root/.cache/go-build and its module cache at /go/pkg/mod. Without a cache
# mount every RUN starts from an empty cache, so each build step recompiles the
# whole dependency graph and `go mod download` re-fetches every module on any
# change to the build context. Both caches are BuildKit cache mounts, so they
# survive across builds and are shared by every step below — a step that builds
# Go and omits them pays the full cold cost again.
RUN --mount=type=cache,target=/root/.cache/go-build \
    --mount=type=cache,target=/go/pkg/mod \
    go mod download

# Copy source code
COPY . .

# Build static binary with CGO disabled
ENV CGO_ENABLED=0

RUN --mount=type=cache,target=/root/.cache/go-build \
    --mount=type=cache,target=/go/pkg/mod \
    LDFLAGS="-s -w \
      -X github.com/zeroroot-ai/gibson/pkg/version.GitCommit=${COMMIT} \
      -X github.com/zeroroot-ai/gibson/pkg/version.BuildTime=${BUILD_TIME}"; \
    if [ -n "$BUILD_TAGS" ]; then \
        go build -tags="$BUILD_TAGS" -ldflags="$LDFLAGS" -o /out/gibson ./cmd/gibson; \
    else \
        go build -ldflags="$LDFLAGS" -o /out/gibson ./cmd/gibson; \
    fi

# Build the auxiliary one-shot tools shipped alongside the daemon. They take
# identical flags, so one `go build` produces all six: the packages they share
# with each other compile once instead of six times. `-o /out/` names each
# binary after its command directory, which is the name the runtime stage and
# every chart Job already use.
#
# - lowercase-tenant-owner (spec auth-resolution-hardening R4) runs as a Helm
#   post-install/post-upgrade Hook Job to lowercase any pre-existing
#   Tenant.spec.owner values. Idempotent.
# - tenant-owner-backfill (spec tenant-role-taxonomy, Req 5.1–5.4) seeds the FGA
#   owner tuple for the founding user of each existing tenant. Runs as a regular
#   Kubernetes Job (no Helm hook) on helm upgrade to v0.27.0+. Idempotent.
# - active-session-backfill (spec instant-session-revocation, gibson#627 Slice 2
#   / gibson#1302) is the chart's pre-upgrade Job that seeds the FGA
#   active_session conditional tuple for every existing human tenant member.
#   Without it, every user already signed in is locked out at the active_session
#   cutover, because ext-authz starts requiring a tuple nobody has. Env-driven
#   (EXT_AUTHZ_FGA_ADDR / _STORE_ID / _MODEL_ID), idempotent, exits zero.
# - gibson-migrate (spec gibson-postgres-migrations, Req 4) is run as
#   `gibson-migrate platform up` by the chart's pre-upgrade platform-db-migrate
#   Job, applying embedded dashboard-DB migrations before the daemon
#   StatefulSet rolls.
# - sandbox-eviction-handler (spec setec-sandbox-prod-default §C7 / ADR-0023 /
#   gibson#211) runs as a sidecar/peer pod of the sandbox-host DaemonSet on each
#   sandbox-host node. It watches the aws-node-termination-handler notice file
#   (/var/run/aws/spot-interruption-notice) and cordons its own Kubernetes node
#   on appearance. The daemon never imports this binary's code — they share only
#   the image.
# - bootstrap-tenant-owner (spec first-admin-bootstrap, gibson#1103) is a
#   one-time, operator-credentialed one-shot that creates the owner's Zitadel
#   human user, grants tenant Zitadel org membership, and seeds the FGA owner
#   tuple for a closed-registration self-hosted install's first tenant. Invoked
#   ad hoc by the operator (no Helm hook, no session) after
#   AdminProvisionTenant has been drained, never wired into the rollout.
#
# Every one of them is invoked by an explicit command override on its Job,
# DaemonSet or `kubectl exec`, so they ship in the daemon image unchanged.
RUN --mount=type=cache,target=/root/.cache/go-build \
    --mount=type=cache,target=/go/pkg/mod \
    go build -ldflags="-s -w" -o /out/ \
        ./cmd/lowercase-tenant-owner \
        ./cmd/tenant-owner-backfill \
        ./cmd/active-session-backfill \
        ./cmd/gibson-migrate \
        ./cmd/sandbox-eviction-handler \
        ./cmd/bootstrap-tenant-owner

# ============================================================================
# Stage 2: Runtime - Minimal Alpine
# ============================================================================
FROM ghcr.io/zeroroot-ai/mirror/alpine:3.21@sha256:48b0309ca019d89d40f670aa1bc06e426dc0931948452e8491e3d65087abc07d AS runtime

# Install ca-certificates for HTTPS connections
RUN apk add --no-cache ca-certificates

# Copy gibson binary + auxiliary tools from builder
COPY --from=builder /out/gibson /usr/local/bin/gibson
COPY --from=builder /out/lowercase-tenant-owner /usr/local/bin/lowercase-tenant-owner
COPY --from=builder /out/tenant-owner-backfill /usr/local/bin/tenant-owner-backfill
COPY --from=builder /out/active-session-backfill /usr/local/bin/active-session-backfill
COPY --from=builder /out/gibson-migrate /usr/local/bin/gibson-migrate
COPY --from=builder /out/sandbox-eviction-handler /usr/local/bin/sandbox-eviction-handler
COPY --from=builder /out/bootstrap-tenant-owner /usr/local/bin/bootstrap-tenant-owner

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
