# ============================================================================
# gibson-bootstrap — bootstrap-secrets Job binary
# ============================================================================
# Produces a minimal distroless image containing only the gibson-bootstrap
# static binary. This image is invoked by the chart's bootstrap-secrets
# pre-install/pre-upgrade Job to provision Zitadel resources (org, OIDC client)
# without relying on the Helm post-install shell-based bootstrap Job.
#
# Build context: repo root.
#
# Build:
#   docker buildx build \
#     -f tools/gibson-bootstrap/Dockerfile \
#     -t ghcr.io/zeroroot-ai/gibson-bootstrap:latest \
#     .
# ============================================================================

# ============================================================================
# Stage 1: Builder
# ============================================================================
FROM ghcr.io/zeroroot-ai/mirror/golang:1.26.8-alpine@sha256:ce864e7223ac17b1775e6fd0b4c0db580c2eb50e7953a427916379e4b92a1628 AS builder

# git is required by the Go toolchain for the `direct` proxy fallback.
RUN apk add --no-cache git ca-certificates

WORKDIR /workspace

# The builder image carries exactly the Go that go.mod names, and the org
# guard (check-go-toolchain.sh, .github#22) fails a PR where they differ.
# GOTOOLCHAIN=local makes a mismatch fail the build instead of downloading a
# toolchain, so the pinned base is the toolchain that built the binary.
ARG GOTOOLCHAIN=local
ENV GOTOOLCHAIN=${GOTOOLCHAIN}
ENV CGO_ENABLED=0

# Copy module manifests first to maximise layer-cache hits.
COPY go.mod go.sum ./

# Fetch dependencies from the public Go proxy. Every first-party module is public.
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

# Copy full source tree (needed for the ./tools/gibson-bootstrap package).
COPY . .

# Build both static binaries. -s -w strips debug symbols for a smaller image.
# They take identical flags, so one `go build` compiles the packages they share
# once; `-o /out/` names each binary after its command directory.
#
# bootstrap-tenant-owner ships alongside gibson-bootstrap because the two halves
# of a first-admin bootstrap are useless apart: seed-first-admin enqueues the
# provisioning op that builds the tenant and its Zitadel org, and
# bootstrap-tenant-owner creates the owner's user in that org and grants it.
# Shipping only the first left deploy#1631 with no way to run the second, so a
# vanilla install produced a tenant nobody could sign into.
RUN --mount=type=cache,target=/root/.cache/go-build \
    --mount=type=cache,target=/go/pkg/mod \
    go build -ldflags="-s -w" -o /out/ \
        ./tools/gibson-bootstrap \
        ./cmd/bootstrap-tenant-owner

# ============================================================================
# Stage 2: Runtime — distroless static (no libc, no shell, no package manager)
# ============================================================================
FROM ghcr.io/zeroroot-ai/mirror/distroless-static:nonroot@sha256:1c2c046bc09ed40fad370b599a0b1ae7987f55b01e247cf27a7c27cd97e5bbc7

COPY --from=builder /out/gibson-bootstrap /gibson-bootstrap
COPY --from=builder /out/bootstrap-tenant-owner /bootstrap-tenant-owner

# gibson-bootstrap stays the default; the chart's first-admin Job overrides
# `command` to run /bootstrap-tenant-owner.
ENTRYPOINT ["/gibson-bootstrap"]
