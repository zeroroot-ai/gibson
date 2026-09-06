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
FROM ghcr.io/zeroroot-ai/mirror/golang:1.25-alpine AS builder

# git is required by the Go toolchain for the `direct` proxy fallback.
RUN apk add --no-cache git ca-certificates

WORKDIR /workspace

ENV GOTOOLCHAIN=auto
ENV CGO_ENABLED=0

# Copy module manifests first to maximise layer-cache hits.
COPY go.mod go.sum ./

# Fetch dependencies from the public Go proxy. Every first-party module is public.
RUN go mod download

# Copy full source tree (needed for the ./tools/gibson-bootstrap package).
COPY . .

# Build a static binary. -s -w strips debug symbols for a smaller image.
RUN go build -ldflags="-s -w" -o /out/gibson-bootstrap ./tools/gibson-bootstrap

# bootstrap-tenant-owner ships alongside it because the two halves of a
# first-admin bootstrap are useless apart: seed-first-admin enqueues the
# provisioning op that builds the tenant and its Zitadel org, and
# bootstrap-tenant-owner creates the owner's user in that org and grants it.
# Shipping only the first left deploy#1631 with no way to run the second, so a
# vanilla install produced a tenant nobody could sign into.
RUN go build -ldflags="-s -w" -o /out/bootstrap-tenant-owner ./cmd/bootstrap-tenant-owner

# ============================================================================
# Stage 2: Runtime — distroless static (no libc, no shell, no package manager)
# ============================================================================
FROM ghcr.io/zeroroot-ai/mirror/distroless-static:nonroot

COPY --from=builder /out/gibson-bootstrap /gibson-bootstrap
COPY --from=builder /out/bootstrap-tenant-owner /bootstrap-tenant-owner

# gibson-bootstrap stays the default; the chart's first-admin Job overrides
# `command` to run /bootstrap-tenant-owner.
ENTRYPOINT ["/gibson-bootstrap"]
