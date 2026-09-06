# ============================================================================
# ext-authz Multi-Stage Dockerfile
# ============================================================================
# Production-ready container producing a distroless binary.
# Pure Go build — CGO_ENABLED=0.
#
# Build from ext-authz directory:
#   docker build -t ghcr.io/zeroroot-ai/ext-authz:latest .
# ============================================================================

# ============================================================================
# Stage 1: Builder — Pure Go compilation (no CGO)
# ============================================================================
FROM ghcr.io/zeroroot-ai/mirror/golang:1.26.4-alpine AS builder

RUN apk add --no-cache git ca-certificates

WORKDIR /workspace

# Copy dependency manifests first for better layer caching.
COPY go.mod go.sum ./

# Every github.com/zeroroot-ai/* module this build needs (sdk, ast-checks,
# setec, testfixtures) is public and served by proxy.golang.org, which also
# holds every version go.sum pins. No GOPRIVATE, no git credential: the build
# runs the same for a stranger as for CI (ADR-0089, scripts/check-airgap-build.sh).
# Defensive complement to the pinned base image (#914 bumped it to
# golang:1.26.4 to match go.mod). The mirror golang image bakes
# GOTOOLCHAIN=local, so if a future go.mod toolchain bump ever outpaces the
# mirror tag the build would fail with "go.mod requires go >= 1.X.Y (running
# go 1.X.Z; GOTOOLCHAIN=local)". GOTOOLCHAIN=auto lets the toolchain
# self-fetch in that window. Matches the daemon Dockerfile pattern after the
# E4 fold (gibson#913).
ENV GOTOOLCHAIN=auto
RUN go mod download

# Copy source.
COPY . .

# Build a fully static binary.
ENV CGO_ENABLED=0
RUN go build -ldflags="-s -w" -o /out/ext-authz ./cmd/ext-authz

# ============================================================================
# Stage 1.5: Pre-create empty mount-point directories the chart bind-mounts
# into the read-only rootfs. With `readOnlyRootFilesystem: true` (chart
# default), kubelet/runc cannot mkdir new subdirectories under existing
# image paths at container-create time — so any volumeMount whose target
# does not already exist in the image layer fails with:
#   error mounting ... to rootfs at "/etc/gibson/sa-identity-map":
#   mkdir .../rootfs/etc/gibson/sa-identity-map: read-only file system
# Pre-creating the empty dirs in a writable builder stage and COPY-ing
# them into the distroless final image side-steps this entirely.
# ============================================================================
FROM ghcr.io/zeroroot-ai/mirror/alpine:3.21 AS rootfs-dirs
RUN mkdir -p /rootfs/etc/gibson/sa-identity-map \
    && mkdir -p /rootfs/etc/oras-auth

# ============================================================================
# Stage 2: Runtime — Distroless (no shell, minimal attack surface)
# ============================================================================
FROM ghcr.io/zeroroot-ai/mirror/distroless-static-debian12:nonroot AS runtime

# Copy the binary and CA certificates from the builder.
COPY --from=builder /out/ext-authz /usr/local/bin/ext-authz
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/

# Copy the pre-created bind-mount target directories. These are empty;
# their purpose is to exist so kubelet's bind-mount under
# readOnlyRootFilesystem succeeds.
COPY --from=rootfs-dirs --chown=nonroot:nonroot /rootfs/etc /etc

# gRPC port (Envoy ExtAuthz + Gibson ExtAuthz).
EXPOSE 9001
# HTTP port (healthz + JWKS).
EXPOSE 9002

USER nonroot:nonroot

ENTRYPOINT ["/usr/local/bin/ext-authz"]
