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
FROM ghcr.io/zeroroot-ai/mirror/golang:1.26.8-alpine@sha256:ce864e7223ac17b1775e6fd0b4c0db580c2eb50e7953a427916379e4b92a1628 AS builder

RUN apk add --no-cache git ca-certificates

WORKDIR /workspace

# Copy dependency manifests first for better layer caching.
COPY go.mod go.sum ./

# Every github.com/zeroroot-ai/* module this build needs (sdk, ast-checks,
# setec, testfixtures) is public and served by proxy.golang.org, which also
# holds every version go.sum pins. No GOPRIVATE, no git credential: the build
# runs the same for a stranger as for CI (ADR-0089, scripts/check-airgap-build.sh).
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

# Copy source.
COPY . .

# Build a fully static binary.
ENV CGO_ENABLED=0
RUN --mount=type=cache,target=/root/.cache/go-build \
    --mount=type=cache,target=/go/pkg/mod \
    go build -ldflags="-s -w" -o /out/ext-authz ./cmd/ext-authz

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
FROM ghcr.io/zeroroot-ai/mirror/alpine:3.21@sha256:48b0309ca019d89d40f670aa1bc06e426dc0931948452e8491e3d65087abc07d AS rootfs-dirs
RUN mkdir -p /rootfs/etc/gibson/sa-identity-map \
    && mkdir -p /rootfs/etc/oras-auth

# ============================================================================
# Stage 2: Runtime — Distroless (no shell, minimal attack surface)
# ============================================================================
FROM ghcr.io/zeroroot-ai/mirror/distroless-static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab AS runtime

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
