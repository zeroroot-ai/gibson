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
FROM ghcr.io/zeroroot-ai/mirror/golang:1.25.11-alpine AS builder

RUN apk add --no-cache git ca-certificates

WORKDIR /workspace

# Copy dependency manifests first for better layer caching.
COPY go.mod go.sum ./

# Private github.com/zeroroot-ai/* modules (platform-clients, sdk) require
# auth — supplied via the optional `ghtoken` BuildKit secret. When the
# secret is absent the build will fail with a clear auth error rather
# than silently fall back. Mirror tenant-operator's Dockerfile pattern.
ENV GOPRIVATE=github.com/zeroroot-ai
RUN --mount=type=secret,id=ghtoken,target=/run/secrets/ghtoken,required=false \
    if [ -s /run/secrets/ghtoken ]; then \
      git config --global url."https://x-access-token:$(cat /run/secrets/ghtoken)@github.com/".insteadOf "https://github.com/"; \
    fi && \
    go mod download && \
    git config --global --remove-section url."https://x-access-token:$(cat /run/secrets/ghtoken 2>/dev/null || echo invalid)@github.com/" 2>/dev/null || true

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
