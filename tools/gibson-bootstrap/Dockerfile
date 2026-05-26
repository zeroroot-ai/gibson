# ============================================================================
# gibson-bootstrap — bootstrap-secrets Job binary
# ============================================================================
# Produces a minimal distroless image containing only the gibson-bootstrap
# static binary. This image is invoked by the chart's bootstrap-secrets
# pre-install/pre-upgrade Job to provision Zitadel resources (org, OIDC client)
# without relying on the Helm post-install shell-based bootstrap Job.
#
# Build context: repo root (core/gibson/), so private module fetch works
# via the ghtoken BuildKit secret.
#
# Build:
#   docker buildx build \
#     --secret id=ghtoken,src=<(gh auth token) \
#     -f tools/gibson-bootstrap/Dockerfile \
#     -t ghcr.io/zeroroot-ai/gibson-bootstrap:latest \
#     .
# ============================================================================

# ============================================================================
# Stage 1: Builder
# ============================================================================
FROM ghcr.io/zeroroot-ai/mirror/golang:1.25-alpine AS builder

# git is required for private module fetches via git config url rewrite.
RUN apk add --no-cache git ca-certificates

WORKDIR /workspace

# Private module access — same pattern as core/gibson/Dockerfile.
ENV GOPRIVATE=github.com/zeroroot-ai
ENV GOTOOLCHAIN=auto
ENV CGO_ENABLED=0

# Copy module manifests first to maximise layer-cache hits.
COPY go.mod go.sum ./

# Fetch dependencies. The optional ghtoken BuildKit secret is forwarded as a
# git credential for github.com/zeroroot-ai/* private modules. When the secret
# is absent (e.g. public CI without private access), this step succeeds only if
# all required modules are already publicly available.
RUN --mount=type=secret,id=ghtoken,target=/run/secrets/ghtoken,required=false \
    if [ -s /run/secrets/ghtoken ]; then \
      git config --global url."https://x-access-token:$(cat /run/secrets/ghtoken)@github.com/".insteadOf "https://github.com/"; \
    fi && \
    go mod download && \
    git config --global --unset-all url."https://x-access-token:$(cat /run/secrets/ghtoken 2>/dev/null)@github.com/".insteadOf 2>/dev/null || true

# Copy full source tree (needed for the ./tools/gibson-bootstrap package).
COPY . .

# Build a static binary. -s -w strips debug symbols for a smaller image.
RUN go build -ldflags="-s -w" -o /out/gibson-bootstrap ./tools/gibson-bootstrap

# ============================================================================
# Stage 2: Runtime — distroless static (no libc, no shell, no package manager)
# ============================================================================
FROM ghcr.io/zeroroot-ai/mirror/distroless-static:nonroot

COPY --from=builder /out/gibson-bootstrap /gibson-bootstrap

ENTRYPOINT ["/gibson-bootstrap"]
