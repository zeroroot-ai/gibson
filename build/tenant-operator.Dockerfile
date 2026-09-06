# Build the manager binary
FROM ghcr.io/zeroroot-ai/mirror/golang:1.26.4 AS builder
ARG TARGETOS
ARG TARGETARCH

WORKDIR /workspace
# Copy the Go Modules manifests
COPY go.mod go.mod
COPY go.sum go.sum
# Install git (needed for private-module direct fetches when go mod
# can't reach the proxy; tenant-operator imports github.com/zeroroot-ai/gibson).
RUN apt-get update && apt-get install -y --no-install-recommends git ca-certificates && rm -rf /var/lib/apt/lists/*
# cache deps before building and copying source so that we don't need to re-download as much
# and so that source changes don't invalidate our downloaded layer
#
# Private github.com/zeroroot-ai/* modules require auth — supplied via
# the optional `ghtoken` BuildKit secret (a file containing a GitHub
# PAT or `gh auth token` output). When the secret is absent the build
# fails fast with a missing-auth error.
ENV GOPRIVATE=github.com/zeroroot-ai
# Defensive complement to the pinned base image (#914 bumped it to
# golang:1.26.4 to match go.mod). The mirror golang image bakes
# GOTOOLCHAIN=local, so if a future go.mod toolchain bump ever outpaces the
# mirror tag the build would fail with "go.mod requires go >= 1.X.Y (running
# go 1.X.Z; GOTOOLCHAIN=local)". GOTOOLCHAIN=auto lets the toolchain
# self-fetch in that window. Matches the daemon Dockerfile pattern after the
# E4 fold (gibson#913).
ENV GOTOOLCHAIN=auto
RUN --mount=type=secret,id=ghtoken,target=/run/secrets/ghtoken,required=false \
    if [ -s /run/secrets/ghtoken ]; then \
      git config --global url."https://x-access-token:$(cat /run/secrets/ghtoken)@github.com/".insteadOf "https://github.com/"; \
    fi && \
    go mod download; GOMOD_RC=$?; \
    git config --global --remove-section url."https://x-access-token:$(cat /run/secrets/ghtoken 2>/dev/null || echo invalid)@github.com/" 2>/dev/null || true; \
    exit $GOMOD_RC

# Copy the Go source (relies on .dockerignore to filter)
COPY . .

# Build
# the GOARCH has no default value to allow the binary to be built according to the host where the command
# was called. For example, if we call make docker-build in a local env which has the Apple Silicon M1 SO
# the docker BUILDPLATFORM arg will be linux/arm64 when for Apple x86 it will be linux/amd64. Therefore,
# by leaving it empty we can ensure that the container and binary shipped on it will have the same platform.
RUN CGO_ENABLED=0 GOOS=${TARGETOS:-linux} GOARCH=${TARGETARCH} go build -a -o manager ./operators/tenant/cmd
# backfill-credentials is the chart's pre-upgrade Helm hook entrypoint
# (Spec tenant-provisioning-unification-phase2 Requirement 8.5).
RUN CGO_ENABLED=0 GOOS=${TARGETOS:-linux} GOARCH=${TARGETARCH} go build -a -o backfill-credentials ./operators/tenant/cmd/backfill-credentials
# backfill-rbac is the pre-upgrade Helm hook for spec
# secrets-blast-radius-reduction — ensures every existing tenant's
# namespace has the per-tenant Role+RoleBinding before the chart
# narrows the operator's ClusterRole.
RUN CGO_ENABLED=0 GOOS=${TARGETOS:-linux} GOARCH=${TARGETARCH} go build -a -o backfill-rbac ./operators/tenant/cmd/backfill-rbac
# migrate-tenant-tiers is the pre-upgrade Helm hook for spec
# plans-and-quotas-simplification — rewrites every Tenant CR's
# spec.tier from a legacy id to the canonical three before the chart's
# new validating webhook (which rejects legacy ids) takes effect.
RUN CGO_ENABLED=0 GOOS=${TARGETOS:-linux} GOARCH=${TARGETARCH} go build -a -o migrate-tenant-tiers ./operators/tenant/cmd/migrate-tenant-tiers

# Use distroless as minimal base image to package the manager binary
# Refer to https://github.com/GoogleContainerTools/distroless for more details
FROM ghcr.io/zeroroot-ai/mirror/distroless-static:nonroot
WORKDIR /
COPY --from=builder /workspace/manager .
COPY --from=builder /workspace/backfill-credentials .
COPY --from=builder /workspace/backfill-rbac .
COPY --from=builder /workspace/migrate-tenant-tiers .
USER 65532:65532

ENTRYPOINT ["/manager"]
