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
    go mod download && \
    git config --global --remove-section url."https://x-access-token:$(cat /run/secrets/ghtoken 2>/dev/null || echo invalid)@github.com/" 2>/dev/null || true

# Copy the Go source (relies on .dockerignore to filter)
COPY . .

# Build the manager binary statically — distroless static requires a
# Go binary with CGO disabled and no dynamic linker references.
# -ldflags '-s -w' strips symbols + debug info for ~30% size reduction.
RUN CGO_ENABLED=0 GOOS=${TARGETOS:-linux} GOARCH=${TARGETARCH} \
    go build -a -ldflags '-s -w' -o manager operators/platform/cmd/main.go

# Distroless static base — minimal, nonroot, no shell, no package manager.
FROM ghcr.io/zeroroot-ai/mirror/distroless-static:nonroot
WORKDIR /
COPY --from=builder /workspace/manager .
USER 65532:65532

ENTRYPOINT ["/manager"]
