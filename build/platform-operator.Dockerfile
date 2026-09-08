# Build the manager binary
FROM ghcr.io/zeroroot-ai/mirror/golang:1.26.8-alpine@sha256:ce864e7223ac17b1775e6fd0b4c0db580c2eb50e7953a427916379e4b92a1628 AS builder
ARG TARGETOS
ARG TARGETARCH

WORKDIR /workspace
# Copy the Go Modules manifests
COPY go.mod go.mod
COPY go.sum go.sum
# Install git (needed for private-module direct fetches when go mod
# can't reach the proxy; tenant-operator imports github.com/zeroroot-ai/gibson).
RUN apk add --no-cache git ca-certificates
# cache deps before building and copying source so that we don't need to re-download as much
# and so that source changes don't invalidate our downloaded layer
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

# Copy the Go source (relies on .dockerignore to filter)
COPY . .

# Build the manager binary statically — distroless static requires a
# Go binary with CGO disabled and no dynamic linker references.
# -ldflags '-s -w' strips symbols + debug info for ~30% size reduction.
RUN --mount=type=cache,target=/root/.cache/go-build \
    --mount=type=cache,target=/go/pkg/mod \
    CGO_ENABLED=0 GOOS=${TARGETOS:-linux} GOARCH=${TARGETARCH} \
    go build -a -ldflags '-s -w' -o manager operators/platform/cmd/main.go

# Distroless static base — minimal, nonroot, no shell, no package manager.
FROM ghcr.io/zeroroot-ai/mirror/distroless-static:nonroot@sha256:1c2c046bc09ed40fad370b599a0b1ae7987f55b01e247cf27a7c27cd97e5bbc7
WORKDIR /
COPY --from=builder /workspace/manager .
USER 65532:65532

ENTRYPOINT ["/manager"]
