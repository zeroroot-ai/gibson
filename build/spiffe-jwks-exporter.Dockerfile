# Sourced from the ghcr.io/zeroroot-ai/mirror copy populated by
# zeroroot-ai/.github :: mirror-images.yml. Pinned by digest; Dependabot
# (docker ecosystem, /build) bumps the digest. To move the Go version, bump
# go.mod, add the tag to mirror-list.yaml, then bump every builder here: the
# org guard (check-go-toolchain.sh, .github#22) keeps them equal.
FROM ghcr.io/zeroroot-ai/mirror/golang:1.26.8-alpine@sha256:ce864e7223ac17b1775e6fd0b4c0db580c2eb50e7953a427916379e4b92a1628 AS build

# git is required by the --mount=type=secret RUN layer below to configure
# private-module credentials. Alpine Go images ship without it.
RUN apk add --no-cache git ca-certificates

WORKDIR /src
# The builder image carries exactly the Go that go.mod names, and the org
# guard (check-go-toolchain.sh, .github#22) fails a PR where they differ.
# GOTOOLCHAIN=local makes a mismatch fail the build instead of downloading a
# toolchain, so the pinned base is the toolchain that built the binary.
ARG GOTOOLCHAIN=local
ENV GOTOOLCHAIN=${GOTOOLCHAIN}
COPY go.mod go.sum ./
# Every github.com/zeroroot-ai/* module this build needs (sdk, ast-checks,
# setec, testfixtures) is public and served by proxy.golang.org, which also
# holds every version go.sum pins. No GOPRIVATE, no git credential: the build
# runs the same for a stranger as for CI (ADR-0089, scripts/check-airgap-build.sh).
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

# The binary now lives in the gibson module and imports internal/infra, so the
# full source tree is required (not just cmd/).
COPY . .
RUN --mount=type=cache,target=/root/.cache/go-build \
    --mount=type=cache,target=/go/pkg/mod \
    CGO_ENABLED=0 GOFLAGS=-trimpath go build -ldflags='-s -w' \
    -o /out/spiffe-jwks-exporter ./cmd/spiffe-jwks-exporter

FROM ghcr.io/zeroroot-ai/mirror/distroless-static:nonroot@sha256:1c2c046bc09ed40fad370b599a0b1ae7987f55b01e247cf27a7c27cd97e5bbc7
USER nonroot:nonroot
COPY --from=build /out/spiffe-jwks-exporter /spiffe-jwks-exporter
ENTRYPOINT ["/spiffe-jwks-exporter"]
