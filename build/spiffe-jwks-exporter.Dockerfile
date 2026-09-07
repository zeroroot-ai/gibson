# Sourced from the ghcr.io/zeroroot-ai/mirror copy populated by
# zeroroot-ai/.github :: mirror-images.yml. Pinned by digest; Dependabot
# (docker ecosystem, /build) bumps the digest. To move the Go version, add
# the tag to mirror-list.yaml, re-run the mirror workflow, then bump here.
FROM ghcr.io/zeroroot-ai/mirror/golang:1.26.4-alpine@sha256:3ad57304ad93bbec8548a0437ad9e06a455660655d9af011d58b993f6f615648 AS build

# git is required by the --mount=type=secret RUN layer below to configure
# private-module credentials. Alpine Go images ship without it.
RUN apk add --no-cache git ca-certificates

WORKDIR /src
# Defensive complement to the pinned base image (#914 bumped it to
# golang:1.26.4 to match go.mod). The mirror golang image bakes
# GOTOOLCHAIN=local, so if a future go.mod toolchain bump ever outpaces the
# mirror tag the build would fail with "go.mod requires go >= 1.X.Y (running
# go 1.X.Z; GOTOOLCHAIN=local)". GOTOOLCHAIN=auto lets the toolchain
# self-fetch in that window. Matches the daemon Dockerfile pattern after the
# E4 fold (gibson#913).
ENV GOTOOLCHAIN=auto
COPY go.mod go.sum ./
# Every github.com/zeroroot-ai/* module this build needs (sdk, ast-checks,
# setec, testfixtures) is public and served by proxy.golang.org, which also
# holds every version go.sum pins. No GOPRIVATE, no git credential: the build
# runs the same for a stranger as for CI (ADR-0089, scripts/check-airgap-build.sh).
RUN go mod download

# The binary now lives in the gibson module and imports internal/infra, so the
# full source tree is required (not just cmd/).
COPY . .
RUN CGO_ENABLED=0 GOFLAGS=-trimpath go build -ldflags='-s -w' \
    -o /out/spiffe-jwks-exporter ./cmd/spiffe-jwks-exporter

FROM ghcr.io/zeroroot-ai/mirror/distroless-static:nonroot@sha256:1c2c046bc09ed40fad370b599a0b1ae7987f55b01e247cf27a7c27cd97e5bbc7
USER nonroot:nonroot
COPY --from=build /out/spiffe-jwks-exporter /spiffe-jwks-exporter
ENTRYPOINT ["/spiffe-jwks-exporter"]
