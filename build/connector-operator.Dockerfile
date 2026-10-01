# Multi-stage build for the gibson connector-operator (ADR-0014).
# ghcr.io/zeroroot-ai/mirror/golang:1.26.8-alpine, the one builder every
# gibson image uses: the Go that go.mod names, kept equal by the org guard
# (check-go-toolchain.sh, .github#22). GOTOOLCHAIN=local makes a mismatch
# fail the build instead of downloading a toolchain.
FROM ghcr.io/zeroroot-ai/mirror/golang:1.26.8-alpine@sha256:ce864e7223ac17b1775e6fd0b4c0db580c2eb50e7953a427916379e4b92a1628 AS build
ARG GOTOOLCHAIN=local
ENV GOTOOLCHAIN=${GOTOOLCHAIN}
WORKDIR /src
COPY . .
# Go cache mounts. The builder image keeps its build cache at
# /root/.cache/go-build and its module cache at /go/pkg/mod. Without a cache
# mount this RUN starts from an empty cache, so any change to the build context
# recompiles and re-downloads the whole dependency graph. A Go step added below
# needs the same two mounts.
RUN --mount=type=cache,target=/root/.cache/go-build \
    --mount=type=cache,target=/go/pkg/mod \
    CGO_ENABLED=0 GOOS=linux go build -trimpath -o /out/connector-operator ./operators/connector/cmd

FROM ghcr.io/zeroroot-ai/mirror/distroless-static:nonroot@sha256:e2e927ec666bae08560abb3c55d0659eceabb657f56b6782ab500a9fc7f555e3
WORKDIR /
COPY --from=build /out/connector-operator /connector-operator
USER 65532:65532
# Elastic License 2.0, "Notices": anyone who gets a copy of the software
# must also get a copy of these terms. A container image is a copy.
# /licenses is the OCI convention for where that text lives.
COPY LICENSE /licenses/LICENSE

ENTRYPOINT ["/connector-operator"]
