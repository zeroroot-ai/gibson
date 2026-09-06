# Multi-stage build for the gibson connector-operator (ADR-0014).
# ghcr.io/zeroroot-ai/mirror/golang:1.26.4 — the same mirrored builder as the
# sibling operator images. go.mod names a newer toolchain than the image
# ships, so GOTOOLCHAIN=auto lets go fetch it through GOPROXY, the same rule
# as build/tenant-operator.Dockerfile.
FROM ghcr.io/zeroroot-ai/mirror/golang:1.26.4 AS build
ENV GOTOOLCHAIN=auto
WORKDIR /src
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -o /out/connector-operator ./operators/connector/cmd

FROM ghcr.io/zeroroot-ai/mirror/distroless-static:nonroot
WORKDIR /
COPY --from=build /out/connector-operator /connector-operator
USER 65532:65532
ENTRYPOINT ["/connector-operator"]
