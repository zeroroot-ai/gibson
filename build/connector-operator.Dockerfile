# Multi-stage build for the gibson connector-operator (ADR-0014).
# ghcr.io/zeroroot-ai/mirror/golang:1.26.4 — the same mirrored builder as the
# sibling operator images. go.mod names a newer toolchain than the image
# ships, so GOTOOLCHAIN=auto lets go fetch it through GOPROXY, the same rule
# as build/tenant-operator.Dockerfile.
FROM ghcr.io/zeroroot-ai/mirror/golang:1.26.6@sha256:640a234f4bea3e399c056b7b8f9c667c4939befae8db2f14e9785e16eccd4205 AS build
ENV GOTOOLCHAIN=auto
WORKDIR /src
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -o /out/connector-operator ./operators/connector/cmd

FROM ghcr.io/zeroroot-ai/mirror/distroless-static:nonroot@sha256:1c2c046bc09ed40fad370b599a0b1ae7987f55b01e247cf27a7c27cd97e5bbc7
WORKDIR /
COPY --from=build /out/connector-operator /connector-operator
USER 65532:65532
ENTRYPOINT ["/connector-operator"]
