# Stage 1: build — compiles the plugin binary with CGO disabled.
#
# THE BUILD CONTEXT IS THE REPOSITORY ROOT, not this directory, so every
# COPY path below starts with `plugins/github/`. Build it with:
#
#     docker build -f plugins/github/Dockerfile -t github:<version> .
#
# The root of the gibson repo is the context because LICENSE lives there and
# the image has to carry it. Copying LICENSE into each plugin directory instead
# would make a second source of truth that drifts. The plugin module is its own
# Go module: the build copies only plugins/github/, never the gibson module.
FROM ghcr.io/zeroroot-ai/mirror/golang:1.27.1-alpine@sha256:8a5910f31396cd4d89662f56c68b3ae31d374308270a1c3bd96672ee5ed43414 AS builder
ARG GOTOOLCHAIN=local
ENV GOTOOLCHAIN=${GOTOOLCHAIN}

WORKDIR /build
COPY plugins/github/go.mod plugins/github/go.sum* ./
RUN go mod download

COPY plugins/github/ ./
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags="-s -w" -o /out/github .

# Stage 2: runtime — minimal image for the pod runtime mode.
#
# static-debian13, not static-debian12. The binary is static and reads nothing
# from the Debian userland, so the only Debian packages in the image are
# base-files, ca-certificates, netbase and tzdata, and the base is chosen by
# which of those is patched. DLA-4792-1 fixes tzdata in
# 2026c-0+deb12u1, and every static-debian12:nonroot build still ships
# 2026b-0+deb12u1 (measured 2026-10-02 on the newest index). The
# static-debian13:nonroot index below ships 2026c-0+deb13u1. Move the digest
# here when a scanner names a package in this image; never dismiss the alert.
# Same fix shape as cve-triage#34 and gibson#462.
FROM ghcr.io/zeroroot-ai/mirror/distroless-static:nonroot@sha256:e2e927ec666bae08560abb3c55d0659eceabb657f56b6782ab500a9fc7f555e3 AS runtime

COPY --from=builder /out/github /github
# The Elastic License 2.0 requires the notice to travel with a
# distribution, and a published image is one. /licenses is the OCI
# convention. LICENSE sits at the repository root, which is why the
# build context is the root and every COPY above is root-relative.
COPY LICENSE /licenses/LICENSE

EXPOSE 8080

ENTRYPOINT ["/github"]
