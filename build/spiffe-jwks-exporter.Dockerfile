ARG GOLANG_VERSION=1.25
# Sourced from the ghcr.io/zeroroot-ai/mirror copy populated by
# zeroroot-ai/.github :: mirror-images.yml. Mirror tags are immutable by
# workflow policy; no SHA pin needed. Bump GOLANG_VERSION + add the matching
# tag to mirror-list.yaml + re-run the workflow.
FROM ghcr.io/zeroroot-ai/mirror/golang:${GOLANG_VERSION}-alpine AS build

# git is required by the --mount=type=secret RUN layer below to configure
# private-module credentials. Alpine Go images ship without it.
RUN apk add --no-cache git ca-certificates

WORKDIR /src
COPY go.mod go.sum ./
# --mount=type=secret,id=ghtoken provides the GitHub token for fetching private
# zeroroot-ai modules. The credential is scoped to this single RUN layer and
# never baked into the image. On CI the secret is passed by
# reusable-image-build.yml via secrets.ghtoken; local builds may omit it if the
# modules are already cached.
RUN --mount=type=secret,id=ghtoken \
    if [ -f /run/secrets/ghtoken ]; then \
      git config --global url."https://x-access-token:$(cat /run/secrets/ghtoken)@github.com/".insteadOf "https://github.com/"; \
    fi && \
    go env -w GOPRIVATE=github.com/zeroroot-ai && \
    go mod download

# The binary now lives in the gibson module and imports internal/infra, so the
# full source tree is required (not just cmd/).
COPY . .
RUN CGO_ENABLED=0 GOFLAGS=-trimpath go build -ldflags='-s -w' \
    -o /out/spiffe-jwks-exporter ./cmd/spiffe-jwks-exporter

FROM ghcr.io/zeroroot-ai/mirror/distroless-static:nonroot
USER nonroot:nonroot
COPY --from=build /out/spiffe-jwks-exporter /spiffe-jwks-exporter
ENTRYPOINT ["/spiffe-jwks-exporter"]
