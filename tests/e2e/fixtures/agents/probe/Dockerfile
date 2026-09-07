# Dockerfile — probe test agent.
# Produces a minimal image <30 MB (scratch + static binary).
# CGO_ENABLED=0 for pure Go build.
# Requirements: R2.1 (image <30 MB).

# Build stage
FROM golang:1.25-alpine@sha256:1ae0735f00daffa3aaf1363a5184c0d2dc55c78e3db4ec70241cdac97bf84b59 AS builder

WORKDIR /build

# Copy go.mod first for layer caching
COPY go.mod go.sum* ./
RUN go mod download

# Copy source
COPY . .

# Build static binary
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build -trimpath -ldflags="-s -w" -o probe .

# Final stage — distroless/scratch for minimal image size
FROM gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab

COPY --from=builder /build/probe /probe
COPY component.yaml /component.yaml

# Health: the probe exits after processing work, so no liveness probe needed.
# The deployment manifest uses a restart policy to keep it available.

ENTRYPOINT ["/probe"]
