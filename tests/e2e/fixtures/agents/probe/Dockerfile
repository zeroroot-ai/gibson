# Dockerfile — probe test agent.
# Produces a minimal image <30 MB (scratch + static binary).
# CGO_ENABLED=0 for pure Go build.
# Requirements: R2.1 (image <30 MB).

# Build stage
FROM golang:1.25-alpine AS builder

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
FROM gcr.io/distroless/static-debian12:nonroot

COPY --from=builder /build/probe /probe
COPY component.yaml /component.yaml

# Health: the probe exits after processing work, so no liveness probe needed.
# The deployment manifest uses a restart policy to keep it available.

ENTRYPOINT ["/probe"]
