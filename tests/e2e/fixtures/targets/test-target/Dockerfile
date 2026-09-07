# Dockerfile — test-target HTTP fixture.
# Produces a minimal image <30 MB (scratch + static binary).
# CGO_ENABLED=0 for pure Go build.
# Requirements: R2.2 (deterministic target fixture).

# Build stage
FROM golang:1.27-alpine@sha256:cf6fca6641884b8433441b2b0652976f975e1d0fdd26d177eaaf8596087f3125 AS builder

WORKDIR /build

# No external dependencies — stdlib only.
COPY go.mod ./
COPY main.go .

RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build -trimpath -ldflags="-s -w" -o test-target .

# Final stage — distroless/static for minimal image size (<30 MB).
FROM gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab

COPY --from=builder /build/test-target /test-target

EXPOSE 8080

ENTRYPOINT ["/test-target"]
