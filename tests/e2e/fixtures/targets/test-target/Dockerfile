# Dockerfile — test-target HTTP fixture.
# Produces a minimal image <30 MB (scratch + static binary).
# CGO_ENABLED=0 for pure Go build.
# Requirements: R2.2 (deterministic target fixture).

# Build stage
FROM golang:1.25-alpine@sha256:1ae0735f00daffa3aaf1363a5184c0d2dc55c78e3db4ec70241cdac97bf84b59 AS builder

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
