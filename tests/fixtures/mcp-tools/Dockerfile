# The fixture MCP server of the Hosted connector exit test (gibson#811). The
# build context is the root of the gibson repo. The exit test builds this
# image in the run and loads it into kind, so it never leaves the run.
FROM ghcr.io/zeroroot-ai/mirror/golang:1.27.2-alpine@sha256:85dc1069ac644ea3c527b177303a406eb3358192816cd7f9e5848eb658851673 AS builder
ARG GOTOOLCHAIN=local
ENV GOTOOLCHAIN=${GOTOOLCHAIN}
WORKDIR /src
COPY tests/fixtures/mcp-tools/main.go ./
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/mcp-tools ./main.go

FROM ghcr.io/zeroroot-ai/mirror/distroless-static:nonroot@sha256:e2e927ec666bae08560abb3c55d0659eceabb657f56b6782ab500a9fc7f555e3
COPY --from=builder /out/mcp-tools /mcp-tools
EXPOSE 8080
ENTRYPOINT ["/mcp-tools"]
