# The fixture MCP server of the Hosted connector exit test (gibson#811). The
# build context is the root of the gibson repo. The exit test builds this
# image in the run and loads it into kind, so it never leaves the run.
FROM ghcr.io/zeroroot-ai/mirror/golang:1.27.4-alpine@sha256:70bd7ddea8b6cbe5d6943cde279d6b67feb10cc924fb9100d1d8757c1575b280 AS builder
ARG GOTOOLCHAIN=local
ENV GOTOOLCHAIN=${GOTOOLCHAIN}
WORKDIR /src
COPY tests/fixtures/mcp-tools/main.go ./
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/mcp-tools ./main.go

FROM ghcr.io/zeroroot-ai/mirror/distroless-static:nonroot@sha256:d62067879de890a1def9da0e7766b7d20810a5e5555cef8506b752437d7a3e88
COPY --from=builder /out/mcp-tools /mcp-tools
EXPOSE 8080
ENTRYPOINT ["/mcp-tools"]
