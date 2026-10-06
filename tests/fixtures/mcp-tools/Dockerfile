# The fixture MCP server of the Hosted connector exit test (gibson#811). The
# build context is the root of the gibson repo. The exit test builds this
# image in the run and loads it into kind, so it never leaves the run.
FROM golang:1.26.8-alpine@sha256:51a7c389a5ddaf82f527191a1e9bff9928655130a44e4975dd1d7e0acf59f1ae AS builder
WORKDIR /src
COPY tests/fixtures/mcp-tools/main.go ./
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/mcp-tools ./main.go

FROM gcr.io/distroless/static-debian13:nonroot@sha256:e2e927ec666bae08560abb3c55d0659eceabb657f56b6782ab500a9fc7f555e3
COPY --from=builder /out/mcp-tools /mcp-tools
EXPOSE 8080
ENTRYPOINT ["/mcp-tools"]
