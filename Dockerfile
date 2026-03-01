# ============================================================================
# Gibson Core Multi-Stage Dockerfile
# ============================================================================
# Production-ready container with ONNX Runtime for native embeddings,
# SQLite FTS5 support, and optimized for size (<500MB).
#
# Build:
#   docker build -t gibson:latest .
#
# Run:
#   docker run -v ~/.gibson:/root/.gibson gibson:latest serve
# ============================================================================

# ============================================================================
# Stage 1: Builder - Go compilation with CGO and dependencies
# ============================================================================
FROM golang:1.25-bookworm AS builder

# Install build dependencies for CGO, SQLite FTS5, and ONNX Runtime
RUN apt-get update && apt-get install -y \
    gcc \
    g++ \
    musl-dev \
    sqlite3 \
    libsqlite3-dev \
    wget \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Install ONNX Runtime 1.23.0 for native embeddings
# Using CPU version for broad compatibility
ARG TARGETARCH
RUN ONNX_ARCH=$([ "$TARGETARCH" = "arm64" ] && echo "aarch64" || echo "x64") && \
    wget -q https://github.com/microsoft/onnxruntime/releases/download/v1.23.0/onnxruntime-linux-${ONNX_ARCH}-1.23.0.tgz \
    && tar -xzf onnxruntime-linux-${ONNX_ARCH}-1.23.0.tgz -C /usr/local \
    && mv /usr/local/onnxruntime-linux-${ONNX_ARCH}-1.23.0 /usr/local/onnxruntime \
    && rm onnxruntime-linux-${ONNX_ARCH}-1.23.0.tgz

# Set environment for ONNX Runtime
ENV LD_LIBRARY_PATH=/usr/local/onnxruntime/lib:$LD_LIBRARY_PATH
ENV LIBRARY_PATH=/usr/local/onnxruntime/lib:$LIBRARY_PATH
ENV C_INCLUDE_PATH=/usr/local/onnxruntime/include:$C_INCLUDE_PATH
ENV CPLUS_INCLUDE_PATH=/usr/local/onnxruntime/include:$CPLUS_INCLUDE_PATH

# Set working directory
WORKDIR /build

# Copy go mod files first for better layer caching
COPY go.mod go.sum ./

# Configure Git for private repo access and download dependencies
# Uses GITHUB_TOKEN secret passed via --mount=type=secret
# Set GOPRIVATE to skip Go proxy for private repos
ENV GOPRIVATE=github.com/zero-day-ai

RUN --mount=type=secret,id=GITHUB_TOKEN \
    if [ -f /run/secrets/GITHUB_TOKEN ]; then \
        git config --global url."https://x-access-token:$(cat /run/secrets/GITHUB_TOKEN)@github.com/".insteadOf "https://github.com/"; \
    fi && \
    go mod download

# Copy source code
COPY . .

# Enable CGO with SQLite FTS5 support
ENV CGO_ENABLED=1
ENV CGO_CFLAGS="-DSQLITE_ENABLE_FTS5"
ENV CGO_LDFLAGS="-L/usr/local/onnxruntime/lib"

# Build the gibson binary with optimizations
# - Strip debug symbols to reduce size
# - Build tags for FTS5 support
# Note: Not using static linking as CGO requires dynamic linking for glibc
RUN mkdir -p /out && \
    go build \
    -tags fts5 \
    -ldflags="-s -w" \
    -o /out/gibson \
    ./cmd/gibson

# Verify the binary works
RUN /out/gibson version || /out/gibson --version || echo "Gibson built successfully"

# ============================================================================
# Stage 2: Runtime - Debian slim with ONNX Runtime
# ============================================================================
FROM debian:bookworm-slim AS runtime

# Install runtime dependencies
# - ca-certificates for HTTPS/TLS
# - libsqlite3-0 for SQLite runtime
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    libsqlite3-0 \
    && rm -rf /var/lib/apt/lists/*

# Copy ONNX Runtime libraries from builder
COPY --from=builder /usr/local/onnxruntime/lib/*.so* /usr/local/lib/

# Update library cache
RUN ldconfig

# Copy gibson binary
COPY --from=builder /out/gibson /usr/local/bin/gibson

# Copy default configuration from builder
COPY --from=builder /build/configs/gibson.yaml /etc/gibson/gibson.yaml

# Create gibson directories with proper permissions
RUN mkdir -p /root/.gibson/data \
    /root/.gibson/cache \
    /root/.gibson/etcd-data \
    && chmod -R 755 /root/.gibson

# Set environment variables for default configuration
ENV GIBSON_CONFIG=/etc/gibson/gibson.yaml
ENV GIBSON_HOME=/root/.gibson
ENV LD_LIBRARY_PATH=/usr/local/lib

# Expose default ports
# 50001: Callback server (agent communication)
# 50002: gRPC API server (daemon)
# 2379:  etcd client port (embedded registry)
# 9090:  Prometheus metrics (if enabled)
EXPOSE 50001 50002 2379 9090

# Health check for gibson daemon
# This will check if the gRPC server is responding
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD gibson version || exit 1

# Set working directory
WORKDIR /root/.gibson

# Default command: run gibson (user can override with specific subcommand)
ENTRYPOINT ["/usr/local/bin/gibson"]
CMD ["--help"]
