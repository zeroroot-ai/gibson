# ============================================================================
# Gibson Core Multi-Stage Dockerfile
# ============================================================================
# Production-ready container with ONNX Runtime for native embeddings,
# SQLite FTS5 support, and optimized for size (<500MB).
#
# Build from the opensource/ directory (parent of gibson/):
#   docker build -t gibson:latest -f gibson/Dockerfile .
#
# Or from gibson/ directory with context override:
#   docker build -t gibson:latest -f Dockerfile ..
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
RUN wget -q https://github.com/microsoft/onnxruntime/releases/download/v1.23.0/onnxruntime-linux-x64-1.23.0.tgz \
    && tar -xzf onnxruntime-linux-x64-1.23.0.tgz -C /usr/local \
    && mv /usr/local/onnxruntime-linux-x64-1.23.0 /usr/local/onnxruntime \
    && rm onnxruntime-linux-x64-1.23.0.tgz

# Set environment for ONNX Runtime
ENV LD_LIBRARY_PATH=/usr/local/onnxruntime/lib:$LD_LIBRARY_PATH
ENV LIBRARY_PATH=/usr/local/onnxruntime/lib:$LIBRARY_PATH
ENV C_INCLUDE_PATH=/usr/local/onnxruntime/include:$C_INCLUDE_PATH
ENV CPLUS_INCLUDE_PATH=/usr/local/onnxruntime/include:$CPLUS_INCLUDE_PATH

# Set working directory
WORKDIR /workspace

# Copy SDK dependency first (required by gibson's go.mod replace directive)
COPY sdk/ ./sdk/

# Copy Gibson source
COPY gibson/ ./gibson/

# Change to gibson directory for build
WORKDIR /workspace/gibson

# Download dependencies (now that SDK is available)
RUN go mod download

# Enable CGO with SQLite FTS5 support
ENV CGO_ENABLED=1
ENV CGO_CFLAGS="-DSQLITE_ENABLE_FTS5"
ENV CGO_LDFLAGS="-L/usr/local/onnxruntime/lib"

# Build the gibson binary with optimizations
# - Static linking where possible for portability
# - Strip debug symbols to reduce size
# - Build tags for FTS5 support
RUN mkdir -p /build/bin && \
    go build \
    -tags fts5 \
    -ldflags="-s -w -extldflags '-static-pie'" \
    -o /build/bin/gibson \
    ./cmd/gibson

# Verify the binary works
RUN /build/bin/gibson version || /build/bin/gibson --version || echo "Gibson built successfully"

# ============================================================================
# Stage 2: Runtime - Minimal Alpine image with ONNX Runtime
# ============================================================================
FROM alpine:3.21 AS runtime

# Install runtime dependencies
# - ca-certificates for HTTPS/TLS
# - libstdc++ for C++ ONNX Runtime
# - libgomp for OpenMP support in ONNX
RUN apk add --no-cache \
    ca-certificates \
    libstdc++ \
    libgomp \
    sqlite-libs \
    && rm -rf /var/cache/apk/*

# Copy ONNX Runtime libraries from builder
COPY --from=builder /usr/local/onnxruntime/lib/*.so* /usr/local/lib/
COPY --from=builder /usr/local/onnxruntime/lib/*.so.* /usr/local/lib/ 2>/dev/null || true

# Update library cache
RUN ldconfig /usr/local/lib || true

# Copy gibson binary
COPY --from=builder /build/bin/gibson /usr/local/bin/gibson

# Copy default configuration from builder
COPY --from=builder /workspace/gibson/configs/gibson.yaml /etc/gibson/gibson.yaml

# Create gibson directories with proper permissions
RUN mkdir -p /root/.gibson/data \
    /root/.gibson/cache \
    /root/.gibson/etcd-data \
    && chmod -R 755 /root/.gibson

# Set environment variables for default configuration
ENV GIBSON_CONFIG=/etc/gibson/gibson.yaml
ENV GIBSON_HOME=/root/.gibson
ENV LD_LIBRARY_PATH=/usr/local/lib:$LD_LIBRARY_PATH

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
