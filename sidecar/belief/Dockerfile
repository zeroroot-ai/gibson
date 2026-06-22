# ============================================================================
# gibson-belief-sidecar — belief-field pgmpy inference sidecar (gibson#750,
# deploy#936, ADR-0005).
# ============================================================================
# A small read-only Python service that runs exact Bayesian inference
# (pgmpy VariableElimination) over versioned attack-path model artifacts and
# returns the belief-field components (juicy/exploitable/reachable) for a host.
#
# The daemon's brain.PgmpyBeliefProvider POSTs host evidence to /score on
# evidence change and records the returned model version on the host so replay
# reproduces (ADR-0005). When GIBSON_BELIEF_SIDECAR_URL is unset the daemon uses
# its deterministic Go placeholder provider, so this sidecar is optional.
#
# Determinism / reproducibility (ADR-0005 §replay):
#   - Python deps are PINNED in requirements.txt (pgmpy==0.1.26, ...).
#   - The model artifacts under models/ are BAKED INTO THE IMAGE LAYER here, not
#     mounted or fetched at runtime — so a given image tag always serves the
#     same versioned artifacts. This mirrors how the embedder model ships: the
#     deterministic artifact travels with the image, never installed at pod
#     start.
#
# Build context: sidecar/belief/ (self-contained; no private Go modules).
#
# Build:
#   docker buildx build -f sidecar/belief/Dockerfile \
#     -t ghcr.io/zeroroot-ai/gibson-belief-sidecar:latest sidecar/belief
# ============================================================================
FROM ghcr.io/zeroroot-ai/mirror/python:3.12-slim

# Don't write .pyc files; flush stdout/stderr immediately so container logs are
# live (the server prints startup + listen lines to stderr).
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

# Install pinned dependencies first to maximise layer-cache hits. pgmpy pulls
# in numpy/networkx/scipy/pandas; --no-cache-dir keeps the layer small.
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

# Bake the sidecar source AND the versioned model artifacts into the image
# layer. models/ ships base-v1.json; the commercial layer drops additional
# models/*.json into its own image build (ADR-0005 §7).
COPY model.py server.py ./
COPY models/ ./models/

# Run as a non-root user (the base image runs as root by default).
RUN useradd --no-create-home --uid 65532 belief
USER 65532

# Exact-inference HTTP server port (server.py default; overridable via BELIEF_PORT).
EXPOSE 8087

# Bind 0.0.0.0 so the sidecar is reachable from the daemon container over the
# pod loopback / localhost; serve the baked artifacts from ./models.
ENV BELIEF_HOST=0.0.0.0 \
    BELIEF_PORT=8087 \
    BELIEF_MODELS_DIR=/app/models

ENTRYPOINT ["python", "-m", "server"]
