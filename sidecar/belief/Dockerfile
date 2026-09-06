# ============================================================================
# gibson-belief-sidecar — belief-field inference sidecar (gibson#750,
# deploy#936, ADR-0005).
# ============================================================================
# A small read-only Python service that runs exact Bayesian inference
# (variable elimination) over versioned attack-path model artifacts and
# returns the belief-field components (juicy/exploitable/reachable) for a host.
#
# The daemon's brain.PgmpyBeliefProvider POSTs host evidence to /score on
# evidence change and records the returned model version on the host so replay
# reproduces (ADR-0005). When GIBSON_BELIEF_SIDECAR_URL is unset the daemon uses
# its deterministic Go placeholder provider, so this sidecar is optional.
#
# Build it from as close to nothing as this workload allows (gibson#1436)
# ----------------------------------------------------------------------------
# Two things used to be in this image that had no business being here.
#
#   1. A Debian userland. `python:3.x-slim` ships 96 dpkg packages, including
#      perl-base, util-linux, ncurses and gzip. That userland was 24 of the 25
#      open HIGH/CRITICAL code-scanning alerts on the whole gibson repo — four
#      CRITICAL in perl-base alone — and most of them carry no fixed version,
#      so there was nothing to bump to. Nothing in this image invokes perl.
#      The runtime stage is now distroless: 37 packages, no perl, no shell, no
#      package manager, no pip.
#
#   2. pgmpy, and therefore torch. `pgmpy==0.1.26` requires torch, which drags
#      in triton, xgboost, scikit-learn, pandas, scipy, statsmodels and sympy —
#      roughly 3 GB of a deep-learning stack, to marginalise a seven-node binary
#      network. sidecar/belief/infer.py runs the same exact algorithm on numpy
#      alone; test_parity.py asserts agreement with pgmpy to 1e-12.
#
# What is left in the runtime image is CPython, numpy, three source files and
# the model artifacts. The build stage keeps pip; the runtime stage does not
# get it.
#
# Determinism / reproducibility (ADR-0005 §replay):
#   - Python deps are PINNED in requirements.txt, hash-verified on install.
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

# ----------------------------------------------------------------------------
# Stage 1 — build the dependency tree.
# ----------------------------------------------------------------------------
# Must match the CPython minor and the Debian release of the runtime stage
# below: wheels are built for a specific ABI tag (cp313) and link against the
# runtime's glibc. python:3.13-slim-trixie and distroless/python3-debian13 are
# both Debian 13 / CPython 3.13, which is what makes the copy in stage 2 valid.
FROM ghcr.io/zeroroot-ai/mirror/python:3.13-slim-trixie AS build

ENV PYTHONDONTWRITEBYTECODE=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /build

# --require-hashes makes pip refuse anything whose artifact does not match the
# hash pinned in requirements.txt, so a compromised or substituted wheel fails
# the build rather than shipping. It also forces every transitive dependency to
# be pinned, which is the property we actually want.
COPY requirements.txt ./
RUN pip install --no-cache-dir --require-hashes --target=/deps -r requirements.txt

# Drop what a runtime never reads. numpy ships its own test suite, its C
# headers and its static libs; none of it is reachable from an inference call.
RUN find /deps -type d -name tests -prune -exec rm -rf {} + \
 && find /deps -type d -name test -prune -exec rm -rf {} + \
 && find /deps -type d -name include -prune -exec rm -rf {} + \
 && find /deps -type d -name __pycache__ -prune -exec rm -rf {} + \
 && find /deps -type f \( -name '*.pyc' -o -name '*.pyi' -o -name '*.a' \) -delete

# ----------------------------------------------------------------------------
# Stage 2 — runtime.
# ----------------------------------------------------------------------------
# distroless: glibc, CPython 3.13 and its stdlib, ca-certificates, tzdata. No
# shell, no package manager, no pip, no perl. `nonroot` runs as uid 65532 and
# owns nothing writable, so there is no `useradd` step and nothing to chown.
FROM ghcr.io/zeroroot-ai/mirror/distroless-python3-debian13:nonroot

# Don't write .pyc files; flush stdout/stderr immediately so container logs are
# live (the server prints startup + listen lines to stderr).
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app:/deps

WORKDIR /app

COPY --from=build /deps /deps

# Bake the sidecar source AND the versioned model artifacts into the image
# layer. models/ ships base-v1.json; the commercial layer drops additional
# models/*.json into its own image build (ADR-0005 §7).
COPY infer.py model.py server.py ./
COPY models/ ./models/

USER 65532

# Exact-inference HTTP server port (server.py default; overridable via BELIEF_PORT).
EXPOSE 8087

# Bind 0.0.0.0 so the sidecar is reachable from the daemon container over the
# pod loopback / localhost; serve the baked artifacts from ./models.
ENV BELIEF_HOST=0.0.0.0 \
    BELIEF_PORT=8087 \
    BELIEF_MODELS_DIR=/app/models

# The distroless python image's ENTRYPOINT is already the interpreter, so CMD
# carries only the script. `python -m server` would need a shell that this image
# deliberately does not have.
CMD ["/app/server.py"]
