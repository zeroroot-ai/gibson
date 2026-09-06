#!/usr/bin/env bash
# check-fga-model-headers.sh — CI guard for cross-repo-cohesion-fixes Fix 5
#
# Spec: cross-repo-cohesion-fixes Requirement 5.4.
#
# Asserts that the authoritative FGA model file carries its required marker:
#   - internal/platform/authz/model.fga must start with AUTHORITATIVE-FGA-MODEL
#
# (The historical generated registry stub at internal/platform/authz/registry/fga_model.fga
# was retired alongside SDK v0.98.x; only the authoritative model remains.)
#
# Exit codes:
#   0  Marker present.
#   1  Marker missing.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

AUTHORITATIVE_MODEL="${REPO_ROOT}/internal/platform/authz/model.fga"

if ! grep -q "AUTHORITATIVE-FGA-MODEL" "${AUTHORITATIVE_MODEL}"; then
    echo "[check-fga-model-headers] ERROR: ${AUTHORITATIVE_MODEL} is missing the AUTHORITATIVE-FGA-MODEL marker." >&2
    echo "[check-fga-model-headers] ERROR: This marker must appear in the file header to identify the authoritative" >&2
    echo "[check-fga-model-headers] ERROR: hand-maintained model fed to fga-init." >&2
    exit 1
fi

echo "[check-fga-model-headers] OK: AUTHORITATIVE-FGA-MODEL marker present."
exit 0
