#!/usr/bin/env bash
# check-fga-model-headers.sh — CI guard for cross-repo-cohesion-fixes Fix 5
#
# Spec: cross-repo-cohesion-fixes Requirement 5.4.
#
# Asserts that both FGA model files carry their required marker lines:
#   - internal/authz/model.fga              must start with AUTHORITATIVE-FGA-MODEL
#   - internal/authz/registry/fga_model.fga must start with GENERATED-FGA-COVERAGE-STUB
#
# These markers prevent a developer from confusing the two files (one is the
# authoritative hand-maintained model applied by the fga-init Job; the other
# is a generated registry coverage stub that is NOT what fga-init reads).
#
# Exit codes:
#   0  Both markers present.
#   1  One or both markers missing.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

AUTHORITATIVE_MODEL="${REPO_ROOT}/internal/authz/model.fga"
GENERATED_STUB="${REPO_ROOT}/internal/authz/registry/fga_model.fga"

FAIL=0

if ! grep -q "AUTHORITATIVE-FGA-MODEL" "${AUTHORITATIVE_MODEL}"; then
    echo "[check-fga-model-headers] ERROR: ${AUTHORITATIVE_MODEL} is missing the AUTHORITATIVE-FGA-MODEL marker." >&2
    echo "[check-fga-model-headers] ERROR: This marker must appear in the file header to distinguish the authoritative" >&2
    echo "[check-fga-model-headers] ERROR: hand-maintained model from the generated registry stub." >&2
    FAIL=1
fi

if ! grep -q "GENERATED-FGA-COVERAGE-STUB" "${GENERATED_STUB}"; then
    echo "[check-fga-model-headers] ERROR: ${GENERATED_STUB} is missing the GENERATED-FGA-COVERAGE-STUB marker." >&2
    echo "[check-fga-model-headers] ERROR: This marker is emitted by cmd/authz-registry-gen and must be present in the" >&2
    echo "[check-fga-model-headers] ERROR: file header to distinguish the generated stub from the authoritative model." >&2
    FAIL=1
fi

if [[ "${FAIL}" -ne 0 ]]; then
    echo "[check-fga-model-headers] FAIL: One or more FGA model header markers are missing." >&2
    echo "[check-fga-model-headers] Run 'make authz-registry' (after bumping the SDK to include the marker change)" >&2
    echo "[check-fga-model-headers] or restore the markers manually per spec cross-repo-cohesion-fixes Fix 5." >&2
    exit 1
fi

echo "[check-fga-model-headers] OK: Both FGA model header markers are present."
exit 0
