#!/usr/bin/env bash
# check-no-gibson-io.sh — CI guard: no gibson.io references in source files.
#
# Spec: naming-and-config-standardization Requirement 1.6, 5.1.
#
# Searches *.go, *.yaml, *.yml, *.tpl, *.txt, *.ts, *.tsx, *.mjs files
# across the workspace for the pattern "gibson.io" and exits non-zero if any
# match falls outside the allowlisted comment-only files.
#
# Allowlist (four files with intentional historical references):
#   enterprise/deploy/helm/gibson/templates/_spiffe-id.tpl
#   enterprise/deploy/helm/gibson/values-aws-prod.yaml
#   enterprise/platform/dashboard/scripts/check-no-direct-daemon-grpc.mjs
#   CLAUDE.md
#
# Exit codes:
#   0  No violations found.
#   1  One or more violations found.
#
# Self-test mode (--selftest):
#   Writes a synthetic violating fixture, asserts the scanner catches it,
#   then deletes the fixture. Exits 0 on a successful self-test, 1 if not.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# Workspace root is five levels up from core/gibson/scripts/
WORKSPACE_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"

GUARD_NAME="check-no-gibson-io"
SELFTEST_FIXTURE="${WORKSPACE_ROOT}/core/gibson/scripts/_check_no_gibson_io_selftest_fixture.txt"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

log_info()  { echo "[${GUARD_NAME}] INFO:  $*"; }
log_error() { echo "[${GUARD_NAME}] ERROR: $*" >&2; }

cleanup_fixture() {
    rm -f "${SELFTEST_FIXTURE}"
}

# ---------------------------------------------------------------------------
# Allowlist — exact workspace-relative paths whose gibson.io references are
# intentional historical documentation. Do not use glob patterns here.
# ---------------------------------------------------------------------------

ALLOWLIST=(
    "enterprise/deploy/helm/gibson/templates/_spiffe-id.tpl"
    "enterprise/deploy/helm/gibson/values-aws-prod.yaml"
    "enterprise/platform/dashboard/scripts/check-no-direct-daemon-grpc.mjs"
    "CLAUDE.md"
)

is_allowlisted() {
    local rel_path="$1"
    for entry in "${ALLOWLIST[@]}"; do
        if [[ "${rel_path}" == "${entry}" ]]; then
            return 0
        fi
    done
    return 1
}

# ---------------------------------------------------------------------------
# Self-test mode
# ---------------------------------------------------------------------------

if [[ "${1:-}" == "--selftest" ]]; then
    log_info "Self-test mode: writing synthetic violating fixture..."
    trap cleanup_fixture EXIT

    cat > "${SELFTEST_FIXTURE}" <<'EOF'
# Synthetic fixture for self-test. Do not commit.
label: gibson.io/role=platform
EOF

    log_info "Running scanner against fixture..."
    if SELFTEST=0 bash "${BASH_SOURCE[0]}" 2>/dev/null; then
        log_error "SELFTEST FAILED: scanner did not detect violation in fixture."
        exit 1
    else
        log_info "SELFTEST PASSED: scanner correctly detected the violation."
        exit 0
    fi
fi

# ---------------------------------------------------------------------------
# Main scan
# ---------------------------------------------------------------------------

VIOLATIONS=0
TOTAL_MATCHES=0

EXTENSIONS=("*.go" "*.yaml" "*.yml" "*.tpl" "*.txt" "*.ts" "*.tsx" "*.mjs")

# Build find include patterns
FIND_INCLUDES=()
for ext in "${EXTENSIONS[@]}"; do
    FIND_INCLUDES+=(-o -name "${ext}")
done
# Remove leading -o
FIND_INCLUDES=("${FIND_INCLUDES[@]:1}")

while IFS= read -r -d '' file; do
    # Get workspace-relative path for allowlist comparison
    rel="${file#${WORKSPACE_ROOT}/}"

    if is_allowlisted "${rel}"; then
        continue
    fi

    # Skip spec-workflow snapshots, docs history, changelogs — read-only reference material
    case "${rel}" in
        .spec-workflow/*|enterprise/docs/*|"CHANGELOG.md"|"*CHANGELOG*") continue ;;
    esac

    # Grep for the pattern (ERE, not PCRE — portable)
    hits=$(grep -En "gibson\.io" "${file}" 2>/dev/null || true)
    if [[ -n "${hits}" ]]; then
        log_error "gibson.io reference found:"
        echo "${hits}" | while IFS= read -r line; do
            echo "  ${rel}:${line}"
        done
        echo "Fix: use zero-day.ai instead (or add to allowlist if intentional)."
        VIOLATIONS=$((VIOLATIONS + 1))
        TOTAL_MATCHES=$((TOTAL_MATCHES + 1))
    fi
done < <(find "${WORKSPACE_ROOT}" \
    \( -path "*/.git" -prune \) \
    -o \( -path "*/.claude" -prune \) \
    -o \( -path "*/.worktrees" -prune \) \
    -o \( -path "*/node_modules" -prune \) \
    -o \( -path "*/vendor" -prune \) \
    -o \( -path "*/.next" -prune \) \
    -o \( "${FIND_INCLUDES[@]}" \) -print0 2>/dev/null)

if [[ "${VIOLATIONS}" -gt 0 ]]; then
    log_error "${VIOLATIONS} file(s) contain gibson.io references outside the allowlist."
    log_error "The correct namespace prefix is zero-day.ai (product: gibson, org: zero-day.ai)."
    log_error "If this reference is intentional history/documentation, add the file path"
    log_error "to the ALLOWLIST in ${BASH_SOURCE[0]}."
    exit 1
fi

log_info "No gibson.io violations found. Guard passed."
exit 0
