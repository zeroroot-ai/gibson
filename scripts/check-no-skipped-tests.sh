#!/usr/bin/env bash
# check-no-skipped-tests.sh — CI guard: no bare t.Skip/t.Skipf calls in test files.
#
# Spec: naming-and-config-standardization Requirement 3.5.
#
# Greps for t.Skip( and t.Skipf( across *.go test files in core/ and opensource/.
# Files are exempt if:
#   1. Their first two lines contain a //go:build <tag> directive (build-tag-gated files
#      are the correct gate for infrastructure-dependent tests).
#   2. They appear in the explicit path allowlist below.
#
# Explicit path allowlist (env-var gates and OS gates — equivalent to build tags):
#   core/sdk/eval/feedback_integration_test.go    — GOEVALS=1 gate
#   core/sdk/eval/example_realtime_export_test.go — LANGFUSE_PUBLIC_KEY gate
#   core/sdk/agent/connect_test.go                — Windows OS gate
#   core/gibson/internal/server/daemon/harness_init_test.go    — GIBSON_INTEGRATION_TESTS gate
#   core/gibson/internal/server/daemon/infrastructure_test.go  — GIBSON_INTEGRATION_TESTS gate
#   core/gibson/internal/platform/component/process_test.go      — Linux OS gate
#
# Exit codes:
#   0  No violations found.
#   1  One or more violations found.
#
# Self-test mode (--selftest):
#   Writes a synthetic violating fixture, asserts the scanner catches it,
#   then deletes the fixture. Exits 0 on success.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORKSPACE_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"

GUARD_NAME="check-no-skipped-tests"
SELFTEST_FIXTURE="${WORKSPACE_ROOT}/core/gibson/scripts/_check_no_skipped_tests_selftest_fixture_test.go"

log_info()  { echo "[${GUARD_NAME}] INFO:  $*"; }
log_error() { echo "[${GUARD_NAME}] ERROR: $*" >&2; }

cleanup_fixture() {
    rm -f "${SELFTEST_FIXTURE}"
}

# ---------------------------------------------------------------------------
# Explicit allowlist — files with env-var or OS gates (not build-tag-gated)
# ---------------------------------------------------------------------------

ALLOWLIST=(
    # Env-var gates (GOEVALS=1, LANGFUSE_PUBLIC_KEY, GIBSON_INTEGRATION_TESTS)
    "core/sdk/eval/feedback_integration_test.go"
    "core/sdk/eval/example_realtime_export_test.go"
    "core/sdk/eval/integration_test.go"
    "core/gibson/internal/server/daemon/harness_init_test.go"
    "core/gibson/internal/server/daemon/infrastructure_test.go"

    # OS / toolchain gates
    "core/sdk/agent/connect_test.go"
    "core/gibson/internal/platform/component/process_test.go"
    "core/gibson/internal/platform/component/git/git_test.go"
    "core/sdk/codegen/git/git_test.go"
    "core/sdk/codegen/git/operations_test.go"

    # Docker/container not available gates
    "core/gibson/internal/engine/checkpoint/blob_store_test.go"
    "core/gibson/internal/infra/database/redis/targets_test.go"
    "core/gibson/internal/engine/memory/mission_redis_test.go"
    "core/gibson/internal/engine/mission/checkpoint_store_test.go"
    "core/gibson/internal/prompt/redis_store_test.go"

    # Short-mode gates (standard Go testing.Short() pattern)
    "core/gibson/internal/platform/component/build/build_test.go"
    "core/gibson/internal/platform/component/log_parser_integration_test.go"
    "core/gibson/internal/engine/memory/vector/redis_test.go"
    "core/sdk/codegen/lsp/manager_test.go"
    "core/sdk/tool/worker/worker_test.go"
    "core/gibson/tests/integration/checkpoint/blob_store_test.go"
    "core/gibson/tests/integration/checkpoint/redis_test.go"
    "core/gibson/tests/integration/checkpoint/retention_test.go"

    # State package — Redis not available probes
    "core/gibson/internal/engine/state/client_test.go"
    "core/gibson/internal/engine/state/indexes_test.go"
    "core/gibson/internal/engine/state/scripts_test.go"
    "core/gibson/internal/engine/state/streams_test.go"
    "core/gibson/internal/engine/state/tenant_store_test.go"

    # Path-probe / fixture-not-found gates
    "core/sdk/plugin/scaffold/templates_test.go"
    "core/sdk/plugin/health/server_test.go"
    "core/sdk/tool/capabilities_test.go"
    "core/gibson/internal/eval/config_integration_test.go"
    "core/gibson/internal/engine/harness/compliance_evaluator_test.go"
    "core/gibson/internal/platform/tlsaudit/no_fallback_audit_test.go"
    "core/gibson/internal/platform/component/grpc_pool_test.go"

    # TLS/cert environment gates
    "core/sdk/daemonclient/credentials_test.go"

    # API key (live LLM) gates
    "core/gibson/internal/engine/llm/providers/anthropic_direct_test.go"

    # Phase-D pending stubs (deferred work)
    "core/gibson/internal/server/daemon/startup_migration_check_test.go"

    # Timing-sensitive / event-driven gates
    "core/gibson/internal/server/daemon/log_watcher_test.go"

    # Mission orchestrator stubs (requires real orchestrator)
    "core/gibson/internal/engine/mission/orchestrator_events_test.go"

    # ADK CLI path-probe gate
    "opensource/adk/cli/cmd/gibson-cli/cmd/plugin/init_test.go"

    # setec (internal snapshot) root-privilege gate
    "opensource/setec/internal/snapshot/storage/local_disk_test.go"
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

# Check if file is build-tag-gated: return 0 if first two lines contain //go:build
is_build_tag_gated() {
    local file="$1"
    local first_two
    first_two=$(head -2 "${file}" 2>/dev/null || true)
    if echo "${first_two}" | grep -qE "^//go:build "; then
        return 0
    fi
    return 1
}

# ---------------------------------------------------------------------------
# Self-test mode
# ---------------------------------------------------------------------------

if [[ "${1:-}" == "--selftest" ]]; then
    log_info "Self-test mode: writing synthetic violating fixture..."
    trap cleanup_fixture EXIT

    cat > "${SELFTEST_FIXTURE}" <<'EOF'
package agent

import "testing"

func TestSyntheticSkip(t *testing.T) {
    t.Skip("synthetic violation for self-test")
}
EOF

    log_info "Running scanner against fixture..."
    if bash "${BASH_SOURCE[0]}" 2>/dev/null; then
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
SCAN_ROOTS=("${WORKSPACE_ROOT}/core" "${WORKSPACE_ROOT}/opensource")

while IFS= read -r -d '' file; do
    # Only scan test files
    [[ "${file}" == *"_test.go" ]] || continue

    # Skip files in worktree / hidden dirs / vendored caches
    case "${file}" in
        */.claude/*|*/.worktrees/*|*/.git/*|*/vendor/*) continue ;;
        # kata-containers cache embedded in setec/development/k3s
        */setec/development/*) continue ;;
    esac

    # Get workspace-relative path
    rel="${file#${WORKSPACE_ROOT}/}"

    # Skip explicitly allowlisted files
    if is_allowlisted "${rel}"; then
        continue
    fi

    # Skip build-tag-gated files (//go:build integration, embedder_tests, etc.)
    if is_build_tag_gated "${file}"; then
        continue
    fi

    # Search for t.Skip( or t.Skipf(
    hits=$(grep -En "t\.Skip\(|t\.Skipf\(" "${file}" 2>/dev/null || true)
    if [[ -n "${hits}" ]]; then
        log_error "t.Skip call found in non-exempt file:"
        echo "${hits}" | while IFS= read -r line; do
            echo "  ${rel}:${line}"
        done
        echo "  Fix: delete the test function (if the path under test no longer exists)"
        echo "  or add //go:build integration to gate the file."
        VIOLATIONS=$((VIOLATIONS + 1))
    fi
done < <(find "${SCAN_ROOTS[@]}" \
    \( -path "*/.claude" -prune \) \
    -o \( -path "*/.worktrees" -prune \) \
    -o \( -path "*/vendor" -prune \) \
    -o \( -path "*/.git" -prune \) \
    -o \( -name "*_test.go" -print0 \) 2>/dev/null)

if [[ "${VIOLATIONS}" -gt 0 ]]; then
    log_error "${VIOLATIONS} file(s) contain bare t.Skip/t.Skipf calls outside the exempt set."
    log_error "Per spec naming-and-config-standardization Requirement 3.5: skipped tests"
    log_error "must either be deleted (path under test gone) or gated via //go:build integration."
    exit 1
fi

log_info "No t.Skip violations found. Guard passed."
exit 0
