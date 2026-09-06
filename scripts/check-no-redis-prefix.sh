#!/usr/bin/env bash
# check-no-redis-prefix.sh — build guard for database-per-tenant-data-plane
#
# Spec: database-per-tenant-data-plane Phase I Task 9.3, Requirement 16.1.
#
# Scans Go source files that import go-redis for patterns where a string
# argument to a Redis client method uses a tenant-prefix ("tenant:" or
# "gibson:tenant:").  The gibsoncheck forbidrediskeyprefix AST analyzer
# covers direct string literals; this script adds coverage for format strings
# passed to fmt.Sprintf in files that demonstrably talk to Redis.
#
# Strategy:
#   1. Find .go files (non-test) that import go-redis (evidence they talk Redis).
#   2. Within those files, scan for "tenant:" or "gibson:tenant:" used as key
#      prefixes in Sprintf calls or direct variable assignments to keys.
#
# Allowlisted paths are excluded by glob pattern (same as the analyzer).
#
# Exit codes:
#   0  No violations found.
#   1  One or more violations found.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

log_info()  { echo "[check-no-redis-prefix] INFO:  $*"; }
log_error() { echo "[check-no-redis-prefix] ERROR: $*" >&2; }

VIOLATIONS=0

# ---------------------------------------------------------------------------
# Find non-test Go files that import the redis package (these are the only
# files that could be constructing Redis keys).
# ---------------------------------------------------------------------------

log_info "Finding Go files that import go-redis..."

# Collect redis-importing files, excluding allowlisted packages.
REDIS_FILES=()
while IFS= read -r f; do
    # Skip allowlisted packages.
    #
    # Folded-in operators (gibson#913 / E4 monorepo fold): the tenant/platform
    # operators are NOT the daemon and do NOT use the daemon's
    # database-per-tenant model. They legitimately address tenants with
    # "tenant:<slug>" keys against the shared control-plane Redis
    # (provisioning-state, FGA pub/sub object IDs, VSS index names). This
    # database-per-tenant guard is daemon-scoped; operators/ is out of scope by
    # design — hence the leading */operators/* exclusion below.
    case "${f}" in
        # Allowlisted data-plane packages (use shared/admin Redis legitimately).
        */operators/*|\
        */internal/infra/datapool/*|\
        */internal/server/admin/*|\
        */internal/server/daemon/*|\
        */internal/platform/component/*|\
        */internal/platform/audit/*|\
        */internal/migrate/*|\
        */cmd/gibson-migrate/*|\
        */tools/*)
            continue
            ;;
        # Legacy packages that owned tenant-prefix Redis keys under the old
        # model; they are marked for deletion under Phase D (database-per-tenant-
        # data-plane tasks 4.7, 4.8).  Exclude them from this guard until the
        # Phase D cleanup commits land.  Once deleted, these globs become no-ops.
        */internal/engine/state/*|\
        */internal/platform/budget/*|\
        */internal/platform/manifest/*|\
        */internal/platform/authz/*)
            continue
            ;;
    esac
    REDIS_FILES+=("${f}")
done < <(grep --recursive --files-with-matches \
             --include='*.go' \
             --exclude='*_test.go' \
             --exclude-dir='.git' \
             --exclude-dir='.claude' \
             --exclude-dir='.worktrees' \
             --exclude-dir='node_modules' \
             '"github.com/redis/go-redis' \
             "${REPO_ROOT}" 2>/dev/null || true)

if [[ ${#REDIS_FILES[@]} -eq 0 ]]; then
    log_info "No non-allowlisted files import go-redis. Guard passed trivially."
    exit 0
fi

log_info "Checking ${#REDIS_FILES[@]} redis-importing file(s) for tenant-prefix patterns..."

# ---------------------------------------------------------------------------
# Scan those files for tenant-prefix key patterns.
# ---------------------------------------------------------------------------

PATTERN='(tenant:|gibson:tenant:)'

for file in "${REDIS_FILES[@]}"; do
    hits=$(grep --line-number --extended-regexp "${PATTERN}" "${file}" 2>/dev/null || true)
    if [[ -n "${hits}" ]]; then
        log_error "Tenant-prefix Redis key pattern in ${file}:"
        echo "${hits}" | while IFS= read -r line; do
            echo "  ${line}"
        done
        VIOLATIONS=$((VIOLATIONS + 1))
    fi
done

# ---------------------------------------------------------------------------
# Report
# ---------------------------------------------------------------------------

if [[ "${VIOLATIONS}" -gt 0 ]]; then
    log_error "${VIOLATIONS} file(s) contain tenant-prefix Redis key patterns."
    log_error "In the database-per-tenant model, Conn.Redis is already scoped"
    log_error "to the tenant's logical DB — no key prefix is needed."
    log_error "Use plain keys (e.g. \"mission:\"+id) with the tenant-bound Conn.Redis."
    log_error "(Spec: database-per-tenant-data-plane Requirement 16.1)"
    exit 1
fi

log_info "Redis key-prefix guard passed."
exit 0
