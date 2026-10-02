#!/usr/bin/env bash
# check-no-tenant-id-column.sh — build guard for database-per-tenant-data-plane
#
# Spec: database-per-tenant-data-plane Phase I Task 9.2, Requirement 16.1.
#
# Searches the PER-TENANT Postgres migrations for the literal token
# "tenant_id" (case-insensitive, whole-word) that appears as an actual column
# reference — not inside a comment and not in a string that describes the
# _absence_ of a tenant_id column (e.g. "-- No tenant_id").
#
# The database-per-tenant model removes the need for tenant_id columns in
# every per-tenant table: the database connection itself carries the tenant
# identity. Any new migration file that introduces a tenant_id column is a
# regression.
#
# ONLY the per-tenant migrations are scanned. The platform migrations build the
# SHARED control-plane database, where tenant_id is the correct way to say which
# tenant a row is about — 19 of those 54 files use it, legitimately. Scanning
# them would make this guard either noisy or permanently red.
#
# Only FORWARD (.up.sql) migrations are scanned. A down migration restores the
# schema its own up migration changed, so the only way one can create a
# tenant_id column is by faithfully restoring a legacy table — which is its job.
# 005_drop_api_keys.down.sql recreates the pre-deletion `api_keys` table, which
# had tenant_id; rewriting it would produce a rollback the old code could not
# use. The invariant is about what the schema IS, not what it was, so the
# exclusion is by KIND of migration and not by filename — nothing here needs
# re-pinning when a migration is added.
#
# There are no Neo4j migration files to scan, and there never will be. The
# per-tenant graph schema is derived from the Taxonomy and applied by the graph
# projector (internal/server/daemon/graph_projector_schema.go, applySchema);
# see the package doc of github.com/zeroroot-ai/gibson/migrations.
#
# This guard used to scan `migrations/postgres` and `migrations/neo4j`, two
# paths that do NOT EXIST — the real migrations are under
# pkg/platform/migrations/postgres/. It reported "Scanned 0 file(s)" and exited
# 0, on every PR, for as long as it has been wired into gibsoncheck.yml. Its
# self-test passed throughout, because the self-test writes its fixture INTO
# the directory it then scans, creating the directory on the way. So the
# self-test proved the regex worked while the real run looked at nothing.
#
# That is why MIN_FILES exists below: a guard that cannot say how much it
# examined cannot be trusted when it says nothing is wrong.
#
# Exit codes:
#   0  No violations found, and the scan covered at least MIN_FILES files.
#   1  One or more violations found, or the scan covered too few files.
#
# Self-test mode (SELFTEST=1):
#   Writes a synthetic violating fixture, asserts the scanner catches it,
#   then deletes the fixture.  Exits 0 on a successful self-test, 1 if the
#   scanner fails to catch the violation.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# MIGRATIONS_TENANT_OVERRIDE exists so the self-test can point the scanner at a
# path that does not exist and assert it fails. Nothing else sets it.
MIGRATIONS_TENANT="${MIGRATIONS_TENANT_OVERRIDE:-${REPO_ROOT}/pkg/platform/migrations/postgres/tenant}"
SELFTEST_FIXTURE="${MIGRATIONS_TENANT}/_check_selftest_fixture.up.sql"

# MIN_FILES is the floor this guard asserts it examined. The per-tenant
# migration set only grows, so a run that sees fewer files than this is a
# broken path, not a shrinking codebase. 10 is below the current count of
# forward migrations with room for a deletion; raise it as the set grows.
MIN_FILES="${MIN_FILES:-10}"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

log_info()  { echo "[check-no-tenant-id-column] INFO:  $*"; }
log_error() { echo "[check-no-tenant-id-column] ERROR: $*" >&2; }

cleanup_fixture() {
    rm -f "${SELFTEST_FIXTURE}"
}

# ---------------------------------------------------------------------------
# Self-test mode
# ---------------------------------------------------------------------------

if [[ "${SELFTEST:-0}" == "1" ]]; then
    log_info "Self-test mode: writing synthetic violating fixture..."
    trap cleanup_fixture EXIT

    # Deliberately NO mkdir. The old self-test created the directory it was
    # about to scan, which is precisely what hid the broken path: with
    # migrations/postgres absent, `mkdir -p` conjured it, the fixture landed in
    # it, the scanner found the fixture and the self-test declared success —
    # while the real scan that followed saw zero files and passed. If the
    # directory is missing, the self-test must fail here.
    if [[ ! -d "$(dirname "${SELFTEST_FIXTURE}")" ]]; then
        log_error "SELFTEST FAILED: ${MIGRATIONS_TENANT} does not exist."
        log_error "The scanner would examine nothing. Fix MIGRATIONS_TENANT."
        exit 1
    fi
    cat > "${SELFTEST_FIXTURE}" <<'SQL'
-- Synthetic fixture for self-test. Do not commit.
CREATE TABLE example (
    id          UUID PRIMARY KEY,
    tenant_id   UUID NOT NULL
);
SQL

    log_info "Running scanner against fixture..."
    # Unset SELFTEST so the child invocation runs the real scan, not self-test.
    # The scanner must exit non-zero when it finds the fixture.
    if SELFTEST=0 bash "${BASH_SOURCE[0]}" 2>/dev/null; then
        log_error "SELFTEST FAILED: scanner did not detect violation in fixture."
        exit 1
    fi
    log_info "SELFTEST PASSED: scanner correctly detected the violation."

    cleanup_fixture

    # The floor has to be able to fail too. This guard spent its whole life
    # scanning a path that did not exist and reporting a pass, so proving the
    # regex works is only half a self-test: prove the guard refuses to pass
    # when it examined too little.
    log_info "Asserting the coverage floor fails a scan that sees too few files..."
    if SELFTEST=0 MIN_FILES=100000 bash "${BASH_SOURCE[0]}" >/dev/null 2>&1; then
        log_error "SELFTEST FAILED: the guard passed with MIN_FILES far above the"
        log_error "real file count. The coverage floor does not work, so a broken"
        log_error "path would report a pass again."
        exit 1
    fi
    log_info "SELFTEST PASSED: the coverage floor refuses an under-covered scan."

    # And a missing directory must fail rather than find nothing.
    log_info "Asserting a missing migration directory fails..."
    if SELFTEST=0 MIGRATIONS_TENANT_OVERRIDE="${REPO_ROOT}/does-not-exist" \
        bash "${BASH_SOURCE[0]}" >/dev/null 2>&1; then
        log_error "SELFTEST FAILED: the guard passed with a nonexistent migration"
        log_error "directory. That is the original defect."
        exit 1
    fi
    log_info "SELFTEST PASSED: a missing migration directory fails the guard."
    exit 0
fi

# ---------------------------------------------------------------------------
# Main scan
# ---------------------------------------------------------------------------

VIOLATIONS=0
SCANNED=0

scan_files() {
    local pattern="$1"
    local comment_prefix="$2"   # regex pattern for single-line comment leaders
    shift 2
    local -a paths=("$@")

    for file_path in "${paths[@]}"; do
        [[ -f "${file_path}" ]] || continue

        SCANNED=$((SCANNED + 1))

        # Find whole-word "tenant_id" (case-insensitive), then filter out:
        #   1. Pure comment lines (first non-whitespace chars are -- or //).
        #   2. Lines that contain a "no tenant_id" explanatory phrase — these
        #      are self-documenting comments inside SQL COMMENT ON TABLE strings
        #      that describe the _absence_ of a tenant_id column, which is the
        #      desired state. Examples:
        #        COMMENT ON TABLE foo IS '... No tenant_id — isolation is by database.'
        #        -- No tenant_id column — the tenant is implied ...
        #
        # We use POSIX grep so the script works on ubuntu-latest CI runners
        # without an extra ripgrep install step; the GNU grep flags used here
        # (-i, -n, -w, -E) are present on every GitHub-hosted runner.
        local hits
        hits=$(grep --line-number --word-regexp --ignore-case \
               'tenant_id' "${file_path}" 2>/dev/null \
               | grep -Ev "^[0-9]+:[[:space:]]*${comment_prefix}" \
               | grep -Eiv "no[[:space:]]+tenant_id|tenant_id[[:space:]]+—|tenant_id.*absent|no.*tenant_id" \
               || true)

        if [[ -n "${hits}" ]]; then
            log_error "tenant_id reference found in ${file_path}:"
            echo "${hits}" | while IFS= read -r line; do
                echo "  ${line}"
            done
            VIOLATIONS=$((VIOLATIONS + 1))
        fi
    done
}

# The directory has to exist. Without this, a moved or renamed path makes the
# guard pass by finding nothing — which is how it spent its whole life.
if [[ ! -d "${MIGRATIONS_TENANT}" ]]; then
    log_error "per-tenant migration directory not found: ${MIGRATIONS_TENANT}"
    log_error "this guard scans nothing, so it cannot pass. Fix the path."
    exit 1
fi

# Scan the per-tenant Postgres SQL migrations — comments start with --
SQL_FILES=()
while IFS= read -r -d '' f; do
    SQL_FILES+=("${f}")
done < <(find "${MIGRATIONS_TENANT}" -name '*.up.sql' -print0 | sort -z)

if [[ ${#SQL_FILES[@]} -gt 0 ]]; then
    scan_files 'tenant_id' '--' "${SQL_FILES[@]}"
fi

# ---------------------------------------------------------------------------
# Report
# ---------------------------------------------------------------------------

log_info "Scanned ${SCANNED} forward migration(s) under ${MIGRATIONS_TENANT#"${REPO_ROOT}/"}/."

# The floor. A guard that examined nothing must not report that nothing is
# wrong, which is exactly what this one did while it pointed at a path that
# did not exist.
if [[ "${SCANNED}" -lt "${MIN_FILES}" ]]; then
    log_error "scanned only ${SCANNED} file(s), expected at least ${MIN_FILES}."
    log_error "The per-tenant migration set does not shrink, so this is a broken"
    log_error "path or a bad glob, not a smaller codebase. A pass here would mean"
    log_error "nothing. Fix MIGRATIONS_TENANT, or lower MIN_FILES deliberately."
    exit 1
fi

if [[ "${VIOLATIONS}" -gt 0 ]]; then
    log_error "${VIOLATIONS} file(s) contain tenant_id references."
    log_error "The database-per-tenant model eliminates the need for tenant_id"
    log_error "columns/properties — the database connection carries the tenant"
    log_error "identity by construction. Remove the tenant_id column/property"
    log_error "and re-author the migration without it."
    log_error "(Spec: database-per-tenant-data-plane Requirement 16.1)"
    exit 1
fi

log_info "No tenant_id violations found. Guard passed."
exit 0
