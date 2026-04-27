#!/usr/bin/env bash
# check-no-tenant-id-column.sh — build guard for database-per-tenant-data-plane
#
# Spec: database-per-tenant-data-plane Phase I Task 9.2, Requirement 16.1.
#
# Searches migrations/postgres/*.sql and migrations/neo4j/*.cypher for the
# literal token "tenant_id" (case-insensitive, whole-word) that appears as an
# actual column/property reference — not inside a comment and not in a string
# that describes the _absence_ of a tenant_id column (e.g. "-- No tenant_id").
#
# The database-per-tenant model removes the need for tenant_id columns in
# every table: the database connection itself carries the tenant identity.
# Any new migration file that introduces a tenant_id column is a regression.
#
# Exit codes:
#   0  No violations found.
#   1  One or more violations found.
#
# Self-test mode (SELFTEST=1):
#   Writes a synthetic violating fixture, asserts the scanner catches it,
#   then deletes the fixture.  Exits 0 on a successful self-test, 1 if the
#   scanner fails to catch the violation.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MIGRATIONS_POSTGRES="${REPO_ROOT}/migrations/postgres"
MIGRATIONS_NEO4J="${REPO_ROOT}/migrations/neo4j"
SELFTEST_FIXTURE="${REPO_ROOT}/migrations/postgres/_check_selftest_fixture.sql"

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
    else
        log_info "SELFTEST PASSED: scanner correctly detected the violation."
        exit 0
    fi
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

        # Use ripgrep to find whole-word "tenant_id" (case-insensitive),
        # then filter out:
        #   1. Pure comment lines (first non-whitespace chars are -- or //).
        #   2. Lines that contain a "no tenant_id" explanatory phrase — these
        #      are self-documenting comments inside SQL COMMENT ON TABLE strings
        #      that describe the _absence_ of a tenant_id column, which is the
        #      desired state. Examples:
        #        COMMENT ON TABLE foo IS '... No tenant_id — isolation is by database.'
        #        -- No tenant_id column — the tenant is implied ...
        local hits
        hits=$(rg --ignore-case --word-regexp --line-number \
               'tenant_id' "${file_path}" 2>/dev/null \
               | grep -Ev "^\s*[0-9]+:?\s*${comment_prefix}" \
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

# Scan Postgres SQL migrations — comments start with --
SQL_FILES=()
if [[ -d "${MIGRATIONS_POSTGRES}" ]]; then
    while IFS= read -r -d '' f; do
        SQL_FILES+=("${f}")
    done < <(find "${MIGRATIONS_POSTGRES}" -name '*.sql' -print0 | sort -z)
fi

if [[ ${#SQL_FILES[@]} -gt 0 ]]; then
    scan_files 'tenant_id' '--' "${SQL_FILES[@]}"
fi

# Scan Neo4j Cypher migrations — comments start with // or --
CYPHER_FILES=()
if [[ -d "${MIGRATIONS_NEO4J}" ]]; then
    while IFS= read -r -d '' f; do
        CYPHER_FILES+=("${f}")
    done < <(find "${MIGRATIONS_NEO4J}" -name '*.cypher' -print0 | sort -z)
fi

if [[ ${#CYPHER_FILES[@]} -gt 0 ]]; then
    scan_files 'tenant_id' '(--|//)' "${CYPHER_FILES[@]}"
fi

# ---------------------------------------------------------------------------
# Report
# ---------------------------------------------------------------------------

log_info "Scanned ${SCANNED} file(s) across migrations/postgres/ and migrations/neo4j/."

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
