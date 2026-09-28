#!/usr/bin/env bash
# check-signin-policy-callers.sh — build guard for ADR-0093 section 9 /
# decision 1.
#
# The sign-in policy (MFA for everyone, passkey or authenticator app only)
# and the username-uniqueness domain policy are instance-wide invariants the
# platform-operator asserts on every reconcile (EnsureLoginPolicy,
# EnsureDomainPolicy in operators/platform/internal/clients/zitadel). If any
# other code path also calls Zitadel's /admin/v1/policies/login or
# /admin/v1/policies/domain endpoints, it can create an org-level policy that
# overrides the instance default for that org (Zitadel: an org with its own
# domain policy keeps its own userLoginMustBeDomain even after the instance
# default changes — see plan section 2.5), silently reopening the very gap
# this slice closes. There must be exactly one caller.
#
# This guard fails if the literal path "policies/login" or "policies/domain"
# appears in any non-test Go source outside
# operators/platform/internal/clients/zitadel/.
#
# Exit codes:
#   0  No violations found.
#   1  One or more violations found.
#
# Self-test mode (SELFTEST=1):
#   Writes a synthetic violating fixture outside the platform-operator client,
#   asserts the scanner catches it, then deletes the fixture. Exits 0 on a
#   successful self-test, 1 if the scanner fails to catch the violation.
#   Ships proof the guard can fail (gibson rule: every guard ships with a
#   failing fixture).

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SELFTEST_FIXTURE="${REPO_ROOT}/internal/_check_signin_policy_callers_selftest_fixture.go"
ALLOWED_DIR="operators/platform/internal/clients/zitadel"

log_info()  { echo "[check-signin-policy-callers] INFO:  $*"; }
log_error() { echo "[check-signin-policy-callers] ERROR: $*" >&2; }

PATTERN='policies/login|policies/domain'

cleanup_fixture() { rm -f "${SELFTEST_FIXTURE}"; }

# ---------------------------------------------------------------------------
# Self-test mode
# ---------------------------------------------------------------------------
if [[ "${SELFTEST:-0}" == "1" ]]; then
    log_info "Self-test mode: writing synthetic violating fixture..."
    trap cleanup_fixture EXIT
    mkdir -p "$(dirname "${SELFTEST_FIXTURE}")"
    cat > "${SELFTEST_FIXTURE}" <<'GOFIXTURE'
// Synthetic fixture for self-test. Do not commit.
package internal

const selftestForbiddenCall = "/admin/v1/policies/login"
GOFIXTURE
    if SELFTEST=0 bash "${BASH_SOURCE[0]}" >/dev/null 2>&1; then
        log_error "SELFTEST FAILED: scanner did not detect the fixture caller."
        exit 1
    fi
    log_info "SELFTEST PASSED: scanner correctly detected the violation."
    exit 0
fi

# ---------------------------------------------------------------------------
# Main scan
# ---------------------------------------------------------------------------
log_info "Scanning non-test Go source for policies/login and policies/domain callers..."

HITS="$(grep --recursive --line-number --extended-regexp --binary-files=without-match \
        --include='*.go' \
        --exclude='*_test.go' \
        --exclude-dir='.git' --exclude-dir='.worktrees' --exclude-dir='.claude' \
        --exclude-dir='node_modules' --exclude-dir='docs' \
        "${PATTERN}" "${REPO_ROOT}" 2>/dev/null \
        | grep -v "/${ALLOWED_DIR}/" \
        || true)"

if [[ -n "${HITS}" ]]; then
    log_error "A caller outside ${ALLOWED_DIR} reaches Zitadel's instance login or domain policy (ADR-0093):"
    echo "${HITS}" | while IFS= read -r line; do echo "  ${line}"; done
    log_error ""
    log_error "The platform-operator is the ONLY writer of the instance default"
    log_error "login and domain policy (EnsureLoginPolicy / EnsureDomainPolicy,"
    log_error "${ALLOWED_DIR}). A second caller can create an org-level policy"
    log_error "that overrides the instance default for that org and reopens the"
    log_error "sign-in / username-uniqueness gap this guard exists to keep closed."
    exit 1
fi

log_info "No callers found outside ${ALLOWED_DIR}. Guard passed."
exit 0
