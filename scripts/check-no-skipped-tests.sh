#!/usr/bin/env bash
# check-no-skipped-tests.sh — CI guard: no unconditionally skipped tests.
#
# Spec: naming-and-config-standardization Requirement 3.5.
# History: gibson#1294 — this guard scanned `core/` and `opensource/`, two
# pre-polyrepo-split directories that do not exist in this module. The `find`
# error was swallowed, the loop ran zero times, and the guard reported PASSED
# on every run since the monorepo layout changed. Same class as gibson#1280.
#
# ---------------------------------------------------------------------------
# The rule
# ---------------------------------------------------------------------------
#
# A `t.Skip(` / `t.Skipf(` call is a VIOLATION when it is unconditional — when
# the innermost block enclosing it is not a conditional. Such a call fires on
# every run in every lane, so the test body never executes anywhere. That is a
# deleted test wearing a passing test's name.
#
#   func TestThing(t *testing.T) {
#       t.Skip("requires Redis")   // VIOLATION — runs nowhere, ever
#       ...
#   }
#
# A skip guarded by a condition is ALLOWED. It selects a lane rather than
# disabling the test: some lane still runs the body, and the guard cannot tell
# a `testing.Short()` gate from an OS gate from an infrastructure probe without
# encoding a policy this script has no business holding.
#
#   if testing.Short()          { t.Skip(...) }   // allowed — full lane runs it
#   if runtime.GOOS != "linux"  { t.Skip(...) }   // allowed — Linux lane runs it
#   if os.Getenv("X") == ""     { t.Skip(...) }   // allowed — gated lane runs it
#   if err != nil               { t.Skip(...) }   // allowed — infra-probe branch
#
# "Conditional" means the innermost enclosing brace block was opened by an
# `if`, `else`, `switch` or `select`. A `case`/`default` body counts, because
# its innermost enclosing brace is the `switch`. A `for` body and a `func`
# literal body do NOT count: an unconditional skip inside a loop or inside a
# `t.Run` closure still disables that subtest unconditionally.
#
# There is deliberately NO path allowlist. The previous version carried 38
# allowlisted paths, all of them written against the dead `core/` +
# `opensource/` layout. A path allowlist grows every time the guard is
# inconvenient and ends up absorbing exactly the violations it exists to
# report — the failure mode this guard was already in. The rule here is
# structural, so there is nothing to exempt: fix the code or the guard fails.
#
# Build-tag-gated files are NOT exempt either, for the same reason. A file
# behind `//go:build integration` still has an integration lane that runs it,
# so an unconditional skip inside it is disabled there too.
#
# ---------------------------------------------------------------------------
# Vacuity guard
# ---------------------------------------------------------------------------
#
# The scan refuses to report success if it visited fewer than MIN_TEST_FILES
# test files (default 100; this module has ~770). A guard that passes because
# it found nothing to look at is worse than no guard.
#
# ---------------------------------------------------------------------------
# Usage
# ---------------------------------------------------------------------------
#
#   bash scripts/check-no-skipped-tests.sh            # scan the module
#   bash scripts/check-no-skipped-tests.sh --selftest # prove the guard can fail
#
#   SCAN_ROOT=<dir>        override the scan root (used by --selftest)
#   MIN_TEST_FILES=<n>     override the vacuity floor
#
# Exit codes:
#   0  No unconditional skips found (and the scan was not vacuous).
#   1  One or more unconditional skips found, or the scan was vacuous.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
GUARD_NAME="check-no-skipped-tests"

log_info()  { echo "[${GUARD_NAME}] INFO:  $*"; }
log_error() { echo "[${GUARD_NAME}] ERROR: $*" >&2; }

# ---------------------------------------------------------------------------
# Classifier
# ---------------------------------------------------------------------------
#
# Walks a Go source file tracking brace depth and, for every open brace, what
# opened it. At each `t.Skip(` / `t.Skipf(` call it reports the state of the
# innermost enclosing block.
#
# Output, one record per skip call:  <line>\t<COND|UNCOND>\t<source line>
#
# This is a lexer, not a Go parser: it tracks raw strings, interpreted strings,
# rune literals and both comment forms so that a brace inside a literal cannot
# be counted as code. Should it ever lose sync anyway, the file will not end at
# brace depth 0, and the END rule emits a DESYNC record that fails the run —
# the classifier reports that it cannot be trusted rather than reporting clean.
# Self-test cases 5 and 6 cover both halves of that.
read -r -d '' SKIP_CLASSIFIER_AWK <<'AWK' || true
BEGIN { reset() }

FNR == 1 { reset() }

# Single left-to-right lexer. Literal state (raw string, interpreted string,
# rune, block comment) carries across lines, so neither a brace inside a
# string nor a backtick inside a string can desynchronise the brace depth.
#
# `seg` is the code seen since the last brace — also carried across newlines,
# so a multi-line `if a() ||\n b() {` still classifies its block as
# conditional. Go requires a brace after every if/else/switch/select header,
# so the keyword can never leak past its own block.
{
    line = $0
    n = length(line)
    for (i = 1; i <= n; i++) {
        c = substr(line, i, 1)

        if (in_block_comment) {
            if (substr(line, i, 2) == "*/") { in_block_comment = 0; i++ }
            continue
        }
        if (in_raw) {
            if (c == "`") { in_raw = 0 }
            continue
        }
        if (in_str) {
            if (c == "\\") { i++ } else if (c == "\"") { in_str = 0 }
            continue
        }
        if (in_rune) {
            if (c == "\\") { i++ } else if (c == "'") { in_rune = 0 }
            continue
        }

        if (substr(line, i, 2) == "//") { break }
        if (substr(line, i, 2) == "/*") { in_block_comment = 1; i++; continue }
        if (c == "`")  { in_raw = 1;  continue }
        if (c == "\"") { in_str = 1;  continue }
        if (c == "'")  { in_rune = 1; continue }

        if (substr(line, i, 7) == "t.Skip(" || substr(line, i, 8) == "t.Skipf(") {
            prev = (i > 1) ? substr(line, i - 1, 1) : " "
            if (prev !~ /[A-Za-z0-9_.]/) {
                if (depth > 0 && stack[depth] == 1) {
                    printf "%d\tCOND\t%s\n", FNR, $0
                } else {
                    printf "%d\tUNCOND\t%s\n", FNR, $0
                }
            }
        }

        if (c == "{") {
            depth++
            stack[depth] = is_conditional(seg)
            seg = ""
        } else if (c == "}") {
            if (depth > 0) { delete stack[depth]; depth-- }
            seg = ""
        } else {
            seg = seg c
        }
    }

    # Interpreted string and rune literals cannot span a newline in Go. If one
    # is still open here the source is malformed; drop the state rather than
    # swallowing the rest of the file. Raw strings and block comments do span
    # lines, so their state carries.
    in_str = 0
    in_rune = 0
}

function reset() {
    depth = 0; seg = ""
    in_raw = 0; in_str = 0; in_rune = 0; in_block_comment = 0
    delete stack
}

END {
    # A file whose braces do not balance means the lexical stripping above
    # lost track, so every verdict in it is untrustworthy. Say so instead of
    # reporting a clean file.
    if (depth != 0) { printf "%d\tDESYNC\t%d\n", FNR, depth }
}

# A brace opened by if / else / switch / select gates its body.
# for and func literals do not.
function is_conditional(text) {
    if (text ~ /(^|[^A-Za-z0-9_])(if|else|switch|select)([^A-Za-z0-9_]|$)/) {
        return 1
    }
    return 0
}
AWK

# ---------------------------------------------------------------------------
# Scan
# ---------------------------------------------------------------------------

run_scan() {
    local scan_root="$1"
    local min_files="$2"

    local files=()
    while IFS= read -r -d '' f; do
        files+=("$f")
    done < <(find "${scan_root}" \
        \( -path "*/.git" -o -path "*/vendor" -o -path "*/.worktrees" \
           -o -path "*/node_modules" -o -path "*/testdata" \) -prune \
        -o -name "*_test.go" -print0)

    local scanned=${#files[@]}
    if [[ "${scanned}" -lt "${min_files}" ]]; then
        log_error "vacuous scan: visited ${scanned} test file(s) under ${scan_root}, expected at least ${min_files}."
        log_error "The scan root is wrong or the tree is empty. Refusing to report success (gibson#1294)."
        return 1
    fi

    local violations=0
    local allowed=0
    local rel line kind src

    for f in "${files[@]}"; do
        rel="${f#"${scan_root}"/}"
        while IFS=$'\t' read -r line kind src; do
            case "${kind}" in
                COND)
                    allowed=$((allowed + 1))
                    ;;
                UNCOND)
                    violations=$((violations + 1))
                    log_error "unconditional skip: ${rel}:${line}"
                    echo "    ${src#"${src%%[![:space:]]*}"}" >&2
                    ;;
                DESYNC)
                    violations=$((violations + 1))
                    log_error "classifier desync: ${rel} ends at brace depth ${src} instead of 0."
                    log_error "  Verdicts for this file are unreliable (a brace hid in a literal the"
                    log_error "  lexical stripper does not model). Fix the stripper, not the file."
                    ;;
            esac
        done < <(awk "${SKIP_CLASSIFIER_AWK}" "${f}")
    done

    log_info "scanned ${scanned} test file(s) under ${scan_root}"
    log_info "${allowed} conditional skip call(s) allowed (lane gates: -short, GOOS, env var, infra probe)"

    if [[ "${violations}" -gt 0 ]]; then
        log_error "${violations} unconditional t.Skip/t.Skipf call(s) found."
        log_error "An unconditional skip disables the test in every lane. Either delete the test"
        log_error "(the path under test is gone) or gate the skip on the condition that makes it"
        log_error "unrunnable — testing.Short(), runtime.GOOS, an env var, or an infra probe."
        return 1
    fi

    log_info "no unconditional skips found. Guard passed."
    return 0
}

# ---------------------------------------------------------------------------
# Self-test — proves the guard can fail, and that it does not fail on clean input
# ---------------------------------------------------------------------------

selftest() {
    local tmp
    tmp="$(mktemp -d)"
    # shellcheck disable=SC2064
    trap "rm -rf '${tmp}'" EXIT

    local rc=0
    local desync_out

    # Case 1: an empty tree must trip the vacuity guard, not report success.
    mkdir -p "${tmp}/empty"
    if run_scan "${tmp}/empty" 1 >/dev/null 2>&1; then
        log_error "SELFTEST case 1 FAILED: empty tree reported success (vacuity guard is dead)."
        rc=1
    else
        log_info "SELFTEST case 1 PASSED: empty tree rejected by the vacuity guard."
    fi

    # Case 2: an unconditional skip must be rejected.
    mkdir -p "${tmp}/bad"
    cat > "${tmp}/bad/synthetic_test.go" <<'EOF'
package synthetic

import "testing"

func TestUnconditionalSkip(t *testing.T) {
	t.Skip("synthetic violation for self-test")
}
EOF
    if run_scan "${tmp}/bad" 1 >/dev/null 2>&1; then
        log_error "SELFTEST case 2 FAILED: scanner did not detect the unconditional skip."
        rc=1
    else
        log_info "SELFTEST case 2 PASSED: unconditional skip rejected."
    fi

    # Case 3: an unconditional skip inside a t.Run closure must be rejected too.
    mkdir -p "${tmp}/badclosure"
    cat > "${tmp}/badclosure/synthetic_test.go" <<'EOF'
package synthetic

import "testing"

func TestSubtestSkip(t *testing.T) {
	t.Run("sub", func(t *testing.T) {
		t.Skip("synthetic subtest violation")
	})
}
EOF
    if run_scan "${tmp}/badclosure" 1 >/dev/null 2>&1; then
        log_error "SELFTEST case 3 FAILED: scanner did not detect the skip inside a closure."
        rc=1
    else
        log_info "SELFTEST case 3 PASSED: unconditional skip inside a closure rejected."
    fi

    # Case 4: conditional skips must be accepted (no false positives on the
    # four idioms the rule allows, including a multi-statement branch body).
    mkdir -p "${tmp}/good"
    cat > "${tmp}/good/synthetic_test.go" <<'EOF'
package synthetic

import (
	"os"
	"runtime"
	"testing"
)

func TestShortGate(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping in short mode")
	}
}

func TestOSGate(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("linux only")
	}
}

func TestEnvGate(t *testing.T) {
	if os.Getenv("GIBSON_INTEGRATION_TESTS") == "" {
		t.Skipf("set GIBSON_INTEGRATION_TESTS=1 to run")
	}
}

func TestProbeGate(t *testing.T) {
	err := os.ErrNotExist
	if err != nil {
		t.Logf("infra unavailable: %v", err)
		t.Skipf("infra unavailable: %v", err)
	}
}

func TestSwitchGate(t *testing.T) {
	switch runtime.GOOS {
	case "windows":
		t.Skip("not on windows")
	default:
	}
}

func TestOneLinerGate(t *testing.T) {
	if testing.Short() { t.Skip("one-liner gate") }
}
EOF
    if run_scan "${tmp}/good" 1 >/dev/null 2>&1; then
        log_info "SELFTEST case 4 PASSED: conditional skips accepted."
    else
        log_error "SELFTEST case 4 FAILED: scanner rejected legitimate conditional skips."
        run_scan "${tmp}/good" 1 || true
        rc=1
    fi

    # Case 5: braces, quotes and // inside literals must not desynchronise the
    # lexer — the unconditional skip after them must still be caught.
    mkdir -p "${tmp}/literals"
    cat > "${tmp}/literals/synthetic_test.go" <<'EOF'
package synthetic

import "testing"

const cypher = `MATCH (n)
WHERE n.name = "x" // data, not a comment, and this brace is data too: {
RETURN n {name: n.name}`

func TestAfterLiterals(t *testing.T) {
	brace := '{'
	_ = brace
	_ = cypher
	t.Skip("must still be caught after the literal soup above")
}
EOF
    if run_scan "${tmp}/literals" 1 >/dev/null 2>&1; then
        log_error "SELFTEST case 5 FAILED: literals desynchronised the lexer and hid a violation."
        rc=1
    else
        log_info "SELFTEST case 5 PASSED: literals did not hide the violation."
    fi

    # Case 6: unbalanced braces must be reported, not silently trusted.
    mkdir -p "${tmp}/desync"
    cat > "${tmp}/desync/synthetic_test.go" <<'EOF'
package synthetic

import "testing"

func TestUnbalanced(t *testing.T) {
	if testing.Short() {
		t.Skip("gated")
	}
EOF
    desync_out="$(run_scan "${tmp}/desync" 1 2>&1 || true)"
    if grep -q "classifier desync" <<<"${desync_out}"; then
        log_info "SELFTEST case 6 PASSED: unbalanced braces reported as a desync."
    else
        log_error "SELFTEST case 6 FAILED: unbalanced braces not reported."
        rc=1
    fi

    if [[ "${rc}" -ne 0 ]]; then
        log_error "SELFTEST FAILED."
        return 1
    fi
    log_info "SELFTEST PASSED (6/6 cases)."
    return 0
}

# ---------------------------------------------------------------------------
# Entrypoint
# ---------------------------------------------------------------------------

if [[ "${1:-}" == "--selftest" ]]; then
    selftest
    exit $?
fi

SCAN_ROOT="${SCAN_ROOT:-${REPO_ROOT}}"
MIN_TEST_FILES="${MIN_TEST_FILES:-100}"

run_scan "${SCAN_ROOT}" "${MIN_TEST_FILES}"
