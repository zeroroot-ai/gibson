#!/usr/bin/env bash
# check-ci-lane-parity.sh — CI guard: no undeclared single-lane gate.
#
# Spec: gibson#1236 (the class), gibson#1233 (the concrete case).
#
# THE PROPERTY
# ------------
# A green `pull_request` must mean the merge queue will accept the PR.
#
# When a gate runs only on `merge_group` and fails, GitHub removes the PR from
# the merge queue and the PR still reports `mergeStateStatus: CLEAN` with
# `failing checks: (none)`. The only evidence is a run on a transient
# `gh-readonly-queue/<base>/pr-<n>-<sha>` branch that is not linked from the PR.
# gibson#1233 observed four consecutive PRs cycling in and out of the queue that
# way, costing hours of diagnosis for a failure that was never displayed.
#
# So: every gate runs in both lanes, or it is declared.
#
# WHAT THIS GUARD ENFORCES
# ------------------------
#  1. Workflow level. A workflow triggered on `merge_group` but not on
#     `pull_request` is queue-only in its entirety. It must declare why.
#
#  2. Job level, in workflows triggered on BOTH events. A job-level `if:`
#     (indented exactly four spaces) that mentions `github.event_name` must
#     mention BOTH `pull_request` and `merge_group` — i.e. it admits both lanes
#     — or it must declare why not.
#
#     The dual-lane idiom is:
#
#       if: github.event_name == 'merge_group' || (github.event_name == 'pull_request' && needs.changes.outputs.go == 'true')
#
#     which runs unconditionally in the queue and, on a PR, only when the change
#     detector says the diff is relevant.
#
#  3. Reporter coverage. Every workflow that can run in the merge queue must be
#     named in the `workflows:` list of
#     .github/workflows/merge-queue-eviction-report.yml, so that when it fails
#     and evicts a PR, the reason lands on the PR instead of on a transient
#     queue branch nobody looks at. A new queue gate cannot be added without
#     also being reported on.
#
# HOW TO DECLARE AN EXCEPTION
# ---------------------------
# Put a `# lane-exception: <reason>` comment in the contiguous comment block
# immediately above the `if:` (or above the `merge_group:` trigger, for rule 1).
# The reason must say why the gate cannot run in both lanes AND — if it is
# queue-only — how its absence is made visible on the PR. See go-ci.yml.
#
# Exit codes:
#   0  No violations.
#   1  One or more undeclared single-lane gates.
#   2  Operational error (workflow directory missing).
#
# Self-test mode (--selftest):
#   Drives the scanner over a synthetic workflow tree in a temp dir (via
#   LANE_PARITY_WORKFLOW_DIR), asserting it passes a fully declared tree and
#   fails on one violation of each rule. Touches nothing in .github/.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
# Overridable so --selftest can point the scanner at a synthetic fixture tree
# instead of mutating the real workflows.
WORKFLOW_DIR="${LANE_PARITY_WORKFLOW_DIR:-${REPO_ROOT}/.github/workflows}"

GUARD_NAME="check-ci-lane-parity"
MARKER="lane-exception:"
REPORTER="${WORKFLOW_DIR}/merge-queue-eviction-report.yml"

log_info() { echo "[${GUARD_NAME}] INFO:  $*"; }
log_err() { echo "[${GUARD_NAME}] ERROR: $*" >&2; }

# has_marker_above <file> <line-number>
#
# Walks up from the line BEFORE <line-number> through the contiguous run of
# comment lines and returns 0 if any of them carries the marker. A blank line or
# any non-comment line ends the block.
has_marker_above() {
    local file="$1" lineno="$2" i line
    for ((i = lineno - 1; i >= 1; i--)); do
        line="$(sed -n "${i}p" "${file}")"
        [[ "${line}" =~ ^[[:space:]]*# ]] || return 1
        [[ "${line}" == *"${MARKER}"* ]] && return 0
    done
    return 1
}

# ---------------------------------------------------------------------------
# Self-test — drives the scanner over a synthetic workflow tree, one fixture per
# rule, asserting it passes clean and fails on each individual violation.
# ---------------------------------------------------------------------------
if [[ "${1:-}" == "--selftest" ]]; then
    TMPDIR_SELFTEST="$(mktemp -d)"
    # shellcheck disable=SC2064
    trap "rm -rf '${TMPDIR_SELFTEST}'" EXIT

    write_clean_tree() {
        cat >"${TMPDIR_SELFTEST}/merge-queue-eviction-report.yml" <<'EOF'
name: merge-queue-eviction-report
on:
  workflow_run:
    workflows:
      - dual-lane
      - queue-only
    types: [completed]
EOF
        cat >"${TMPDIR_SELFTEST}/dual-lane.yml" <<'EOF'
name: dual-lane
on:
  pull_request:
  merge_group:
jobs:
  gate:
    if: github.event_name == 'merge_group' || (github.event_name == 'pull_request' && needs.changes.outputs.go == 'true')
    runs-on: ubuntu-latest
    steps:
      - run: "true"
EOF
        cat >"${TMPDIR_SELFTEST}/queue-only.yml" <<'EOF'
name: queue-only
on:
  # lane-exception: synthetic fixture.
  merge_group:
jobs:
  gate:
    runs-on: ubuntu-latest
    steps:
      - run: "true"
EOF
    }

    run_scanner() {
        LANE_PARITY_WORKFLOW_DIR="${TMPDIR_SELFTEST}" bash "${BASH_SOURCE[0]}" >/dev/null 2>&1
    }

    expect_pass() {
        if ! run_scanner; then
            log_err "SELFTEST FAILED: $1 — scanner rejected a clean tree."
            exit 1
        fi
    }

    expect_fail() {
        if run_scanner; then
            log_err "SELFTEST FAILED: $1 — scanner accepted a violating tree."
            exit 1
        fi
    }

    log_info "Self-test: a fully declared tree must pass..."
    write_clean_tree
    expect_pass "baseline"

    log_info "Self-test: rule 2 — undeclared single-lane job must fail..."
    write_clean_tree
    cat >"${TMPDIR_SELFTEST}/dual-lane.yml" <<'EOF'
name: dual-lane
on:
  pull_request:
  merge_group:
jobs:
  gate:
    if: github.event_name == 'merge_group'
    runs-on: ubuntu-latest
    steps:
      - run: "true"
EOF
    expect_fail "rule 2"

    log_info "Self-test: rule 1 — undeclared queue-only workflow must fail..."
    write_clean_tree
    cat >"${TMPDIR_SELFTEST}/queue-only.yml" <<'EOF'
name: queue-only
on:
  merge_group:
jobs:
  gate:
    runs-on: ubuntu-latest
    steps:
      - run: "true"
EOF
    expect_fail "rule 1"

    log_info "Self-test: rule 3 — queue workflow missing from the reporter must fail..."
    write_clean_tree
    cat >"${TMPDIR_SELFTEST}/merge-queue-eviction-report.yml" <<'EOF'
name: merge-queue-eviction-report
on:
  workflow_run:
    workflows:
      - dual-lane
    types: [completed]
EOF
    expect_fail "rule 3"

    log_info "SELFTEST PASSED (rules 1, 2 and 3)."
    exit 0
fi

# ---------------------------------------------------------------------------
# Main scan
# ---------------------------------------------------------------------------
if [[ ! -d "${WORKFLOW_DIR}" ]]; then
    log_err "no workflow directory at ${WORKFLOW_DIR}"
    exit 2
fi

shopt -s nullglob
WORKFLOWS=("${WORKFLOW_DIR}"/*.yml "${WORKFLOW_DIR}"/*.yaml)
shopt -u nullglob

if [[ ${#WORKFLOWS[@]} -eq 0 ]]; then
    log_err "no workflows found under ${WORKFLOW_DIR}"
    exit 2
fi

# The reporter's `workflows:` list: the `- <name>` entries between `workflows:`
# and the following `types:` key.
reported_workflows() {
    [[ -f "${REPORTER}" ]] || return 0
    awk '
        /^ +workflows:/ { in_list = 1; next }
        in_list {
            if ($0 ~ /^ +- /) { sub(/^ +- */, ""); print; next }
            in_list = 0
        }
    ' "${REPORTER}"
}

mapfile -t REPORTED < <(reported_workflows)

is_reported() {
    local needle="$1" w
    for w in "${REPORTED[@]}"; do
        [[ "${w}" == "${needle}" ]] && return 0
    done
    return 1
}

VIOLATIONS=0
SCANNED=0

for wf in "${WORKFLOWS[@]}"; do
    rel="${wf#"${REPO_ROOT}"/}"
    if [[ "${wf}" == "${REPORTER}" ]]; then
        continue
    fi

    # Trigger keys sit at exactly two spaces of indent inside the `on:` block.
    mg_line="$(grep -nE '^  merge_group:' "${wf}" | head -1 | cut -d: -f1 || true)"
    pr_line="$(grep -nE '^  pull_request:' "${wf}" | head -1 | cut -d: -f1 || true)"

    [[ -n "${mg_line}" || -n "${pr_line}" ]] || continue

    # --- rule 3: queue-capable workflows must be reported on ----------------
    if [[ -n "${mg_line}" ]]; then
        wf_name="$(grep -m1 -E '^name:' "${wf}" | sed 's/^name:[[:space:]]*//' || true)"
        if [[ -z "${wf_name}" ]]; then
            log_err "${rel}: has a merge_group trigger but no top-level 'name:'."
            log_err "  merge-queue-eviction-report.yml keys its watch list on workflow names."
            VIOLATIONS=$((VIOLATIONS + 1))
        elif ! is_reported "${wf_name}"; then
            log_err "${rel}: runs in the merge queue but '${wf_name}' is not in the"
            log_err "  'workflows:' list of .github/workflows/merge-queue-eviction-report.yml."
            log_err "  A failure here would evict a PR with no comment explaining why."
            VIOLATIONS=$((VIOLATIONS + 1))
        fi
    fi

    # --- rule 1: whole workflow is queue-only -------------------------------
    if [[ -n "${mg_line}" && -z "${pr_line}" ]]; then
        SCANNED=$((SCANNED + 1))
        if ! has_marker_above "${wf}" "${mg_line}"; then
            log_err "${rel}:${mg_line}: workflow triggers on merge_group but not pull_request,"
            log_err "  and carries no '# ${MARKER} <reason>' comment above the trigger."
            VIOLATIONS=$((VIOLATIONS + 1))
        fi
        continue
    fi

    # --- rule 2: per-job lane gates in dual-trigger workflows ---------------
    [[ -n "${mg_line}" && -n "${pr_line}" ]] || continue
    SCANNED=$((SCANNED + 1))

    while IFS=: read -r lineno content; do
        [[ -n "${lineno}" ]] || continue
        [[ "${content}" == *"github.event_name"* ]] || continue

        if [[ "${content}" == *"pull_request"* && "${content}" == *"merge_group"* ]]; then
            continue # admits both lanes
        fi

        if has_marker_above "${wf}" "${lineno}"; then
            continue
        fi

        log_err "${rel}:${lineno}: job-level 'if:' pins this gate to one lane:"
        log_err "  ${content#"${content%%[![:space:]]*}"}"
        log_err "  Either admit both lanes, e.g."
        log_err "    if: github.event_name == 'merge_group' || (github.event_name == 'pull_request' && needs.changes.outputs.go == 'true')"
        log_err "  or add a '# ${MARKER} <reason>' comment immediately above it."
        VIOLATIONS=$((VIOLATIONS + 1))
    done < <(grep -nE '^    if:' "${wf}" || true)
done

if [[ "${SCANNED}" -eq 0 ]]; then
    log_err "scanned no merge_group-aware workflows — the parser is probably broken."
    log_err "Refusing to pass vacuously."
    exit 2
fi

if [[ "${VIOLATIONS}" -gt 0 ]]; then
    log_err "${VIOLATIONS} undeclared single-lane gate(s)."
    log_err "A gate that runs only in the merge queue evicts PRs while they still"
    log_err "report CLEAN with no failing check (gibson#1233). Run it in both lanes,"
    log_err "or declare the exception and say how its absence is made visible."
    exit 1
fi

log_info "Lane parity holds across ${SCANNED} merge_group-aware workflow(s)."
exit 0
