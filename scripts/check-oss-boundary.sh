#!/usr/bin/env bash
# check-oss-boundary.sh — CI guard (gibson#817, gibson#711, ADR-0089):
# no repo links a module of a more closed license layer.
#
# The org has three layers (ADR-0089):
#
#   permissive  sdk, adk, setec               Apache-2.0
#   ELv2        gibson, gibson-executor       Elastic License 2.0
#   closed      billing, and the private repos
#
# The guard applies one rule to each layer:
#
#  1. Permissive layer (sdk, adk, setec): the pruned module graph
#     (`go list -m all` = every module needed to build the main module and its
#     tests) must not contain an ELv2 module (gibson, gibson-executor,
#     dashboard), the closed module (billing), or a private one (hosted).
#     Also each go.mod in the repo (examples, tooling) is searched for the
#     same set. This is the gibson-side sweep that complements the local
#     guard of each repo (e.g. `make check-no-gibson` of the sdk).
#
#  2. ELv2 layer, gibson-executor: the same two checks, against the closed
#     module and the private ones only. An ELv2 repo can link an ELv2 module.
#
#  3. ELv2 layer, gibson itself: go.mod must not require the closed billing
#     repo. The billing component connects at run time (ADR-0060). go.mod
#     also must not require gibson-executor: the tool images are their own
#     repo, and the daemon reaches a tool through dispatch (ADR-0056). go.mod
#     lists all direct and indirect requirements (Go 1.17+ graph pruning), so
#     a search of its require lines is exact at this layer.
#
# Usage: scripts/check-oss-boundary.sh [workdir]
#        scripts/check-oss-boundary.sh --selftest
#   workdir  scratch dir for the repo clones (default: mktemp -d).
#            If OSS_BOUNDARY_REPOS_DIR is set and contains sdk/ adk/ setec/
#            gibson-executor/ checkouts, those are used and nothing is cloned
#            (offline/local mode).
#   --selftest  run each layer rule on fixtures. Each layer has at least one
#            fixture that must fail. No network.
#
# Exit codes: 0 = boundary clean, 1 = violation found, 2 = setup failure.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# Each pattern matches a module name exactly: after the name comes a space, a
# slash or the end of the line. So `gibson` does not match `gibson-executor`.
#
# Forbidden for the permissive layer: each ELv2, closed and private module.
FORBIDDEN_PERMISSIVE_RE='github\.com/zeroroot-ai/(gibson|gibson-executor|billing|dashboard|hosted)([[:space:]/]|$)'
# Forbidden for an ELv2 repo: the closed module and the private ones.
FORBIDDEN_ELV2_RE='github\.com/zeroroot-ai/(billing|hosted)([[:space:]/]|$)'
# Forbidden for gibson itself: the closed module, and gibson-executor.
FORBIDDEN_GIBSON_RE='github\.com/zeroroot-ai/(billing|gibson-executor)([[:space:]/]|$)'

# Each checked repo with its layer, and the path of its primary Go module.
PERMISSIVE_REPOS=(sdk adk setec)
ELV2_REPOS=(gibson-executor)
ALL_REPOS=("${PERMISSIVE_REPOS[@]}" "${ELV2_REPOS[@]}")
declare -A MODULE_DIR=([sdk]="." [adk]="gibson" [setec]="." [gibson-executor]=".")
declare -A LAYER=([sdk]="permissive" [adk]="permissive" [setec]="permissive" [gibson-executor]="ELv2")

# forbidden_re <layer> prints the pattern of the layer.
forbidden_re() {
  case "$1" in
    permissive) printf '%s' "${FORBIDDEN_PERMISSIVE_RE}" ;;
    ELv2)       printf '%s' "${FORBIDDEN_ELV2_RE}" ;;
    gibson)     printf '%s' "${FORBIDDEN_GIBSON_RE}" ;;
    *) echo "SETUP FAILURE: unknown layer '$1'" >&2; exit 2 ;;
  esac
}

# layer_hits <layer> reads module lines on stdin (a module graph or a go.mod)
# and prints each line that the layer forbids. It returns 1 when no line
# matches. Each check below, and the self-test, goes through this function.
layer_hits() {
  grep -nE "$(forbidden_re "$1")"
}

selftest() {
  local failures=0 cases=0
  # expect <fail|pass> <layer> <name> <text>
  expect() {
    local want=$1 layer=$2 name=$3 text=$4 got=pass
    cases=$((cases + 1))
    if layer_hits "${layer}" <<<"${text}" >/dev/null; then got=fail; fi
    if [[ "${got}" != "${want}" ]]; then
      echo "selftest FAILED: ${layer}: ${name}: want ${want}, got ${got}" >&2
      failures=$((failures + 1))
    fi
  }
  # Fixtures that must FAIL. Each layer has at least one.
  expect fail permissive "the graph holds gibson" "github.com/zeroroot-ai/gibson v0.150.0"
  expect fail permissive "the graph holds gibson-executor" "github.com/zeroroot-ai/gibson-executor v0.9.0"
  expect fail permissive "a go.mod requires billing" $'require (\n\tgithub.com/zeroroot-ai/billing v0.1.0\n)'
  expect fail permissive "the graph holds a sub-package of dashboard" "github.com/zeroroot-ai/dashboard/x v0.1.0"
  expect fail ELv2 "the graph holds billing" "github.com/zeroroot-ai/billing v0.1.0"
  expect fail ELv2 "a go.mod requires hosted" $'\tgithub.com/zeroroot-ai/hosted v0.2.0 // indirect'
  expect fail gibson "go.mod requires billing" $'\tgithub.com/zeroroot-ai/billing v0.1.0'
  expect fail gibson "go.mod requires gibson-executor" $'\tgithub.com/zeroroot-ai/gibson-executor v0.9.0'
  # Fixtures that must PASS.
  expect pass permissive "the graph holds the sdk and setec" $'github.com/zeroroot-ai/sdk v0.193.1\ngithub.com/zeroroot-ai/setec v0.118.0'
  expect pass permissive "a name that only starts with gibson" "github.com/zeroroot-ai/gibson-other v0.1.0"
  expect pass ELv2 "the graph holds gibson and the sdk" $'github.com/zeroroot-ai/gibson v0.150.0\ngithub.com/zeroroot-ai/sdk v0.193.1'
  expect pass gibson "go.mod requires the sdk and setec" $'\tgithub.com/zeroroot-ai/sdk v0.193.1\n\tgithub.com/zeroroot-ai/setec v0.118.0'
  expect pass gibson "the module line of gibson" "module github.com/zeroroot-ai/gibson"
  if (( failures > 0 )); then exit 1; fi
  if (( cases < 13 )); then echo "selftest FAILED: ran ${cases} cases, floor 13" >&2; exit 1; fi
  echo "check-oss-boundary: selftest OK (${cases} cases, 8 must fail)"
}

if [[ "${1:-}" == "--selftest" ]]; then
  selftest
  exit 0
fi

fail=0
SKIPPED=()

note() { printf '%s\n' "$*"; }
violation() { printf 'BOUNDARY VIOLATION: %s\n' "$*" >&2; fail=1; }

# --- gibson itself: no closed billing, no gibson-executor -------------------
note "== gibson (ELv2): go.mod must not require zeroroot-ai/billing or zeroroot-ai/gibson-executor"
if layer_hits gibson <"${REPO_ROOT}/go.mod"; then
  violation "gibson go.mod requires billing or gibson-executor (ADR-0060, ADR-0056)"
else
  note "   OK: gibson go.mod requires neither"
fi

# --- The other repos: each one against the rule of its layer ---------------
if [[ -n "${OSS_BOUNDARY_REPOS_DIR:-}" ]]; then
  workdir="${OSS_BOUNDARY_REPOS_DIR}"
  note "== using existing checkouts in ${workdir} (no clone)"
else
  workdir="${1:-$(mktemp -d)}"
  mkdir -p "${workdir}"
  for repo in "${ALL_REPOS[@]}"; do
    if [[ ! -d "${workdir}/${repo}/.git" ]]; then
      note "== cloning zeroroot-ai/${repo} (public, anonymous, shallow)"
      # Anonymous on purpose: this whole gate resolves each repo the way
      # an external customer does, with no private-module carve-out. Supplying
      # a token here would defeat the check rather than fix it.
      #
      # A repo that is not publicly reachable is therefore SKIPPED, not
      # authenticated and not fatal. Its privacy is an owner decision (setec
      # went private 2026-08-25), not a boundary violation, and failing the
      # whole gate on it blocks every branch for a reason no PR caused. The
      # skip is recorded and reported so a degraded run never reads as a clean
      # one.
      if ! GIT_TERMINAL_PROMPT=0 git -c credential.helper= clone --quiet --depth 1 \
        "https://github.com/zeroroot-ai/${repo}.git" "${workdir}/${repo}" 2>/dev/null; then
        rm -rf "${workdir:?}/${repo}"
        note "   SKIPPED: zeroroot-ai/${repo} is not publicly reachable; its module graph is NOT checked"
        SKIPPED+=("${repo}")
      fi
    fi
  done
fi

for repo in "${ALL_REPOS[@]}"; do
  if [[ ! -d "${workdir}/${repo}/.git" ]]; then
    continue
  fi
  mod_dir="${workdir}/${repo}/${MODULE_DIR[${repo}]}"
  layer="${LAYER[${repo}]}"
  note "== ${repo} (${layer} layer): module graph check (${MODULE_DIR[${repo}]})"
  if [[ ! -f "${mod_dir}/go.mod" ]]; then
    echo "SETUP FAILURE: expected go.mod at ${mod_dir}" >&2; exit 2
  fi
  # Pruned module graph: everything required to build the module + its tests.
  graph="$(cd "${mod_dir}" && go list -m all)" \
    || { echo "SETUP FAILURE: go list -m all failed for ${repo}" >&2; exit 2; }
  if hits="$(layer_hits "${layer}" <<<"${graph}")"; then
    violation "${repo} (${layer} layer) module graph links a module of a more closed layer:"$'\n'"${hits}"
  else
    note "   OK: module graph clean"
  fi

  # Every other go.mod in the repo (examples, tooling): mechanical grep of
  # require lines. Skips vendored caches and scaffold testdata fixtures.
  while IFS= read -r modfile; do
    if hits="$(layer_hits "${layer}" <"${modfile}")"; then
      violation "${repo} (${layer} layer): ${modfile#"${workdir}"/} requires a module of a more closed layer:"$'\n'"${hits}"
    fi
  done < <(find "${workdir}/${repo}" -name go.mod \
             -not -path '*/testdata/*' -not -path '*/.cache/*' \
             -not -path '*/node_modules/*' -not -path '*/vendor/*')
done

if [[ ${fail} -ne 0 ]]; then
  echo "check-oss-boundary: FAILED — a repo links a module of a more closed layer (ADR-0089, gibson#817)" >&2
  exit 1
fi
if (( ${#SKIPPED[@]} > 0 )); then
  note "check-oss-boundary: PARTIAL — ${#SKIPPED[@]} repo(s) not publicly reachable and NOT checked: ${SKIPPED[*]}"
  note "   (make the repo public to restore full coverage; this is not a boundary violation)"
fi
note "check-oss-boundary: OK — no repo links a module of a more closed layer"
