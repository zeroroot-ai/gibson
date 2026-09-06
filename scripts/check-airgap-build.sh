#!/usr/bin/env bash
# check-airgap-build.sh — CI gate (gibson#818, E14 / ADR-0050): a clean-room
# clone of the OSS stack (sdk, adk, setec, gibson-executor — the Apache
# layer) builds air-gapped with zero undeclared external fetch. This is the
# self-hostable/defense promise: mirror the public modules once, build
# forever offline.
#
# Three phases per repo:
#   0. Clean-room clone: anonymous shallow https clone of the PUBLIC repo —
#      no credentials, no GOPRIVATE carve-out. Proves the repo (and every
#      Go dependency, phase 1) is reachable without any zeroroot-ai secret.
#   1. Mirror warm-up (network ALLOWED): `go mod download` into a dedicated
#      empty GOMODCACHE resolved via the public proxy + sumdb only. Fails if
#      any dependency (build or test) is private or undeclared.
#   2. Air-gapped build (network DENIED): GOPROXY=off GOSUMDB=off, and — when
#      the host supports unprivileged user namespaces — the commands run
#      under `unshare -r -n` (true no-network namespace). Builds all
#      packages and compiles+links every test binary (`go test -run '^$'`),
#      proving nothing reaches out at build time.
#
# Runtime phone-home / license-server checks are out of scope here: the OSS
# stack has no license client by construction (ADR-0050/0054 — enforced
# structurally by scripts/check-oss-boundary.sh, gibson#817); this gate pins
# the build-time half of the air-gap promise.
#
# Usage: scripts/check-airgap-build.sh [workdir]
#   workdir  scratch dir for clones + GOMODCACHE (default: mktemp -d).
#            Re-running with the same workdir reuses existing clones.
#
# Exit codes: 0 = all repos build air-gapped, 1 = gate failure, 2 = setup failure.

set -euo pipefail

OSS_REPOS=(sdk adk setec gibson-executor)
declare -A MODULE_DIR=([sdk]="." [adk]="gibson" [setec]="." [gibson-executor]=".")

workdir="${1:-$(mktemp -d)}"
mkdir -p "${workdir}"
export GOMODCACHE="${workdir}/gomodcache"
export GOPATH="${workdir}/gopath"
# Resolve everything the way an external customer does: public proxy + sumdb.
export GOPRIVATE="" GONOPROXY="" GONOSUMDB="" GOFLAGS=""
export GIT_TERMINAL_PROMPT=0
# Air-gapped builders use their own installed toolchain — never let go
# auto-download one mid-gate (a toolchain fetch inside phase 2 would be an
# external fetch and, with GOSUMDB=off, unverifiable anyway). The installed
# go must satisfy every OSS repo's `go` directive; the CI workflow installs
# the latest stable for exactly that reason.
export GOTOOLCHAIN=local

note() { printf '%s\n' "$*"; }

# True network isolation when available (Linux w/ unprivileged user
# namespaces — GitHub ubuntu runners qualify). Fallback: GOPROXY=off alone,
# which still fails closed for every Go-mediated fetch. Inside the netns the
# loopback is brought up so test binaries may bind 127.0.0.1 — loopback is
# not "external"; the outside world stays unreachable.
HAVE_NETNS=0
if unshare -r -n true 2>/dev/null; then
  HAVE_NETNS=1
  note "== air-gap enforcement: unshare -r -n (no-network namespace) + GOPROXY=off"
else
  note "== air-gap enforcement: GOPROXY=off only (unshare user-ns unavailable)"
fi

# airgap_exec <dir> <cmd...> — run cmd in dir with module fetches disabled,
# inside a no-network namespace when available.
airgap_exec() {
  local dir="$1"; shift
  if [[ "${HAVE_NETNS}" -eq 1 ]]; then
    unshare -r -n bash -c \
      'ip link set lo up 2>/dev/null || true; cd "$0" && GOPROXY=off GOSUMDB=off "$@"' \
      "${dir}" "$@"
  else
    (cd "${dir}" && GOPROXY=off GOSUMDB=off "$@")
  fi
}

for repo in "${OSS_REPOS[@]}"; do
  if [[ ! -d "${workdir}/${repo}/.git" ]]; then
    note "== ${repo}: clean-room clone (public, anonymous, shallow)"
    git -c credential.helper= clone --quiet --depth 1 \
      "https://github.com/zeroroot-ai/${repo}.git" "${workdir}/${repo}" \
      || { echo "SETUP FAILURE: cannot anonymously clone public repo zeroroot-ai/${repo}" >&2; exit 2; }
  fi
  mod_dir="${workdir}/${repo}/${MODULE_DIR[${repo}]}"
  [[ -f "${mod_dir}/go.mod" ]] || { echo "SETUP FAILURE: no go.mod at ${mod_dir}" >&2; exit 2; }

  note "== ${repo}: phase 1 — go mod download (public proxy, dedicated module cache)"
  (cd "${mod_dir}" && GOPROXY="https://proxy.golang.org,direct" go mod download) || {
    echo "AIR-GAP GATE FAILED: ${repo} has a dependency not publicly fetchable or not declared (gibson#818)" >&2
    exit 1
  }

  note "== ${repo}: phase 2 — air-gapped go build ./..."
  airgap_exec "${mod_dir}" go build ./... || {
    echo "AIR-GAP GATE FAILED: ${repo} build needs a network fetch beyond the warmed module cache (gibson#818)" >&2
    exit 1
  }

  note "== ${repo}: phase 2 — air-gapped test compile (go test -run '^\$' ./...)"
  airgap_exec "${mod_dir}" go test -run '^$' -count=1 ./... >/dev/null || {
    echo "AIR-GAP GATE FAILED: ${repo} test build needs a network fetch beyond the warmed module cache (gibson#818)" >&2
    exit 1
  }
  note "   OK: ${repo} builds air-gapped"
done

note "check-airgap-build: OK — clean-room OSS clones build with zero external fetch"
