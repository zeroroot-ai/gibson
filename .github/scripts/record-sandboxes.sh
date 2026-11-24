#!/usr/bin/env bash
# Record the sandboxes of setec while an exit test runs. The fix loop test and
# the bank test share this one script.
#
# The log of a member is public: the run log and the artifact are public. The
# stdout of a member is the whole stream-json transcript of Claude Code. It
# holds every Bash command and its output, so it can hold a forge token or a
# bearer. The record therefore keeps only the lines that the member writes as
# its own diagnostics. With --prefix a line starts with `[pod/<name>/<container>] `.
# The member writes its own lines as `[zerocool-claude-member] <text>`
# (zerocool-plugins, packages/claude-member/src/member-main.ts). The filter keeps
# those lines and drops every other line, JSON lines included.
#
# Usage:
#   record-sandboxes.sh watch <file>      record every INTERVAL seconds until killed
#   record-sandboxes.sh cycle <file>      record one time
#   record-sandboxes.sh filter            stdin to stdout: keep the member lines, hide keys
#   record-sandboxes.sh redact            stdin to stdout: hide keys only
#   record-sandboxes.sh append <file>     stdin to the file, up to MAX_BYTES
#   record-sandboxes.sh --selftest
#
# Bounds: each cycle reads at most LOG_TAIL lines of each pod, from the start of
# the last cycle. The file stops growing at MAX_BYTES and ends with one line that
# says so.
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INTERVAL="${INTERVAL:-20}"
LOG_TAIL="${LOG_TAIL:-200}"
MAX_BYTES="${MAX_BYTES:-52428800}"
MEMBER_TAG='[zerocool-claude-member]'

# Hide a key that reaches a line that the filter keeps. This is a second layer.
# The first layer is that the filter keeps only the member own lines.
redact() {
  sed -E \
    -e 's/sk-ant-[A-Za-z0-9_-]+/sk-ant-HIDDEN/g' \
    -e 's/(gh[pousr]_|github_pat_|glpat-)[A-Za-z0-9_-]+/\1HIDDEN/g' \
    -e 's/([Bb]earer )[A-Za-z0-9._~+\/=-]+/\1HIDDEN/g' \
    -e 's/eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*/JWT-HIDDEN/g'
}

filter() {
  # Keep a line only when the text after the pod prefix starts with the tag.
  grep -F -- "${MEMBER_TAG}" | sed -nE 's/^(\[pod\/[^]\/]+\/[^]]+\] )(\[zerocool-claude-member\] .*)$/\1\2/p' | redact
}

# Append stdin to the file. At MAX_BYTES write one final line and stop.
append() {
  local file=$1 size
  while IFS= read -r line || [ -n "${line}" ]; do
    [ -e "${file}.full" ] && continue
    size=$(stat -c %s "${file}" 2>/dev/null || echo 0)
    if [ "${size}" -ge "${MAX_BYTES}" ]; then
      printf '=== the record stopped: the file reached %s bytes\n' "${MAX_BYTES}" >> "${file}"
      : > "${file}.full"
      continue
    fi
    printf '%s\n' "${line}" >> "${file}"
  done
}

cycle() {
  local file=$1 since=${2:-} ns pod now
  now=$(date -u +%FT%TZ)
  local since_arg=()
  [ -n "${since}" ] && since_arg=(--since-time="${since}")
  {
    echo "=== ${now}"
    kubectl get sandboxes.setec.zeroroot.ai -A -o wide
    kubectl -n setec-system get pods -o wide
    kubectl -n setec-system get events --sort-by=.lastTimestamp | tail -n 15
    for ns in $(kubectl get ns -l setec.zeroroot.ai/sandbox-namespace -o name | cut -d/ -f2); do
      echo "--- namespace ${ns}"
      kubectl -n "${ns}" get pods -o wide
      kubectl -n "${ns}" get events --sort-by=.lastTimestamp | tail -n 30
      for pod in $(kubectl -n "${ns}" get pods -o name); do
        # The status only, never the spec: the spec holds the key of the member.
        kubectl -n "${ns}" get "${pod}" -o jsonpath='{.metadata.name}{" phase="}{.status.phase}{" "}{range .status.conditions[*]}{.type}={.status}/{.reason} {end}{range .status.containerStatuses[*]}{.name}={.ready}/{.state} {end}{"\n"}'
        kubectl -n "${ns}" logs "${pod}" --all-containers --prefix --tail="${LOG_TAIL}" "${since_arg[@]}" 2>&1 | filter
      done
    done
    # The pods of setec-system are not members. Their logs hold no transcript.
    for pod in $(kubectl -n setec-system get pods -o name); do
      kubectl -n setec-system logs "${pod}" --all-containers --prefix --tail=40 "${since_arg[@]}" 2>&1 | redact
    done
  } 2>&1 | append "${file}"
  CYCLE_START=${now}
}

watch_loop() {
  local file=$1
  CYCLE_START=""
  while true; do
    cycle "${file}" "${CYCLE_START}"
    sleep "${INTERVAL}"
  done
}

selftest() {
  local fixture="${SCRIPT_DIR}/testdata/sandbox-transcript.txt" out tmp fail=0
  out=$(filter < "${fixture}")
  if printf '%s\n' "${out}" | grep -q 'fixture-forge-token'; then
    echo "selftest FAIL: a transcript line with a token passed the filter" >&2; fail=1
  fi
  if printf '%s\n' "${out}" | grep -q '^{\|"type"'; then
    echo "selftest FAIL: a JSON line passed the filter" >&2; fail=1
  fi
  if ! printf '%s\n' "${out}" | grep -q 'heartbeat: \[unavailable\] getaddrinfo ENOTFOUND'; then
    echo "selftest FAIL: the ENOTFOUND heartbeat line did not pass the filter" >&2; fail=1
  fi
  if printf '%s\n' "${out}" | grep -q 'sk-ant-FIXTUREKEY'; then
    echo "selftest FAIL: a key in a kept line was not hidden" >&2; fail=1
  fi
  if [ "$(printf '%s\n' "${out}" | wc -l)" -ne 2 ]; then
    echo "selftest FAIL: the filter must keep exactly 2 lines of the fixture" >&2; fail=1
  fi
  # The size limit: the file stops at MAX_BYTES and says so one time.
  tmp=$(mktemp -d)
  seq 1 100 | MAX_BYTES=100 append "${tmp}/rec.log"
  seq 1 100 | MAX_BYTES=100 append "${tmp}/rec.log"
  if [ "$(grep -c 'the record stopped' "${tmp}/rec.log")" -ne 1 ] \
     || [ "$(stat -c %s "${tmp}/rec.log")" -gt 200 ]; then
    echo "selftest FAIL: the size limit did not stop the file with one final line" >&2; fail=1
  fi
  rm -rf "${tmp}"
  [ "${fail}" -eq 0 ] && echo "selftest PASS"
  return "${fail}"
}

case "${1:-}" in
  --selftest) selftest ;;
  filter) filter ;;
  redact) redact ;;
  append) append "${2:?file}" ;;
  cycle) cycle "${2:?file}" ;;
  watch) watch_loop "${2:?file}" ;;
  *) echo "usage: $0 watch|cycle|filter|redact|append <file>|--selftest" >&2; exit 2 ;;
esac
