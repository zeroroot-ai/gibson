#!/usr/bin/env bash
# check-proxy-drops.sh — the network dropped the packets that a sandbox sent
# to the proxy of a connector (gibson#723, D76).
#
# The input is the output of `cilium-dbg monitor --type drop` from each Cilium
# agent. The check passes when each file shows that the monitor ran, and one
# file holds a drop by a policy of a TCP SYN to <ip>:<port>.
#
# Usage: bash tests/fixtures/mcp-tools/check-proxy-drops.sh <ip> <port> <monitor log>...
#        bash tests/fixtures/mcp-tools/check-proxy-drops.sh --selftest
# Exit codes: 0 a drop is found, 1 no drop or a monitor did not run, 2 usage.
set -euo pipefail

check() {
  local ip=$1 port=$2
  shift 2
  local log found=0
  for log in "$@"; do
    if ! grep -q 'Listening for events' "$log"; then
      echo "::error::the Cilium monitor of ${log} did not start, so the check looked at nothing"
      return 1
    fi
    # A line looks like:
    # xx drop (Policy denied) flow 0x0 to endpoint 812, ifindex 9, file bpf_lxc.c:2069, , identity 4932->21071: 10.244.0.84:51618 -> 10.244.0.30:8080 tcp SYN
    if grep -F 'Policy denied' "$log" | grep -F -- "-> ${ip}:${port} tcp SYN" >/dev/null; then
      found=1
    fi
  done
  if [ "$found" -ne 1 ]; then
    echo "::error::no policy dropped a TCP SYN to the connector proxy ${ip}:${port}. A sandbox reached the proxy, or the scan did not run."
    return 1
  fi
  echo "the network dropped the SYN packets to the connector proxy ${ip}:${port}"
}

selftest() {
  local dir rc
  dir=$(mktemp -d)
  trap 'rm -rf "$dir"' RETURN
  local start='Listening for events on 4 CPUs with 64x4096 of shared memory'
  local drop='xx drop (Policy denied) flow 0x0 to endpoint 812, ifindex 9, file bpf_lxc.c:2069, , identity 4932->21071: 10.244.0.84:51618 -> 10.244.0.30:8080 tcp SYN'
  printf '%s\n%s\n' "$start" "$drop" > "$dir/drop.log"
  printf '%s\n' "$start" > "$dir/quiet.log"
  printf '%s\n' "$drop" > "$dir/nostart.log"
  printf '%s\n%s\n' "$start" "${drop/8080/9090}" > "$dir/otherport.log"
  printf '%s\n%s\n' "$start" "${drop/Policy denied/CT: Unknown L4 protocol}" > "$dir/otherreason.log"

  check 10.244.0.30 8080 "$dir/drop.log" "$dir/quiet.log" >/dev/null || { echo "selftest: a drop was not found"; return 1; }
  for bad in quiet nostart otherport otherreason; do
    rc=0
    check 10.244.0.30 8080 "$dir/$bad.log" >/dev/null 2>&1 || rc=$?
    [ "$rc" -eq 1 ] || { echo "selftest: the fixture ${bad} passed, want a failure"; return 1; }
  done
  # One file of two with a monitor that did not start fails the check.
  rc=0
  check 10.244.0.30 8080 "$dir/drop.log" "$dir/nostart.log" >/dev/null 2>&1 || rc=$?
  [ "$rc" -eq 1 ] || { echo "selftest: a monitor that did not start passed"; return 1; }
  echo "check-proxy-drops selftest: each fixture fails, the drop passes"
}

if [ "${1:-}" = "--selftest" ]; then
  selftest
  exit $?
fi
if [ $# -lt 3 ]; then
  echo "usage: $0 <ip> <port> <monitor log>... | --selftest" >&2
  exit 2
fi
check "$@"
