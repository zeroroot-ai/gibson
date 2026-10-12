#!/usr/bin/env bash
# check-proxy-drops.sh — the network dropped the packets that a sandbox Pod
# sent to the proxy of a connector (gibson#723, gibson#1088, D76).
#
# The inputs are the output of `cilium-dbg monitor --type drop` from each
# Cilium agent, and the sandbox Pods that the run saw: one "<name> <ip>"
# line for each Pod event in a sandbox namespace. The check passes when each
# monitor ran, at least one sandbox Pod has an address, and one monitor
# holds a drop by a policy of a TCP SYN from the address of a sandbox Pod to
# <ip>:<port>. A drop from any other source does not count.
#
# Usage: bash tests/fixtures/mcp-tools/check-proxy-drops.sh <ip> <port> <sandbox pods> <monitor log>...
#        bash tests/fixtures/mcp-tools/check-proxy-drops.sh --selftest
# Exit codes: 0 a drop is found, 1 no drop or a monitor did not run, 2 usage.
set -euo pipefail

check() {
  local ip=$1 port=$2 pods=$3
  shift 3
  local log found=0 src
  local -a sources=()
  if [ -s "$pods" ]; then
    mapfile -t sources < <(awk 'NF >= 2 && $2 ~ /^[0-9a-f.:]+$/ {print $2}' "$pods" | sort -u)
  fi
  if [ "${#sources[@]}" -eq 0 ]; then
    echo "::error::no sandbox Pod with an address was seen in ${pods}, so no drop can be tied to a sandbox"
    return 1
  fi
  for log in "$@"; do
    if ! grep -q 'Listening for events' "$log"; then
      echo "::error::the Cilium monitor of ${log} did not start, so the check looked at nothing"
      return 1
    fi
    # A line looks like:
    # xx drop (Policy denied) flow 0x0 to endpoint 812, ifindex 9, file bpf_lxc.c:2069, , identity 4932->21071: 10.244.0.84:51618 -> 10.244.0.30:8080 tcp SYN
    for src in "${sources[@]}"; do
      if grep -F 'Policy denied' "$log" | grep -F -- "-> ${ip}:${port} tcp SYN" |
        grep -E -- ": ${src//./\\.}:[0-9]+ -> " >/dev/null; then
        found=1
        echo "the network dropped a SYN from the sandbox Pod ${src} to the connector proxy ${ip}:${port}"
      fi
    done
  done
  if [ "$found" -ne 1 ]; then
    echo "::error::no policy dropped a TCP SYN from a sandbox Pod (${sources[*]}) to the connector proxy ${ip}:${port}. A sandbox reached the proxy, or the scan did not run."
    return 1
  fi
}

selftest() {
  local dir rc
  dir=$(mktemp -d)
  trap 'rm -rf "$dir"' RETURN
  local start='Listening for events on 4 CPUs with 64x4096 of shared memory'
  local drop='xx drop (Policy denied) flow 0x0 to endpoint 812, ifindex 9, file bpf_lxc.c:2069, , identity 4932->21071: 10.244.0.84:51618 -> 10.244.0.30:8080 tcp SYN'
  printf 'launcher-abc 10.244.0.84\nlauncher-abc\n' > "$dir/pods.txt"
  printf 'launcher-xyz 10.244.0.99\n' > "$dir/other-pods.txt"
  : > "$dir/no-pods.txt"
  printf '%s\n%s\n' "$start" "$drop" > "$dir/drop.log"
  printf '%s\n' "$start" > "$dir/quiet.log"
  printf '%s\n' "$drop" > "$dir/nostart.log"
  printf '%s\n%s\n' "$start" "${drop/8080/9090}" > "$dir/otherport.log"
  printf '%s\n%s\n' "$start" "${drop/Policy denied/CT: Unknown L4 protocol}" > "$dir/otherreason.log"
  printf '%s\n%s\n' "$start" "${drop/10.244.0.84:51618/10.244.0.85:51618}" > "$dir/othersource.log"
  printf '%s\n%s\n' "$start" "${drop/10.244.0.84:51618/110.244.0.84:51618}" > "$dir/prefixsource.log"

  check 10.244.0.30 8080 "$dir/pods.txt" "$dir/drop.log" "$dir/quiet.log" >/dev/null ||
    { echo "selftest: a drop from the sandbox Pod was not found"; return 1; }
  for bad in quiet nostart otherport otherreason othersource prefixsource; do
    rc=0
    check 10.244.0.30 8080 "$dir/pods.txt" "$dir/$bad.log" >/dev/null 2>&1 || rc=$?
    [ "$rc" -eq 1 ] || { echo "selftest: the fixture ${bad} passed, want a failure"; return 1; }
  done
  # A drop from a Pod that is not a sandbox of the run does not count.
  rc=0
  check 10.244.0.30 8080 "$dir/other-pods.txt" "$dir/drop.log" >/dev/null 2>&1 || rc=$?
  [ "$rc" -eq 1 ] || { echo "selftest: a drop from a Pod that is not a sandbox passed"; return 1; }
  # No sandbox Pod seen fails: the check cannot tie a drop to a sandbox.
  rc=0
  check 10.244.0.30 8080 "$dir/no-pods.txt" "$dir/drop.log" >/dev/null 2>&1 || rc=$?
  [ "$rc" -eq 1 ] || { echo "selftest: a run with no sandbox Pod passed"; return 1; }
  # One file of two with a monitor that did not start fails the check.
  rc=0
  check 10.244.0.30 8080 "$dir/pods.txt" "$dir/drop.log" "$dir/nostart.log" >/dev/null 2>&1 || rc=$?
  [ "$rc" -eq 1 ] || { echo "selftest: a monitor that did not start passed"; return 1; }
  echo "check-proxy-drops selftest: each fixture fails, the drop from the sandbox Pod passes"
}

if [ "${1:-}" = "--selftest" ]; then
  selftest
  exit $?
fi
if [ $# -lt 4 ]; then
  echo "usage: $0 <ip> <port> <sandbox pods> <monitor log>... | --selftest" >&2
  exit 2
fi
check "$@"
