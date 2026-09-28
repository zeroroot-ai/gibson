#!/usr/bin/env bash
# run-capped.sh — run a heavy build/analysis command under a LOCAL resource cap.
#
# Why (gibson#302): the whole-program dead-code gate builds ./cmd/... ./operators/...
# which fans out into hundreds of parallel compiler subprocesses and spiked the
# 1-minute load average to ~180-230 on an 8-core workstation.
#
# The binding lever for LOAD is build PARALLELISM, not CPU time: load average counts
# runnable processes, so an unbounded `-p` fan-out drives load sky-high even under a
# CPUQuota (which only time-slices those processes). So the primary control here is
# `go`'s `-p` flag (via GOFLAGS), which bounds how many compile/link actions run at
# once. CPUQuota + soft MemoryHigh are secondary belts.
#
# In CI, or when systemd-run is unavailable, the command runs DIRECTLY: CI runners
# are isolated and sized and have no `--user` systemd session, so CI must not change.
#
# Env overrides: CAP_P (go -p build parallelism, default 2), CAP_CPU (default 300%),
# CAP_MEM (soft MemoryHigh, default 6G), CAP_LOAD (wait until 1-min load is below this
# before starting locally, default 6; 0 disables the wait), CAP_WAIT_SECS (max wait,
# default 300). Memory is SOFT (MemoryHigh) and never OOM-kills: unlike a lint run you
# can defer to CI, the deadcode baseline must complete locally.
set -euo pipefail

if [ "$#" -eq 0 ]; then echo "run-capped.sh: no command given" >&2; exit 2; fi

# CI → exactly as before (direct, uncapped). Do not change CI behavior.
if [ -n "${CI:-}" ]; then exec "$@"; fi

# Bound go build parallelism — the real driver of the load spike.
CAP_P="${CAP_P:-2}"
export GOFLAGS="${GOFLAGS:-} -p=${CAP_P}"
export GOMAXPROCS="${CAP_GOMAXPROCS:-${CAP_P}}"

# Locally, wait for load to settle so a heavy run never stacks on a busy box.
CAP_LOAD="${CAP_LOAD:-6}"
if [ "${CAP_LOAD}" != "0" ]; then
  waited=0; max="${CAP_WAIT_SECS:-300}"
  while :; do
    load1=$(cut -d' ' -f1 /proc/loadavg)
    # integer compare on the whole part is enough for a coarse gate
    if [ "${load1%.*}" -lt "${CAP_LOAD}" ] 2>/dev/null; then break; fi
    if [ "$waited" -ge "$max" ]; then
      echo "run-capped.sh: load ${load1} still >= ${CAP_LOAD} after ${max}s; proceeding anyway" >&2
      break
    fi
    echo "run-capped.sh: load ${load1} >= ${CAP_LOAD}; waiting for it to settle..." >&2
    sleep 15; waited=$((waited+15))
  done
fi

# No systemd-run → the -p bound above is our only lever; run with it.
if ! command -v systemd-run >/dev/null 2>&1; then exec "$@"; fi

exec systemd-run --user --scope --quiet \
  -p CPUQuota="${CAP_CPU:-300%}" \
  -p MemoryHigh="${CAP_MEM:-6G}" \
  "$@"
