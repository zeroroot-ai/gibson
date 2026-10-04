#!/usr/bin/env bash
# run-capped.sh — run a heavy build/analysis command LOCALLY: one at a time, under
# a hard memory cap.
#
# Why (gibson#302): the whole-program dead-code gate builds ./cmd/... ./operators/...
# which fans out into hundreds of parallel compiler subprocesses and spiked the
# 1-minute load average to ~180-230 on an 8-core workstation.
#
# Why the lock and the hard cap: the first version bounded each run by itself,
# with a soft MemoryHigh and a load wait that printed "proceeding anyway" after
# 300 s. A bound per run does not bound the sum. Three worktrees ran the gate at
# the same time, the gate self-test added three fixture runs each, one deadcode
# run holds about 6.3G, and the workstation filled its swap and hung. So:
#
#   1. ONE machine-wide lock. A second run WAITS for the first, with no timeout.
#      The lock file is outside the tree, so every worktree and every repo that
#      uses the same path shares it.
#   2. A HARD MemoryMax with no swap. The kernel kills the run before the
#      workstation swaps. Exit 137 means the cap worked: push and let CI run it.
#   3. A free-memory floor and a load ceiling that REFUSE (exit 75). Neither
#      proceeds on a busy workstation.
#
# The binding lever for LOAD is build PARALLELISM, not CPU time: load average counts
# runnable processes, so an unbounded `-p` fan-out drives load sky-high even under a
# CPUQuota (which only time-slices those processes). So `go`'s `-p` flag (via
# GOFLAGS) bounds how many compile/link actions run at once.
#
# In CI, or when systemd-run is unavailable, the command runs DIRECTLY: CI runners
# are isolated and sized and have no `--user` systemd session, so CI must not change.
#
# Env overrides: CAP_P (go -p build parallelism, default 2), CAP_CPU (default 300%),
# CAP_MEM (hard MemoryMax, default 10G), CAP_MIN_FREE_MB (refuse under this much
# available memory, default 10000; 0 disables), CAP_LOAD (refuse when the 1-min
# load stays at or above this, default 6; 0 disables), CAP_WAIT_SECS (how long to
# wait for the load before the refusal, default 300), CAP_LOCK (lock file).
set -euo pipefail

# run_selftest proves each control can fail. It never reads the real lock.
run_selftest() {
  local self fails=0 tmp out rc start elapsed
  self="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/$(basename "${BASH_SOURCE[0]}")"
  tmp="$(mktemp -d)"
  # shellcheck disable=SC2064
  trap "rm -rf '$tmp'" RETURN
  # The self-test exercises the LOCAL path, so it drops CI and any held lock.
  local -a clean=(env -u CI -u ZEROROOT_HEAVY_HELD CAP_LOCK="$tmp/lock" CAP_LOAD=0 CAP_MIN_FREE_MB=0)

  # 1. Two runs must not overlap. Each appends start and end. An overlap gives
  #    start,start,end,end.
  "${clean[@]}" bash "$self" bash -c "echo start >>'$tmp/order'; sleep 1; echo end >>'$tmp/order'" &
  "${clean[@]}" bash "$self" bash -c "echo start >>'$tmp/order'; sleep 1; echo end >>'$tmp/order'" &
  wait
  if [ "$(tr '\n' ',' <"$tmp/order")" = "start,end,start,end," ]; then
    echo "selftest PASS: two runs took the lock one after the other"
  else
    echo "selftest FAIL: two runs overlapped ($(tr '\n' ',' <"$tmp/order"))" >&2; fails=1
  fi

  # 2. A run that already holds the lock (make -> script -> run-capped) must not
  #    wait for itself.
  start=$(date +%s)
  if "${clean[@]}" bash "$self" bash "$self" true && elapsed=$(( $(date +%s) - start )) && [ "$elapsed" -lt 30 ]; then
    echo "selftest PASS: a nested run does not wait for its own lock"
  else
    echo "selftest FAIL: a nested run failed or waited for its own lock" >&2; fails=1
  fi

  # 3. Under the memory floor the run is refused, and the command never starts.
  set +e
  out="$("${clean[@]}" CAP_MIN_FREE_MB=999999999 bash "$self" touch "$tmp/ran" 2>&1)"; rc=$?
  set -e
  if [ "$rc" -eq 75 ] && [ ! -e "$tmp/ran" ] && grep -q "REFUSED.*available memory" <<<"$out"; then
    echo "selftest PASS: a run under the memory floor is refused"
  else
    echo "selftest FAIL: memory floor: exit $rc, ran=$([ -e "$tmp/ran" ] && echo yes || echo no): $out" >&2; fails=1
  fi

  # 4. A load at or above the ceiling is refused, and never "proceeds anyway".
  #    The fake loadavg holds the load at 99.
  echo "99.00 99.00 99.00 1/1 1" >"$tmp/loadavg"
  set +e
  out="$("${clean[@]}" CAP_LOAD=6 CAP_WAIT_SECS=0 CAP_LOADAVG_FILE="$tmp/loadavg" bash "$self" touch "$tmp/ran" 2>&1)"; rc=$?
  set -e
  if [ "$rc" -eq 75 ] && [ ! -e "$tmp/ran" ] && grep -q "REFUSED.*load" <<<"$out"; then
    echo "selftest PASS: a run on a loaded workstation is refused"
  else
    echo "selftest FAIL: load ceiling: exit $rc, ran=$([ -e "$tmp/ran" ] && echo yes || echo no): $out" >&2; fails=1
  fi

  # 5. The hard cap kills a run that takes more memory than CAP_MEM. This needs
  #    a user systemd session, which a CI runner does not have.
  if command -v systemd-run >/dev/null 2>&1 && systemd-run --user --scope --quiet true 2>/dev/null; then
    set +e
    "${clean[@]}" CAP_MEM=100M bash "$self" bash -c 'x=$(head -c 400000000 /dev/zero | tr "\0" a); echo "${#x}" >'"'$tmp/survived'" 2>/dev/null; rc=$?
    set -e
    if [ "$rc" -ne 0 ] && [ ! -e "$tmp/survived" ]; then
      echo "selftest PASS: a run over the hard memory cap is killed (exit $rc)"
    else
      echo "selftest FAIL: a 400MB run survived a 100M cap (exit $rc)" >&2; fails=1
    fi
  else
    echo "selftest SKIP: no user systemd session, so the hard cap does not apply here"
  fi

  return "$fails"
}

if [ "${1:-}" = "--selftest" ]; then run_selftest; exit $?; fi

if [ "$#" -eq 0 ]; then echo "run-capped.sh: no command given" >&2; exit 2; fi

# CI → exactly as before (direct, uncapped). Do not change CI behavior.
if [ -n "${CI:-}" ]; then exec "$@"; fi

# One heavy run at a time on this machine. fd 9 stays open across the exec
# below, so the lock lasts as long as the command. ZEROROOT_HEAVY_HELD marks a
# process tree that already holds it.
if [ "${ZEROROOT_HEAVY_HELD:-}" != "1" ]; then
  CAP_LOCK="${CAP_LOCK:-${XDG_RUNTIME_DIR:-/tmp}/zeroroot-heavy.lock}"
  exec 9>>"$CAP_LOCK"
  if ! flock -n 9; then
    echo "run-capped.sh: another heavy run holds ${CAP_LOCK} ($(cat "${CAP_LOCK}.holder" 2>/dev/null || echo unknown)). Waiting." >&2
    flock 9
  fi
  echo "pid=$$ since=$(date -Is) cwd=$PWD cmd=$*" >"${CAP_LOCK}.holder"
  export ZEROROOT_HEAVY_HELD=1
fi

# Bound go build parallelism — the real driver of the load spike.
CAP_P="${CAP_P:-2}"
export GOFLAGS="${GOFLAGS:-} -p=${CAP_P}"
export GOMAXPROCS="${CAP_GOMAXPROCS:-${CAP_P}}"

# Refuse on a workstation with too little free memory.
CAP_MIN_FREE_MB="${CAP_MIN_FREE_MB:-10000}"
if [ "${CAP_MIN_FREE_MB}" != "0" ]; then
  free_mb=$(awk '/^MemAvailable:/{print int($2/1024)}' /proc/meminfo)
  if [ "$free_mb" -lt "$CAP_MIN_FREE_MB" ]; then
    echo "run-capped.sh: REFUSED. ${free_mb}MB of available memory is under the ${CAP_MIN_FREE_MB}MB floor. Free memory, or push and let CI run it." >&2
    exit 75
  fi
fi

# Wait for the load to settle. A load that does not settle refuses the run.
CAP_LOAD="${CAP_LOAD:-6}"
if [ "${CAP_LOAD}" != "0" ]; then
  waited=0; max="${CAP_WAIT_SECS:-300}"
  while :; do
    load1=$(cut -d' ' -f1 "${CAP_LOADAVG_FILE:-/proc/loadavg}")
    # integer compare on the whole part is enough for a coarse gate
    if [ "${load1%.*}" -lt "${CAP_LOAD}" ] 2>/dev/null; then break; fi
    if [ "$waited" -ge "$max" ]; then
      echo "run-capped.sh: REFUSED. The load is ${load1}, at or above ${CAP_LOAD}, after ${max}s. Stop the other work, or push and let CI run it." >&2
      exit 75
    fi
    echo "run-capped.sh: load ${load1} >= ${CAP_LOAD}; waiting for it to settle..." >&2
    sleep 15; waited=$((waited+15))
  done
fi

# No systemd-run → the lock, the floor and the -p bound are the levers; run with them.
if ! command -v systemd-run >/dev/null 2>&1; then exec "$@"; fi

exec systemd-run --user --scope --quiet \
  -p CPUQuota="${CAP_CPU:-300%}" \
  -p MemoryMax="${CAP_MEM:-10G}" \
  -p MemorySwapMax=0 \
  "$@"
