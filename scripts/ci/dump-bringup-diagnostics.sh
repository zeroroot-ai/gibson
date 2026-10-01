#!/usr/bin/env bash
# dump-bringup-diagnostics.sh — print why an Argo bringup failed.
#
# Why this exists. The four exit tests stand the cluster up with hosted's
# `make recreate`, and when that fails the only line in the log is:
#
#   ✗ [recreate] an Application's sync operation failed and Argo has spent its
#     retries (a sync task or hook Job keeps dying)
#
# The task is never named. exit-test-bank, exit-test-tool-dispatch and
# exit-test-sandboxed-dispatch have failed on that one line on every run since
# 2026-09-29 and not one of them could be root-caused from its log: their
# `Diagnostics on failure` steps dump the test's own workloads, which do not
# exist yet when the bringup is what failed. The cluster is torn down with the
# runner, so there is no second chance to look.
#
# This dumps the state that names the cause: each Application's phase and
# message, every resource the sync could not apply, every Job in the watched
# namespaces with its pods' events and logs, and the warning events.
#
# It is a diagnostic, never a gate. It ALWAYS exits 0 and swallows every error,
# so it can neither fail a green run nor mask the real failure.
#
# Usage:
#   bash scripts/ci/dump-bringup-diagnostics.sh                 # NS, or gibson
#   NS=gibson ARGOCD_NS=argocd bash scripts/ci/dump-bringup-diagnostics.sh
#   bash scripts/ci/dump-bringup-diagnostics.sh --selftest      # no cluster needed

NS="${NS:-gibson}"
ARGOCD_NS="${ARGOCD_NS:-argocd}"
LOG_TAIL="${DIAG_LOG_TAIL:-200}"
KUBECTL="${KUBECTL:-kubectl}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
JQ_PROGRAM="${JQ_PROGRAM:-$SCRIPT_DIR/argo-app-problems.jq}"

group() { echo "::group::$*"; }
endgroup() { echo "::endgroup::"; }

have_cluster() {
  $KUBECTL version --request-timeout=10s >/dev/null 2>&1
}

dump_applications() {
  group "Argo Applications"
  $KUBECTL -n "$ARGOCD_NS" get applications -o wide 2>&1 || true
  endgroup

  local apps
  apps=$($KUBECTL -n "$ARGOCD_NS" get applications -o name 2>/dev/null | sed 's#.*/##')
  if [ -z "$apps" ]; then
    echo "no Applications in namespace $ARGOCD_NS (Argo itself may not be up)"
    return 0
  fi

  local app
  for app in $apps; do
    group "Application $app — phase, message, failed resources"
    # The message is the sentence Argo wrote when the sync gave up. It is the
    # single most useful line and nothing printed it before.
    $KUBECTL -n "$ARGOCD_NS" get application "$app" -o json 2>/dev/null \
      | jq -r -f "$JQ_PROGRAM" 2>&1 \
      || $KUBECTL -n "$ARGOCD_NS" get application "$app" -o yaml 2>&1 | tail -60
    endgroup
  done
}

# Every hook Job and every Job in the namespace, because "a hook Job keeps
# dying" is the stated cause and the Job's own pod log says which assertion or
# which missing input killed it.
dump_jobs() {
  local ns=$1
  local jobs
  jobs=$($KUBECTL -n "$ns" get jobs -o name 2>/dev/null | sed 's#.*/##')
  if [ -z "$jobs" ]; then
    echo "no Jobs in namespace $ns"
    return 0
  fi

  group "Jobs in $ns"
  $KUBECTL -n "$ns" get jobs 2>&1 || true
  endgroup

  local job state
  for job in $jobs; do
    state=$($KUBECTL -n "$ns" get job "$job" -o jsonpath='{.status.succeeded}' 2>/dev/null)
    [ "$state" = "1" ] && continue   # a Job that completed needs no autopsy

    group "Job $ns/$job — did NOT complete"
    $KUBECTL -n "$ns" get job "$job" -o json 2>/dev/null \
      | jq -r '
          "active=\(.status.active // 0) succeeded=\(.status.succeeded // 0) failed=\(.status.failed // 0)",
          "backoffLimit=\(.spec.backoffLimit // "-")",
          ((.status.conditions // []) | .[] | "condition \(.type)=\(.status): \(.reason // "") \(.message // "")")
        ' 2>&1 || true
    $KUBECTL -n "$ns" describe job "$job" 2>/dev/null | sed -n '/^Events/,$p' || true

    local pod
    for pod in $($KUBECTL -n "$ns" get pods -l "job-name=$job" -o name 2>/dev/null); do
      echo "--- $pod containers"
      $KUBECTL -n "$ns" get "$pod" -o jsonpath='{range .status.initContainerStatuses[*]}init {.name}: {.state}{"\n"}{end}{range .status.containerStatuses[*]}{.name}: {.state}{"\n"}{end}' 2>/dev/null || true
      echo "--- $pod logs (all containers, last $LOG_TAIL)"
      $KUBECTL -n "$ns" logs "$pod" --all-containers --tail="$LOG_TAIL" 2>&1 || true
      echo "--- $pod previous logs, if it restarted"
      $KUBECTL -n "$ns" logs "$pod" --all-containers --previous --tail="$LOG_TAIL" 2>/dev/null || true
      echo "--- $pod events"
      $KUBECTL -n "$ns" describe "$pod" 2>/dev/null | sed -n '/^Events/,$p' || true
    done
    endgroup
  done
}

dump_events() {
  local ns=$1
  group "Warning events in $ns"
  $KUBECTL -n "$ns" get events --field-selector type=Warning \
    --sort-by=.lastTimestamp 2>&1 | tail -40 || true
  endgroup
}

dump_pods() {
  local ns=$1
  group "Pods in $ns"
  $KUBECTL -n "$ns" get pods -o wide 2>&1 || true
  endgroup
}

main() {
  echo "bringup diagnostics: NS=$NS ARGOCD_NS=$ARGOCD_NS"
  if ! have_cluster; then
    echo "no reachable cluster, so there is nothing to dump."
    echo "If the bringup never created the cluster, the failure is before Argo."
    return 0
  fi

  dump_applications
  local ns
  for ns in "$NS" "$ARGOCD_NS"; do
    dump_pods "$ns"
    dump_jobs "$ns"
    dump_events "$ns"
  done
}

# The selftest proves the dumper runs to completion, exits 0 and says something
# useful when there is no cluster at all. That is the state a workflow is in
# when the bringup dies before the API server answers, and a dumper that
# crashed there would hide the one failure it exists to explain.
selftest() {
  local out status fails=0
  out=$(KUBECTL=/nonexistent-kubectl bash "${BASH_SOURCE[0]}" 2>&1)
  status=$?
  if [ "$status" -ne 0 ]; then
    echo "selftest FAIL: the dumper exited $status with no cluster; it must exit 0" >&2
    fails=1
  elif ! printf '%s' "$out" | grep -q "no reachable cluster"; then
    echo "selftest FAIL: the dumper said nothing about the missing cluster. It said:" >&2
    printf '%s\n' "$out" >&2
    fails=1
  else
    echo "selftest PASS: no cluster reachable is reported, and exits 0"
  fi

  # jq must be present, or every Application dump degrades to a yaml tail.
  if ! command -v jq >/dev/null 2>&1; then
    echo "selftest FAIL: jq is not installed, so the Application dump cannot run" >&2
    return 1
  fi

  # The filter, against two recorded Applications. The healthy one carries the
  # real field shapes taken off staging, where a hook reads status: null and
  # hookPhase: "Succeeded" — the shape that made the first version of this
  # dumper report 31 succeeded hooks as failures.
  local healthy="$SCRIPT_DIR/testdata/argo-app-healthy.json"
  local failed="$SCRIPT_DIR/testdata/argo-app-failed.json"
  local verdict

  if [ ! -f "$healthy" ] || [ ! -f "$failed" ]; then
    echo "selftest FAIL: fixtures missing under $SCRIPT_DIR/testdata" >&2
    return 1
  fi

  verdict=$(jq -r -f "$JQ_PROGRAM" "$healthy" 2>&1)
  if printf '%s' "$verdict" | grep -qE "^  (ServiceAccount|ConfigMap|Job|Role|ClusterRole)"; then
    echo "selftest FAIL: the healthy Application reported a resource as a problem:" >&2
    printf '%s\n' "$verdict" >&2
    fails=1
  else
    echo "selftest PASS: a synced Application reports no problem resources"
  fi

  verdict=$(jq -r -f "$JQ_PROGRAM" "$failed" 2>&1)
  if ! printf '%s' "$verdict" | grep -q "hookPhase=Failed"; then
    echo "selftest FAIL: the failed hook Job was not reported:" >&2
    printf '%s\n' "$verdict" >&2
    fails=1
  elif ! printf '%s' "$verdict" | grep -q "health=Degraded"; then
    echo "selftest FAIL: the degraded resource was not reported:" >&2
    printf '%s\n' "$verdict" >&2
    fails=1
  else
    echo "selftest PASS: a failed hook Job and a degraded resource are both named"
  fi

  return "$fails"
}

if [ "${1:-}" = "--selftest" ]; then
  selftest
  exit $?
fi

main
exit 0
