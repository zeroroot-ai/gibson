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
POD_SELECTOR="${POD_SELECTOR:-$SCRIPT_DIR/pod-needs-dump.jq}"

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
    group "Application $app — retry budget and sync windows"
    # The configured ordering and retry budget, so a reader does not have to go
    # read the chart to know what Argo was told. A sync that exhausts its retries
    # inside a dependency's startup window looks identical to a broken
    # dependency unless both numbers are here.
    $KUBECTL -n "$ARGOCD_NS" get application "$app" -o json 2>/dev/null \
      | jq -r '"retry: \(.spec.syncPolicy.retry // "none configured")",
               "operation startedAt: \(.status.operationState.startedAt // "?")",
               "operation finishedAt: \(.status.operationState.finishedAt // "?")",
               "revision: \(.status.operationState.syncResult.revision // "?")"' 2>&1 || true
    endgroup

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

# dump_misbehaving_pods prints the logs of every pod that misbehaved, whether or
# not it is unhealthy by the time anyone looks.
#
# The selector is deliberately NOT "not ready". The OpenBao outage that cost
# three days of blind exit-test failures read `2/2 Running` at dump time: its
# readiness and liveness probes had been timing out since minute one, the
# bringup had already given up, and by the time this script ran the pod looked
# perfect. "Not ready" would have skipped it and printed nothing.
#
# So a pod is dumped when ANY of these is true:
#   - a container has restarted
#   - a container is not ready, or the pod is not Running/Succeeded
#   - the pod is named in a Warning event
#
# The third is what catches the probe case. A probe failure is an event about a
# pod that may be perfectly healthy now, and it is the only trace left of a
# window that has closed. Job pods are skipped here because dump_jobs already
# prints them with their spec and conditions.
dump_misbehaving_pods() {
  local ns=$1
  local named restarted selected pod

  # Pods named in Warning events. `-o custom-columns` on the involved object is
  # steadier than parsing the human table, which pads and truncates names.
  named=$($KUBECTL -n "$ns" get events --field-selector type=Warning \
    -o custom-columns=NAME:.involvedObject.name,KIND:.involvedObject.kind \
    --no-headers 2>/dev/null | awk '$2 == "Pod" { print $1 }' | sort -u)

  # Pods with a restart, a not-ready container, or a non-running phase. The
  # selector lives in its own jq file so the fixtures can exercise it; see the
  # header there for why Succeeded pods are excluded before the readiness tests.
  restarted=$($KUBECTL -n "$ns" get pods -o json 2>/dev/null \
    | jq -r -f "$POD_SELECTOR" 2>/dev/null | sort -u)

  selected=$(printf '%s\n%s\n' "$named" "$restarted" | sed '/^$/d' | sort -u)
  if [ -z "$selected" ]; then
    echo "no pod in $ns restarted, went unready, or drew a warning event"
    return 0
  fi

  local dumped=0
  for pod in $selected; do
    # Already covered with its spec and conditions by dump_jobs.
    if $KUBECTL -n "$ns" get pod "$pod" \
        -o jsonpath='{.metadata.labels.job-name}' 2>/dev/null | grep -q .; then
      continue
    fi
    dumped=$((dumped + 1))

    group "Pod $ns/$pod — restarted, unready, or warned about"
    $KUBECTL -n "$ns" get pod "$pod" -o json 2>/dev/null \
      | jq -r '"phase=\(.status.phase)  node=\(.spec.nodeName // "-")",
               "ready=\((.status.conditions // []) | map(select(.type == "Ready")) | .[0].status // "?")",
               "--- WHEN each condition last flipped, which is the only way a",
               "--- post-mortem dump can say whether this pod was usable at the",
               "--- moment something else depended on it",
               ((.status.conditions // [])[] | "condition \(.type)=\(.status) at \(.lastTransitionTime // "?")"),
               "startedAt=\(.status.startTime // "?")",
               ((.status.containerStatuses // [])[] | "\(.name) running since \(.state.running.startedAt // .state.terminated.finishedAt // "?")"),
               ((.status.initContainerStatuses // [])[] | "init \(.name): ready=\(.ready) restarts=\(.restartCount) \(.state | keys[0])"),
               ((.status.containerStatuses // [])[] | "\(.name): ready=\(.ready) restarts=\(.restartCount) \(.state | keys[0])")' 2>&1 || true

    echo "--- probes as declared, because a missing timeoutSeconds is 1 second"
    $KUBECTL -n "$ns" get pod "$pod" -o json 2>/dev/null \
      | jq -r '(.spec.containers // [])[]
                 | . as $c
                 | (["livenessProbe", "readinessProbe", "startupProbe"][]
                     | select($c[.] != null)
                     | "\($c.name).\(.): timeout=\($c[.].timeoutSeconds // 1) period=\($c[.].periodSeconds // 10) initialDelay=\($c[.].initialDelaySeconds // 0) failureThreshold=\($c[.].failureThreshold // 3)")' 2>&1 || true

    echo "--- resources, because a CPU limit throttles even on an idle node"
    $KUBECTL -n "$ns" get pod "$pod" -o json 2>/dev/null \
      | jq -r '(.spec.containers // [])[] | "\(.name): requests=\(.resources.requests // {} | tojson) limits=\(.resources.limits // {} | tojson)"' 2>&1 || true

    echo "--- logs (all containers, last $LOG_TAIL)"
    $KUBECTL -n "$ns" logs "$pod" --all-containers --tail="$LOG_TAIL" 2>&1 || true
    echo "--- previous logs, if it restarted"
    $KUBECTL -n "$ns" logs "$pod" --all-containers --previous --tail="$LOG_TAIL" 2>/dev/null || true
    echo "--- events"
    $KUBECTL -n "$ns" describe pod "$pod" 2>/dev/null | sed -n '/^Events/,$p' || true
    endgroup
  done

  # Silence must never look like "the check did not run".
  if [ "$dumped" -eq 0 ]; then
    echo "every pod selected in $ns belongs to a Job; dump_jobs covers those"
  fi
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
    dump_misbehaving_pods "$ns"
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

  # The pod selector, against one fixture carrying every case that matters.
  local pods="$SCRIPT_DIR/testdata/pods-mixed.json"
  if [ ! -f "$pods" ]; then
    echo "selftest FAIL: $pods missing" >&2
    return 1
  fi
  local picked
  picked=$(jq -r -f "$POD_SELECTOR" "$pods" 2>&1)

  local want
  for want in gibson-daemon-0 gibson-envoy-7f9c-pending gibson-ext-authz-init-stuck; do
    if ! printf '%s\n' "$picked" | grep -qx "$want"; then
      echo "selftest FAIL: the pod selector missed $want. It picked:" >&2
      printf '%s\n' "$picked" >&2
      fails=1
    fi
  done

  # A completed Job pod reports ready=false on a terminated container. Selecting
  # it would dump every successful run on a cluster that has been up for days.
  if printf '%s\n' "$picked" | grep -q "fga-init"; then
    echo "selftest FAIL: a completed Job pod was selected" >&2
    fails=1
  fi
  if printf '%s\n' "$picked" | grep -qx "cert-manager-655fccd6d9-2ks28"; then
    echo "selftest FAIL: a healthy running pod was selected" >&2
    fails=1
  fi

  # The case that cost three days: gibson-openbao-0 read 2/2 Running with zero
  # restarts by the time anyone looked, so this selector CANNOT find it and must
  # not pretend to. The Warning-event union is the half that does.
  if printf '%s\n' "$picked" | grep -qx "gibson-openbao-0"; then
    echo "selftest FAIL: the fixture's healthy-now OpenBao pod matched the status selector," >&2
    echo "               which means the fixture no longer represents the case it was built for" >&2
    fails=1
  fi
  if [ "$fails" -eq 0 ]; then
    echo "selftest PASS: the pod selector picks the crashlooper, the pending pod and the stuck init"
    echo "selftest PASS: it skips healthy pods, completed Jobs, and the healthy-now probe case"
  fi

  # And the event half, which is what finds a pod that looks fine now.
  local events="$SCRIPT_DIR/testdata/warning-events.txt"
  if [ -f "$events" ]; then
    if awk '$2 == "Pod" { print $1 }' "$events" | grep -qx "gibson-openbao-0"; then
      echo "selftest PASS: a pod named only in a Warning event is found by the event half"
    else
      echo "selftest FAIL: the Warning-event selector missed gibson-openbao-0" >&2
      fails=1
    fi
  else
    echo "selftest FAIL: $events missing" >&2
    fails=1
  fi

  return "$fails"
}

if [ "${1:-}" = "--selftest" ]; then
  selftest
  exit $?
fi

main
exit 0
