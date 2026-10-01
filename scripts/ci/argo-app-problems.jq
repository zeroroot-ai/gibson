# argo-app-problems.jq — turn one Argo Application's JSON into the lines that
# say why its sync failed.
#
# Keep the two selects honest, because the shapes are not symmetric. Measured on
# a healthy staging Application (424 synced resources):
#
#   .status.operationState.syncResult.resources[]
#     hooks        → status: null,     hookPhase: "Succeeded"
#     plain        → status: "Synced", hookPhase: "Succeeded"
#   .status.resources[]
#     56 of 448    → status: null, and no .health key at all
#
# So a filter of `.status != "Synced"` reports every hook on a green cluster: the
# first version of this dumper listed 31 succeeded hooks as "could not settle".
# A missing field means "nothing to report", never "broken".
def problem_resources:
  (.status.operationState.syncResult.resources // [])
  | map(select(
      ((.hookPhase // null) != null and (.hookPhase | IN("Succeeded", "Running")) == false)
      or ((.status // null) != null and .status != "Synced")
    ));

def unhealthy_resources:
  (.status.resources // [])
  | map(select(
      ((.health.status // null) != null and .health.status != "Healthy")
      or ((.status // null) != null and .status != "Synced")
    ));

"sync:      \(.status.sync.status // "?")",
"health:    \(.status.health.status // "?") \(.status.health.message // "")",
"operation: \(.status.operationState.phase // "?")",
"message:   \(.status.operationState.message // "none")",
"startedAt: \(.status.operationState.startedAt // "?")",
"",
"conditions:",
((.status.conditions // []) | if length == 0 then "  none" else
  (.[] | "  \(.type): \(.message // "")") end),
"",
"resources the sync could not settle:",
((problem_resources | if length == 0 then ["  none"] else
  map("  \(.kind)/\(.name) status=\(.status // "-") hookPhase=\(.hookPhase // "-") \(.message // "")")
  end)[]),
"",
"resources reporting unhealthy:",
((unhealthy_resources | if length == 0 then ["  none"] else
  map("  \(.kind)/\(.name) sync=\(.status // "-") health=\(.health.status // "-") \(.health.message // "")")
  end)[])
