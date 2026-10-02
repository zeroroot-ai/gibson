# argo-failed-resource-refs.jq — the resources an Argo sync could not settle, as
# machine-readable refs so the shell can go and ask each one WHY.
#
# Its sibling argo-app-problems.jq prints the Application's own view, which is
# all the Application knows: for a ClusterSecretStore the whole message is
#
#   ClusterSecretStore/gibson-secrets hookPhase=Failed unable to create client
#
# and the cause is the suffix after that colon, which lives on the LIVE object's
# status.conditions and never reaches the Application at all. Five days of
# exit-test-bank failures were diagnosed down to that truncated line and no
# further (gibson#575).
#
# Emits one TAB-separated `kind<TAB>namespace<TAB>name` per resource. Namespace
# is "-" for a cluster-scoped kind, which is most of the ones that strand a
# bringup. Argo writes `"namespace": ""` for those, not null, so `// "-"` alone
# does not catch it and the field would come out empty.
#
# The selects match argo-app-problems.jq exactly. A missing field means "nothing
# to report", never "broken" — a filter of `.status != "Synced"` reports every
# hook on a green cluster.
(.status.operationState.syncResult.resources // [])
| map(select(
    ((.hookPhase // null) != null and (.hookPhase | IN("Succeeded", "Running")) == false)
    or ((.status // null) != null and .status != "Synced")
  ))
| .[]
| [
    (.kind // "?"),
    (if ((.namespace // "") | length) == 0 then "-" else .namespace end),
    (.name // "?")
  ]
| @tsv
