#!/usr/bin/env bash
# Assert that a real mission wrote its run nodes to the graph of a tenant
# (gibson#1021).
#
# The projector writes PascalCase nodes (ADR-0112): one MissionRun keyed on
# `id` (graph_projector_mission_graph.go) and one AgentRun keyed on
# `brain_id` (graph_projector_neo4j.go) for each run. The audit_v4 suite that
# asserted lowercase labels left with gibson#1015, so after it no exit test
# checked that a mission reaches the graph at all.
#
# Usage: assert-run-nodes.sh <tenant>
#
# It reads the tenant Neo4j directly: the bolt NetworkPolicy of the tenant
# admits the daemon only, so the check runs cypher-shell inside the Neo4j pod
# with the password of the tenant Secret. Each count must be a whole number of
# at least one. An empty answer, an error or a zero fails the check.
set -euo pipefail

TENANT="${1:?tenant}"
ns="tenant-${TENANT}"
sts="tenant-${TENANT}-neo4j"
pod="${sts}-0"

password=$(kubectl -n "$ns" get secret "${sts}-auth" -o jsonpath='{.data.password}' | base64 -d)
if [ -z "$password" ]; then
  echo "::error::the Secret ${sts}-auth in $ns holds no password"
  exit 1
fi

# count <label> <key>: the number of nodes of <label> whose <key> is set.
count() {
  local out
  out=$(kubectl -n "$ns" exec "$pod" -c neo4j -- \
    cypher-shell -u neo4j -p "$password" --format plain \
    "MATCH (n:$1) WHERE n.$2 IS NOT NULL RETURN count(n)")
  # --format plain prints a header line, then the value.
  out=$(printf '%s\n' "$out" | tail -n 1 | tr -d '[:space:]')
  case "$out" in
    ''|*[!0-9]*) echo "::error::cypher-shell gave no count for :$1 (got '$out')" >&2; return 1 ;;
  esac
  printf '%s' "$out"
}

status=0
for spec in MissionRun:id AgentRun:brain_id; do
  label=${spec%%:*}
  key=${spec#*:}
  n=$(count "$label" "$key") || { status=1; continue; }
  if [ "$n" -lt 1 ]; then
    echo "::error::the graph of tenant $TENANT holds no :$label node with $key after a real mission"
    status=1
  else
    echo "the graph of tenant $TENANT holds $n :$label node(s) with $key"
  fi
done
exit "$status"
