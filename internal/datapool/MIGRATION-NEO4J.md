# MIGRATION-NEO4J.md — Per-tenant Community → Shared Enterprise multi-DB

Operational runbook for migrating the Neo4j data plane from **Pattern B**
(per-tenant Community StatefulSets) to **Pattern A** (shared Enterprise
cluster, per-tenant named databases).

These five steps match `requirements.md` Req 5.6. The daemon side is
migration-ready: `multiDBResolver` at
[`neo4j_endpoint_resolver_multidb.go`](./neo4j_endpoint_resolver_multidb.go)
is built, unit-tested, and dormant under `Neo4j.TenantMode: instance`.
Step 3 flips one config field and the resolver takes over.

> **When:** see the decision tree in [`README.md`](./README.md). Triggers:
> fleet 75-100 tenants, Enterprise license procured, or N-StatefulSet ops
> burden exceeds tolerance.

> **Pre-flight:** plan a maintenance window. Steps 2-3 need a brief per-tenant
> write freeze. Notify tenants 48h prior.

---

## Step 1 — Provision Enterprise cluster

Deploy Neo4j Enterprise (in-chart subchart or external managed). Cluster MUST
be reachable from the daemon namespace at a stable Bolt URI.

```bash
helm upgrade --install gibson ./enterprise/deploy/helm/gibson -n gibson \
  --reuse-values \
  --set neo4jEnterprise.enabled=true \
  --set neo4jEnterprise.acceptLicenseAgreement=yes \
  --set neo4jEnterprise.image.tag=5.26.0-enterprise \
  --set neo4jEnterprise.cluster.coreServers=3 \
  --set neo4jEnterprise.cluster.readReplicas=2

# Verify license activation:
kubectl exec -n gibson gibson-neo4j-cluster-core-0 -- \
  cypher-shell -u neo4j -p "$NEO4J_PASSWORD" \
  "CALL dbms.components() YIELD edition RETURN edition;"
# Expected: "enterprise"

kubectl get statefulset,svc,pvc -n gibson -l app.kubernetes.io/name=neo4j-enterprise
```

Expected resources:
- `StatefulSet/gibson-neo4j-cluster-core` (3 replicas)
- `StatefulSet/gibson-neo4j-cluster-replica` (2 replicas)
- `Service/gibson-neo4j-cluster` (Bolt :7687)
- `PVC/data-gibson-neo4j-cluster-core-{0..2}`

**Rollback:** delete the new StatefulSets/PVCs and the values block.
Per-tenant instances continue serving traffic untouched.

---

## Step 2 — Per-tenant export + import

For **each** tenant (smallest data first to validate), dump the Community
instance and load it into the Enterprise cluster as `tenant_<sanitized>`.

```bash
TENANT_ID="acme-corp"
SANITIZED=$(echo -n "$TENANT_ID" | tr -c 'a-z0-9' '_')
SRC_BOLT="bolt://tenant-${SANITIZED}-neo4j.gibson.svc.cluster.local:7687"
DST_BOLT="bolt://gibson-neo4j-cluster.gibson.svc.cluster.local:7687"

# Per-tenant Vault namespace path: infra/neo4j
SRC_USER=$(vault kv get -field=username -namespace=tenant-$SANITIZED infra/neo4j)
SRC_PASS=$(vault kv get -field=password -namespace=tenant-$SANITIZED infra/neo4j)

# Stop tenant writes (operator drops it from the routing table; reads continue):
kubectl annotate tenant "$TENANT_ID" \
  gibson.zero-day.ai/migration-freeze=true --overwrite

# Export from Community via apoc:
kubectl exec -n gibson "tenant-${SANITIZED}-neo4j-0" -- \
  cypher-shell -u "$SRC_USER" -p "$SRC_PASS" -a "$SRC_BOLT" \
    "CALL apoc.export.cypher.all('/tmp/${SANITIZED}.cypher', \
       {format:'cypher-shell', useOptimizations:{type:'UNWIND_BATCH', unwindBatchSize:100}});"

kubectl cp gibson/"tenant-${SANITIZED}-neo4j-0":/tmp/${SANITIZED}.cypher \
  ./dumps/${SANITIZED}.cypher

# CREATE DATABASE runs against system DB:
kubectl exec -n gibson gibson-neo4j-cluster-core-0 -- \
  cypher-shell -u neo4j -p "$DST_PASS" -d system \
    "CREATE DATABASE tenant_${SANITIZED} IF NOT EXISTS WAIT;"

# Import:
kubectl cp ./dumps/${SANITIZED}.cypher \
  gibson/gibson-neo4j-cluster-core-0:/tmp/${SANITIZED}.cypher
kubectl exec -n gibson gibson-neo4j-cluster-core-0 -- \
  cypher-shell -u neo4j -p "$DST_PASS" -d "tenant_${SANITIZED}" \
    -f /tmp/${SANITIZED}.cypher

# Verify counts match source:
for SIDE in src dst; do
  case $SIDE in
    src) POD="tenant-${SANITIZED}-neo4j-0"; U=$SRC_USER; P=$SRC_PASS; D="";;
    dst) POD="gibson-neo4j-cluster-core-0"; U=neo4j; P=$DST_PASS; D="-d tenant_${SANITIZED}";;
  esac
  kubectl exec -n gibson "$POD" -- cypher-shell -u "$U" -p "$P" $D \
    "MATCH (n) RETURN count(n);"
done
```

Repeat for every tenant in lowest-traffic-first order. Track in a spreadsheet:
`tenant_id, src_count, dst_count, status`.

**Rollback:** `DROP DATABASE tenant_<sanitized>` against system DB and
unfreeze. Source data is untouched.

---

## Step 3 — Flip daemon config to multi-db

With every tenant's data resident in Enterprise, switch the daemon to
`multiDBResolver`. Single config-and-rollout op.

```bash
helm upgrade gibson ./enterprise/deploy/helm/gibson -n gibson --reuse-values \
  --set daemon.config.neo4j.tenantMode=multi-db \
  --set daemon.config.neo4j.sharedClusterURI=bolt://gibson-neo4j-cluster.gibson.svc.cluster.local:7687

kubectl rollout restart statefulset/gibson -n gibson
kubectl rollout status   statefulset/gibson -n gibson --timeout=5m

# Confirm the resolver swap:
kubectl logs -n gibson gibson-0 | grep -E "neo4j.*resolver|tenantMode"
# Expected: "neo4j: constructed multiDBResolver"

kubectl exec -n gibson gibson-0 -- /usr/local/bin/gibson health --data-plane
```

After rollout the daemon reads from the Enterprise cluster for every tenant
call. `multiDBResolver` returns
`{BoltURI: shared, Database: "tenant_<sanitized>"}` (see
[`neo4j_endpoint_resolver_multidb.go:55-67`](./neo4j_endpoint_resolver_multidb.go)).

**Rollback:** revert chart value to `neo4j.tenantMode=instance` and re-roll.
Per-tenant Community instances are still running and still hold the
authoritative pre-freeze data — they continue serving traffic until Step 4
removes them.

---

## Step 4 — Operator deprovisions per-tenant StatefulSets

With the daemon no longer reading per-tenant instances, deprovision **one
tenant at a time**, lowest-traffic first. Wait 24-48h between batches to
confirm multi-db is healthy under each tenant's actual query mix. The
operator's existing `Deprovision` saga step at
`enterprise/platform/tenant-operator/internal/dataplane/neo4j.go` handles
cleanup; trigger via annotation.

```bash
TENANT_ID="acme-corp"

# Verify multi-db path healthy first:
kubectl exec -n gibson gibson-0 -- /usr/local/bin/gibson \
  tenant verify --tenant "$TENANT_ID" --store neo4j

# Trigger Neo4j-only deprovisioning (NOT the tenant itself):
kubectl annotate tenant "$TENANT_ID" \
  gibson.zero-day.ai/deprovision-neo4j-instance=true --overwrite

kubectl logs -n gibson -l app.kubernetes.io/name=tenant-operator --tail=200 \
  | grep -E "$TENANT_ID|neo4j"

# Confirm cleanup (StatefulSet + PVC + Service + K8s Secret + Vault path +
# endpoint registry row all gone):
kubectl get statefulset,pvc,svc,secret -n gibson | grep "tenant-${SANITIZED}-neo4j"
# Expected: empty
```

**Rollback:** restore the per-tenant StatefulSet from its most recent Velero
backup (Req 10.1) and flip `neo4j.tenantMode` back to `instance` for the
affected tenant in the registry table. Expensive — exhaust normal debugging
first.

---

## Step 5 — Chart cleanup

After **all** tenants migrated and 30 days of stable multi-db operation,
remove per-tenant scaffolding from the chart.

```bash
cd enterprise/deploy/helm/gibson

git rm templates/tenant-neo4j/tenant-neo4j-template.yaml
git rm templates/backup/tenant-neo4j-backup-cronjob.yaml
git rm templates/quotas/tenant-neo4j-quota.yaml

yq -i 'del(.tenantNeo4j)' values.yaml
yq -i '.version = "X.Y.Z"' Chart.yaml
git commit -am "chart: remove per-tenant neo4j scaffolding post-Enterprise migration"

# Stage first, verify clean daemon startup:
helm upgrade gibson . -n gibson -f values-staging.yaml
kubectl rollout status statefulset/gibson -n gibson
```

After this the chart no longer ships any Pattern B Neo4j scaffolding. The
daemon's `instanceResolver` code path remains compiled and unit-tested — it
becomes inert with no per-tenant Bolt URIs registered, but the abstraction is
preserved for future re-introduction (e.g. cost-driven downgrade off
Enterprise).

**Rollback:** revert the chart-removal commit and `helm upgrade`. Daemon code
is unchanged; only declarative resources go away in this step.

---

## Post-migration verification

```bash
# Every tenant resolved via multi-db:
kubectl exec -n gibson gibson-0 -- /usr/local/bin/gibson \
  tenant list --json | jq '.[] | {id, neo4jMode}'

# No per-tenant Neo4j resources remain:
kubectl get all -n gibson -l app.kubernetes.io/component=tenant-neo4j
# Expected: No resources found

# Enterprise cluster healthy:
kubectl exec -n gibson gibson-neo4j-cluster-core-0 -- \
  cypher-shell -u neo4j -p "$DST_PASS" -d system \
    "SHOW DATABASES YIELD name, currentStatus WHERE name STARTS WITH 'tenant_';"
```

Migration is complete when every row of the final query shows
`currentStatus: online`.
