# Runbook: Saga step recovery after a bug fix

When a bug in a saga step causes a tenant to permanently fail, the operator
sets `Blocked=True` (Reason: `SagaFailed`) on the Tenant CR and stops
retrying. Deploying a fixed operator image does **not** automatically clear
this condition — the tenant stays stuck until you explicitly signal a retry.

This runbook covers how to identify permanently-failed tenants, determine
when the retry annotation is appropriate, and execute the recovery.

---

## 1. Identify permanently-failed tenants

```bash
kubectl get tenants -A -o json \
  | jq -r '
      .items[] |
      select(.status.conditions[]? |
        .type == "Blocked" and .status == "True" and .reason == "SagaFailed"
      ) |
      "\(.metadata.name)  phase=\(.status.phase // "unknown")"
    '
```

This lists every Tenant whose saga is permanently blocked. Expected output:

```
acme-corp  phase=Initializing
another-co  phase=DataPlaneProvisioning
```

To see which step failed and why:

```bash
kubectl get tenant <name> -o json \
  | jq '.status.conditions[] | select(.type != "Ready")'
```

Look for a condition with `status: "False"` and a `message` that names the
failing step and the root error (e.g. `DataPlaneProvisioned: ... 409 conflict`).

---

## 2. When to use the retry annotation

Use `gibson.zeroroot.ai/saga-retry-from` **only** when `reason == "SagaFailed"`.

The operator recognises two other permanent-failure reasons that require human
intervention before retrying:

| Reason | Meaning | Recovery path |
|---|---|---|
| `SagaFailed` | Step returned a `clients.WrapPermanent` error (bug or transient infra issue now fixed) | Apply retry annotation (this runbook) |
| `SlugCollision` | The tenant's slug already exists; another tenant holds the namespace | Rename or delete the colliding tenant first |
| `InvalidSpec` | The Tenant CR's spec is structurally invalid (missing required field, unknown tier) | Fix the spec manually; the saga unblocks automatically |

> Setting the retry annotation on a `SlugCollision` or `InvalidSpec` tenant
> is safe — the annotation is a no-op when the reason is not `SagaFailed`.
> The condition survives and the tenant remains blocked until the spec is
> corrected.

---

## 3. Apply the retry annotation

The value is the **step name** where the saga should re-start. Use the name
that appears in the operator logs or in the failing condition message.

```bash
kubectl annotate tenant <name> \
  gibson.zeroroot.ai/saga-retry-from=<StepName>
```

Common step names (provision flow):

| Step | Phase | What it does |
|---|---|---|
| `ProvisionSecretsBackend` | Initializing | Creates the per-tenant Vault namespace |
| `ConfigureSecretsJWTAuth` | Initializing | Mounts JWT auth backend in Vault |
| `WriteSecretResolveGrantFGA` | Initializing | Writes FGA tuples for secret resolution |
| `DataPlaneProvisioned` | DataPlaneProvisioning | Runs the full Postgres/Neo4j/Redis/Vector pipeline |
| `TenantBrokerConfigWritten` | DataPlaneProvisioning | Writes the broker config Vault secret |
| `InitRedisKeyspace` | DataPlaneProvisioning | Allocates the per-tenant Redis logical DB |
| `InitNeo4jScope` | DataPlaneProvisioning (legacy) | Creates the Neo4j subgraph (pre-DataPlane cutover) |
| `CreateStripeCustomer` | Initializing | Creates the Stripe billing customer |
| `WriteInitialFGA` | Initializing | Writes initial FGA member/owner tuples |

To re-run **from the very first step**, use the step that failed (the saga
re-runs all steps in order from that name onwards — steps that already
completed are skipped via their `AlreadyProvisioned` or `IsConditionTrue`
guard).

Example (the Qdrant 409 bug from 2026-05-23, tenant-operator#197):

```bash
kubectl annotate tenant one \
  gibson.zeroroot.ai/saga-retry-from=DataPlaneProvisioned
```

---

## 4. Verify recovery

After annotating, the operator picks up the change on the next reconcile
(within the `RequeueInterval`, typically a few seconds). Watch the condition
transitions:

```bash
kubectl get tenant <name> -w -o json \
  | jq -r '
      now as $t |
      "[\(.metadata.resourceVersion)] \(.status.phase) | " +
      ([ .status.conditions[] | "\(.type)=\(.status)" ] | join(", "))
    '
```

Healthy recovery sequence:

1. `Blocked=True` disappears (annotation honored, condition cleared)
2. The failed step re-runs; step condition transitions to `True`
3. Downstream steps continue in sequence
4. `DataPlaneProvisioned=True` (or equivalent final step)
5. `Ready=True`; `phase` moves to the target phase

To confirm in operator logs:

```bash
kubectl logs -n gibson-workloads -l control-plane=controller-manager \
  --since=5m | grep -i "saga-retry\|<name>"
```

Look for:

```
honoring saga-retry-from annotation; clearing Blocked + retrying
```

followed by the step execution logs.

---

## 5. Bulk recovery after a fix deploy

When a bug affects multiple tenants, annotate all permanently-failed ones in
one pass:

```bash
kubectl get tenants -A -o json \
  | jq -r '
      .items[] |
      select(.status.conditions[]? |
        .type == "Blocked" and .status == "True" and .reason == "SagaFailed"
      ) |
      .metadata.name
    ' \
  | xargs -I{} kubectl annotate tenant {} \
      gibson.zeroroot.ai/saga-retry-from=<StepName>
```

Replace `<StepName>` with the step that the fixed bug was in. If the failing
step is different across tenants, query the condition message and script the
step name extraction accordingly.

---

## See also

- [Dirty schema migration recovery](runbook-dirty-schema-migrations.md) — Postgres-specific
- `internal/saga/runner.go` — `HonorRetryAnnotation` and `AnnotationSagaRetryFrom` constants
- `internal/saga/flows/provision.go` — step names and ordering for the provision saga
