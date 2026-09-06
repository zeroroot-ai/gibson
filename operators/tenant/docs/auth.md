# auth.md — `zeroroot-ai/tenant-operator`

Auth model from the tenant-operator's perspective. AI-agent-facing.
Spec: `unified-identity-and-authorization` Requirement 11.

## What this is

The tenant-operator is a Kubernetes operator that reconciles `Tenant`
CRDs. Its auth surface has three sides:

1. **Outbound to the Gibson daemon** — uses its own Zitadel service
   account to call admin RPCs (CG-JWT not required; all calls are
   workload-acting).
2. **Outbound to Zitadel admin API** — provisions per-tenant Zitadel
   organizations and project memberships during the saga's
   `EnsureZitadelOrg` step.
3. **Outbound to OpenFGA** — writes tenant→admins / tenant→members
   tuples via the FGA write API. Reverse on tenant teardown.

The operator authenticates to **everyone** with its own Zitadel
service-account JWT obtained via the OAuth2 client_credentials grant.
No static tokens, no PATs, no `gsk_` keys.

## Files

| Concern | File |
|---|---|
| Service identity (Zitadel client_credentials → daemon gRPC dial) | [`internal/grpc/client.go`](../internal/grpc/client.go) |
| Tenant lifecycle saga (Zitadel org create + FGA tuples + data plane) | [`internal/saga/flows/provision.go`](../internal/saga/flows/provision.go), [`provision_zitadel.go`](../internal/saga/flows/provision_zitadel.go) |
| Tenant teardown saga (reverse order: data plane → FGA → Zitadel org) | [`internal/saga/flows/teardown.go`](../internal/saga/flows/teardown.go), [`teardown_zitadel.go`](../internal/saga/flows/teardown_zitadel.go) |
| Zitadel admin API client | [`internal/clients/zitadel/client.go`](../internal/clients/zitadel/client.go) |
| FGA HTTP client | [`internal/clients/fga/`](../internal/clients/fga/) |
| Operator main / wiring | [`cmd/main.go`](../cmd/main.go) |

## Service identity

The operator pod has its own Zitadel service account, distinct from the
dashboard's. Two env vars are required:

```
ZITADEL_TENANT_OPERATOR_CLIENT_ID
ZITADEL_TENANT_OPERATOR_CLIENT_SECRET
ZITADEL_ISSUER         # e.g. https://auth.zeroroot.ai
```

The Helm Secret `gibson-zitadel-tenant-operator` mounts these
([`enterprise/deploy/helm/gibson/templates/auth/zitadel-service-accounts-secret.yaml`](../../../deploy/helm/gibson/templates/auth/zitadel-service-accounts-secret.yaml)).

[`internal/grpc/client.go`](../internal/grpc/client.go) constructs an
oauth2 client_credentials TokenSource that:

- exchanges client_id/client_secret for a Zitadel JWT,
- caches the JWT and refreshes before expiry,
- attaches `Authorization: Bearer <jwt>` to every outbound daemon RPC
  via a gRPC interceptor.

The dial target is the Envoy edge (the chart wires it via the
`gibson` Service / Ingress); the daemon never sees direct operator
traffic. SPIFFE X509-SVID mTLS is composed automatically when the
Workload API socket is present.

The credentials never appear in any log line; the
`scripts/check-no-legacy-auth.sh` and pre-commit gitleaks both catch
accidental references.

## Tenant lifecycle saga

Tenant creation flows through a saga ([`internal/saga/runner.go`](../internal/saga/runner.go))
of idempotent steps. Each step has a CRD condition; the saga commits
each condition before running the next.

```
Tenant create:
  1. EnsureZitadelOrg            -> Status.ZitadelOrgID
  2. EnsureFGAOwnerTuple         -> Status.FGAOwnerTupleWritten
  3. ProvisionPostgresDatabase   -> Status.DataPlane.Postgres.Ready
  4. ProvisionNeo4jDatabase      -> Status.DataPlane.Neo4j.Ready
  5. ProvisionRedisLogicalDB     -> Status.DataPlane.Redis.Ready
  6. ProvisionVectorCollection   -> Status.DataPlane.Vector.Ready
  ...
Tenant delete:
  reverse order, each step idempotent on 404 / not-found.
```

The two auth-relevant steps:

- **EnsureZitadelOrg** ([`provision_zitadel.go`](../internal/saga/flows/provision_zitadel.go))
  calls Zitadel's Management API to create the organization. The
  fast-path verifies an existing `Status.ZitadelOrgID` still exists
  before re-creating. Idempotent: 409/already-exists is treated as
  success.
- **FGA tuple writes** (in [`provision.go`](../internal/saga/flows/provision.go))
  call the FGA HTTP API to add the initial tenant→admin / tenant→member
  tuples. The owner tuple binds the human who initiated tenant creation
  (carried on the Tenant CRD spec) to the new tenant.

The data-plane steps are documented separately in
[`data-plane.md`](./data-plane.md). They are gated by FGA tuple
existence — provisioning a tenant's Postgres database without the
corresponding FGA tuples leaves an unreachable database.

## Zitadel admin API client

[`internal/clients/zitadel/client.go`](../internal/clients/zitadel/client.go)
wraps the Zitadel Management API for org / member CRUD. Auth uses a
**Personal Access Token (PAT)** mounted from the
`<release>-zitadel-iam-admin-pat` Secret — this is a Zitadel-side
constraint (the Management API requires IAM-admin authority that
client_credentials grants do not carry). The PAT is issued out-of-band
(the bootstrap Job at deploy time) and rotates on operator schedule.

Operations:

- `CreateOrganization`, `GetOrganization`, `DeleteOrganization` (all
  idempotent).
- `AddMember`, `RemoveMember` (idempotent; 409 / 404 → success).
- `SendInvitation` for the initial owner email.

The PAT is **the only place** in the polyrepo where a long-lived
admin credential exists, and it is held in a Secret separate from the
tenant-operator's service-account credentials. The dashboard does not
have access to it.

## FGA HTTP client

[`internal/clients/fga/`](../internal/clients/fga/) is a thin HTTP
client to OpenFGA's `gibson-fga:8080` endpoint. The operator writes
tuples directly (it does not go through ext-authz, which only reads
tuples). On tuple writes the operator emits a per-tenant invalidation
event the daemon forwards to ext-authz's cache for fast invalidation.

## What's gone

| Removed | Why |
|---|---|
| `gsk_` API key issuance code | Replaced by the dashboard's Register Agent UI calling Zitadel admin API directly. The operator no longer mints credentials. |
| Static-token handling | Operator authenticates with its own Zitadel service account; tokens are short-lived and refreshed automatically. |
| Direct connection from dashboard to Zitadel admin API for tenant org CRUD | The dashboard creates per-tenant org via the operator's saga; only agent-machine-user creation lives in the dashboard. |

## Three deployment shapes

| Shape | Operator deployment |
|---|---|
| Wholly on-prem | Operator runs in the customer cluster; Zitadel + FGA in the same cluster. |
| SaaS + customer-network agents | Operator runs in the SaaS cluster; reconciles SaaS tenants. Customer-network agents are Zitadel service accounts under the SaaS tenant's org. |
| Pure SaaS (your-managed agents) | Same as above — operator only ever runs in the cluster that owns the Tenant CRD instances. |

## Cross-link

- Adding a new auth-touching code path (e.g. wiring a new dashboard
  provisioning API caller): [`how-to-add-an-auth-call.md`](./how-to-add-an-auth-call.md).
- Wrong vs right code shapes: [`forbidden-patterns.md`](./forbidden-patterns.md).
- Machine-readable rules: [`rules.yaml`](./rules.yaml).
- Per-tenant data plane (the data-plane half of the saga): [`data-plane.md`](./data-plane.md).
- Daemon-side: `core/gibson/docs/auth.md`.
- Dashboard auth: `enterprise/platform/dashboard/docs/auth.md`.
- Helm-side wiring (Zitadel service-account Secrets, FGA chart): `enterprise/deploy/docs/auth.md`.
