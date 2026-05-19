# Credential Storage in Gibson

This doc maps **every credential** in the Gibson control plane to where it lives, why, and which patterns are canonical for new credentials.

## TL;DR — the canonical pattern

For any new **per-tenant runtime credential**:

1. **Operator writes** to the per-tenant Vault namespace at provisioning time, using the existing admin Vault client (`enterprise/platform/tenant-operator/internal/clients/vault/`).
2. **Daemon reads** via the existing secrets broker (`internal/secrets/service.go`). The broker handles per-tenant routing, caching, circuit breaking, and audit.
3. **Path convention**: `infra/<store>/<key>` for daemon-managed infra creds; user-supplied creds use whatever path/name the user picked via `SetSecret`.

If you find yourself writing K8s-Secret aggregation, projected-volume mounts, or sidecar reflectors for a per-tenant runtime cred, **stop** — Vault + broker is the answer. The only exceptions are documented below.

## The full credential map

### Layer 1 — Per-tenant runtime credentials (Vault + broker)

| Credential | Stored | Read by | Notes |
|---|---|---|---|
| **LLM provider keys** (OpenAI, Anthropic, etc.) | Per-tenant Postgres `tenant_secrets` table (default broker), or per-tenant Vault namespace if tenant configured Vault as their broker | Daemon via `internal/secrets/Service.Resolve` | User-supplied via `SetSecret` RPC. Envelope-encrypted with per-tenant KEK. |
| **Agent runtime credentials** | Same as above | Same | Same shape — user supplies via `SetSecret`. |
| **Per-tenant Neo4j infra creds** (`infra/neo4j/{username,password}`) | Per-tenant Vault namespace | Daemon's `instanceResolver` via the broker | Operator writes at provisioning (`Provision` step in `internal/dataplane/neo4j.go`); deletes on Deprovision. Pod's `NEO4J_AUTH` env var still uses a per-tenant K8s Secret — see Layer 4. |
| Future: per-tenant Qdrant API key, ClickHouse password, etc. | Per-tenant Vault namespace | Daemon via broker | Pattern: `infra/<store>/<key>`. |

**The broker stack** (`internal/secrets/`):

```
TenantConfigStore  — raw DB row I/O for tenant_secrets_broker_config
      |
ConfigStore        — Get/Set/Delete with Probe + audit
      |
Registry           — per-tenant provider cache; default-Postgres fallback
      |
CircuitBreaker     — per-(tenant,provider) fault containment
      |
AuditWriter        — compliance_signal events via Redis Streams
      |
Service            — single entry point for gRPC handlers
```

Provider factories registered (`internal/secrets/registry.go`):
- `postgres` — default; envelope-encrypted in per-tenant `tenant_secrets`. Always available.
- `vault` — opt-in per tenant via `tenant_secrets_broker_config`. Used for per-tenant infra creds (Neo4j, future stores).
- `awssm`, `gcpsm`, `azurekv` — factory hooks defined; not active by default.

Tenant→provider routing happens in `Registry.For(tenant)`, which reads the tenant's broker config row. If unset, falls back to Postgres.

### Layer 2 — Per-tenant computed credentials (no storage)

| Credential | Source | Read by | Notes |
|---|---|---|---|
| **Per-tenant Postgres role password** | KEK-derived: `derivePostgresPassword(masterKEK, tenantID)` at `internal/datapool/pgxpool_per_tenant.go` | Daemon's `pgxpool_per_tenant.ForTenant` derives independently per request | **Not stored anywhere.** Operator creates the per-tenant role with this exact derived password; daemon derives the same password to connect. Deterministic — same KEK + tenant always yields same password. Rotation = master KEK rotation. |

This is the cleanest "credential" of all: no storage means no leak surface. Other per-tenant infra creds could in principle follow this pattern, but Neo4j's password format restrictions and the operator/daemon needing to share the credential plane independently of the master KEK make Vault a better fit for new stores.

### Layer 3 — Per-tenant non-credentials (logical isolation, shared password)

| Credential | Stored | Notes |
|---|---|---|
| Per-tenant Redis | Single shared Redis password across all tenants (cluster-level). Per-tenant isolation is via **logical DB index 0..N**, allocated by the operator and tracked in the Redis master index DB. | The Redis password itself is a Layer 4 cluster-bootstrap cred. There is no per-tenant Redis credential. |

### Layer 4 — Cluster-level bootstrap credentials (K8s Secrets)

These exist for pod-startup needs and **deliberately do not live in Vault** — Vault itself depends on these to start, so chicken-and-egg.

| Credential | K8s Secret | Consumed by | Why K8s Secret |
|---|---|---|---|
| `AUTH_SECRET` | `gibson-dashboard-secrets` (key `better-auth-secret`) | Dashboard pod env var | Dashboard's Auth.js HMAC. Needed before any Gibson service is reachable. |
| Zitadel client secret | `gibson-zitadel-dashboard` | Dashboard pod env var | OIDC client cred. Needed for the Auth.js callback before Vault is up. |
| DB admin passwords (dashboard, FGA, langfuse, zitadel, tenant-postgresql) | One Secret per service, chart-managed | Each service's pod | Pod-bootstrap. Static set per-cluster. |
| Vault root token / unseal keys | `gibson-vault-init` (or external, depending on overlay) | Vault pod itself; operator's admin client | Vault's own bootstrap. Cannot live in Vault. |
| Per-tenant Neo4j pod's `NEO4J_AUTH` | `tenant-<id>-neo4j-auth` (one per tenant) | Neo4j pod's startup env | Neo4j has no native Vault integration. The operator creates this Secret with the same KEK-derived password it writes to Vault. **Daemon never reads this Secret** — only Neo4j itself does, at first boot. After Neo4j initializes its auth DB, the Secret is technically unneeded. Eliminating it would require a Vault Agent Injector sidecar in every tenant Neo4j pod — possible, not currently warranted. |

These all share a single property: **the consumer cannot reach Vault yet**, so a static K8s Secret is the only option.

### Layer 5 — Master KEK (root of trust)

| Credential | Source | Notes |
|---|---|---|
| Master KEK | `KeyProvider` abstraction at `internal/crypto/providers/`. In kind: `kubernetes` provider (reads K8s Secret `gibson-master-kek`). In production: `vault` provider (reads from Vault root namespace) is also supported. | The master KEK derives every per-tenant KEK and every Layer 2 (computed) credential. **Root of trust for Vault itself**, so cannot live in Vault for the kubernetes provider. The vault-provider variant moves the KEK into Vault's root namespace; the operator pre-provisions a Vault client token via the standard `VAULT_TOKEN` env var (the daemon does NOT initiate any Vault `auth/kubernetes` login — see ADR-0009 / jwt-spiffe-everywhere). |

### Layer 6 — Workload identity (not credentials)

SPIFFE/SPIRE X.509-SVIDs and JWT-SVIDs flow through the SPIRE Workload API socket. These are mTLS / JWT identities for service-to-service auth, not credentials in the "secret value" sense. They're emitted on demand by the SPIRE agent based on workload selectors; never stored.

## Decision tree for adding a new credential

```
┌─ Is this a credential a tenant USER would set or rotate?
│   └─ YES → broker stack via SetSecret RPC. Done.
│
├─ Is this a per-tenant infra credential the operator generates?
│   ├─ Can it be deterministically derived from master KEK?
│   │   └─ YES → Layer 2 (computed). No storage.
│   │
│   └─ NO → write to per-tenant Vault namespace at `infra/<store>/<key>`.
│      Read from daemon via broker.
│
├─ Does this credential need to exist BEFORE Vault is reachable?
│   └─ YES → Layer 4 (K8s Secret + chart-managed env injection).
│
└─ Is it the master KEK itself?
    └─ YES → KeyProvider abstraction; pick `kubernetes` or `vault` per env.
```

If none of the above fits, you've found a sixth pattern — **stop and discuss**. The five patterns above cover every credential category in Gibson today, by design.

## Code references

| Concern | File |
|---|---|
| Daemon broker entry point | `core/gibson/internal/secrets/service.go` |
| Provider factories (Postgres / Vault / cloud) | `core/gibson/internal/secrets/registry.go` |
| Postgres provider impl | `core/gibson/internal/secrets/providers/postgres/provider.go` |
| Master KEK provider abstraction | `core/gibson/internal/crypto/providers/{kubernetes,vault}.go` |
| Per-tenant Postgres password derivation | `core/gibson/internal/datapool/pgxpool_per_tenant.go` (`derivePostgresPassword`) |
| Per-tenant Neo4j credential resolver | `core/gibson/internal/datapool/neo4j_endpoint_resolver_instance.go` |
| Operator's admin Vault client | `enterprise/platform/tenant-operator/internal/clients/vault/` |
| Operator's per-tenant Vault namespace creation | `enterprise/platform/tenant-operator/internal/saga/flows/ensure_vault_namespace.go` |
| Operator's Neo4j credential write | `enterprise/platform/tenant-operator/internal/dataplane/neo4j.go` (`Provision`) |
| K8s Secret env injection | Helm chart `templates/*/statefulset.yaml` and `templates/*/secret.yaml` |

## Related docs

- `core/gibson/docs/data-plane.md` — per-tenant data isolation (Postgres, Neo4j, Redis, Vector)
- `core/gibson/docs/auth.md` — workload identity (SPIFFE) and Zitadel OIDC
- Spec `per-tenant-data-plane-completion` — the in-flight work that established the Vault-based Neo4j credential path
- Spec `secrets-broker` — the original broker stack design
