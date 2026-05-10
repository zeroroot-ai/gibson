# Changelog

All notable changes to the gibson daemon are documented here.

---

## Unreleased — working-memory-persistence

### Breaking change: checkpoint schema version 2

The checkpoint schema has been bumped from version 1 to version 2. The new
schema persists working memory and mission memory across daemon crashes and
records per-child execution status for parallel groups.

**Before upgrading:** Run `gibson mission drain --all` to complete or cancel
all in-flight missions. The new daemon refuses to resume version-1 checkpoints
with a clear error message:

```
unsupported checkpoint schema version 1 (this daemon requires version 2):
drain in-flight missions before upgrading
```

Completed or cancelled missions are unaffected.

**No SDK changes required.** All changes are confined to `core/gibson/`. No
`go.mod` bump is needed in any consumer repo (`core/ext-authz/`,
`opensource/adk/`, `opensource/gibson-tool-runner/`).

### Added

- `WorkingMemory.GetAll()` — point-in-time snapshot of the agent's ephemeral
  key-value scratchpad. Non-JSON-serializable values are skipped with a
  `level=warn` log. Snapshots larger than 1 MB are truncated lexicographically.
- `MissionMemory.GetAll(ctx)` — SMEMBERS + pipelined JSON.GET snapshot of the
  mission's Redis-backed shared context. Used as a recovery aid in checkpoints;
  Redis remains the authoritative source of truth on resume.
- `ParallelGroupState` checkpoint struct — records per-child `ChildStatus`
  (`pending`, `in_flight`, `completed`, `failed`) and child outputs for every
  active parallel group. Replaces the former `ParallelState map[string][]string`
  which only recorded completed-node IDs.
- `CheckpointIntegration.MarkChildDispatched` — transitions a child to
  `ChildStatusInFlight` when the scheduler dispatches it.
- `CheckpointIntegration.SetParallelGroupFailFast` — registers fail-fast
  semantics for a parallel group.
- `StateRestorer.RestoreFromCheckpoint` — now accepts optional
  `memory.WorkingMemory` and `memory.MissionMemory` parameters. When provided,
  working-memory entries are re-hydrated via `Set`, and mission-memory Redis
  availability is probed before resume (fail-fast on connection error).
- `ErrMissionMemoryUnavailable` sentinel — returned when Redis is unreachable
  at resume time.

### Changed

- `checkpoint.NewCheckpoint` — `Version` field now set to `CurrentCheckpoint
  Version` (2) instead of hard-coded 1.
- `checkpoint.FromCheckpoint` — fail-fast version guard at the top of the
  function; rejects any checkpoint whose `Version` field does not equal 2.
- `checkpoint.ValidateCheckpointVersion` — updated to accept only version 2.
- `DAGTraversalState.ParallelState` — retagged `json:"-" msgpack:"-"`
  (deprecated, excluded from wire in schema version 2).

---

## [0.36.0](https://github.com/zero-day-ai/gibson/compare/v0.35.1...v0.36.0) (2026-05-10)


### Features

* **daemon:** collapse TenantQuota to two enforced fields + Postgres reader ([01a90b6](https://github.com/zero-day-ai/gibson/commit/01a90b64904f0d5c61a2c27f780d24800c89dba2))
* install release-please and pr-title-lint ([#24](https://github.com/zero-day-ai/gibson/issues/24)) ([54e1375](https://github.com/zero-day-ai/gibson/commit/54e137584dac076976699d9a9d59e72ad4d95bc1))
* **mission:** add protojson MarshalDefinitionJSON / UnmarshalDefinitionJSON ([#28](https://github.com/zero-day-ai/gibson/issues/28)) ([8d05586](https://github.com/zero-day-ai/gibson/commit/8d05586ee7aa6ae1da520af26656e4ecda3c6113))
* **mission:** flip writer to protojson + dual-shape readers ([#30](https://github.com/zero-day-ai/gibson/issues/30)) ([e91ede9](https://github.com/zero-day-ai/gibson/commit/e91ede98207f3983927f2084fc193427fa71f9cc))
* **mission:** MissionStore interface speaks proto MissionDefinition ([#33](https://github.com/zero-day-ai/gibson/issues/33)) ([6a5400c](https://github.com/zero-day-ai/gibson/commit/6a5400c4fa3c500ff52cb4bbc31446504dbdff8f))
* **mission:** retype daemon helpers to proto MissionDefinition ([#34](https://github.com/zero-day-ai/gibson/issues/34)) ([a9f136a](https://github.com/zero-day-ai/gibson/commit/a9f136a720627aedf2d0b3d02d5d3cbfab71e890))
* **mission:** swap orchestrator pkg to proto MissionDefinition ([#31](https://github.com/zero-day-ai/gibson/issues/31)) ([5e5731c](https://github.com/zero-day-ai/gibson/commit/5e5731c04369c05c03b3c898fb77835659b2f530))


### Bug Fixes

* **authz:** remove misleading user-typed wildcard tuple comment ([3ddd29b](https://github.com/zero-day-ai/gibson/commit/3ddd29bde209e7e16f5adadad49ae91c0ff92798))

## v0.32.0 — 2026-05-04 — daemon reads per-tenant credentials from Vault (tenant-provisioning-unification-phase2 Phase 6)

The daemon's per-tenant Postgres + Neo4j credential resolution now
prefers typed Vault payloads over local KEK derivation and Postgres
registry-table lookups. Operator-side counterpart (Phase 3 + Phase
6.3 typed Neo4j writer) writes credentials to Vault during
provisioning so the daemon never needs to hold MasterKEK or
cross-reference a registry for the bolt URI.

Spec: `tenant-provisioning-unification-phase2`.

### Changed

- **`internal/datapool/pgxpool_per_tenant.go`** — new `resolveDSN`
  method routes between Vault-sourced (production) and KEK-derived
  (parent-spec fallback) paths. When `Config.PostgresSecretsReader`
  is wired, the daemon reads `pdataplane.PostgresCredentials` JSON
  from Vault `infra/postgres` via `broker.Resolve(ctx, name)` and
  uses `creds.DSN` unchanged (with `pool_max_conns` appended). When
  the reader is nil, falls back to the legacy KEK-based derivation.

- **`internal/datapool/neo4j_endpoint_resolver_instance.go`** — new
  `tryVaultPayload` helper reads the typed
  `pdataplane.Neo4jCredentials` JSON from a single Vault path
  `infra/neo4j` (BoltURI + Username + Password). Eliminates the
  cross-reference to the `tenant_neo4j_endpoints` Postgres registry
  table for clusters where the operator has shipped Phase 6.3.
  Legacy split-key reader (`infra/neo4j/username` +
  `infra/neo4j/password`) + registry-table fallback retained for
  clusters mid-cutover.

- **`internal/daemon/daemon.go`** — wires `PostgresSecretsReader` via
  `FuncSecretsReader` closure that defers to `d.secretsService`
  resolve at RPC time (same pattern as the Neo4j resolver — captured
  lazily because `secretsService` is initialized after `NewPool`).

### Migration safety

Both refactors preserve the parent-spec code paths as fallbacks. A
cluster running this daemon with an older operator (no Vault writes)
continues to work via the legacy paths. The fallbacks are removable
once the chart's pre-upgrade backfill Job (Phase 8) has populated
Vault for every existing tenant — that is a future release.

---

## v0.31.0 — 2026-05-04 — platform package extensions (tenant-provisioning-unification-phase2 Phase 1)

Adds the platform-package primitives the tenant-operator + daemon need
for the Vault-as-credential-store cutover (Phase 2-8 of
tenant-provisioning-unification-phase2). Non-functional for the daemon
itself; consumed by the operator and daemon refactors in subsequent
releases.

Spec: `tenant-provisioning-unification-phase2`.

### Added

- **`pkg/platform/dataplane/payloads.go`** — typed Vault credential
  payload structs: `PostgresCredentials`, `Neo4jCredentials`,
  `RedisCredentials`, `VectorCredentials`, `LangfuseCredentials`. The
  operator marshals one of these to the canonical per-tenant Vault path
  (`infra/postgres`, `infra/neo4j`, etc.); the daemon unmarshals the
  same struct. Single source of truth for the JSON shape — no drift
  between operator writer and daemon reader.

- **`pkg/platform/saga/adapt.go`** — `FromStepFn` adapter wraps a
  function-form step into the new `Step` interface, with `AdaptOption`
  pattern (`WithRequires`, `WithRequiredClients`, `WithSkipFn`,
  `WithDeprovisionFn`). Eases incremental migration of the operator's
  flow files: a closure can be wrapped today and converted to a struct
  implementation later without changing runner-side construction.

- **`pkg/platform/saga.ValidateAtStartupVerbose`** — returns a one-line
  success summary suitable for the operator's startup log:
  `"saga: validated N step(s), all M capabilit(ies) satisfied
  (production mode | dev mode (capability checks bypassed))"`. Existing
  `ValidateAtStartup` signature unchanged for parent-spec callers;
  verbose form delegates to it.

### Tests

12 new unit tests covering JSON round-trip for every payload struct,
field-name regression guard, FromStepFn defaults + all options
together + nil-fn panic, and ValidateAtStartupVerbose
production/dev/failure paths.

### Module discipline

`go list -deps github.com/zero-day-ai/gibson/pkg/platform/...` still
resolves only to stdlib + `github.com/zero-day-ai/sdk/auth` + the
controller-runtime/k8s.io types from the parent spec. No new
transitive deps.

---

## v0.30.0 — 2026-05-04 — platform package foundation (tenant-provisioning-unification Phase 1)

Adds `core/gibson/pkg/platform/` — a leaf package that holds the
canonical naming, KEK derivation, saga step abstraction, and
shared-store constants that both the gibson daemon and the
tenant-operator must agree on byte-for-byte.

This release is non-functional for the daemon itself (no internal/
package consumes the new pkg/platform/ types yet — that wiring lands in
later phases). It exists so the tenant-operator can pin against
`gibson@v0.30.0` and start importing from `gibson/pkg/platform/...`
without us having to maintain duplicate copies of the naming logic in
two repos.

Spec: `tenant-provisioning-unification`.

### Added

- **`pkg/platform/tenant.Names`** value type. Sealed wrapper around
  `auth.TenantID` exposing typed methods for every per-tenant resource
  name: `PostgresDB()`, `PostgresAppRole()`, `Neo4jStatefulSet()`,
  `Neo4jBoltURI(operatorNs)`, `RedisIndexField()`, `QdrantCollection()`,
  `VaultPathPrefix()`, `VaultPolicyName()`, `VaultJWTRoleName()`,
  `FGAObject()`, `ZitadelOrgSlug()`, `LangfuseProject()`, `Namespace()`.
  Replaces the duplicated sanitizer code that lived in both the operator
  and the daemon. The Postgres role suffix is canonical `_app` (the
  legacy `_role` is retired by spec Requirement 1.3).

- **`pkg/platform/tenant.DeriveTenantKEK`** + `PostgresPasswordFromKEK`
  + `Zeroize`. HKDF-SHA256 derivation with KEKInfo
  `gibson/v1/tenant-kek` — byte-for-byte identical to the legacy
  `internal/datapool/kek.go` and `tenant-operator/internal/dataplane/kek.go`
  (verified by KAT vectors in tests). Used in dev mode; production paths
  call Vault transit derive instead.

- **`pkg/platform/saga.Step`** unified interface (`Name`, `Condition`,
  `Requires`, `RequiredClients`, `Provision`, `Deprovision`, `Skip`),
  plus `ConditionedObject` carrier interface. Replaces both the old
  `tenant-operator/internal/saga.Step` struct and the parallel
  `dataplane.Step` struct with a single abstraction.

- **`pkg/platform/saga.ClientCapability`** enum (12 values: postgres-admin,
  vault-admin, vault-transit, kubernetes, zitadel-admin, fga,
  redis-admin, qdrant-admin, stripe, langfuse, daemon-grpc, smtp).
  Each `Step` declares its required capabilities; the runner's
  `ValidateAtStartup` check fails the operator pod startup in
  production mode if any required capability isn't satisfied — killing
  the silent-no-op bug class.

- **`pkg/platform/saga.Runner`** with topological-order execution
  (`TopoSort`), aggregated startup-gate validation, exponential
  retry/backoff capped at MaxBackoff, condition writes via shared
  `SetCondition`/`FindCondition`/`IsConditionTrue` helpers, and
  pluggable `AuditHook` + `MetricsHook` so operator-specific Loki/
  Prometheus integration plugs in cleanly without polluting the
  platform package.

- **`pkg/platform/dataplane`** constants: `RedisIndexHashKey =
  "gibson:tenant:index"` (replacing the historical operator/daemon
  mismatch), `PlatformDB = "gibson_platform"` (renamed from
  `gibson_dashboard`; one-time chart Job handles the rename),
  `LegacyPlatformDB`, `VaultMasterKEKKey`, plus the per-tenant Vault
  path constants `VaultPathInfra{Postgres,Neo4j,Redis,Vector,Langfuse,KEK}`.

### Tests

22 new unit tests across `pkg/platform/{tenant,saga}/`. Including KAT
vectors for KEK derivation, regression guards against the recurring
`_role` vs `_app` and `tenant:index` vs `tenant_db_index` mistakes,
topo-sort cycle/unknown-ref/duplicate-name detection, and
ValidateAtStartup aggregation in both production and dev modes.

### Module discipline

`go list -deps github.com/zero-day-ai/gibson/pkg/platform/...` resolves
only to stdlib + `github.com/zero-day-ai/sdk/auth` + the standard
controller-runtime/k8s.io types needed for `metav1.Condition` and
`record.EventRecorder`. No daemon-internal driver pulls — keeping the
operator's go.sum footprint small when it adds the gibson dep in
Phase 2.

---

## v0.29.0 — 2026-05-04 — tenant secrets broker completion

Wires the per-tenant secrets-broker switch end-to-end. The dashboard's
`/settings/secrets-backend` page now actually changes which broker serves a
tenant's secrets — before this change, calls landed as `Unimplemented`
because the SDK admin v1 service was never registered, and even if a
config row had been written, the in-memory broker cache wouldn't have
invalidated until the daemon restarted.

Spec: `tenant-secrets-broker-completion`.

### Added

- **`gibson.admin.v1.TenantAdminService` is now registered in production.**
  `internal/daemon/grpc.go` constructs `internal/admin.NewTenantAdminServer`
  using the broker-stack outputs (`d.configStore`, `d.brokerAuditWriter`,
  `d.brokerFactories`, `d.secretsRegistry`, `d.secretsService`) stored on
  `daemonImpl` by `initBrokerStack`. Coexists alongside the daemon-local
  `gibson.tenant.v1.TenantAdminService` (different proto package). When
  the broker stack failed to initialize (no system KEK or dashboard
  Postgres), the new `internal/admin.NewUnavailableTenantAdminServer()`
  stub is registered instead, returning `codes.Unavailable` on each
  broker-config RPC so dashboards see an actionable error rather than the
  misleading `Unimplemented`.
- **`SetBrokerConfig` now invalidates the per-tenant broker cache.** The
  handler calls `Registry.Reload(ctx, tenant)` immediately after a
  successful persist. Without this, a tenant who switched providers kept
  hitting the previously-cached broker until the next pod restart.
- **`CountSecrets` admin RPC handler.** Delegates to
  `secrets.Service.List(ctx, sdksecrets.Filter{})` and returns
  `int64(len(names))`. No names, values, or per-row metadata leak through
  the response. Dashboard uses this to gate the migration-warning UX
  before a provider switch.
- **`MapProbeFactory`** in `internal/admin/probe_factory.go` adapts
  `map[string]secrets.ProviderFactory` to the `ProviderProbeFactory`
  interface for `TenantAdminConfig`.
- **`TenantAdminConfig.Reloader` and `TenantAdminConfig.SecretsService`**
  narrow interfaces (`Reload(ctx, tenant)` and `List(ctx, Filter)
  ([]string, error)`) — `*secrets.Registry` and `*secrets.Service`
  satisfy them implicitly, tests substitute fakes.

### Changed

- **SDK pin bumped to `v0.99.0`** (adds the `CountSecrets` RPC).
- **Authz registry regenerated** — one new entry in each of
  `registry.go`, `registry.yaml`, `permissions.ts`, `audit.csv` for
  `/gibson.admin.v1.TenantAdminService/CountSecrets` (`relation: "admin"`,
  `allowed_identities: USER`, same envelope as the rest of the
  broker-config trio).

### Tests

- New `internal/admin/tenant_admin_integration_test.go` drives the full
  handler → real `secrets.Registry` round-trip in-memory and asserts that
  post-`Set`, `Registry.For` returns the just-configured provider — the
  central regression-guard for this spec. Verified to fail red if the
  `Reload` call is removed.
- New unit tests cover `Reload`-on-success / no-`Reload`-on-probe-failure
  / no-`Reload`-on-persist-failure, plus `CountSecrets` happy path /
  empty / no-tenant-context / `List`-error-propagates, plus extended
  constructor validation for the two new required deps.

---

## v0.28.0 — 2026-05-02 — drop fga_model.fga coverage stub

Bumps SDK to v0.98.1 (drops the generator's FGA coverage stub) and removes
the now-unused `internal/authz/registry/fga_model.fga`. The OpenFGA model
remains hand-maintained at `internal/authz/model.fga` (the only source the
`gibson-fga-init` Job has ever consumed, via `files/fga-model.json`).

### Changes

- **`internal/authz/registry/fga_model.fga` deleted** — the generator no
  longer emits it; the file existed only as a derived snapshot of the
  proto-annotated relations and was never read at runtime.
- **`internal/authz/model.fga` banner** simplified — the "DO NOT confuse
  with the registry stub" warning is gone with the stub itself.
- **`scripts/check-fga-model-headers.sh`** trimmed to only assert the
  `AUTHORITATIVE-FGA-MODEL` marker on `model.fga`.
- **`.github/workflows/publish-private-authz-registry.yml`** stops pushing
  the `fga_model.fga` layer to `ghcr.io/zero-day-ai/internal-authz-registry`;
  three layers ship now (`registry.yaml`, `permissions.ts`, `registry.go`).
- **`go.mod`** bumped to `github.com/zero-day-ai/sdk v0.98.1`.

Spec: ad-hoc cleanup informed by the cross-repo-cohesion-fixes audit.

---

## v0.27.0 — 2026-05-02 — tenant-role-taxonomy

Introduces the three-tier tenant role hierarchy (`owner > admin > member`)
at the FGA level and surfaces the highest role through the daemon's
`ListMyMemberships` RPC. Adds a one-shot backfill binary to seed owner
tuples for existing tenants.

Spec: `tenant-role-taxonomy`.

### Changes

- **FGA model:** `internal/authz/model.fga` — `type tenant` gains
  `define owner: [user]` as the first relation. `define admin: [user]`
  is rewritten to `define admin: [user] or owner` (computed union). The
  existing `define member: [user] or admin` is unchanged. This means:
  - Check(`owner`, `admin`) → true (downward propagation)
  - Check(`owner`, `member`) → true (downward propagation)
  - Check(`admin`, `owner`) → false (no upward propagation)
  - Header documentation and `RELATION SEMANTICS` block updated with
    worked tuple examples for each role.

- **Daemon `ListMyMemberships`** — builds a `2*N`-item `BatchCheck`
  (one owner check + one admin check per tenant) in a single FGA call.
  New private helper `pickHighestRole(isOwner, isAdmin bool) string`
  returns the highest role. Per-tenant audit log line names the resolved
  role. Fail-closed-to-member degrade path on BatchCheck error preserved.

- **`cmd/tenant-owner-backfill`** — new binary that:
  - Lists all `Tenant` CRs (cluster-scoped).
  - For each tenant: finds the founding `TenantMember` (earliest
    `creationTimestamp` with non-empty `status.userId`).
  - Calls FGA Check for the `owner` relation; writes the tuple if missing.
  - Logs structured per-tenant outcome:
    `outcome=backfilled|already_owner|no_founder_found`.
  - Exits zero unconditionally (per-tenant skips do not fail the Job).
  - Built into the gibson container image at
    `/usr/local/bin/tenant-owner-backfill`.

- **`fga-smoke-test` CI workflow** — new
  `.github/workflows/fga-smoke-test.yml` runs `TestModel_TenantRoleHierarchy`
  (three hierarchy assertions against an ephemeral OpenFGA container via
  testcontainers) on every PR touching `internal/authz/model.fga`.

### No OCI registry / proto changes

The authz registry artifacts (`internal/authz/registry/`) are unchanged —
no proto annotations were modified. The OCI artifact at
`ghcr.io/zero-day-ai/internal-authz-registry:v0.27.0` is published by CI
on tag push but its content is identical to v0.26.0.

### Validation

- `go build ./...` and `go test ./internal/authz/... ./internal/daemon/api/...` clean.
- `TestPickHighestRole` table test: 4 input combinations, all pass.
- `TestListMyMemberships_RoleDerivation_*`: 4 new cases, all pass.
- `go build ./cmd/tenant-owner-backfill/...` succeeds.

---

## v0.26.0 — 2026-05-01 — discovery-bitfield-coherence

Corrects the `allowed_identities` bitmask on the eleven
`DiscoveryService` RPCs from `8` (PLATFORM_OPERATOR-only) to `7`
(USER | SERVICE | COMPONENT). These RPCs carry `relation: "member"` —
any tenant member should be able to call them — but the incoherent
bitfield was silently blocking every USER caller after
`zero-trust-hardening` Req 2 enabled per-RPC identity-class
enforcement at ext-authz.

Spec: `discovery-bitfield-coherence`.

### Changes

- **SDK bump:** `github.com/zero-day-ai/sdk` v0.95.0 → v0.96.0.
- **Registry regen:** all five registry artifacts regenerated via
  `make authz-registry`. The eleven affected RPCs (`WhoAmI`,
  `ListPlugins`, `DescribePlugin`, `ListTools`, `DescribeTool`,
  `ListAgents`, `DescribeAgent`, `ListLLMSlots`, `ListReportSurfaces`,
  `ValidateComponent`, `SuggestMissingCapability`) now show
  `allowed_identities: [USER, SERVICE, COMPONENT]` in `registry.yaml`
  and `USER|SERVICE|COMPONENT` in `audit.csv`. The `fga_model.fga` is
  unchanged — the FGA relations and object types are unaffected.
- **OCI artifact:** `ghcr.io/zero-day-ai/internal-authz-registry:v0.26.0`
  published by the `publish-private-authz-registry` CI workflow on tag
  push.

### No handler changes

The daemon's `listCatalog` already unions the caller's tenant catalogue
with the `_system` shared catalogue; no code change was required.
Tenant-scoping is preserved at the FGA layer via
`object_deriver: "tenant_from_identity"` — a USER cannot probe another
tenant's catalogue.

### Validation

- `go build ./...` and `go test ./internal/authz/registry/...` clean.
- Registry drift gate: `make authz-registry && git diff --exit-code
  internal/authz/registry/` exits 0.

---

## v0.25.1 — 2026-05-01 — daemon loose-mode bypass for self-mode RPCs

Bugfix on top of v0.25.0. The daemon's `registryAwareUnary` /
`registryAwareStream` interceptors only bypassed strict tenant
validation for `entry.Unauthenticated` (Connect, Ping). Self-mode RPCs
(`ListMyMemberships`, `GetMyPermissions`) by design have no tenant
context — sign-in calls them BEFORE the active-tenant cookie is set —
but they fell through to the SDK's strict 5-header interceptor and
denied with `auth: identity headers absent: missing
[x-gibson-identity-tenant]`.

### Fix

Extended the bypass condition to `entry.Unauthenticated || entry.Self`.
The handler still receives a `caller.Subject` extracted from
ext-authz's verified identity header; tenant is left zero (handler
self-scopes). The four-layer defense from zero-trust-hardening is
unchanged: Envoy `jwt_authn` + ext-authz subject minting + daemon
SPIFFE-mTLS-pinned listener + ext-authz `AllowedIdentities` bitfield.

### Validation

- `go build ./...` and `go vet ./...` clean.
- Live verification on kind-gibson: sign-in flow's
  `ListMyMemberships` now returns 200 OK; ext-authz logs show
  `entry_mode=self result=allow`; daemon logs show no further
  `identity-check denied` warnings on these RPCs.

Closes self-mode-authz Req 4.6.

---

## v0.25.0 — 2026-05-01

### Security — self-mode-authz spec

- **SDK bump to v0.95.0; authz registry regenerated.**
  `GetMyPermissions` and `ListMyMemberships` now carry `self: true +
  allowed_identities: [USER]` in the generated registry, replacing the
  hotfix `unauthenticated: true` annotations. The `self` mode preserves
  JWT authentication via Envoy `jwt_authn` and applies the identity-class
  bitfield check (USER only) at ext-authz, while skipping the FGA tuple
  lookup that was impossible for pre-tenant-context self-bootstrap calls.
  Layer 4 of defense-in-depth (per-RPC identity-class enforcement) is
  restored on these two RPCs. Spec: self-mode-authz Req 4.1–4.3.

- **OCI registry artifact `ghcr.io/zero-day-ai/internal-authz-registry:v0.25.0`
  is the first artifact containing `self: true` entries.**
  Requires ext-authz v0.2.0+ to parse; see Req 6.1 for release order
  requirements.

### Audit trail

- **`audit.csv` gains a `mode` column at the END of each row** (positional
  compatibility per design.md decision). Values: `rule | self |
  unauthenticated`. Self-mode rows populate `identities` while
  `relation`/`object_type`/`deriver` remain empty strings. Spec:
  self-mode-authz Req 5.1, 5.2, 5.3.

### Tests

- `TestGetMyPermissionsAndListMyMembershipsAreAuthenticated` — reworked to
  assert the new self-mode shape: `Self==true`, `AllowedIdentities.Has(USER)`,
  `Unauthenticated==false`, `Relation==""`. Failure message references spec
  `self-mode-authz`.
- `TestSelfModeEntriesAreUserOnly` — new test walking `registry.Registry`;
  asserts every `Self==true` entry has the USER bit in `AllowedIdentities`.
- `TestOnlyConnectAndPingAreUnauthenticated` — unchanged; the
  `unauthenticated: true` set does not grow (Req 4.5).

---

## v0.24.0 — 2026-05-01

### Fix — zero-trust-hardening follow-up

- **Authz registry: revert `tenant_admin`/`tenant_member` relations back to
  `admin`/`member`** on all `TenantAdminService` and `AdminService` RPCs.
  The v0.23.0 registry regen introduced the wrong relation names from a
  stale SDK proto snapshot; this fixes the drift.

---

## v0.23.0 — 2026-05-01

### Security — zero-trust-hardening spec

- **SDK bump to v0.92.0; authz registry regenerated.**
  `GetMyPermissions` and `ListMyMemberships` no longer carry `unauthenticated: true` in the
  generated registry — they now require an authenticated USER token through Envoy.
  Only `Connect` and `Ping` remain unauthenticated (pre-auth liveness checks).
  Closes the confused-deputy permission-enumeration oracle (Req 5.1, 5.2).

- **SPIFFE init is now fail-closed (Req 1.1).**
  Previously, if `workloadapi.NewX509Source` failed the daemon logged a warning
  and fell back to a plaintext gRPC listener, exposing the identity-header trust path
  to any in-cluster attacker that could reach the pod IP during a SPIRE outage.
  The daemon now returns a fatal error and refuses to start.

- **Non-loopback bind rejected without SPIFFE (Req 1.2).**
  Added `rejectNonLoopbackWithoutSPIFFE()` validator called at `buildGRPCServer` startup.
  Addresses `0.0.0.0`, `[::]`, `:port`, routable IPs, and non-loopback hostnames.
  Loopback-only builds (`127.0.0.1`, `localhost`, `[::1]`) continue to work with a
  startup warning.

- **Dead HMAC code removed (Req 8.1).**
  `loadHMACSecret()` in `internal/daemon/grpc.go` was a vestige of a removed identity-header
  HMAC verification layer. The function and its associated env var
  (`GIBSON_IDENTITY_HMAC_SECRET_PATH`) are deleted. The trust model is
  SPIFFE X.509 mTLS between Envoy and the daemon; no shared secret is involved.
  Stale `HMAC-verified` doc comments updated in `authconfig.go` and test files (Req 8.3).

### Tests

- `TestRejectNonLoopbackWithoutSPIFFE` — table-driven, 9 address cases (loopback/non-loopback).
- `TestSPIFFEInitFailClosed` — source-text value-lock asserting the old warn-and-fallback
  pattern is gone.
- `TestBuildGRPCServer_NonLoopbackWithoutSPIFFE` / `TestBuildGRPCServer_LoopbackWithoutSPIFFE`.
- `TestIdentityResolverHasNoAuthCallers` — AST walk via `golang.org/x/tools/go/packages`
  asserting zero non-test imports of `identityresolver` outside the package (Req 3.4).
- `TestOnlyConnectAndPingAreUnauthenticated` — registry regression guard (Req 5.3).
- `TestGetMyPermissionsAndListMyMembershipsAreAuthenticated` — explicit assertion on the
  two previously-misconfigured RPCs.

---
