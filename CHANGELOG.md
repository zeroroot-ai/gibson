# Changelog

All notable changes to the gibson daemon are documented here.

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
