# Gibson daemon — CLAUDE.md

> **Workflow rules:** see [`zeroroot-ai/.github` → `AGENTS.md`](https://github.com/zeroroot-ai/.github/blob/main/AGENTS.md) for branch / PR / commit / release / rebase rules. Conventional Commits MANDATORY (drives release-please). Never push to main, never merge your own PR. Repo-local rules below override only when explicitly noted.

Read this before editing the daemon. The daemon module is rooted at the repo top (`internal/`, `cmd/`, `pkg/`, `models/`); there is no `core/gibson/` subtree.

## Authz registry pipeline

The authorization rule book lives at `internal/platform/authz/registry/`:
- `registry.go` — Go map `Registry` (import path `github.com/zeroroot-ai/gibson/internal/platform/authz/registry`)
- `registry.yaml` — runtime YAML; `embed.go` embeds it and the daemon serves it to ext-authz over mTLS (see below). `YAML()` returns the bytes.
- `permissions.ts` — TypeScript map for the dashboard sister spec
- `audit.csv` — auditor-friendly flat table (rpc, relation, object_type, deriver, identities, source_proto_file)

**Runtime delivery to ext-authz (deploy#852).** The daemon serves the embedded
`registry.yaml` from an mTLS listener (`internal/server/daemon/authz_registry_subsystem.go`,
`GET /authz/registry.yaml` on `GIBSON_AUTHZ_REGISTRY_PORT`, default `:8086`),
authorized to an explicit SPIFFE reader allow-list
(`GIBSON_AUTHZ_REGISTRY_READER_SVIDS`, e.g. the ext-authz SVID). ext-authz
fetches it at startup (`EXT_AUTHZ_REGISTRY_URL`), pinning the daemon's SVID. This
makes the daemon the **single source of truth**: `registry.go` (the daemon's own
enforcement view) and the served `registry.yaml` are generated together, so
ext-authz can never enforce a policy that has drifted behind the deployed daemon.
The old separately-versioned OCI artifact (`internal-authz-registry:<tag>` + chart
`sdk.version` pin) is retired — it silently default-denied any RPC added after the
last manual publish (e.g. `SetSignupProgress`).

The OpenFGA model itself is hand-maintained at `internal/platform/authz/model.fga`
(compiled to the JSON `gibson-fga-init` loads by `cmd/gen-fga-model-json`,
which the Helm chart runs to produce the init ConfigMap); the registry
generator no longer emits an FGA stub.

These are **generated artifacts** — do NOT hand-edit them. Run regen instead.

The annotations come from **two** proto sources (after the platform-sdk dissolution, gibson#781), merged via `cmd/fds-merge` into a single FileDescriptorSet before codegen:

- **OSS SDK** at the pinned `github.com/zeroroot-ai/sdk` module (`gibson.daemon.v1.*` — customer-callable `DaemonService` RPCs only; admin protos no longer live here per sdk#105).
- **daemon-local** protos at `internal/server/daemon/api/gibson/<pkg>/v1/**` — anything no other repo consumes, **plus** the genuinely-private platform services that used to live in the separate `platform-sdk` module (`gibson.daemon.operator.v1.*` `DaemonOperatorService`, `gibson.daemon.discovery.v1.*` `DiscoveryService`). platform-sdk was dissolved into this monorepo (open-core consolidation, ADR-0056, gibson#781). The former tenant-admin surface (`gibson.tenant.v1.*`, user, usage) is **customer-callable** but is **daemon-local** — it moved out of the OSS SDK into this repo at `internal/server/daemon/api/gibson/tenant/v1` (E6/sdk#390). The wire package name (`gibson.tenant.v1`) is unchanged, so it stays customer-callable; Envoy gates its admin prefixes. Billing (`gibson.billing.v1`) is **no longer in gibson** — the closed billing tier (Stripe/plans/`BillingService`) was ripped out to the closed `billing` repo and injects via the entitlements seam (ADR-0003/0050/0054, gibson#798/#915). Do not vendor; if a customer-facing repo needs a daemon type, expose it through the OSS SDK.

Both sets must carry `option (gibson.auth.v1.authz) = {…};` on every authenticated RPC. The codegen tool fails closed on any unannotated method.

The annotation extension itself (`gibson.auth.v1.options.proto`) lives in EXACTLY ONE module — the OSS SDK — and every other proto module imports it via BSR.

### Regenerating

```bash
# In the gibson repo root:
make authz-registry
```

This will:
1. Resolve the pinned SDK module dir from `go.mod`
2. Build `cmd/authz-registry-gen` from that SDK version, plus `cmd/fds-merge` and `cmd/audit-csv-gen` locally
3. Run `buf build` against the SDK protos → `.tmp/sdk-fds.binpb`
4. Run `buf build` against the daemon-local protos in a synthesized workspace (so `gibson/auth/v1/options.proto` resolves from the SDK) → `.tmp/gibson-fds.binpb`
5. `fds-merge` concatenates the two FDSes → `.tmp/combined-fds.binpb`
6. `authz-registry-gen` writes the four registry artifacts; `audit-csv-gen` writes `audit.csv`

After regen, verify with:
```bash
git diff --exit-code internal/platform/authz/registry/
```
CI runs the same check (`authz-registry-drift` step). A clean PR means no drift.

### When to regen

- After bumping the OSS SDK version (`github.com/zeroroot-ai/sdk`) in `go.mod` (mandatory — new customer-callable RPCs may have been added).
- After adding or modifying a daemon-local RPC under `internal/server/daemon/api/`.
- After CI fails the drift gate.

### When you add a daemon-local RPC

1. Add the `rpc` to the relevant `.proto` under `internal/server/daemon/api/gibson/<pkg>/v1/`.
2. In the same `rpc` block, add an `option (gibson.auth.v1.authz) = {…};` matching the rule you want enforced. If the file has no other authz-annotated RPCs yet, add `import "gibson/auth/v1/options.proto";` at the top.
3. Run `make authz-registry` and `make proto`.
4. Commit both the proto edit and the regenerated `internal/platform/authz/registry/*` artifacts in the same change.

There is no manual restoration step. Anything that previously had to be hand-merged into `registry.yaml` or `registry.go` is now driven entirely from proto annotations. Spec: `unified-authz-regen`.

### Drift suspicion

If you suspect the committed registry doesn't match the current SDK protos:
```bash
make authz-registry
git diff internal/platform/authz/registry/
```
Non-empty diff = genuine drift. Commit the regen output.

### OCI publish

On every tag push (`v[0-9]+.[0-9]+.[0-9]+`), the CI workflow
`.github/workflows/publish-private-authz-registry.yml` runs `make authz-registry`
(asserts no drift), then pushes the four artifacts to
`ghcr.io/zeroroot-ai/internal-authz-registry:<tag>`.

The ext-authz init container in the Helm chart pulls from that tag at pod
startup. The chart's `sdk.version` value must track the gibson release version.

Spec: `private-authz-registry`.

## Proto regeneration

The daemon-local protos live at `internal/server/daemon/api/gibson/<pkg>/v1/*.proto`. Their `.pb.go` + `_grpc.pb.go` bindings are checked into the same directory; CI does not regenerate them, so committing-the-output-of-`make proto` alongside any `.proto` change is mandatory.

```bash
make proto
```

The recipe synthesises a buf workspace at `.tmp/proto-ws/` with symlinks to the daemon-local protos (`gibson-local/`) and the pinned SDK protos (`sdk-proto/`), so `gibson/auth/v1/options.proto` resolves from the SDK during codegen. Without the synthesised workspace, a standalone `buf generate` would fail on that cross-tree import (gibson#122). The same synthesised-workspace pattern is used by the `authz-registry` recipe above.

Codegen settings worth knowing:

- `buf.gen.yaml` enables managed mode but disables the `go_package` override, so the daemon protos keep the import paths declared in-file. Managed mode auto-emits java/csharp/php/ruby file options for consistency with the upstream protos.
- `inputs: directory: gibson-local` restricts code generation to the daemon-local tree. The SDK protos are visible for import resolution but no Go is emitted for them (Go bindings for the SDK ship via the published `github.com/zeroroot-ai/sdk` module).
- An `M`-mapping redirects `google/protobuf/descriptor.proto` to `google.golang.org/protobuf/types/descriptorpb`. The SDK vendors `descriptor.proto` with `option go_package = "descriptor"` (a leftover from an upstream copy), and without the override protoc-gen-go rejects it.

After regen, verify with:

```bash
git diff --exit-code internal/server/daemon/api/
```

CI does not run `make proto` itself, but the `authz-registry-drift` gate exercises the same workspace setup; if your `make proto` output drifts you'll see the breakage when downstream code fails to compile.

### When you add a daemon-local RPC

1. Add the `rpc` to the relevant `.proto` under `internal/server/daemon/api/gibson/<pkg>/v1/`.
2. In the same `rpc` block, add `option (gibson.auth.v1.authz) = {…};`. If the file has no other authz-annotated RPCs yet, add `import "gibson/auth/v1/options.proto";` at the top.
3. Run `make proto` (which depends on `proto-deps` + `authz-registry`). This regenerates both the `.pb.go` / `_grpc.pb.go` and the four `internal/platform/authz/registry/*` artifacts in one pass.
4. Commit the `.proto` edit, the regenerated bindings, and the regenerated authz-registry files in the same change.

## Two-surface platform contract (post-2026-05 refactor)

The daemon consumes:

- **OSS SDK** (`github.com/zeroroot-ai/sdk`) — customer-facing types. Imports here are visible to customers via the public surface. Per docs ADR-0025: agent / tool / plugin interfaces, customer-callable `DaemonService`, `gibson.budget.v1` types, the `gibson.auth.v1` annotation extension.
- **daemon-local platform protos** (`internal/server/daemon/api`) — the genuinely-private platform services: `DaemonOperatorService` (`gibson.daemon.operator.v1`), `DiscoveryService` (`gibson.daemon.discovery.v1`). These used to live in a separate `platform-sdk` module; it was dissolved into this monorepo (gibson#781), so they are now daemon-local protos. Private; never re-exported through the OSS SDK; never vendored out. (Billing — `gibson.billing.v1` / `BillingService` — was ripped out of gibson into the closed `billing` repo and injects via the entitlements seam: ADR-0003/0050/0054, gibson#798/#915.)
- **platform-clients** (`github.com/zeroroot-ai/platform-clients`) — shared Go primitives. Mandated for transport, secrets, readiness, pools, observability, authz per docs ADR-0026. Do NOT reinvent these primitives in this repo; CI greps for ad-hoc OTel init / interceptor chains / pool constructors.

The daemon registers **many gRPC services on `:50051`** — the customer-facing `gibson.daemon.v1.DaemonService` plus the decomposed, daemon-local tenant-admin surface (`gibson.tenant.v1` — `TenantService`, `UserService`, `UsageService`, `ProviderService`, `MembershipService`, `GrantsService`, `SecretsService`, `ModelAccessService`, `PluginAdminService`, `BudgetService`, `AgentIdentityService`), the daemon-local `TracesService` / `GraphService` / `IdentityService` / `IntelligenceService` / `ComponentService` / `HarnessCallbackService` / `PluginInvokeService`, and the private `DaemonOperatorService` (daemon-local). (`BillingService` was removed from gibson — gibson#915.)

There is a single listener. Surface separation is enforced on the wire by **Envoy's route table**, which gates the admin/operator prefixes — `/gibson.daemon.operator.v1.DaemonOperatorService/`, `/gibson.tenant.v1.TenantAdminService/`, `/gibson.platform.v1.PlatformOperatorService/` — behind the admin JWT requirement (see `enterprise/deploy/helm/gibson-workloads/files/envoy/envoy.yaml`, deploy#172). The daemon does NOT maintain a second listener.

The operator protos and the customer-callable tenant-admin protos are both daemon-local (in-tree); tenant.v1 moved out of the OSS SDK in E6 (sdk#390) but keeps its `gibson.tenant.v1` wire package name, so it stays customer-callable, gated by Envoy:

```go
import (
    daemonoperatorv1 "github.com/zeroroot-ai/gibson/internal/server/daemon/api/gibson/daemon/operator/v1"
    discoverypb      "github.com/zeroroot-ai/gibson/internal/server/daemon/api/gibson/daemon/discovery/v1"
    tenantv1         "github.com/zeroroot-ai/gibson/internal/server/daemon/api/gibson/tenant/v1" // customer-callable, daemon-local since E6/sdk#390
)
```

The platform protos moved in-tree when `platform-sdk` was dissolved (gibson#781); they are no longer a separate Go module. A daemon handler that imports `github.com/zeroroot-ai/platform-sdk/...` is dead code; that module no longer exists.

## Service-account identity (canonical sub)

The daemon's FGA Check uses the canonical Zitadel **numeric `sub`** forwarded from ext-authz as `X-Gibson-Identity-Subject`. The fga-init Helm Job seeds platform_operator tuples keyed by that numeric form, sourced from the chart-managed `gibson-sa-identity-map` ConfigMap. No translation in the daemon hot path.

The package `internal/platform/auth/identityresolver` provides a numeric→readable lookup. It is for **log enrichment only** — never call it from a code path that reaches an allow/deny decision. The mounted source path is `/etc/gibson/sa-identity-map` (one file per SA, kubelet's native ConfigMap projection); the resolver also accepts a single JSON file for compatibility with the dashboard's init-container output.

Spec: `canonical-service-identity`.

## Deployment mode (deleted)

The `GIBSON_MODE` env var, the `Mode`/`ModeSaaS`/`ModeSelfhost`/`ModeDev` types, and the `cfg.Mode()` accessor were deleted as part of the one-code-path epic (`deploy#205`). The daemon binary boots identically in every environment — kind, staging, prod, customer self-hosted. Per-environment differences live ONLY in helm values (which fail-loud on missing dependencies).

Do NOT re-introduce a deployment-mode env var. Per-feature gates that genuinely need a knob should consume a dedicated, single-purpose env var (e.g. `GIBSON_STRICT_TENANT`), validated at config-load time, NOT a multi-valued mode enum.
