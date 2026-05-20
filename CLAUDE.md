# Gibson daemon — CLAUDE.md

> **Workflow rules:** see [`zero-day-ai/.github` → `AGENTS.md`](https://github.com/zero-day-ai/.github/blob/main/AGENTS.md) for branch / PR / commit / release / rebase rules. Conventional Commits MANDATORY (drives release-please). Never push to main, never merge your own PR. Repo-local rules below override only when explicitly noted.

Read this before editing the daemon (`core/gibson/`).

## Authz registry pipeline

The authorization rule book lives at `internal/authz/registry/`:
- `registry.go` — Go map `Registry` (import path `github.com/zero-day-ai/gibson/internal/authz/registry`)
- `registry.yaml` — runtime YAML consumed by ext-authz via oras pull
- `permissions.ts` — TypeScript map for the dashboard sister spec
- `audit.csv` — auditor-friendly flat table (rpc, relation, object_type, deriver, identities, source_proto_file)

The OpenFGA model itself is hand-maintained at `internal/authz/model.fga`
(loaded by `gibson-fga-init` via `files/fga-model.json`); the registry
generator no longer emits an FGA stub.

These are **generated artifacts** — do NOT hand-edit them. Run regen instead.

The annotations come from **three** proto sources after the two-surface refactor (docs ADR-0025), merged via `cmd/fds-merge` into a single FileDescriptorSet before codegen:

- **OSS SDK** at the pinned `github.com/zero-day-ai/sdk` module (`gibson.daemon.v1.*` — customer-callable `DaemonService` RPCs only; admin protos no longer live here per sdk#105).
- **platform-sdk** at the pinned `github.com/zero-day-ai/platform-sdk` module (`gibson.daemon.admin.v1.*`, `gibson.platform.v1.*`, `gibson.tenant.v1.*`, `gibson.user.v1.*`, `gibson.usage.v1.*`). This is the **private** internal proto module that hosts admin shapes. Cross-module proto sharing flows through BSR (`buf.build/zero-day-ai-platform/platform-sdk`); no local proto includes (docs ADR-0028 Clause 6).
- **daemon-local** protos at `core/gibson/internal/daemon/api/**` — anything no other repo consumes. If another repo needs a type from here, promote it to `platform-sdk` and consume via BSR. Do not vendor.

All three sets must carry `option (gibson.auth.v1.authz) = {…};` on every authenticated RPC. The codegen tool fails closed on any unannotated method.

The annotation extension itself (`gibson.auth.v1.options.proto`) lives in EXACTLY ONE module — the OSS SDK — and every other proto module imports it via BSR.

### Regenerating

```bash
# In core/gibson/:
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
git diff --exit-code internal/authz/registry/
```
CI runs the same check (`authz-registry-drift` step). A clean PR means no drift.

### When to regen

- After bumping the OSS SDK version (`github.com/zero-day-ai/sdk`) in `go.mod` (mandatory — new customer-callable RPCs may have been added).
- After bumping the platform-sdk version (`github.com/zero-day-ai/platform-sdk`) in `go.mod` (mandatory — new admin RPCs may have been added).
- After adding or modifying a daemon-local RPC under `internal/daemon/api/`.
- After CI fails the drift gate.

### When you add a daemon-local RPC

1. Add the `rpc` to the relevant `.proto` under `internal/daemon/api/gibson/<pkg>/v1/`.
2. In the same `rpc` block, add an `option (gibson.auth.v1.authz) = {…};` matching the rule you want enforced. If the file has no other authz-annotated RPCs yet, add `import "gibson/auth/v1/options.proto";` at the top.
3. Run `make authz-registry` and `make proto`.
4. Commit both the proto edit and the regenerated `internal/authz/registry/*` artifacts in the same change.

There is no manual restoration step. Anything that previously had to be hand-merged into `registry.yaml` or `registry.go` is now driven entirely from proto annotations. Spec: `unified-authz-regen`.

### Drift suspicion

If you suspect the committed registry doesn't match the current SDK protos:
```bash
make authz-registry
git diff internal/authz/registry/
```
Non-empty diff = genuine drift. Commit the regen output.

### OCI publish

On every tag push (`v[0-9]+.[0-9]+.[0-9]+`), the CI workflow
`.github/workflows/publish-private-authz-registry.yml` runs `make authz-registry`
(asserts no drift), then pushes the four artifacts to
`ghcr.io/zero-day-ai/internal-authz-registry:<tag>`.

The ext-authz init container in the Helm chart pulls from that tag at pod
startup. The chart's `sdk.version` value must track the gibson release version.

Spec: `private-authz-registry`.

## Proto regeneration

The daemon-local protos live at `internal/daemon/api/gibson/<pkg>/v1/*.proto`. Their `.pb.go` + `_grpc.pb.go` bindings are checked into the same directory; CI does not regenerate them, so committing-the-output-of-`make proto` alongside any `.proto` change is mandatory.

```bash
make proto
```

The recipe synthesises a buf workspace at `.tmp/proto-ws/` with symlinks to the daemon-local protos (`gibson-local/`) and the pinned SDK protos (`sdk-proto/`), so `gibson/auth/v1/options.proto` resolves from the SDK during codegen. Without the synthesised workspace, a standalone `buf generate` would fail on that cross-tree import (gibson#122). The same synthesised-workspace pattern is used by the `authz-registry` recipe above.

Codegen settings worth knowing:

- `buf.gen.yaml` enables managed mode but disables the `go_package` override, so the daemon protos keep the import paths declared in-file. Managed mode auto-emits java/csharp/php/ruby file options for consistency with the upstream protos.
- `inputs: directory: gibson-local` restricts code generation to the daemon-local tree. The SDK protos are visible for import resolution but no Go is emitted for them (Go bindings for the SDK ship via the published `github.com/zero-day-ai/sdk` module).
- An `M`-mapping redirects `google/protobuf/descriptor.proto` to `google.golang.org/protobuf/types/descriptorpb`. The SDK vendors `descriptor.proto` with `option go_package = "descriptor"` (a leftover from an upstream copy), and without the override protoc-gen-go rejects it.

After regen, verify with:

```bash
git diff --exit-code internal/daemon/api/
```

CI does not run `make proto` itself, but the `authz-registry-drift` gate exercises the same workspace setup; if your `make proto` output drifts you'll see the breakage when downstream code fails to compile.

### When you add a daemon-local RPC

1. Add the `rpc` to the relevant `.proto` under `internal/daemon/api/gibson/<pkg>/v1/`.
2. In the same `rpc` block, add `option (gibson.auth.v1.authz) = {…};`. If the file has no other authz-annotated RPCs yet, add `import "gibson/auth/v1/options.proto";` at the top.
3. Run `make proto` (which depends on `proto-deps` + `authz-registry`). This regenerates both the `.pb.go` / `_grpc.pb.go` and the four `internal/authz/registry/*` artifacts in one pass.
4. Commit the `.proto` edit, the regenerated bindings, and the regenerated authz-registry files in the same change.

## Two-surface platform contract (post-2026-05 refactor)

The daemon consumes:

- **OSS SDK** (`github.com/zero-day-ai/sdk`) — customer-facing types. Imports here are visible to customers via the public surface. Per docs ADR-0025: agent / tool / plugin interfaces, customer-callable `DaemonService`, `gibson.budget.v1` types, the `gibson.auth.v1` annotation extension.
- **platform-sdk** (`github.com/zero-day-ai/platform-sdk`) — internal proto module. Hosts every admin proto and service stub (`DaemonAdminService`, `PlatformOperatorService`, `TenantAdminService`). Private; never re-exported through OSS SDK; never vendored. Cross-module proto sharing flows through BSR (`buf.build/zero-day-ai-platform/platform-sdk`).
- **platform-clients** (`github.com/zero-day-ai/platform-clients`) — shared Go primitives. Mandated for transport, secrets, readiness, pools, observability, authz per docs ADR-0026. Do NOT reinvent these primitives in this repo; CI greps for ad-hoc OTel init / interceptor chains / pool constructors.

The daemon registers **two services on `:50051`**:

- `gibson.daemon.v1.DaemonService` (proto in OSS SDK; FGA relation `member` / `can_use`).
- `gibson.daemon.admin.v1.DaemonAdminService` (proto in platform-sdk; FGA relation `admin` / `writer`).

Envoy's route table gates the admin prefix `/gibson.daemon.admin.v1.*` with the admin JWT requirement (deploy#172). The daemon does NOT maintain a second listener; the route-gate enforcement on Envoy keeps the two surfaces distinct on the wire.

Admin protos are imported from platform-sdk:

```go
import (
    daemonadminv1 "github.com/zero-day-ai/platform-sdk/gen/gibson/daemon/admin/v1"
    platformv1   "github.com/zero-day-ai/platform-sdk/gen/gibson/platform/v1"
    tenantv1     "github.com/zero-day-ai/platform-sdk/gen/gibson/tenant/v1"
)
```

A daemon handler that imports `github.com/zero-day-ai/sdk/gen/gibson/admin/...` is post-purge dead code; that path no longer exists.

## Service-account identity (canonical sub)

The daemon's FGA Check uses the canonical Zitadel **numeric `sub`** forwarded from ext-authz as `X-Gibson-Identity-Subject`. The fga-init Helm Job seeds platform_operator tuples keyed by that numeric form, sourced from the chart-managed `gibson-sa-identity-map` ConfigMap. No translation in the daemon hot path.

The package `internal/auth/identityresolver` provides a numeric→readable lookup. It is for **log enrichment only** — never call it from a code path that reaches an allow/deny decision. The mounted source path is `/etc/gibson/sa-identity-map` (one file per SA, kubelet's native ConfigMap projection); the resolver also accepts a single JSON file for compatibility with the dashboard's init-container output.

Spec: `canonical-service-identity`.

## Deployment mode (deleted)

The `GIBSON_MODE` env var, the `Mode`/`ModeSaaS`/`ModeSelfhost`/`ModeDev` types, and the `cfg.Mode()` accessor were deleted as part of the one-code-path epic (`deploy#205`). The daemon binary boots identically in every environment — kind, staging, prod, customer self-hosted. Per-environment differences live ONLY in helm values (which fail-loud on missing dependencies).

Do NOT re-introduce a deployment-mode env var. Per-feature gates that genuinely need a knob should consume a dedicated, single-purpose env var (e.g. `GIBSON_STRICT_TENANT`), validated at config-load time, NOT a multi-valued mode enum.
