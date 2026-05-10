# Gibson daemon — CLAUDE.md

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

The annotations come from **two** proto sources, merged via `cmd/fds-merge` into a single FileDescriptorSet before codegen:
- the pinned SDK at `core/sdk/api/proto/**` (gibson.admin.v1.*, gibson.daemon.v1.*, …)
- daemon-local protos at `core/gibson/internal/daemon/api/**` (gibson.tenant.v1.*, gibson.platform.v1.*, gibson.user.v1.*)

Both sets must carry `option (gibson.auth.v1.authz) = {…};` on every authenticated RPC. The codegen tool fails closed on any unannotated method.

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

- After bumping the SDK version in `go.mod` (mandatory — new RPCs may have been added)
- After adding or modifying a daemon-local RPC under `internal/daemon/api/`
- After CI fails the drift gate

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

## Service-account identity (canonical sub)

The daemon's FGA Check uses the canonical Zitadel **numeric `sub`** forwarded from ext-authz as `X-Gibson-Identity-Subject`. The fga-init Helm Job seeds platform_operator tuples keyed by that numeric form, sourced from the chart-managed `gibson-sa-identity-map` ConfigMap. No translation in the daemon hot path.

The package `internal/auth/identityresolver` provides a numeric→readable lookup. It is for **log enrichment only** — never call it from a code path that reaches an allow/deny decision. The mounted source path is `/etc/gibson/sa-identity-map` (one file per SA, kubelet's native ConfigMap projection); the resolver also accepts a single JSON file for compatibility with the dashboard's init-container output.

Spec: `canonical-service-identity`.

## Deployment mode (`GIBSON_MODE`, never `GIBSON_ENV`)

Production-vs-dev gates read `GIBSON_MODE` from the environment. The valid values are `saas`, `selfhost`, `dev` (defaults to `selfhost` when unset). Implementation lives at `core/gibson/internal/config/mode.go`; consumers access the resolved value via `cfg.Mode()`, which returns one of `config.ModeSaaS`, `config.ModeSelfhost`, `config.ModeDev`.

Some older spec drafts referenced `GIBSON_ENV=prod` as a tentative env-var name. **`GIBSON_ENV` is not a thing** — do not introduce it. New gates that need a "production" check should compare `cfg.Mode() == config.ModeSaaS`.

The setec-sandbox-prod-default spec's R1.4 fail-closed startup self-check (in `cmd/gibson/main.go`) follows this convention: it refuses startup when `cfg.Mode() == config.ModeSaaS && version.BuildTagSetecIntegration != "on"`.

Spec: `setec-sandbox-prod-default` (Cleanup R1.4).
