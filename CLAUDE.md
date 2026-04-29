# Gibson daemon — CLAUDE.md

Read this before editing the daemon (`core/gibson/`).

## Authz registry pipeline

The authorization rule book lives at `internal/authz/registry/`:
- `registry.go` — Go map `Registry` (import path `github.com/zero-day-ai/gibson/internal/authz/registry`)
- `registry.yaml` — runtime YAML consumed by ext-authz via oras pull
- `fga_model.fga` — OpenFGA model fed to the fga-init Job
- `permissions.ts` — TypeScript map for the dashboard sister spec

These are **generated artifacts** — do NOT hand-edit them. Run regen instead.

### Regenerating

```bash
# In core/gibson/:
make authz-registry
```

This will:
1. Resolve the pinned SDK module dir from `go.mod`
2. Build `cmd/authz-registry-gen` from that SDK version
3. Run `buf build` against the SDK protos to produce a FileDescriptorSet
4. Invoke the generator with `-output internal/authz/registry`

After regen, verify with:
```bash
git diff --exit-code internal/authz/registry/
```
CI runs the same check (`authz-registry-drift` step). A clean PR means no drift.

### When to regen

- After bumping the SDK version in `go.mod` (mandatory — new RPCs may have been added)
- After CI fails the drift gate

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
