# Tools are manifest-seeded components: one path, per-tenant, signed

A shared tool (nmap, httpx, nuclei, …) is a first-party component gibson ships.
This ADR decides how a tool enters the catalog, how a tenant turns it on, and how
it is supply-chain-checked — and makes those answers identical to every other
component kind. It amends [ADR-0010](0010-untrusted-execution-isolation-boundary.md)
(untrusted tool execution) and [ADR-0015](0015-platform-component-catalog.md) (the
platform component catalog), and it is a wholesale flip under
`ADR-0027` discipline: the runtime tool
refresher is deleted, not kept behind a flag.

## Context

ADR-0015 made agents, connectors, and plugins **manifest-seeded** catalog
components: a manifest baked into the signed gibson image, `platform_enabled`
seeded at boot, `tenant_enabled` as the opt-in that makes a component run, dispatch
gated on `can_execute`, and an image pinned by signed digest.

Tools never joined that model. They are discovered at runtime by the **catalog
refresher**, which launches each image in `tool_runner.images` as
`gibson-runner --list-tools` inside a setec microVM and writes one
`ComponentRegistry` entry per tool under `tenant=_system`, `UNTRUSTED`,
`SANDBOXED`. Tool dispatch (`CallToolProto`) resolves from `_system` with **no
authorization check**. Three problems follow:

1. **No per-tenant control.** A refresher-discovered tool is available to every
   tenant the moment its image is listed. `tenant_enabled` never applies, so a
   tenant cannot be given (or denied) a specific tool.
2. **No supply-chain enforcement.** The refresher launches whatever string is in
   `tool_runner.images` — a tag is accepted as readily as a digest, and no cosign
   signature is checked. (The ADR-0015 manifest loader enforces a signed digest;
   the refresher path does not.)
3. **A parallel codepath (ADR-0027).** Tools reach a tenant through the refresher;
   every other kind reaches a tenant through the manifest catalog. Two ways to
   publish a component, with different security properties, is exactly what
   ADR-0027 forbids.

The refresher's one virtue is that the tool image declares its own tools
(`--list-tools`), so the catalog never drifts from the binary. Any replacement
must keep that property.

## Decision

**1. A tool is a manifest-seeded `kind: tool` component, identical to an agent.**
It has the canonical object ref `component:tool/<name>`, its manifest is baked into
the signed gibson image, the daemon seeds `platform_enabled` for it at boot, and it
is listed platform-wide only through that manifest. There is no other way a tool
enters the catalog.

**2. Per-tenant control is the same gate as every other kind.** `tenant_enabled`
is the opt-in that makes a tool runnable in a tenant; `SetCatalogEnabled(tool/<name>)`
sets it. `CallToolProto` resolves the tool **tenant-scoped** and gates on
`can_execute` before launching, fail-closed — a registry or authz error denies, it
never falls through. A tenant that has not enabled a tool cannot call it, and
nothing is launched.

**3. Supply-chain enforcement is checked at load, not assumed.** A tool manifest's
image MUST be a `@sha256` digest, and the loader **cosign-verifies** that digest
against the release identity before seeding `platform_enabled`. This closes the
"runtime verification deferred" note in ADR-0015 and applies to every image-bearing
kind (tool, agent, plugin, hosted connector), not just tools. An unsigned or
wrong-identity image is refused at load, fail-loud.

**4. The manifests are generated from the image, so the image stays the source of
truth.** A release-time codegen runs the executor image's `gibson-runner
--list-tools` and emits one committed `kind: tool` manifest per tool (name,
`image@digest`, input schema, resources). A drift gate fails CI when the committed
manifests disagree with the image's `--list-tools`. This keeps the refresher's one
virtue — the binary declares its tools — without a runtime discovery path.

**5. The runtime refresher is deleted (ADR-0027 hard cutover).** The catalog
refresher, its leader-election and TTL machinery, `ToolRunnerConfig`, the helm
`toolRunner` value and its configmap block, and the ungated `_system` tool dispatch
path are removed. Not disabled, not flagged — removed. After this, the only tool
codepath is the manifest path shared with every other kind.

## Consequences

**Good.**
- One publish/enable/isolate model for all four kinds; tools stop being the special
  case.
- Per-tenant control over tools, for free, via the existing enablement gate.
- Every platform image — tools included — is signature-verified at load.
- No parallel discovery path to reason about or secure.
- The catalog is still generated from the binary, so it cannot drift.

**Costs and risks.**
- Adding a tool is now a generated-manifest entry + a release, not a live config
  edit. The codegen keeps this cheap, but it is no longer "add a string to a helm
  value."
- Runtime auto-discovery is gone: a tool that ships in the executor image but is not
  in the generated manifests will not appear until the manifests are regenerated.
- Cosign-verify-at-load adds a verification dependency to the daemon boot/seed path;
  it must fail loud, never fail open.

## Alternatives considered

- **Keep the refresher, add the gates to it.** Rejected: it leaves two publish
  paths (refresher + manifest), which is the ADR-0027 violation this ADR exists to
  remove.
- **Hand-write the `kind: tool` manifests.** Rejected: they drift from what the
  executor image actually provides, and every tool becomes a manual manifest.
  Generation keeps the image authoritative.
- **Per-tenant control via a separate tool-ACL, not `tenant_enabled`.** Rejected:
  a second authorization concept for one kind is the opposite of one code path.

## Status

Proposed. Amends [ADR-0010](0010-untrusted-execution-isolation-boundary.md) and
[ADR-0015](0015-platform-component-catalog.md); enforced under ADR-0027.
Implementation tracked in gibson#1635.
