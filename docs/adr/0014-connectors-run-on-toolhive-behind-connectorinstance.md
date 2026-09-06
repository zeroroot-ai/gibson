# Connectors run any third-party MCP server through ToolHive, behind a gibson ConnectorInstance

A connector is any third-party MCP server that gibson makes callable to an agent.
The platform runs each connector as a pod in the customer's own tenant namespace.
ToolHive (the Stacklok Kubernetes operator, CRD `toolhive.stacklok.dev/v1beta1`)
runs the pod. Gibson does not expose ToolHive to the product. Gibson exposes its
own `ConnectorInstance`. A `connector-operator` translates each `ConnectorInstance`
into one ToolHive `MCPServer` and one External Secrets Operator (ESO)
`ExternalSecret`. FGA stays the only authorization brain. setec is an optional
hardening upgrade, not the default.

This is a wholesale flip under `ADR-0027`
discipline: no parallel codepath, no flag. The `internal/engine/connector`
setec-only launcher and the "stdio requires setec" rule are deleted, not kept.

## Context

Today a connector is a hand-written YAML manifest with `runtime: mcp-bridge`. The
launcher (`internal/engine/connector/launcher.go`) supports one runtime: a setec
microVM. `transport: stdio` fails without setec. The OAuth grant lives in the
platform broker and rotates there. A human authorizes a connector by pasting a
URL and running a local listener by hand (the demo did this on `127.0.0.1:8899`).

Three problems block the product:

1. **Only vendors with a built-in MCP server work well.** GitLab ships its own
   MCP server, so the bridge is a client and needs no runtime. A vendor with no
   MCP server needs the platform to run a standalone server. The setec path is the
   only option, and it is heavy.
2. **setec is the wrong default.** setec gives hardware isolation, but it costs
   money and it is not needed for every connector. It also held the credentials,
   so an ephemeral sandbox lost them.
3. **The surfaces do not exist.** There is no catalog, no dashboard button, and no
   single API for the full connector lifecycle.

## Decision

**1. ToolHive runs the MCP server; gibson never shows ToolHive to a user.**
The `connector-operator` reconciles a `ConnectorInstance` (gibson's own
namespace-scoped CRD) into a ToolHive `MCPServer` plus an ESO `ExternalSecret`,
both in the tenant namespace. The `MCPServer` fields map one to one to the
requirements:

| Requirement | ToolHive `MCPServer` field |
|---|---|
| MCP code comes from a Docker image URL | `spec.image` |
| Private registry needs credentials | `resourceOverrides.proxyDeployment.imagePullSecrets` |
| Support every MCP type | `transport: stdio \| sse \| streamable-http`; a stdio server is wrapped and re-exposed over http by `proxyMode` |
| Confine egress to the vendor | `permissionProfile` (`network` + a custom ConfigMap allow-list) |
| Inject vendor credentials | `secrets[]` from a Kubernetes Secret |
| The daemon reaches the server | the operator makes a ClusterIP proxy Service |

Wrapping ToolHive behind `ConnectorInstance` is mandatory. The CRD is `v1beta1`.
The wrapper lets gibson replace or upgrade ToolHive later without a change to the
catalog, the RPC, or the CLI. `MCPServer` must never appear in a product surface.

**2. The default runtime is a pod in the customer's tenant namespace. setec is an
opt-in upgrade.** ToolHive runs a plain pod with a network permission profile. The
permission profile confines egress to the vendor hosts. A customer who needs
hardware isolation selects setec on the `ConnectorInstance`; the operator then
runs the same image as a setec sandbox instead of a pod. The default is free. The
setec tier is a paid upgrade.

**3. All credentials live in the customer's secret store; ESO injects them; the
runtime never holds a durable credential.** The customer's secret store is the
platform OpenBao for a self-hosted install, or a bring-your-own store (Vault, AWS
Secrets Manager) for SaaS. The `connector-operator` writes an `ExternalSecret`
that pulls the vendor credential and the registry credential from that store into
a Kubernetes Secret. ToolHive injects that Secret into the server pod. Because the
credential is in a durable store, an ephemeral runtime never loses it. This is why
setec no longer needs to hold the credential.

> **Superseded by ADR-0015.** The AWS/GCP/Azure backends were removed (epic
> secrets-hosted-byo) — the only backend is Vault/OpenBao, hosted or BYO — and the
> ESO `ExternalSecret` step was never built. ADR-0015 replaces this: the **daemon**
> materializes `<connector>-connector-cred` from the tenant's store (reusing its
> tenant vault provider), no ESO. The rest of ADR-0014 stands.

**4. FGA is the only authorization brain. ToolHive OIDC only gates daemon access.**
ToolHive ships its own authorization (Cedar) and per-server OIDC. Gibson does not
use ToolHive Cedar. The daemon is the only client of the ToolHive proxy Service.
Gibson sets `oidcConfigRef` so that only the daemon's identity can call the proxy,
with an audience bound per server to stop token replay. All tool-level
authorization stays in FGA and the `search_tools` / `invoke_tool` meta-tools
(ADR-0047). ToolHive is a dumb, isolated runtime. Gibson is the policy brain.

**5. http connectors use a curated catalog and a button, not YAML.** Gibson ships
a curated catalog of known connectors (GitLab first). A catalog entry holds the
preloaded configuration: the image or remote endpoint, the transport, the OAuth
metadata, and the egress allow-list. The customer selects an entry and clicks
"Enable". The customer does not author YAML. The FGA `system_tenant` catalog gate
(the `platform_enabled` concept) lists the public catalog. A custom connector
(advanced) can still supply a full `ConnectorInstance` spec, but that path is not
the product default.

**6. ToolHive fronts both connector shapes.**
   - **Vendor-hosted (http), e.g. GitLab.** The vendor runs the MCP server.
     ToolHive proxies the remote server (its "proxy remote MCP servers" mode). The
     daemon still mints and rotates the OAuth access token (see
     `ConnectorAuthService` below) and writes it to the Secret ToolHive presents.
   - **Self-hosted (container), e.g. a Slack MCP image.** ToolHive pulls the image
     and runs the pod. The server holds the vendor credential (from ESO) and calls
     the vendor API itself. ToolHive confines the pod egress to the vendor host.

## The full lifecycle, one behavior across CLI, RPC, and UI

The API/RPC is the source of truth. The CLI (`gibson connector …`) and the
dashboard are thin clients of the same RPCs. The lifecycle is:

1. **List catalog** — read the curated catalog the tenant may enable.
2. **Enable** — create a `ConnectorInstance` from a catalog entry. The operator
   creates the `MCPServer` + `ExternalSecret`. The pod starts. ToolHive runs
   `tools/list`. The daemon registers the tools in the connector catalog as
   `mcp:<connector>:<tool>`.
3. **Authorize** (OAuth connectors) — `StartConnectorAuthorization` returns an
   authorize URL; the human approves once in a browser; the daemon callback
   completes the grant. See the RPC change below.
4. **Status** — `GetConnectorAuthStatus` reports UNAUTHORIZED / AUTHORIZED /
   REFRESH_FAILING, and the operator reports the pod health.
5. **Revoke / Disable** — `RevokeConnectorGrant` drops the grant;
   deleting the `ConnectorInstance` deletes the `MCPServer` and the Secret.

## What ConnectorAuthService must change

The existing service (`GetConnectorAuthStatus`, `CompleteConnectorAuthorization`,
`RevokeConnectorGrant`) ingests a finished grant. It must gain the front half of
the flow, so no human pastes a URL and no listener runs by hand.

1. **Add `StartConnectorAuthorization(connector, instance_url)`.** The daemon does
   RFC 8414 discovery and RFC 7591 dynamic client registration. It generates PKCE
   and `state`. It stores `{verifier, state, endpoints, client_id}` in a
   short-TTL server-side store, keyed by `state`. It returns the authorize URL.
2. **Host the callback on the pre-auth Envoy route** (the same bucket as
   `/.well-known/gibson-login`). The callback validates `state`, exchanges the
   code with the PKCE verifier, and stores the grant. `state` is the CSRF binding.
3. **`Complete` takes the `code`, not the `refresh_token`.** The daemon does the
   code-to-token exchange, because the `connectorauth.Refresher` already reaches
   the vendor every 5 minutes. The refresh token is minted, stored, and rotated
   entirely in the daemon tier. Only the short-lived access token leaves. The
   refresh token never transits the dashboard.
4. **Write the access token where ToolHive reads it.** The refresher writes the
   rotating access token to the tenant Secret that ToolHive injects, through the
   customer's secret store.

## Consequences

**Good.**
- One runtime abstraction runs every MCP server type, vendor-hosted or self-hosted.
- The default is cheap (a pod), and hardening (setec) is a clean upgrade.
- Credentials are durable and customer-owned; the runtime holds none.
- The dashboard, the CLI, and the API share one lifecycle.
- Gibson keeps its security model: FGA authorizes every tool call, and the audit
  trail attributes every call to an agent, a mission, and a human.

**Costs and risks.**
- ToolHive is `v1beta1`. The `ConnectorInstance` wrapper contains this risk. Pin
  the ToolHive version. Never leak `MCPServer` into a product surface.
- A self-hosted container runs third-party code. The default pod isolation plus the
  egress permission profile is the fence. setec is the stronger fence for a
  customer who needs it.
- Two operators now write to the tenant namespace (tenant-operator and
  connector-operator). Ownership must be clear: the connector-operator owns
  `MCPServer`, `ExternalSecret`, and the connector Secret only.

## Plan to get it going

1. **Spike ToolHive (1 slice).** Install the ToolHive operator on kind-vanilla.
   Apply one `MCPServer` by hand (a public stdio image). Confirm the ClusterIP
   proxy answers `tools/list`. Confirm the egress profile blocks a non-vendor host.
   Exit test: the daemon reaches the proxy and lists tools.
2. **`ConnectorInstance` CRD + connector-operator.** Define the CRD (catalog id,
   tenant, runtime = pod | setec, cred refs). Reconcile it into `MCPServer` +
   `ExternalSecret`. Delete the setec-only launcher. Exit test: creating a
   `ConnectorInstance` starts a pod and registers its tools.
3. **Catalog + enable RPC/CLI/UI.** Ship the curated catalog (GitLab first). Add
   `ListCatalog` and `EnableConnector`. Wire the CLI and one dashboard page. Exit
   test: "Enable GitLab" from the dashboard creates the `ConnectorInstance`.
4. **Authorize flow (the RPC change above).** Add `StartConnectorAuthorization`
   and the daemon callback. Change `Complete` to take the code. Exit test: a human
   clicks one dashboard button, approves at the vendor, and the status reads
   AUTHORIZED with no manual step.
5. **ESO credential model.** Route the vendor credential, the registry credential,
   and the rotating access token through the customer's secret store. Exit test:
   no connector credential exists outside the customer store.
6. **setec as an upgrade.** Add `runtime: setec` to `ConnectorInstance`. Exit
   test: the same connector runs as a setec sandbox when selected.

## Alternatives considered

- **Keep the setec-only launcher.** Rejected. setec is the wrong default, and it
  held the credentials.
- **Roll our own container runtime for MCP servers.** Rejected. ToolHive already
  does the isolation, the transport proxy, the secret injection, and the egress
  profile. We build the gibson value on top, not the commodity below.
- **Use ToolHive Cedar authorization.** Rejected. Two authorization brains is a
  defect. FGA is the one brain.

## Spike 1 results — validated on kind-vanilla (2026-08-21)

The substrate spike ran on kind-vanilla and passed. The evidence:

- The ToolHive operator installs from OCI helm charts
  (`oci://ghcr.io/stacklok/toolhive/toolhive-operator-crds` and
  `…/toolhive-operator`, version `0.12.1`) into `toolhive-system`.
- The chart serves the API version **`toolhive.stacklok.dev/v1alpha1`**, NOT
  `v1beta1` as the docs state. Use `v1alpha1`.
- An `MCPServer` (image `ghcr.io/stackloklabs/osv-mcp/server`, transport
  `streamable-http`) reconciles to `phase: Running`. The operator makes the
  server pod, a proxy pod, and a ClusterIP proxy Service `mcp-<name>-proxy`. The
  server URL is `http://mcp-<name>-proxy.<namespace>.svc.cluster.local:8080/mcp`.
- An in-cluster client completes the MCP handshake through the proxy and gets
  `tools/list`. The osv server returned real tools (`get_vulnerability`,
  `query_vulnerabilities_batch`). So the daemon can run any MCP server as a pod
  and discover its tools.
- The CRD set includes **`MCPRemoteProxy`** (the vendor-hosted http case, e.g.
  GitLab) and **`MCPRegistry`** (a catalog primitive). Both are `v1alpha1`. So
  ToolHive fronts both connector shapes, and it has catalog machinery to study.

Two findings change the plan:

1. **Egress enforcement needs a custom profile.** The builtin `network`
   permission profile is permissive — it makes NO restrictive NetworkPolicy.
   Real egress confinement needs a CUSTOM permission profile (a ConfigMap
   allow-list). Slice 3 owns this. (CORRECTION, verified in Slice 3: kind-vanilla
   DOES enforce NetworkPolicy — the gibson-tenant-default-deny actively severed
   the proxy→server hop until the connector-operator emitted an allow-policy. The
   earlier "kindnet does not enforce" note was wrong for this cluster. So the
   connector-operator emits, per ConnectorInstance, one owned NetworkPolicy that
   admits daemon→proxy, proxy→server, DNS, and vendor 443 to PUBLIC IPs only —
   private ranges are blocked for SSRF containment.)
2. **The version is `v1alpha1`.** Pin it in the `connector-operator`, and revisit
   on every ToolHive bump — the `ConnectorInstance` wrapper absorbs the churn.

## Status

Proposed, substrate validated. Owner review is required for the ToolHive
adoption and the `ConnectorAuthService` change. The connector lane owner (author
of `ConnectorAuthService`) must confirm the `Complete`-takes-code change.
