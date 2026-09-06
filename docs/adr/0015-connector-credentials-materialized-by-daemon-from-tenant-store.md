# Connector credentials are materialized by the daemon from the tenant store

A connector fronts a third-party MCP server that ToolHive runs in the customer's
tenant namespace (ADR-0014, ADR-0065). ToolHive forwards a vendor credential as
an `Authorization` header, read from a Kubernetes Secret. This ADR decides who
puts the credential in that Secret, where the credential lives, and how it stays
fresh — superseding ADR-0014 decision 3.

## Context

ADR-0014 decision 3 said: *"All credentials live in the customer's secret store;
ESO injects them … The customer's secret store is … AWS Secrets Manager for SaaS.
The connector-operator writes an ESO `ExternalSecret` that pulls the vendor
credential … into a Kubernetes Secret."* Two later changes invalidated it:

1. **The only secret backend is Vault/OpenBao.** Epic secrets-hosted-byo removed
   the aws/gcp/azure backends (they were stubs). The `BrokerProvider` enum is
   `{UNSPECIFIED, VAULT_HOSTED, VAULT_BYO}`. Hosted = gibson's OpenBao, per-tenant
   namespace `tenant-<id>`; BYO = the customer's own Vault, path-prefix
   `tenant/<id>`. The daemon already speaks both through one tenant vault provider
   and a shared `brokercodec`.
2. **ToolHive replaced the mcp-bridge (ADR-0065).** The `connectorauth` package
   was written for the bridge, which *resolved* its access token through
   `GetCredential`. ToolHive does not call `GetCredential` — it reads a k8s Secret.
   So the "connector resolves from the store" assumption is dead.

The result on a live cluster: the connector-operator references a Secret
`<connector>-connector-cred` that nothing writes (the ESO step was never built —
it is a stub). The ToolHive proxy pod fails `CreateContainerConfigError: secret
"<connector>-connector-cred" not found`, and the ConnectorInstance never leaves
`Provisioning`.

What already exists and this ADR builds on:

- **The two-secret split.** The **Grant** (refresh token, client id, token
  endpoint, scope, expiry) is platform-*code*-only — the connector/vendor MCP
  server can never read it. The **access token** is a separate, short-lived secret
  and is the only thing a connector is ever shown.
- **A daemon-owned refresh loop.** `registerConnectorAuth` launches a connector-
  token reconciler that walks each tenant's ConnectorInstance CRs on a 5-minute
  clock and refreshes the access token before expiry, persisting rotated refresh
  tokens. Freshness is already the daemon's job.
- **The invariant: no RPC ever emits the token.** The refresh token crosses the
  API exactly once, inbound. No RPC hands out the access token either.

## Decision

**1. The daemon materializes `<connector>-connector-cred`; ESO is not used for
connector or tenant credentials.** ESO stays what it already is — platform-infra
only (postgres, ghcr, masterkeys, in the `gibson` namespace). The daemon is the
only component with tenant vault access (the operator has k8s `secrets` RBAC but
no Vault client), so it is the only component that *can* read a customer's
`auth: secret` credential or hold an `auth: oauth` access token. It writes the
Secret from the connector loop it already runs, for both auth modes: `oauth`
(refresh → write), `secret` (read tenant store → write). The Secret value is the
full `Bearer <token>` header.

**2. The token never crosses an RPC.** The daemon writes the Secret directly
rather than serving the token to the operator over a new RPC — preserving the
existing invariant and keeping the token's blast radius to the daemon alone. This
requires scoped `Secret` create/update/delete for the daemon SA in tenant
namespaces. The Secret carries an `ownerReference` to its ConnectorInstance, so
Kubernetes garbage-collects it when the connector is deleted.

**3. Credentials live in the tenant's configured store — customer owns
everything.** Grant and access token live in whatever store the tenant configured:
the hosted OpenBao namespace `tenant-<id>` for hosted, the customer's BYO Vault
for BYO. gibson-minted OAuth material follows the tenant into their BYO store; it
does not sit in a gibson platform location. "platform-only" describes *access*
(only daemon code touches the Grant, never the connector), not a storage location.
The isolation invariant holds regardless of store: the connector only ever reads
the short-lived access token from the k8s Secret, and ToolHive has no Vault client.

**4. Fail hard and loud.** On a refresh or store failure — revoked grant, vendor
down, BYO Vault unreachable — the daemon stops updating the Secret and reports the
reason through `GetConnectorAuthStatus`; the operator surfaces the ConnectorInstance
as `Degraded`, never a silent `Active`. There is no fallback cache. Rotation is
write-safe: a rotated refresh token is only treated as consumed once the write-back
to the store succeeds; if the store write fails, the refresh aborts and the old
grant is retried next pass. Recovery is re-authorization.

**5. The ConnectorInstance finalizer revokes the grant on delete.** The finalizer
(today a reserved stub) calls `RevokeConnectorGrant` so the vendor grant is revoked
and the Grant/access-token secrets are removed. The k8s Secret is garbage-collected
by its `ownerReference`; the grant needs an explicit revoke.

## Consequences

**Good.**

- One materializer, one owner, one clock — the daemon, reusing machinery it
  already has (tenant vault provider, `brokercodec`, the 5-minute loop).
- Smallest token-exposure surface: the token stays inside the daemon and the
  tenant k8s Secret; it never enters the operator or an RPC.
- Cloud-agnostic and BYO-uniform for free — the vault provider already abstracts
  hosted-namespace vs BYO-path-prefix. No ESO `SecretStore` to keep in sync with
  the broker config; no cloud secret-manager dependency.
- The customer gets full ownership, visibility, and revocation of their own
  connector credential.

**Costs and risks.**

- A BYO tenant's Vault becomes a **hard dependency** for connector uptime, and the
  daemon needs **read+write** to it (rotation write-back). A write failure during
  refresh-token rotation can break a connector until re-auth — mitigated by the
  write-safe rotation rule, surfaced by fail-loud status.
- New daemon RBAC: tenant-namespace `Secret` write. A real privilege add, justified
  because the daemon already holds the plaintext.
- `connectorauth` docs carry pre-ADR-0065 terminology ("bridge", ADR-0047/0049) and
  need a pass to say ToolHive / ADR-0065.

## Alternatives considered

- **Operator pulls the token over a new RPC, then writes the Secret.** Keeps the
  namespace boundary but breaks "no RPC ever emits the token" and spreads the token
  to a second component. Rejected.
- **ESO `ExternalSecret` per connector (the old ADR-0014 §3).** With only a Vault
  backend the daemon already speaks, ESO becomes a second representation of each
  tenant's Vault connection to keep in sync, plus a polling lag against a
  short-lived token. Rejected for connector/tenant credentials; ESO stays for
  platform-infra secrets.
- **Daemon egress proxy (token never touches k8s).** ToolHive already is a generic
  remote-MCP proxy with header injection; reimplementing it in the daemon to avoid a
  tenant-scoped k8s Secret is a large surface for an incremental gain, since ~20
  other tenant secrets already live in k8s under the same trust model. Kept as a
  possible future escalation if "no vendor token in k8s at all" ever becomes the bar.

## Status

Proposed. Supersedes ADR-0014 decision 3.
