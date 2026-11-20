# The platform component catalog

The catalog is the set of manifests in `manifests/`. The `gibson` binary embeds them (`catalog.go`, `//go:embed manifests/*.yaml`). The embedded catalog is the one source of each connector, tool, agent and plugin that the platform offers (ADR-0136, ADR-0065 rule R6). No other repo holds a copy, and no code syncs a copy.

## How a new connector reaches a running platform

1. Write one manifest in `manifests/<id>.yaml` with `kind: connector`. A connector has no handler code and no image build. The `spec` states one tool class in `class`: `siem`, `edr`, `scanner`, `identity`, `cloud`, `observability`, `git-host`, `ticket`, `paging` or `patch` (ADR-0177). The loader refuses a connector with no class or with a class outside this list.
2. Open a pull request in `gibson`. The catalog loader validates the manifest in the tests (`catalog_test.go`).
3. Merge the pull request. The next `gibson` release embeds the manifest.
4. Upgrade the daemon to that release. At start, the daemon seeds the `platform_enabled` tuple of each catalog entry, and removes the tuple of an entry that left the catalog.

A new or changed connector thus needs a `gibson` release (owner decision of 2026-10-05, gibson#727). A signed catalog file outside `gibson` can come later, if on-prem customers need new connectors faster than they upgrade the daemon.

## A Remote connector with an endpoint for each tenant

Some vendors host one MCP server for each customer, or one for each Region or site. A manifest states `endpointPatterns` in `spec`. A tenant gives one `endpoint` when it enables the connector. The daemon accepts the endpoint only when it matches a pattern.

The proxy of the connector sends the credential of the tenant to the endpoint. The rules are strict for that reason.

- A pattern is an `https` URL. It has no user info, no query, no fragment and no escape.
- The host is a DNS name. The loader refuses an IP address and a name with one label.
- A pattern host is exact, or it starts with one wildcard label (`*.vendor.com`). The wildcard matches exactly one label.
- The part after the wildcard must be a registrable domain. The loader refuses a public suffix such as `herokuapp.com` or `co.uk`, because anyone can make a name below it. The error says that the host "leaves the vendor domain".
- A path segment is a literal or one `*`. The `*` matches one segment of letters, digits and `-._~`.
- The port is part of the pattern. It is 443 when the pattern states none.
- A pattern manifest can state a default `endpoint`. The default must match a pattern. With no default, `egressAllow` must be empty.
- Use an exact pattern for each Region or site of a vendor (Datadog, AWS, PagerDuty). Use a wildcard host only for a vendor that gives each customer a name below its own domain.

The egress allow-list of the `ConnectorInstance` follows the endpoint. With a tenant endpoint, it holds only `host:port` of that endpoint. A Hosted connector takes no endpoint.

The daemon checks the stored endpoint again each time it gives the connector to the operator. If a later manifest no longer matches the endpoint, the connector gets no endpoint and fails with a clear error. It never runs against a host that the manifest does not allow.

A pattern cannot reach a private address or a cluster service. A pattern names a vendor domain, and the `CiliumNetworkPolicy` of the connector also refuses a private address (ADR-0114).

## A Remote connector with its credential in a named header

A Remote connector with `auth: secret` sends the stored secret in one header. The default is `Authorization: Bearer <secret>`. A manifest can name another header and a value format in `credentialHeader` (gibson#1535).

```yaml
auth: secret
credentialHeader:
  name: X-ApiKeys
  format: "accessKey={accessKey};secretKey={secretKey}"
```

- `{secret}` stands for the whole stored secret.
- Any other placeholder, such as `{accessKey}`, stands for a property of the stored secret. The tenant then stores a JSON object.
- The loader refuses `credentialHeader` on an entry that is not Remote with `auth: secret`. It refuses a header that a connector must not set (`Host`, `Content-Length`, `Cookie` and others) and a format with no placeholder.
- The daemon refuses a value with a control character, so a secret cannot add a second header.
- An error about the format names the missing property and never a value. The value is in no log.

## OAuth with a client that the tenant registers

An entry with `auth: oauth` has `oauthClient: dynamic` by default. The daemon registers a client at the vendor (RFC 7591). A vendor with no dynamic client registration, such as Microsoft Entra ID, needs `oauthClient: tenant` (gibson#1538).

- The tenant registers a client at its own identity provider.
- The tenant stores the client secret as a named secret in its secret store.
- The tenant enables the connector with `oauth_client_id` and `oauth_client_secret_name`. The daemon refuses these fields for an entry that registers its own client. The table keeps the name and never the value.
- `StartConnectorAuthorization` reads the secret by name, and `instance_url` must be a host of the connector.

`oauthScope` is the scope that the authorization asks for. The daemon reads it in `StartConnectorAuthorization`, for the authorize URL and for a dynamic registration. The loader refuses `oauthScope` and `oauthClient` on an entry that does not use OAuth.

## A Hosted vendor connector

A `Hosted` connector runs as a pod with an image reference (ADR-0114, ADR-0136).

- The manifest names the image of the vendor in the registry of the vendor, pinned by digest. The catalog loader refuses a Hosted image with no digest.
- Nothing is mirrored, and nothing is signed again.
- The platform owner approves the connector when the manifest pull request merges. The catalog entry is that approval.

A Hosted manifest states its configuration in five fields (gibson#1536). The connector operator renders them. No value of a credential is in a manifest.

| Field | Meaning |
|---|---|
| `credentials` | A list of `{secret, property, env}`. Each `secret` is the name of a secret in the secret store of the tenant (OpenBao). The daemon reads the value and the pod gets it as the variable `env`. |
| `env` | Plain variables, as a map. The loader refuses a name that looks like a credential (`SECRET`, `TOKEN`, `PASSW`, `API_KEY` and others). Put such a variable in `credentials`. |
| `args` | The arguments of the server process. |
| `port` | The port of the server, from 1024 to 65535. The default is 8080. |
| `imagePullSecret` | The name of a secret of the tenant that holds the Docker config JSON of the registry. The operator writes a pull Secret from it. |

A variable name is used once, across `credentials` and `env`. A Remote connector states none of these five fields.

## A first-party plugin

A plugin in `plugins/<name>/` of this repo is its own Go module. The image workflow builds and signs its image, and writes the digest into its manifest through a pull request (gibson#790). No person edits that image line.
