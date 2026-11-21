# The platform component catalog

The catalog is the set of manifests in `manifests/`. The `gibson` binary embeds them (`catalog.go`, `//go:embed manifests/*.yaml`). The embedded catalog is the one source of each connector, tool, agent and plugin that the platform offers (ADR-0136, ADR-0065 rule R6). No other repo holds a copy, and no code syncs a copy.

## How a new connector reaches a running platform

1. Write one manifest in `manifests/<id>.yaml` with `kind: connector`. A connector has no handler code and no image build. The `spec` states one tool class in `class`: `siem`, `edr`, `scanner`, `identity`, `cloud`, `observability`, `git-host`, `ticket`, `paging` or `patch` (ADR-0177). The loader refuses a connector with no class or with a class outside this list.
2. Open a pull request in `gibson`. The catalog loader validates the manifest in the tests (`catalog_test.go`).
3. Merge the pull request. The next `gibson` release embeds the manifest.
4. Upgrade the daemon to that release. At start, the daemon seeds the `platform_enabled` tuple of each catalog entry, and removes the tuple of an entry that left the catalog.

A new or changed connector thus needs a `gibson` release (owner decision of 2026-10-05, gibson#727). A signed catalog file outside `gibson` can come later, if on-prem customers need new connectors faster than they upgrade the daemon.

## Approval for a response action

A response action is a tool call through a connector, for example "isolate a host" or "disable an account". A response action waits for a person only when it destroys data (owner decision of 2026-11-20, ADR-0180, ADR-0132, gibson#1474). Revoke a session, disable an account and isolate a host carry no approval mark: the grant is enough. The manifest marks each tool that destroys data by its name.

```yaml
spec:
  responseActions: true
  tools:
    delete_device:
      approval: required
      blastRadius: one device and its data
    isolate_host:
      approval: none
      undo: release_host
    release_host:
      approval: none
    revoke_session:
      approval: none
    disable_account:
      approval: none
```

- `approval: required` sends each call of the tool to the approval queue. `approval: none` needs only the grant (`can_execute`).
- The mark is a per-catalog decision. It is not derived from "has an undo". The owner decision is that a tool that destroys data needs approval, and that revoke a session, disable an account and isolate a host do not. The manifest states `approval: none` for each of those three acts.
- `undo` names the tool of the same connector that undoes this tool. The approver sees `reversible` only when the manifest names one. With no `undo`, the approver sees `irreversible`.
- `blastRadius` is a short text for the approver. The daemon adds the arguments of the call to it.
- Only the manifest sets the mark. An agent cannot set it, and the annotations of the MCP server do not change it.

**The rule for a tool that the manifest does not name.**

- A connector with `responseActions: true` marks it. A new tool of the MCP server waits for a person until a manifest names it. This fail-closed rule is the deliberate default: the platform cannot know if a new tool of the vendor destroys data. Such a connector can mark no named tool `required`, because a containment destroys no data.
- A connector without `responseActions` needs only the grant for it. This is the choice for the connectors that only read. The platform has no list of the tools of a vendor, and a mark on every tool would make each read wait for a person. The cost is real: a vendor can add a write tool to a read-only server. Two measures limit it. The grant still applies. A reviewer who adds a connector that can write must set `responseActions: true`. A tool of a read-only connector that is dangerous can also be named with `approval: required`, and `approval: none` is then not allowed there.

**What happens at tool dispatch.** `metatool.Handler.Call` is the one path for an `mcp:` id. The harness (`invoke_tool`) and the `CallTool` RPC both use it. The order is: mission policy, grant, approval, dispatch.

1. A call of a marked tool with no decision records one request. It returns `pending authorization` to the agent at once. The agent is not blocked, and the connector gets no call.
2. A person decides in the approval queue (`DestructiveAuthorizationService`). A denial is final. The call then returns permission denied.
3. The next identical call runs one time after an approval. The daemon records the use as the event `destructive_action.consumed`. A later identical call needs a new approval.

An approval covers one call. The request key is a hash of the tenant, the mission, the connector, the tool and the canonical arguments. A call with another target, tool or mission needs its own approval. If the approval queue is not wired, a marked call is refused.

**The merge tool of a Git host (gibson#1458).** A Git host connector names the tool that merges a merge request with `role: merge`. Such an entry needs no `approval` on a connector without `responseActions`.

```yaml
  tools:
    merge_merge_request:
      role: merge
```

The order at dispatch is then: mission policy, grant, merge slot, approval, dispatch. The call must name the merge request in the argument `merge_request`, with the key that the fix job recorded (the URL, or the ref when the URL is empty). The daemon reads the World of the tenant and runs the call only when the merge request holds its merge slot (`World.MayMerge`, ADR-0179: one fix at a time for each Application). Otherwise the call returns `merge not granted yet`, and the connector gets no call. The daemon never takes the word of the agent that a slot is granted. A Git host connector that does not name its merge tool has no merge gate, so each Git host manifest with a merge tool must name it.

**A tool that only the daemon calls.** `role: daemon` marks a tool that the daemon calls on its own governed path, and no agent calls. The fix loop reverts a merge with `revert_merge_request` only after a failed health signal that the daemon read, so both fix loop manifests give that tool this role. An agent call of such a tool is refused as a blocked call before it reaches the connector.

```yaml
  tools:
    revert_merge_request:
      role: daemon
```

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

## A Hosted connector with a value from the tenant

Some Hosted servers must reach a host that only the customer knows. The Ansible Automation Platform MCP server needs `BASE_URL`, the address of the AAP of the customer (gibson#1508). A manifest declares a `variables` list in `spec`.

```yaml
shape: Hosted
variables:
  - name: base_url        # the key in the enable request
    env: BASE_URL         # the variable of the pod
    kind: endpoint        # the only kind: an https URL
    patterns:             # the hosts of the vendor, same grammar as endpointPatterns
      - https://*.vendor.example
    installPatterns: true # the platform owner of the install adds patterns
```

The tenant gives a value for each variable in `EnableConnector` (`variables`). The pod gets the canonical value as the variable `env`. The egress allow-list of the pod holds the exact `host:port` of the value, in addition to the `egressAllow` of the manifest.

The daemon applies these rules at enable time and again each time it hands the connector to the operator:

- The value is an https URL. It has no user info, no query, no fragment, no escape and no IP address.
- The host is a public DNS name. Its last label must be a public suffix of the ICANN list. This refuses `localhost`, `.svc`, `.cluster.local`, `.local`, `.internal`, `.lan` and `.corp`.
- The port is 443 or a number from 1024 to 65535.
- The value must match a host pattern. The loader refuses a variable with no `patterns` and no `installPatterns`. The egress entry is never a wildcard.
- The daemon refuses a missing value and a value that the manifest does not declare.
- A stored value that a later manifest or rule refuses gives the pod no value and no egress host.

### A server that the customer hosts

A GitHub Enterprise Server, a GitLab of the customer, a Prometheus and a Puppet Enterprise have no vendor domain. A pattern in the manifest cannot name them. A rule of "any public name" lets a tenant name `169.254.169.254.nip.io`, a public name that resolves to the cloud metadata address. So the rule is this:

- The manifest sets `installPatterns: true`.
- The platform owner of the install states the patterns in the chart, in `GIBSON_CONNECTOR_INSTALL_PATTERNS`, as JSON: `{"gitlab-fixloop/base_url": ["https://gitlab.customer.example"]}`.
- The daemon reads them at start. A value that does not parse, an unknown connector, a variable without `installPatterns` and a bad pattern fail the start.
- With no pattern from the manifest or the install, the variable takes no value.

The tenant never states a pattern, because the tenant is the party that the rule limits. The platform owner of a single-customer install knows the hosts of that customer. The SaaS states only the vendor patterns.

### The network layer

A public name can resolve to a private address. The daemon does not resolve names. The `CiliumNetworkPolicy` of each connector has an `egressDeny` rule (`operators/internal/ciliumegress.DenyRules`). It denies 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 169.254.0.0/16, 127.0.0.0/8, 100.64.0.0/10, 0.0.0.0/8, fc00::/7, fe80::/10, ::1 and ::, and the pod and the service ranges in `CONNECTOR_CLUSTER_CIDRS` of the connector operator. A Cilium deny rule wins over each allow rule, a `toFQDNs` allow too ([Deny Policies](https://docs.cilium.io/en/stable/security/policy/deny/)). A deny rule cannot name a host, but the address that a `toFQDNs` name resolves to is denied when it is in a denied range. So a server of the customer on a private address cannot be a connector. It needs a public address.

A CIDR rule of Cilium does not select a pod or a node that Cilium manages, so the deny does not block kube-dns or the `kube-apiserver` entity. Cilium before 1.14.16, 1.15.10 and 1.16.3 can drop a CIDR deny when a narrower CIDR allow exists (CVE-2024-47825). The install must run a fixed version.
