# Gibson

The runtime that gives an AI agent an identity, a grant for every tool it
touches, a sandbox for untrusted work, and a replayable record of what it did.

Writing an agent takes an afternoon. Running a fleet of them somewhere a
security review will accept is the hard part, and it is the same hard part
whether the agent patches CVEs, reconciles config or triages alerts. This
repository is the platform that solves it.

> **Elastic License 2.0.** You can read, download, run and modify this. You
> cannot offer it to third parties as a hosted or managed service. GitHub shows
> this repository as "NOASSERTION" because ELv2 is not an OSI-approved license —
> the terms are in [`LICENSE`](LICENSE).
>
> The surface you *build against* is permissive: the
> [SDK](https://github.com/zeroroot-ai/sdk) and
> [ADK](https://github.com/zeroroot-ai/adk) are Apache-2.0, and what you write
> with them is yours.

## What is in here

This is the platform monorepo. It absorbed what used to be six separate repos,
so these are subdirectories of one Go module rather than services you install
separately.

| Path | What it is |
|---|---|
| `cmd/gibson` | the daemon — orchestration, mission execution, the graph, the brain |
| `cmd/ext-authz` | the Envoy external-authorization service |
| `cmd/spiffe-jwks-exporter` | exports SPIFFE JWKS for off-cluster verifiers |
| `operators/tenant` | tenant lifecycle: provisioning, keys, teardown |
| `operators/platform` | platform bootstrap and its readiness conditions |
| `operators/connector` | MCP connector enablement |
| `internal/` | engine, server, infra. Not a public API |
| `pkg/` | the few packages that are |
| `migrations/` | database migrations |

`go 1.26`. The module is `github.com/zeroroot-ai/gibson`.

## The controls, briefly

- **Identity per agent.** SPIFFE/SPIRE inside the cluster, Ed25519 capability grants outside it. An agent is not a shared service account.
- **Authorization per tool call.** OpenFGA, Zanzibar-style. A grant is checked at call time, not assumed at start time.
- **Isolation for untrusted code.** Kata/Firecracker microVMs via [setec](https://github.com/zeroroot-ai/setec), which is Apache-2.0 and useful on its own.
- **A replayable record.** Per-tenant world state and timeline, so "what did it do" has an answer that is not a log grep.

## Tenant isolation

Each tenant has its own stores: a Postgres database, a Neo4j instance, a Redis
logical database and a vector collection. The world state, the timeline and the
knowledge graph of a tenant live in those stores. A request from a tenant
reaches the stores of that tenant only. [`docs/data-plane.md`](docs/data-plane.md)
describes the mechanism.

Some data is shared by design. The platform Postgres database holds platform
records, for example the quota of each tenant. OpenFGA holds the access tuples of all
tenants in one store.

Two RPC groups read or change more than one tenant by design. Each one needs a
role on the object `system_tenant:_system`, and no tenant role gives it.

| RPC group | Role | Who holds the role | What it does |
|---|---|---|---|
| `gibson.daemon.operator.v1.DaemonOperatorService` | `platform_operator` | Platform service accounts, for example the tenant operator | Tenant provisioning, tenant status, quotas, access tuples, connector grants, audit events |
| `gibson.tenant.v1.AdminTenantService` | `platform_owner` | The one Platform owner of the install, a person | Approve or reject a registration. Provision, update or delete a tenant. Read the billing state of a tenant |

This list comes from the authz registry. The full list is each row with the
object type `system_tenant` in
[`internal/platform/authz/registry/audit.csv`](internal/platform/authz/registry/audit.csv).

## Running it

You do not install this repository directly. It is deployed by the umbrella
chart:

```sh
helm install gibson oci://ghcr.io/zeroroot-ai/charts/gibson --version <x.y.z>
```

The chart is [zeroroot-ai/charts](https://github.com/zeroroot-ai/charts) and is
Apache-2.0. **The images it references are private** and need a registry
credential — the chart being open does not make the product free. Without the
credential the install fails at image pull, which is expected rather than
broken.

## Building

```sh
make bin          # build
make test-race    # tests with the race detector
make check        # the full local gate: fmt, vet, guards, tests
```

`make check` runs a set of invariant guards, not just tests — no cross-tenant
identifiers, FGA headers present, no skipped tests, build tags consistent. They
exist because each one is a bug that reached main once.

## Related repositories

| Repo | What | License |
|---|---|---|
| [`sdk`](https://github.com/zeroroot-ai/sdk) | component-development API | Apache-2.0 |
| [`adk`](https://github.com/zeroroot-ai/adk) | CLI and component scaffold | Apache-2.0 |
| [`setec`](https://github.com/zeroroot-ai/setec) | standalone microVM operator | Apache-2.0 |
| [`charts`](https://github.com/zeroroot-ai/charts) | the install chart | Apache-2.0 |
| [`dashboard`](https://github.com/zeroroot-ai/dashboard) | the console | Elastic v2 |
| [`gibson-executor`](https://github.com/zeroroot-ai/gibson-executor) | in-guest execution agent | Elastic v2 |

## Security

Please do not open a public issue for a vulnerability. See
[`SECURITY.md`](SECURITY.md).

## License and history

Elastic License 2.0. See [LICENSE](LICENSE). Zero Root AI is the licensor.

Issue and pull request numbers cited in comments and documents dated before 2026-09-05 refer to the tracker before the history reset, archived offline. They do not resolve on GitHub.
