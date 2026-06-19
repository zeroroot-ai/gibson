# Entity ↔ graph mapping (ECS World ⇄ knowledge graph)

The decision table for how each taxonomy node type ([`opensource/sdk/taxonomy/core.yaml`])
is represented in the Tenant World and projected to the per-tenant Neo4j graph.
Grounds [ADR-0007](../adr/0007-world-sourced-graph-projection.md) (graph = projection of
the World) and [ADR-0002](../adr/0002-scope-relative-entity-identity.md) (scope-relative
identity). The graph is a **read-model**: every node/edge below is *materialized by the
projector from the World*, never written by an agent.

## Representation kinds

- **Entity** — a first-class ECS entity in the World: own component, observation event,
  reducer, and scope-relative identity resolution. Projects to a graph node.
- **Sub-state** — folded into a parent entity's component (no independent identity per
  ADR-0002). Projects to a graph node + containment edge derived from the parent.
- **Lifecycle** — execution provenance already modeled by the brain's Mission / WorkItem
  (fed by the daemon event stream, not by agent observations). Projects from lifecycle.
- **Marker** — a derived flag on an entity (not its own node).

## The table

| Node type | Kind | Identity (ADR-0002) | Parent / projection edge | Status |
|---|---|---|---|---|
| `scope` | partition key | the partition itself | top-level `ScopeID` on every entity | **done** (field) |
| `host` | **entity** | `(scope, address)` + ssh-key / cloud-id strong signals | — → `:Host` | **done** |
| `port` | sub-state | `number` within host | host `HAS_PORT` → `:Port` | **done** |
| `service` | sub-state | `(host, port)` + protocol | port `RUNS_SERVICE` → `:Service` | **S1 (this slice)** |
| `endpoint` | sub-state | `(service, path)` | service `HAS_ENDPOINT` → `:Endpoint` | **done** (World; projected as `:Service` props — node promotion deferred) |
| `certificate` | sub-state | fingerprint (content) | service `SERVES_CERTIFICATE` → `:Certificate` | **done** (World; projected as `:Service` props) |
| `technology` | sub-state | `name` (+ version) | `USES_TECHNOLOGY` → `:Technology` | **done** (World; projected as `:Service` props) |
| `domain` | **entity** | `(scope, name)` | — → `:Domain` | planned |
| `subdomain` | **entity** | `(scope, fqdn)` | domain `HAS_SUBDOMAIN`; `RESOLVES_TO` host | planned |
| `credential` | **entity** | secret hash (content) | `:Credential` (scope-partitioned) | **done** |
| `account` | **entity** | `(scope, identifier)` | `:Account` | **done** |
| `finding` | **entity** | content / id | `AFFECTS` → asset; `:Finding` | **done** (FindingRaised) |
| `evidence` | sub-state | — | finding `HAS_EVIDENCE` → `:Evidence` | planned |
| `technique` | reference | external id (e.g. `T1190`) | finding `USES_TECHNIQUE` → `:Technique` | planned |
| `compliance_signal` | sub-state | `(finding, control)` | `EMITTED_SIGNAL` → `:ComplianceSignal` | planned |
| `mission` | lifecycle | id | `:Mission` (from Mission entity) | **done** |
| `mission_run` | lifecycle | run id | `RUN_OF` mission | **done** (WorkItem/Mission) |
| `agent_run` | **entity** | run id (harness-assigned) | parent run `DELEGATED_TO` → `:AgentRun` | **done** (AgentRunObserved; run-provenance sole-written by projector, #837) |
| `tool_execution` | lifecycle | id | `USED_TOOL`; `PRODUCED` | **done** (WorkItem) |
| `llm_call` | lifecycle | id | `TRIGGERED` | lifecycle |

## Why service/endpoint/certificate/technology are sub-state, not entities

Per ADR-0002 an entity's identity is `parent + one local discriminator`. A service has no
meaning without its `(host, port)`; an endpoint none without its service; a certificate is
identified by its own fingerprint but is always *served by* a service. Folding them into
the parent entity keeps identity resolution a single scope-partitioned loop over **hosts**
(the only thing with cross-address identity) rather than a join across types. The projector
re-expands them into distinct `:Service` / `:Endpoint` / … nodes with the containment edges,
so the **graph** is fully normalized even though the **World** keeps them as parent sub-state.

## What S1 delivers

`service` as port sub-state: `ServiceInfo{Protocol,Name,Product,Version}` on
`PortObservation`, carried by `HostObserved.Services` (keyed by port), folded by
`reconcilePorts` with progressive enrichment (a richer scan refines detail; a barer
re-scan never erases it), exposed on `HostSnapshot.Services`, and replay-deterministic.
Remaining rows are added as their observation events + reducers land (tracked under the
S1 follow-ups of the ADR-0007 epic).

[`opensource/sdk/taxonomy/core.yaml`]: ../../../../opensource/sdk/taxonomy/core.yaml
