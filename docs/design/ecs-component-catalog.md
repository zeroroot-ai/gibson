# ECS component catalog

Derived from `taxonomy/v1` (the codegen source — [ADR-0001](../adr/0001-ecs-native-mission-brain.md))
and the identity model ([ADR-0002](../adr/0002-scope-relative-entity-identity.md)). Each type
becomes an ark component; relationships become ark relationships. Every type marks **identity**
fields (used by scoped loop-compare) vs **volatile** fields (updated on match, time-bounded,
never compared).

## Entities

### Capability (static, projected from registry/manifests — not in `taxonomy/v1`)
| Component | Identity | Notes |
|---|---|---|
| `Tool` | name@version | what the Orchestrator queries to dispatch |
| `Agent` | name@version | capabilities + target-types (for matching) |
| `Plugin` | name@version | incl. MCP-bridge plugins |

### Execution (dynamic, born on dispatch — unique per run, never deduped)
| Component | Identity | Volatile |
|---|---|---|
| `Mission` | mission id (launched) | goal, status |
| `MissionRun` | run id | status, result |
| `AgentRun` | run id | status, step hints |
| `ToolExecution` | run id | state (running/waiting/done), output |
| `LlmCall` | call id | tokens, cost, completion |

### Asset / target (the attack surface — identity is **scope-relative**)
| Component | Identity | Volatile |
|---|---|---|
| `Scope` ⚠️ | declared (RoE) / landmark-fingerprint (gateway + landmark host keys) on re-entry | reachability |
| `Host` | strong: `ssh_host_key` / `cloud_id` / MAC · local: `address` **within scope** | open ports, banners, OS guess, last-seen |
| `Port` | parent `Host` + `number`(+proto) | open/closed (interval) |
| `Service` | parent `Port` (≈1:1) | version, banner |
| `Endpoint` | parent `Service` + `path` | status, params |
| `Domain` | `name` | — |
| `Subdomain` | parent `Domain` + label | resolves-to |
| `Technology` | `name`+`version` (shared ref) | — |
| `Certificate` | `fingerprint` | validity, SANs |
| `Credential` ⚠️ | secret-material `hash` | works-on set |
| `Account` ⚠️ | (idp, subject) | roles, status |

### Result
| Component | Identity | Volatile |
|---|---|---|
| `Finding` | (target + finding-signature) | severity, status (confirmed/dismissed), labels |
| `Evidence` | parent `Finding` + content hash | — |
| `Technique` | ATT&CK id (ref) | — |
| `ComplianceSignal` | (signal-type + subject) | control_ids (stamped by compliance system) |
| `ComplianceMapping` | (framework, control) ref | — |

### Open-world escape hatch
| Component | Notes |
|---|---|
| `Observations` | `Value`/`MapValue`-backed bag of not-yet-typed perceptions; `surprise` score lives here; promotes into typed components as patterns recur |

## Relationships (from `CoreRelationType` → ark relationships)
`HAS_SUBDOMAIN`, `RESOLVES_TO`, `HAS_PORT`, `RUNS_SERVICE`, `HAS_ENDPOINT`, `USES_TECHNOLOGY`,
`SERVES_CERTIFICATE`, `HAS_EVIDENCE`, `USES_TECHNIQUE`, `LEADS_TO`, `AFFECTS`, plus execution
edges `USED_TOOL`, `DELEGATED_TO`, `EMITTED_SIGNAL`, `TRIGGERED`. The execution↔capability↔
asset↔result links (`instance_of`, `ran_against`, `launched_by`, `produced`) tie the graph.

## Confirmed additions to `taxonomy/v1` (decided)
**Add `Scope`, `Credential`, `Account`** (marked ⚠️ above) — load-bearing in the design,
absent from `taxonomy/v1` today — with identity/volatile markers. **Drop** the generic
`GraphNode` / `CoreNodeType` / `Relationship` carriers (ADR-0002); keep `Value`/`MapValue`
for `Observations` only.
