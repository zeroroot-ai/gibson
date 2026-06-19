# SDK breaking-change inventory

The ECS rebuild is a **major-version SDK break** (no cutover — it's a clean build, not
released). This inventories what rips and what the new surface is. Touches `opensource/sdk`
(+ consumers: `adk`, examples, `debug-plugin`, `gibson-tool-runner`).

## Removed entirely
- **`opensource/sdk/memory/`** — the whole package. `Store`, `WorkingMemory`, `MissionMemory`,
  `LongTermMemory`, `Item`, `Result`. (Memory is now the World; nobody calls read/write —
  [ADR-0001](../adr/0001-ecs-native-mission-brain.md).)
- **Harness recall methods** — `GetFindings`, `FindSimilarFindings`, `GetRelatedFindings`,
  `GetPreviousRunFindings` (replaced by ambient projection).
- **taxonomy/v1 generic carriers** — `GraphNode`, `CoreNodeType`, `Relationship`
  ([ADR-0002](../adr/0002-scope-relative-entity-identity.md)).

## Changed
- **`agent.Agent`**: `Execute(ctx, harness, task) (Result, error)` → `Execute(ctx, harness, task) error`.
  `Result` shrinks to a terminal status; the real output is emitted observations.
- **Harness** becomes **emit-only**: a read-only **live `WorldView`** + **`Emit(observation)`**.
  - `SubmitFinding` → `Emit` (emits a `Finding` observation).
  - `ReportStepHints` → an emitted hint signal to the Orchestrator.
- **`serve/`**: the callback/tracer path (`callback_harness`, `callback_client`, `tracer`,
  `proxy_exporter`) becomes the **domain-event emit bus** (Emit → events → daemon reducer).
  `callback_memory.go` is removed.
- **taxonomy/v1**: typed entities → ark components; `CoreRelationType` → relationship kinds;
  `Value`/`MapValue` survive **only** for `Observations`.

## Added
- **taxonomy/v1**: `Scope`, `Credential`, `Account` entities; per-type **identity vs. volatile**
  field markers (drives the resolution loop-compare).
- A **label event** type (HITL labels — [ADR-0006](../adr/0006-closed-loop-learning.md)).

## Unchanged (deliberately)
- The agent/tool/plugin **dispatch** path (capability-grant, gRPC) and the manifest facility.
- Tools/plugins still run in sandboxes / tool-runner; `ToolExecution` tracks long runs
  ([ADR-0004](../adr/0004-clock-tick-runtime-engine.md)).

## Consumer ripple
`adk` (scaffolding + `gibson-cli`), `examples/`, `debug-plugin`, `gibson-tool-runner` — update
to the emit-only harness + `Execute … error`. Docs/onboarding rewritten. One coordinated major
bump; no compat shims (ADR-0027 wholesale-flip, no transition since unreleased).
