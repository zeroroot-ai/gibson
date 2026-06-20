# Dispatch as a Timeline side-effect; fail in-flight work on resume

The ECS brain is pure event-sourcing: Systems return events, the single reducer folds them,
and `World == fold(Timeline)` so the World is rebuilt by replay (ADR-0001). But **actually
launching** an agent/tool/plugin is a side effect (Redis enqueue, gRPC dial). We keep the
reducer and replay pure by making dispatch an effect *driven by* events, not part of folding
them:

- A **dispatch effect-handler** subscribes to **live** `WorkDispatched` events and actuates
  the real launch via the existing dispatch infra; when the SDK callback path reports back it
  `Submit()`s `WorkCompleted`. The World holds *intent* (`WorkItem{State: running}`); the
  handler is the *actuator*. This is the same "async consumer of the Timeline" pattern as the
  graph projector (ADR-0007) and the async Decider worker.
- **Replay/crash-resume re-folds the Timeline silently — no effects re-fire.** The handler
  listens only to live, post-replay events.
- **On resume, work still `running` with no completion is marked `WorkFailed`.** A mechanical
  retry System re-dispatches it iff the CUE node's `RetryPolicy` allows (deterministic); the
  Decider re-engages with judgment for goal missions.

## Considered and rejected

- **Blind auto-re-dispatch of in-flight work on resume.** Rejected: it would silently
  **re-fire a side-effectful tool** — e.g. re-run an exploit that already landed before the
  crash. A crash *is* a failure; surfacing it as `WorkFailed` and letting the deterministic
  retry policy / the Decider decide whether to retry is both safe and already-built machinery.
- **Adopt-and-ask** (mark orphaned, ask the Decider on every resume). Rejected for v1: adds a
  new state and a forced Decider round-trip on every resume for marginal benefit over
  fail-and-react.
- **Side-effecting from inside a System or the reducer.** Rejected: breaks replay purity —
  folding the Timeline would re-trigger real dispatches.

## Consequences

- Dispatch is idempotent on `WorkItem` ID; the effect-handler is the one place that touches
  the outside world, keeping the rest of the brain replayable and testable in-memory.
- A daemon crash mid-exploit will not silently repeat the exploit, but it *will* surface that
  work as failed — downstream reporting and the Decider must treat `WorkFailed`-on-resume as a
  normal outcome, not an anomaly.
