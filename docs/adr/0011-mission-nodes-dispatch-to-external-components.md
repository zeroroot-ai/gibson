# Mission nodes dispatch to external components, for every component kind

A mission node names a component and its work: an agent node names an agent, a tool node
names a tool. **Where that component runs is not the node's business.** In-cluster or on a
laptop, first-party or customer-authored — a node that names a registered component gets
dispatched to it.

Until now that was true for tools and plugins only. The harness enqueued remote work in
exactly two places (`execute_proto` for tools, `plugin_invoke` for plugins), so a component
registered as `kind=agent` enrolled correctly, heartbeated correctly, polled correctly, and
was never handed anything. The platform could be **called by** an external agent but could
not **run one**.

## Decision

**Agent mission nodes dispatch to external components**, over the same component work queue
tools and plugins already use, with work type `agent_execute`.

- The wire contract is the one the in-cluster gRPC agent client already speaks —
  `gibson.agent.v1.ExecuteRequest` / `ExecuteResponse` — so an agent that serves either
  transport implements one thing.
- A remote agent gets **no child harness object**; it is not in this process. It reaches
  harness operations (LLM, tools, findings) back over `HarnessCallbackService`, authorized by
  the task-scoped capability grant carried in the work item's context — the same mechanism a
  remote tool already uses.
- **A component advertising its own `grpc_endpoint` is dialled directly**, not queued.
  Queueing a reachable component would put a slower path in front of it.
- Depth caps, the untrusted-execution dispatch gate (ADR-0010), and the `concurrent_agents`
  quota apply identically to local and remote delegation. A remote agent is a delegation, not
  a loophole.

## Why not the other answer

The defensible alternative was: external agents *drive* missions rather than *serve* them —
they call `CreateMission` / `RunMission` and the platform only ever runs in-process agents.
Rejected, because it makes component kind decide capability. A customer authoring an agent
would find that the thing the SDK calls an agent cannot do what a mission node asks of an
agent, and the workaround — register your agent as a tool — is the sort of advice that
outlives every explanation of it. The two framings are not exclusive anyway: an external
agent can still drive missions; this decides what happens when a mission points at one.

Doing nothing was not an option. The pre-existing behaviour was a silent block: correct
registration, correct heartbeat, empty stream, forever.

## Consequences

- `kind` selects a wire contract, not a privilege level. Adding a kind means adding a work
  type and a payload contract, nothing more.
- The harness's remote paths (tool, plugin, agent) now differ only in marshalling; the queue
  mechanics are shared in `dispatchWorkAndWait`.
- Component SDK docs that told authors to register an agent as a tool to receive mission work
  are obsolete.
