# Clock-tick runtime engine

The brain runs as a **fixed clock-tick game loop**, not a fixed `for`-loop ReAct iteration
and not a fine-grained event-driven cascade. See [`CONTEXT.md`](../../CONTEXT.md); builds on
the log-first model in [ADR-0001](0001-ecs-native-mission-brain.md).

## Decision

1. **Tick rate ≈ 50 ms — one gRPC round-trip** (home-cable→AWS). That is the fastest an
   *external* result (LLM response, tool completion) can physically arrive; ticking faster
   would poll for results that can't exist yet, ticking much slower adds dead latency to
   sequential LLM chains.
2. **Each tick:** ingest results that arrived since last tick → run systems, **sweeping to
   quiescence** (re-run until no new events — so in-memory reasoning cascades complete
   *within* one tick) → emit changes as events → advance.
3. **Long operations run async between ticks.** LLM calls (seconds) and tools (minutes–
   hours) are not done "in a tick"; they run in the background and are picked up at whatever
   tick they complete. (A `ToolExecution`/`LlmCall` entity tracks them — [ADR-0001](0001-ecs-native-mission-brain.md).)
4. **We store events, not frames.** Empty ticks (the vast majority, since work is slow)
   produce no events and cost nothing. Replay/recreate comes from the event log, not from
   re-running ticks (which would be non-deterministic — LLM/tool outputs can't be re-simulated).
5. **Tick rate ≠ display rate.** The Scroller buckets the event log into coarser, readable
   frames for scrubbing; the 50 ms execution tick is not the display granularity.

## Considered and rejected

- **Fixed `for`-loop ReAct iteration** (the status quo): serial, LLM-in-the-loop every step;
  the thing being replaced.
- **Slow tick (e.g., 10 s):** adds up to a tick of latency per external result, accumulating
  badly across LLM-heavy chains; the only motivation (coarse uniform frames) is better served
  by separating display granularity from tick rate.
- **Fine-grained event-driven reactive cascade** (flecs-observer style): ark ships no
  scheduler and isn't built for it; hand-building observer cascades is more complex to order
  and terminate than a swept tick, and buys nothing the log doesn't already give for replay.

## Consequences

- ark provides storage/queries/relationships; **we own the loop** (ark has no scheduler) —
  the tick + sweep-to-quiescence driver is ours to write.
- ~20 sweeps/sec over a small World with sweep-to-quiescence is microseconds each —
  negligible cost for network-speed responsiveness.
- A cable connection under load (bufferbloat) can exceed 50 ms RTT; the tick is a target, not
  a hard real-time guarantee — a slow tick just means a slightly later pickup, never
  incorrectness.
