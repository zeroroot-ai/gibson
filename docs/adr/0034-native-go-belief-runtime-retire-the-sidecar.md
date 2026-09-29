# The belief runtime is native Go; the Python sidecar is retired

Runtime belief inference and the sequential planner run **in-process in Go**
(gonum for the linear algebra). The Python belief sidecar is retired. **pgmpy
stays only as the offline training / reference oracle** — never a deployed
dependency. This amends [ADR-0005](0005-belief-field-pgm.md)'s "pgmpy runs as a
sidecar" premise. See [`CONTEXT.md`](../../CONTEXT.md). Issues: #333, #346.

## Context

ADR-0005 put belief inference in a Python sidecar (pgmpy). In practice the runtime
already dropped pgmpy — `infer.py` runs the exact algorithm (variable elimination
+ noisy-OR over a bounded DAG slice) on **numpy alone**, parity-tested to 1e-12 —
precisely because pgmpy drags torch/xgboost/scipy, too heavy for the sandbox. That
algorithm is small and dependency-light, so it ports to Go. The BAMCP planner
(#333) would otherwise pay a cross-process round-trip per simulation.

## Decision

1. **Native Go runtime inference.** Port the exact VE + noisy-OR to Go (gonum),
   parity-tested against pgmpy the same way `infer.py` is (agreement to 1e-12 in
   CI). Belief is computed in-process, on evidence change, over the bounded slice.

2. **Native Go BAMCP.** The sequential planner (#333) runs in-process against the
   in-memory belief model — no sidecar round-trip per rollout, which matters for a
   planner that runs many simulations.

3. **Deterministic replay via a recorded seed.** BAMCP is Monte-Carlo /
   Thompson-sampled, which tensions with ADR-0005's "exact, deterministic replay."
   The planner records its RNG seed; replay reproduces the exact rollouts. In-
   process seeding is far easier to control than cross-process nondeterminism.
   ADR-0005's "exact inference" still holds for belief itself (VE, not sampling);
   only the *planner* samples, and it is seeded.

4. **pgmpy is offline-training-only.** `braintrain` keeps using pgmpy to fit CPTs
   and enablement-edge strengths offline, and pgmpy remains the CI parity oracle.
   It ships in no runtime image.

5. **The belief sidecar image is retired.** `gibson-belief-sidecar` and its chart
   pin go away; `SliceBeliefProvider` becomes an in-process call, not an HTTP
   round-trip.

## Considered and rejected

- **Keep the Python sidecar.** A container + a cross-process seam + a per-rollout
  round-trip + cross-process nondeterminism, for an algorithm small enough to run
  natively.
- **An off-the-shelf Go/Python POMDP library for BAMCP.** Most are sampling
  frameworks that fight the determinism requirement; a seeded bespoke Go planner
  gives exact replay control. Reconsider if a library proves it can be seeded
  end-to-end.

## Consequences

One language for the brain, no belief-sidecar container, no round-trip, and
simpler deterministic replay. The runtime gains a gonum dependency and a Go VE +
noisy-OR implementation with a pgmpy parity test in CI. `braintrain` stays Python.
The whole class of belief-sidecar image-pin problems disappears.
