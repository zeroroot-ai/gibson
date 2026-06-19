# Belief field computed by a PGM (pgmpy), trained offline

The belief field (`P(juicy)` / `P(exploitable)` / `P(reachable)`, propagated over the
attack graph — the unified score / prioritization / attention model from
[ADR-0001](0001-ecs-native-mission-brain.md)) is computed by a real **probabilistic
graphical model** — **pgmpy** — not by the LLM and not by hand-tuned weights. See
[`CONTEXT.md`](../../CONTEXT.md).

## Decision

1. **A PGM does the calculation, not the LLM.** LLMs are bad probability calculators —
   poorly calibrated, non-deterministic, slow, expensive. A Bayes net is calibrated, fast,
   free, and belief-propagation-over-a-graph is literally what it does.
2. **Exact inference only** (VariableElimination/BeliefPropagation), never sampling — so the
   field is **deterministic and reproducible**, which the 1:1 replay / Scroller requires.
3. **Read-only at runtime.** The brain consults the network for posteriors when evidence
   changes; it never trains online (online learning would drift the field mid-mission and
   break replay).
4. **Learning is out-of-band.** A batch job turns event logs into training data — labels are
   largely automatic because the log records outcomes (`evidence → outcome`) — fits CPTs
   (and optionally structure), validates, and ships a **versioned** network.
5. **Missions pin their model version**, so replay re-loads the exact model and reproduces.
6. **The LLM fills gaps, not the math.** For *novel* nodes the network has no table for, the
   LLM estimates a prior/likelihood that feeds the net.
7. **Sources, honoring no-cross-tenant:** a curated **base model** (vendor red-team + public
   CVE / MITRE ATT&CK) every deployment starts from, plus optional **per-tenant refinement**
   from that tenant's own logs. No cross-tenant data pooling.

## Considered and rejected

- **LLM scoring (per-entity).** Non-deterministic (breaks replay), uncalibrated, and
  absurdly expensive for an always-on field.
- **Hand-authored CPTs / ad-hoc influence-map weights.** Expert-system authoring — the same
  pattern rejected for playbooks; the PGM learns its tables from data instead.
- **Online learning.** Drifts the field within a mission; breaks deterministic replay.

## Consequences

- pgmpy is Python; it runs as a **sidecar**. This is fine: training is fully offline (no
  hot path), and inference is only on evidence change (not every tick).
- A model artifact + version registry is needed; missions record the version they used.
- The curated base model is a **commercial asset** — trained only on vendor red-team + public
  CVE/MITRE ATT&CK data, **never on tenant data**. OSS ships without it (or a minimal default);
  the commercial layer serves it. See [ADR-0003](0003-open-core-boundary.md).
