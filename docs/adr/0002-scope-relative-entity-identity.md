# Scope-relative entity identity and resolution

Entities in the Tenant World are identified **relative to a scope**, not globally, and
resolution is done by a **scoped loop-compare** rather than a maintained index. See
[`CONTEXT.md`](../../CONTEXT.md) for terminology; this refines [ADR-0001](0001-ecs-native-mission-brain.md).

## Decision

1. **An address is meaningless without its scope.** The coordinate of anything is
   `(scope, address)`. The same IP in two networks is two valid, distinct entities; one
   physical host reachable from two networks is one entity bridging two scopes (a juicy
   finding). **Scope** is the network/addressing context, carried by the agent's vantage
   (its foothold) — declared up front in the CUE mission (Rules of Engagement) or minted
   on pivot. Scope is the World's top-level partition.

2. **Identity is hierarchical, not a per-type composite key.** Things live inside things
   (`scope / host / port / service`), which the taxonomy already encodes as containment.
   An entity's identity = its parent + one local discriminator (Host→`address`,
   Port→`number`, Endpoint→`path`); a few are identified by their own content
   (Certificate→fingerprint, Credential→secret hash). A type marks only *which fields are
   identity vs. volatile state* — a small, mostly-obvious set — never a composite key.

3. **Resolution is a scoped loop-compare — no index, no merge.** On each observation:
   build a temporary entity, **iterate existing entities of that type within the same
   scope** (cheap — archetype/relationship iteration is the ECS's strength), and compare
   **identity signals only, exactly**. Match → fold the new data into the existing entity
   and update its volatile state; no match → the temp entity becomes new. Volatile state
   (open ports, banners, last-seen) is *updated on match*, never *compared*. Scoping the
   loop keeps it O(small) and avoids O(n²) blow-up on large scans.

4. **Nothing is deleted; associations are time-bounded.** "Port closed" / "IP reassigned"
   closes a validity interval and opens a new one (append-only, fits the event log). The
   history is intel.

5. **Identity contradictions are anomalies, not merges.** Same `scope+address` but a
   different SSH host key ⇒ a different entity *and* an anomaly-channel event (reimage,
   MITM, DHCP churn) — the security-correct behavior, resolved deterministically.

## Considered and rejected

- **A maintained `(scope,address)→entity` index.** Rejected: it's a side structure to keep
  in sync, and an archetype ECS is already fast at the iteration this needs. The scoped
  loop-compare uses the ECS's strength instead of bolting on what it doesn't natively do.
- **Per-type composite keys declared by hand.** Rejected as drift-prone bookkeeping;
  identity falls out of containment + one local-discriminator field instead.
- **Global (scope-less) identity keyed on IP.** Wrong: overlapping RFC1918 / VPC ranges
  mean the same IP legitimately recurs across networks.
- **Fuzzy/after-the-fact merge events.** Rejected: comparison is exact on strong signals;
  the rare two-entities-before-they-could-be-linked case is deterministic re-attribution.

## Consequences

- A type must declare which of its fields are identity vs. volatile state (light, on the
  type, drift-free — same pattern as durability and taxonomy codegen).
- Leans on ark being fast at scoped iteration (its core competency) — no value-indexing
  required, which sidesteps the one thing archetype ECSs don't do natively.
- Scope must be established before deep resolution works: declared in the mission, or
  minted + landmark-fingerprinted when re-entered from a new vantage.
