# The technique hierarchy lives in the taxonomy

There is one technique vocabulary, owned by the taxonomy: **categories and
fine-grained techniques are both pack-defined**, a technique declares its parent
category as a taxonomy relationship, and everything — settlement bindings,
reputation, capability coverage, VoI dispatch — keys on the same taxonomy
identifiers. The old fixed Go enum degrades to seed constants. See
[`CONTEXT.md`](../../CONTEXT.md). Issue: #347.

## Context

Two technique vocabularies existed at different granularities: `types.TechniqueType`
(a fixed 8-value Go enum of coarse AI-attack categories) and `settlement.TechniqueID`
(an open, fine-grained, pack-defined string). VoI dispatch must map a candidate
(keyed by the fine id) to a capability (keyed by the coarse enum), which had no
bridge — the #347 blocker.

## Decision

1. **One vocabulary, in the taxonomy.** Both coarse **categories** and
   fine-grained **techniques** are taxonomy nodes, pack-defined and pack-
   extensible ([ADR-0033](0033-domain-packs-two-tier-catalog-and-tenant-extensions.md)).
   The current enum values seed the core categories in the core pack.

2. **Rollup is a taxonomy relationship.** Each technique declares its parent
   category (a `subCategoryOf`-style edge). The hierarchy *is* the bridge — no
   separate reconciliation table.

3. **Everything keys on taxonomy identifiers.** Settlement predicate bindings,
   reputation (technique × environment), and VoI candidates all reference the same
   technique/category ids. `types.TechniqueType` becomes seed constants, not the
   authority.

4. **Capabilities declare coverage.** A capability declares the categories and/or
   specific techniques it covers, as taxonomy refs. VoI dispatch gating maps
   `candidate.Technique` → its category (via the taxonomy) → capabilities whose
   coverage includes that technique or category.

5. **The candidate side is already tagged.** `HypothesisObservation.Technique`
   (sdk#88) threaded into `brain.Hypothesis` (#353); VoI candidates derive from
   hypotheses, so a candidate already carries its technique.

## Considered and rejected

- **Keep coarse categories as a fixed Go enum**, techniques open beneath it: the
  smaller change, but categories then can't grow with a vertical, and two
  authorities (enum + taxonomy) persist. Rejected in favor of a single taxonomy
  authority.
- **A translation table between the two vocabularies.** More machinery than a
  parent pointer, and it rots.

## Consequences

The taxonomy is the single authority for the technique hierarchy. Code using
`types.TechniqueType` migrates to taxonomy refs; capabilities gain a coverage
declaration. #347 is unblocked: the candidate is tagged, capabilities declare
coverage, and VoI dispatch bridges through the hierarchy.
