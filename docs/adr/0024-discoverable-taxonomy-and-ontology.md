# Discoverable taxonomy and ontology via safety-gated settlement

The fleet discovers taxonomy and ontology at runtime through the hypothesis→settle
loop ([ADR-0021](0021-agents-emit-hypotheses.md), [ADR-0023](0023-bet-settlement.md)).
No one writes them up front for each new target type. This **supersedes** the rule
in [`CONTEXT.md`](../../CONTEXT.md) that taxonomy promotion is a reviewed code
change. It builds on [ADR-0007](0007-world-sourced-graph-projection.md).

## Context

Taxonomy labels become Cypher query structure, so an unvalidated label is an
injection surface. That is why promotion was locked to a code review. But the
control does not have to be a human writing code. It can be an automated safety
gate plus settlement.

## Decision

1. **Ontology discovery is data-level.** New classes, relationships, and
   identifying-properties register through the existing `RegisterExtension`, which
   already rejects cycles and unknown prefixes. This is a light gate.

2. **Taxonomy discovery is gated before it reaches Cypher.** A proposed label is
   held as a safe-by-construction identifier and lives as data (an `Observation`)
   meanwhile. It is promoted to query structure only after it passes
   `ValidIdentifier` (automated safety) **and** it settles (recurrence plus HITL
   confirmation). Nothing unvalidated ever reaches Cypher.

3. **Discovery is the same loop as finding a vuln.** A structural proposal is a
   hypothesis. It settles on evidence and a human verdict. It earns technique ×
   environment reputation like anything else.

## Consequences

The platform grows a richer model of a vertical or target type every time it runs
there, with no up-front authoring. The label-promotion gate is a security-critical
path and is built and tested with that in mind.
