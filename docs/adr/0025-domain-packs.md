# Domain Packs: discovered structure accumulates into portable per-vertical assets

A **Domain Pack** is the discovered taxonomy and ontology for one vertical or
target type: k8s, web, a LAN, defense, healthcare. It accumulates from real usage
([ADR-0024](0024-discoverable-taxonomy-and-ontology.md)) and it is portable. This
is the unit the product sells per vertical. See [`CONTEXT.md`](../../CONTEXT.md).

## Decision

1. **A Pack is structure, reputation is judgment.** The Pack holds the taxonomy and
   ontology for a domain. Technique × environment reputation
   ([ADR-0022](0022-betting-prediction-market.md)) holds what works. They compose,
   and both are per domain.

2. **Seed minimally, grow from usage.** A Pack starts from a minimal seed, or from
   a one-time LLM bootstrap of the first observations. Discovery grows it. No one
   authors an extensive Pack up front.

3. **A Pack is portable.** It can be packaged and shipped: "we have a Defense Pack,
   a Healthcare Pack." Every engagement in a vertical makes that vertical's Pack
   richer.

## Consequences

The moat compounds with usage. The more the platform runs in a vertical, the more
valuable its Pack, and the harder it is for a competitor to match without the same
run history. A Pack never carries cross-tenant data; it carries structure, and
structure is not a tenant's secrets.
