# Settlement predicates are CEL expressions over a gibson-owned evidence environment

A success predicate is a **CEL expression carried in a Domain Pack** (data), not
a Go evaluator registered per technique (code). gibson owns the **CEL
environment** — the evidence schema and helper-function catalog the expression
may reference. A pack predicate gibson has never seen is read in and just works,
as long as it stays within that environment. See [`CONTEXT.md`](../../CONTEXT.md).
Issues: #360, #361.

## Context

The shipped settlement code fuses three things in one call
(`RegisterHTTPStatusEquals(r, technique)`): a generic evaluator (code), a
predicate-type name, and a per-technique binding. With packs as the sole binding
source ([ADR-0033](0033-domain-packs-two-tier-catalog-and-tenant-extensions.md)),
those have to separate, and the question became whether a new predicate should
require new gibson code at all.

## Decision

1. **Predicates are CEL expressions in pack data.** A pack declares, per
   technique, a CEL expression over recorded evidence (e.g.
   `evidence.exists(e, e.type == "http_response" && e.status == 200)`). No Go
   evaluator per predicate type.

2. **The seam is the CEL environment, gibson-owned.** gibson defines and
   version-controls the environment an expression may reference: the evidence
   schema (`finding.EnhancedEvidence` shapes) plus a curated helper catalog
   (regex match, jsonpath, status extraction, …). A pack predicate that stays
   within the environment is compiled, type-checked, and evaluated at load with
   **no gibson change** — that is the "read it in and it just works" property.

3. **Extending the environment is the only thing that needs gibson code.** A
   predicate that needs a field or helper the environment does not expose (a new
   evidence type, a CVSS function) requires a gibson env extension. That is the
   rare case; the common cases (text match, status, jsonpath, marker) are pure
   pack data.

4. **Safety is inherent.** CEL is non-Turing-complete and terminating, with no
   side effects, so evaluating an untrusted pack's expression is bounded and
   safe. This is what makes accepting community-contributed packs viable
   ([ADR-0033](0033-domain-packs-two-tier-catalog-and-tenant-extensions.md)):
   packs ship no code, only bounded expressions over a gibson-owned environment.

## Considered and rejected

- **A bespoke Go evaluator catalog** (auditable, typed) with packs binding to
  evaluator names: every new predicate needs a gibson release, so packs are not
  self-contained — rejected against the packs-as-sole-binding-source decision.
- **Arbitrary code in packs / plugins for predicates:** unbounded blast radius;
  rejected in favor of CEL's bounded evaluation.

## Consequences

`cel-go` (already used in `brain/condition.go`) backs settlement predicates. The
builtin per-technique registration is refactored away; the evidence CEL
environment becomes a first-class, versioned gibson surface with its own
compatibility discipline (removing a field breaks packs). Packs become fully
self-contained and safe to accept from anyone.
