# Compliance evidence is derived at query time; the signal pipeline is deleted

The audit log is the **only** compliance evidence base. Control mappings are computed
from retained audit events at read time, by the same rules that would have computed them
at write time. The entire `compliance_signal` emission pipeline — middleware, evaluator,
rule registry, resource resolver, sink, audit projector, and the Neo4j read path over
signal nodes — is deleted rather than finished.

This is a wholesale flip under `ADR-0027` discipline:
no parallel codepath, no flag, no seam left behind for someone to re-wire.

## Context

A `compliance_signal` was the audit entry we already write — tenant, actor, action,
resource, decision, result, timestamp — **plus exactly one field the audit entry does not
have: `control_ids`**, the list of framework controls the event satisfies or violates.
Everything else in the signal was a copy.

That one field was stamped by a `RuleEvaluator`, and the pipeline never had one:

- The field was declared optional and never assigned. `ComplianceMiddleware` carried
  `RuleEvaluator ComplianceRuleEvaluator // optional; no control_ids if nil`, and no
  production codepath ever set it.
- The only evaluator in the tree could not have been assigned to it. The interface wanted
  `Evaluate(sig, tenantID string) []string`; `ComplianceEvaluator.Evaluate` was
  `Evaluate(sig *taxonomypb.ComplianceSignal, rules []taxonomy.Rule) []string`. Wiring
  them together required changing one of the two — this was never a switch someone forgot
  to flip.

So the pipeline, switched on as written, would have emitted signals with **no
`control_ids`**: a second copy of the audit log, written into Neo4j, carrying no
information the audit log did not already carry.

The rest of it was equally dark, and had been for long enough that four independent
safety nets grew holes in the same place (gibson#1299):

- `ComplianceSink` was hardcoded `nil` at `harness_init.go:145`, and the factory skips the
  middleware entirely on a nil sink. The middleware never ran in production, ever.
- `AuditLogger.SetSignalProjector` — documented as the seam where "daemon startup wires
  the projector … so that every audit log entry also lands as a `compliance_signal`" — had
  zero callers. Definition only.
- There was no read path. No `ListComplianceEvidence`, no compliance RPC of any kind, in
  any `.proto` in any repo. `SemanticQuerier.FindingsByControl` issued real Cypher against
  `(:compliance_signal)` nodes that nothing had ever written, and had no caller beyond the
  factory that constructed it.
- The eleven integration tests covering exactly these behaviours were `t.Skip("TODO")`
  with zero assertions (gibson#1296), in a build tag no CI lane selected (gibson#1280),
  behind a skip-guard scanning `core/` paths that had not existed since the polyrepo split
  (gibson#1294).

The file names said SOC2. A reader auditing the tree — or an auditor reading a control
matrix — would have concluded this ground was covered. It was not partially covered. It
was off.

Re-enabling it as it stood was never on the table for a second reason: the removed sink
was **shared-Neo4j-backed**, which violates per-tenant graph isolation. Restoring it would
have reintroduced a cross-tenant write path, and re-homing it correctly meant building it
on the single-writer ingress of [ADR-0012](0012-single-writer-graph-ingress.md) — real
work, for a pipeline whose output was a duplicate.

## Decision

**Control mapping is derived at read time.** Mapping is rule-based: rules over
`(action, resource, effect)`. Anything a rule can compute from an event at write time, the
same rule can compute from the same retained event at read time. A second write pipeline
buys no information — it buys a second copy, a second failure mode, and a second thing to
keep tenant-isolated.

**The audit log is the evidence base.** Not one of two. The Redis Streams tenant log and
the Postgres `audit_log` table already record what a compliance signal recorded, minus the
field nothing populated. They are the record.

**Delete the pipeline, do not park it.** `ComplianceMiddleware` and its twenty-three
supporting files, `ComplianceEvaluator`, the rule registry, the resource resolver, the tag
merger and size enforcer, the metrics and health surfaces, `SignalSink`, `ComplianceSink`,
`SignalProjector` / `SetSignalProjector`, the `AuthzDecision` context key that existed only
so the middleware could read it, and the `SemanticQuerier` Cypher over signal nodes all go
in one change. A documented integration point with zero callers is worse than neither: it
reads as a design that exists.

**Manual curation survives; automatic stamping does not.** See "What deliberately stays"
below — the two are different mechanisms that happen to share the word "compliance".

## What write-time stamping would have bought, and why it lost

One real property, and it is worth naming precisely: **a frozen record of what the rules
said at the time**.

Under query-time derivation, control mappings are always computed by *today's* rules.
Change a rule in 2027 and 2026's evidence silently re-maps. An auditor who asks "what did
your system consider this event to be, on the day it happened?" gets an answer computed
today. Write-time stamping answers that question by construction.

It lost on three counts. It is not worth a write pipeline **today** — we have no evidence
read surface at all, so there is no consumer to be misled. It is recoverable **later
without stamping**, by versioning the rule catalog and evaluating a query against the
catalog version in force at the event's timestamp, which is a read-side change. And the
pipeline that would have bought it did not actually buy it: with no evaluator wired, it
would have frozen an empty `control_ids` list — a record of nothing, at the time.

If we later need point-in-time fidelity, the move is a versioned rule catalog, not a
resurrected emitter.

## What this makes load-bearing

Two things that were previously merely good hygiene are now the whole strategy.

**1. Audit-log reliability — gibson#1286.** If audit drops records, this decision fails,
because there is no second copy to reconcile against. #1286 (*chain audit_log rows and stop
losing records quietly*) is a prerequisite, not a nice-to-have. Both writers currently drop
on the floor by design: `AuditLogger.Log` is non-blocking and drops on a full queue
(`gibson_audit_write_drops_total`), and `audit.Writer` drops on a full buffer
(`gibson_audit_dropped_total`) and logs — but does not retry — a failed batch INSERT.
Counters exist; a gap in the record does not announce itself to a reader of the record.

**2. Audit retention — unresolved, and worse than assumed.** This ADR does not decide it,
but it must correct the premise it was reasoned from. Retention was believed unbounded.
It is not:

- The Redis Streams audit log is **capped**: `XADD … MAXLEN ~ 10000` per tenant
  (`auditStreamMaxLen`, `internal/platform/audit/logger.go`). Past roughly ten thousand
  events, a tenant's oldest evidence is trimmed away — approximately, silently, with no
  metric and no floor on age. That is a hard ceiling on the evidence base this decision
  just made authoritative.
- The Postgres `audit_log` table has no trim, no TTL and no partition rotation in the
  tree. It also has **no DDL in this repo** — neither `pkg/platform/migrations/postgres/`
  nor the deploy chart creates the table that `audit.Writer` INSERTs into and
  `audit.Query` reads from.

Unbounded retention is right for evidence and wrong for Redis memory; a 10k ring buffer is
wrong for evidence and right for Redis memory. The tension is real and this ADR
deliberately does not resolve it — but "we retain everything" is not the status quo, and
anyone reasoning from that assumption is reasoning from a false premise. Track it
separately.

## What deliberately stays

**`internal/engine/finding/compliance_update.go` (`UpdateComplianceMappings`).** This is
*human curation* of finding→control mappings — an analyst asserting that a specific
finding evidences a specific control, with an audit entry recording the diff. It is the
complement of what is being deleted, not an instance of it: automatic stamping was
rule-derivable, and therefore redundant with query-time derivation; a curator's judgement
is **not** derivable from any rule, so query-time derivation cannot replace it. Deleting it
would remove the one kind of mapping this decision cannot reconstruct. It has no wire
surface today (gibson#1299 item 4), which is a real gap and is tracked there.

**All audit logging.** `internal/platform/secrets/audit.go` matched the search for
`compliance_signal` only in its doc comments; it is the secrets broker's audit writer and
feeds the Redis pipeline. Every audit writer, reader, metric and guard in
`internal/platform/audit/` is untouched except for the removal of the projector hook. The
audit log gained importance under this decision — deleting audit functionality in its name
would be the exact inversion of the intent.

**The ontology reasoner.** `SemanticQuerier` is deleted, but the reasoner it closed over is
used independently by `ComponentService` for extension registration, and ontology
expansion is machinery a future query-time mapper would want.

**The Neo4j `compliance_signal` uniqueness constraint** in
`migrations/neo4j/001_initial_constraints.up.cypher`. Applied migrations are immutable;
editing one retroactively puts deployed databases out of step with the file that claims to
describe them. The constraint is inert — a uniqueness guarantee over a label with no
writer — and comes out in a forward migration, not by rewriting history.

## Considered options

**Build the evidence surface.** Design the read API, wire the projector on ADR-0012's
single-writer ingress, give the curator path an RPC. Rejected: it starts by building a
write pipeline whose entire output is a duplicate of the audit log, and defers the only
open question that matters (what does an evidence read actually look like) behind it.

**Wire emission now, defer retrieval.** Rejected for the same reason, more sharply: it
ships the duplicate and none of the value, and leaves the read surface exactly as absent as
it is today while looking like progress.

**Fix the evaluator signature and leave the pipeline dark.** Rejected: this is the
"documented seam with no callers" failure that produced gibson#1299 in the first place.
Code that compiles into a shape nobody runs is not readiness, it is a claim.

**Keep `SetSignalProjector` as a generic audit hook.** Rejected: it is a projector to a
sink that no longer exists. A general-purpose audit tap is a different design with
different constraints, and if we want one we should write that one.

## Consequences

- **No compliance evidence surface exists, and the tree now says so.** That is the point.
  The previous state also had no surface, but had ~4,500 lines and eleven SOC2-named test
  files implying otherwise.
- **Whoever builds evidence reads starts from the audit log**, and inherits the two
  load-bearing items above as prerequisites rather than discovering them late.
- **Rule changes retroactively re-map historical evidence.** Accepted today; the fix, if
  needed, is a versioned rule catalog evaluated against the event's timestamp.
- **The `signal_tags` component-manifest field is now inert.** It declared the tag keys a
  component stamps onto compliance signals. It stays because it is a customer-visible
  manifest schema field, and removing it is a manifest-compatibility decision, not this one.
- **`tests/e2e/secrets/*` assert audit rows against a Postgres table named
  `compliance_signals`** which no migration in the tree creates. Those files carry the `e2e`
  tag, which no CI lane runs, so the discrepancy has never surfaced. They are audit
  assertions and are left in place under this ADR; the table-name mismatch is a separate
  defect.
