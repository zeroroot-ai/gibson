# Single-writer graph ingress: no write API, APOC labels-as-parameters, global taxonomy

The Knowledge graph keeps exactly **one** write path — the projector — and gains no
generic write RPC. Shape flexibility comes from `apoc.merge.node`, which takes labels
and relationship types as **parameters** rather than query text, gated by a **global**
Taxonomy; anything outside it lands as an `Observation`. Tenant and Scope are resolved
**server-side** from the mission record, never from the emitted payload. Every other code
path that can open a Neo4j write session is deleted, and an analyzer keeps it that way.

This implements the boundary [ADR-0007](0007-world-sourced-graph-projection.md) asserts
but does not enforce, and inherits identity from
[ADR-0002](0002-scope-relative-entity-identity.md).

## Context

ADR-0007 established the graph as a projection rather than a store. In practice the
invariant was a convention, and the code had drifted:

- `graph_projector_neo4j.go` — the intended sole writer. Constant Cypher, `$params`.
- `grpc.go` — an inline `MERGE (m:Mission …)` in the RPC layer. A second data writer.
- `graphrag/loader/loader.go` (**deleted**, gibson#1266) — string-built Cypher from tool output: labels,
  relationship types and property names spliced with `fmt.Sprintf`. **Unwired at
  runtime but not unreferenced**: `NewGraphLoader` is never constructed in
  production (`harness_init.go` passes a permanently-nil `sbxDiscovery`), yet
  seven production files import the package — the `graphrag/ingest` discovery
  processor, three harness callback files, `harness/sandboxed/executor.go`,
  `sandboxed_setec_adapter.go` and `platform/component/service.go`. Deleting it
  cascades into removing the whole `DiscoveryResult` ingest path.
- `graphrag/local_provider.go` — **a live generic graph-write API.**
  `ComponentService/StoreNode` and `StoreRelationship` are callable RPCs in the
  authz registry (`can_execute`, `component` identity) that splice caller-chosen
  labels and relationship types into Cypher with `fmt.Sprintf`. Injection is
  contained — `sanitizeIdentifier` is an allow-list that keeps only
  `[A-Za-z0-9_]`, so no Cypher syntax survives it — but containment of injection
  is not the point: this is a generic write API by any other name, and its
  existence is the thing this ADR argues against.
- `GraphClient.ExecuteWrite` on the interface, plus a deprecated `ExecuteWriteQuery`
  taking an arbitrary Cypher string. Any holder of a client could write anything.
- `gibson-migrate` (DDL) and `gibson-backup` (APOC export). Operational, not data-plane.

So "sole writer" was true of the design and false of the code, and nothing detected the
drift. Separately, the request that prompted this — "let any agent write most any shape,
but prevent cross-tenant writes and breakouts" — reads as a generic write API, which is
the one thing that would make the injection surface permanent.

## Decision

**No write API.** `Emit` stays the sole ingress and the projector stays the sole writer.
A generic graph-write RPC is rejected: "any shape" and "no injection" are in tension, and
every mitigation for a generic API reconstructs what the projection already provides.

**Shape via APOC, not string-building.** `apoc.merge.node($labels, $ident, $onCreate)`
and `apoc.merge.relationship(...)` accept labels and types as runtime arguments, so no
Cypher is assembled from input in our code.

**This does not make a label inert, and an earlier revision of this ADR wrongly
said it did.** APOC quotes labels with `apoc.util.Util.quote`, which wraps a
non-identifier in backticks and **does not escape backticks inside the name**. A label
carrying a backtick therefore closes the quoting and reaches the query as structure.
Verified against `neo4j:5.26.27-community` while implementing this ADR: the statement
executes, affects nodes, and returns **no rows and no error**, so the caller observes
success.

The correct reading is narrower: passing labels as parameters removes *our*
string-building, and the **Taxonomy is what makes a label safe** — not APOC. The
Taxonomy therefore carries a hard constraint rather than a stylistic one: every
promoted label and relationship type must be a plain identifier, enforced in code, so a
name APOC cannot quote losslessly can never reach the driver.

There is no live exposure in gibson: emitted labels are compile-time constants, and the
paths that spliced caller-supplied labels are removed by the deletion order below. This
is a false premise corrected before anything was built on it, which is the only reason
it is cheap.

**Global Taxonomy.** The allow-list of labels and relationship types is platform-wide and
versioned in code. Promotion is a reviewed change, performed by `Sensing`. Out-of-taxonomy
shapes are never rejected — they land as `Observations` — so an agent can always write and
can never invent schema.

**Server-side tenant and scope.** Tenant comes from the mission record the daemon created,
reached via the capability grant's `mission_id`. Scope comes from that mission's target
definition. Neither is readable from the payload; there is no field for them. The bar is
not "a user was present" — agents outlive the session — but "every write is attributable
to a mission a user launched".

**Identity from the Timeline.** Observation nodes key on the Timeline event id, so
projection is replayable. A content hash rides along as a property for recurrence
detection; repeat sightings stay distinct, because "seen again three weeks later" is
signal in this domain.

**Entity references are generational handles; new entities are named by coordinate.**
An agent refers to something it was *shown* by the opaque handle carried in its
`WorldView` slice, and to something it has just *discovered* by the coordinate it
observed. The two are complementary: creation is bounded by the mission's server-side
Scope, reference is bounded by what the slice contained. An agent can express neither
"the host at some other network's address" (no Scope field exists) nor "entity 4213"
(handles are not constructible), so both cross-scope creation and enumeration are
unrepresentable rather than rejected.

The handle is ark's `ecs.Entity` — `{id, gen}`, a **generational index**, the standard ECS
solution to dangling and recycled references. This is deliberately the boring answer:

- **Staleness is automatic.** A destroyed-and-recycled slot bumps `gen`, so an old handle
  fails the generation check. No expiry policy, no TTL to tune.
- **Re-projection does not invalidate.** Generations advance on destruction, not on
  refresh, so a long mission's handles stay valid across `WorldView` re-projection. The
  "do handles expire mid-mission?" question dissolves — a stale handle means the entity is
  genuinely gone, which the agent should see as an error.
- **Validation is table-backed, not signed.** The daemon already materialised the task's
  slice, so "was this shown to you?" is an O(1) set lookup against per-task state. Signing
  would add a key to distribute and rotate for no gain, since the daemon must consult
  per-task state regardless to enforce the slice boundary.
- **Cross-tenant is structural.** Handles are indices into a per-tenant World; a handle
  from one tenant names nothing in another because it is a different arena.

In-process ECS treats handles as trusted because everything shares an address space. Here
the agent is remote and untrusted, so the one adaptation is that the handle is validated
against the issuing task's slice on the way in — the generational check catches staleness,
the slice check catches "not yours".

**This surface now exists (gibson#1377) — the correction below records the
history.** The SDK read half shipped in v0.161.0, and the gibson handler landed
in v0.162.0: `HarnessCallbackService.WorldView` (`internal/engine/harness/worldview.go`)
projects a mission-Scope-limited slice of the tenant World back to the agent,
wired to the per-tenant brain in `internal/server/daemon/brain_worldview.go`.
Every entity in a slice is named by a **server-minted, non-constructible opaque
handle** (HMAC over scope+kind+brain-id under a process-random key), so the
agent references entities it was shown without ever seeing a raw brain id and
cannot enumerate past the slice boundary. The tenant and scope are read off the
daemon's mission record, not the request, so an agent cannot widen its slice.

The **generational-staleness / cross-slice** validator half (the `focus` refusal
that rejects a handle never issued to this caller) is implemented server-side in
`focusSlice`. The earlier text below described this surface as non-existent; that
was true when written (sdk#341 had delivered only the emit half) and is retained
for the record. `gibson.world.v1.WorldService` remains dashboard-facing and
distinct — the agent-facing read is `WorldView`, with its own handle-named
shape, not the dashboard views.

What holds today is the **coordinate** half and the **negative**. An agent names
a new entity by the coordinate it observed — `ObserveRequest`'s observations are
address, FQDN, secret hash, identifier and nothing else — and no raw brain id is
accepted from the payload: the harness callback path used to adopt the emitter's
`Finding.id`, and the daemon now assigns that identity itself, as the component
path always has (gibson#1259). Both are guarded in
`internal/engine/harness/emit_identity_test.go`, structurally over the generated
descriptors for the first and behaviourally for the second. The generational
handle waits on gibson#1377.

**APOC Core only.** `dbms.security.procedures.allowlist` admits the merge procedures and
nothing else. File and network procedures (`apoc.export.*`, `apoc.load.*`,
`apoc.cypher.runFile`) stay disabled, and `dbms.security.procedures.unrestricted` is never
set.

**Deletion.** `loader/` goes. The inline mission MERGE folds into the projector.
`ExecuteWriteQuery` goes and `ExecuteWrite` leaves the `GraphClient` interface. A
`gibsoncheck` analyzer fails the build on any Neo4j write outside the projector package.
`gibson-migrate` remains a separate Job — DDL and data have different lifecycles, and
folding schema authority into the daemon would put *more* privilege in the request path.

**Network boundary.** The tenant-operator emits a NetworkPolicy admitting bolt only from
the daemon. This is defence in depth, not the primary control: it is enforced by the
cluster rather than by our own discipline, which matters because Neo4j Community has no
in-database RBAC.

## Write contract

**Append-only.** An agent emits observations; it never updates or deletes. The reducer
folds, the projector materialises. This follows from ADR-0007 (the graph is a projection)
and ADR-0002 (associations are time-bounded, never deleted — a port no longer seen is
`Open=false`, not removed). Deletion is a platform operation on the Timeline, not an agent
capability. It also removes a whole class of question: there is no update path to
authorise, and no way for a compromised tool to erase evidence of itself.

**Bounded.** The emitter is remote and untrusted, so the payload carries explicit caps
rather than trusting the producer: maximum payload bytes, maximum properties per
observation, maximum property-key length, maximum observations per task. Over-limit is
**rejected, never truncated** — silent truncation corrupts data in a system whose whole
output is evidence. The existing 100 KiB input / 1 MiB output bounds on the sandbox path
are the precedent.

**Property keys are data, not schema.** Promoted types take their properties from the
Taxonomy. Everything else lives inside the `Observation` payload map, where keys are map
entries passed as parameters — so unbounded keys are a schema-sprawl and memory concern,
not an injection one, and the caps above are what address them.

## Deletion order

Dependency-ordered so the tree is green at every step and the analyzer never needs a
baseline of pre-existing violations:

1. **Delete `internal/engine/graphrag/engine` (the `CypherBuilder`).** Genuinely
   zero importers, so this is the free one. `graphrag/loader/` was originally
   listed here as "zero callers" — that was wrong (seven production importers,
   see Context), and the correction is why the loader now has its own step below
   rather than leading the sequence.
2. **Fold the inline `MERGE (m:Mission …)` from `grpc.go` into the projector.**
   Behaviour-preserving move; the projector already owns entity materialisation.
3. **Delete `ExecuteWriteQuery`.** Zero callers; it is a generic arbitrary-Cypher
   primitive with no legitimate use.
4. **Remove `ExecuteWrite` from the `GraphClient` interface.** The projector reaches the
   driver through a narrower type nothing else can obtain.

   **Status (gibson#1300): partly done, not yet a pure type-system property.**
   `ExecuteWrite` is not on the interface, and the dormant `CreateNode` /
   `CreateRelationship` / `DeleteNode` write methods were removed (they had no
   production callers). But `Query` remains write-capable — it selects its
   transaction mode from the statement text, which schema DDL migrations and the
   being-retired ingest loader (gibson#1266) still rely on. So "sole writer" is
   currently held jointly by three things, not by the type system alone: the
   projector being the only *entity* writer, `Query`'s only write consumers being
   DDL and the loader, and the `graphwrite` analyzer — which now exempts only the
   specific driver-adapter files (`neo4j.go`, `session_client.go`) rather than the
   whole `graphrag/graph` package, so a new write-capable method added elsewhere
   in it is flagged. Making it a pure type-system property means splitting `Query`
   into a read-only entry point plus an explicit DDL/loader write path; that is the
   tracked remainder of gibson#1300.
5. **Turn the `graphwrite` analyzer on as blocking.** By this point there are no
   violations, so it ships without a baseline — a baseline is a list of exceptions that
   never shrinks, and this class does not need one.

   **Know what it does not cover.** `graphwrite` governs *who opens a write
   transaction*, not *how a query string is built*. It is blind to steps 7 and 8
   by construction: both write through legitimately-held clients. Do not read a
   green `graphwrite` as "the write surface is closed" until those land.
6. **Provisioning: APOC Core plugin + allowlist, and the tenant NetworkPolicy.** Separate
   from the code work — a StatefulSet change and a restart, per tenant.
7. **Retire the `ComponentService` graph-write RPCs.** `StoreNode` and
   `StoreRelationship` are the generic write API this ADR rejects, live and in
   the authz registry today. They predate the decision, so retiring them is a
   wholesale flip (ADR-0027): the callers move to `Emit`, and the RPCs and their
   registry entries go in the same change. No deprecation window, no parallel
   codepath.
8. **Unwind `graphrag/loader/` and the `DiscoveryResult` ingest path.** Seven
   production importers, so this is a real refactor rather than a deletion, and
   it is last because it is the only step whose blast radius reaches outside the
   graph packages. **Landed (gibson#1266).** `loader/` is gone, and
   `graphrag/engine/` went with it — the loader was the only caller of its
   `Sanitize*` helpers. Discovery now folds into the World and the projector
   materializes it. Two things the plan did not anticipate:

   - **The refactor had to wire the path, not just move it.** Replacing a
     dormant importer with a dormant importer of a different shape would satisfy
     the letter of this step and none of its point, so the processor is now
     constructed at startup and reaches all three dispatch paths: the harness
     callback service, the Setec sandbox executor, and
     `ComponentService.SubmitResult`. Field-100 discoveries reached nothing
     before; they reach the graph now.
   - **Step 4 was incomplete.** `GraphClient` still carried `CreateNode`,
     `CreateRelationship` and `DeleteNode`, each opening its own
     `session.ExecuteWrite` with a `fmt.Sprintf`-spliced label or relationship
     type — and `CreateRelationship` did not sanitise its. Dropping
     `ExecuteWrite` from the interface did not close the write surface, because
     those three were a write surface in their own right. The loader was their
     only caller, so they went with it. `graphwrite` would not have flagged
     them: they open the transaction from inside the `graph` package, and the
     analyzer governs which package may write, not which caller asked.

   Out-of-taxonomy shapes — evidence, custom nodes, explicit relationships —
   have no World vocabulary. They are counted as skipped and logged, never
   invented. That is the `Observations` fallback above, which this step does not
   build.

`gibson-migrate` and `gibson-backup` are untouched throughout; they are operational tools
outside the data plane.

**On the sequence changing under us.** Steps 1–5 were authored believing the
loader was dead code and that four paths could write. Both were wrong, and the
error was caught by an implementer checking the premise rather than executing
it. The order above is the corrected one; treat it as evidence that this list is
a plan, not a survey.

## Considered options

**A generic write RPC** (the original request). Rejected: it makes the injection surface
permanent, and "only an authed user may call it" is unsatisfiable — agents are not users,
they run asynchronously after the user has gone, and any service account added to bridge
that gap reopens the hole.

**Per-tenant Taxonomy.** Rejected: the Taxonomy *is* the schema. Per-tenant shapes push
multi-tenancy back into every query and let `Host` / `HOST` / `host_v2` diverge unnoticed.
`Observations` already supplies the flexibility without the divergence.

**Full APOC, unrestricted.** Rejected. On Community there is no RBAC, so `unrestricted`
applies to every connection holding the credential — the same credential the projector
uses, on a platform whose input is attacker-influenced. It converts a graph-write bug into
a cluster pivot.

**Wait for the `SubmitFinding` → `Emit` rename.** Rejected: the properties above are
independent of the rename, and coupling them means they ship when the rewrite ships.
Hardening first also shrinks the rewrite — one writer to point at instead of four.

## Consequences

- **APOC Core becomes a required plugin** on every tenant Neo4j StatefulSet. This is a
  provisioning change and a restart, not a daemon-only change.
- **Graph backup stays broken.** `gibson-backup` needs `apoc.export.*`, which needs the
  file settings this ADR declines to enable. It already degrades to "store skipped"; that
  remains true and visible. Enabling backups is a separate decision that reintroduces the
  pivot and deserves its own ADR.
- **A new node type is a code change.** That is the intended cost of a global Taxonomy.
- **The NetworkPolicy is inert until CNI policy enforcement is enabled** in the cluster
  (the VPC CNI addon has `enableNetworkPolicy` off today). Worth writing now regardless.
- The remaining internet-facing risk for customer-run agents is **not** the database — it
  is the callback listener that `Emit` lives on, which needs the per-peer method policy
  the main gRPC listener already has.
