// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

//go:build integration

package daemon

import (
	"context"
	"sort"
	"testing"
	"time"

	"github.com/neo4j/neo4j-go-driver/v5/neo4j"

	"github.com/zeroroot-ai/gibson/internal/engine/brain"
)

// The application-lifecycle projection (gibson#1656) against a real Neo4j
// provisioned the way the tenant operator provisions one. The unit tests next
// door can only say the label and the edge type are passed as parameters.
// Whether Neo4j then materialises them as a label NAME and a relationship TYPE,
// and whether a second pass converges rather than duplicating, are properties
// of the server — so they are asserted against the server.

// projectEntity runs the production entity query with the production
// parameters, so nothing here can pass against a query the projector does not
// actually issue.
func projectEntity(t *testing.T, ctx context.Context, drv neo4j.DriverWithContext, e brain.EntitySnapshot) {
	t.Helper()
	params, err := entityUpsertParams(e)
	if err != nil {
		t.Fatalf("entityUpsertParams(%s:%s): %v", e.Label, e.Key, err)
	}
	runWrite(t, ctx, drv, upsertEntityCypher, params)
}

// TestLifecycleEntityProjectsUnderItsOwnLabel: every label the Taxonomy admits
// for the lifecycle materialises as that label, and a second pass converges.
func TestLifecycleEntityProjectsUnderItsOwnLabel(t *testing.T) {
	ctx := context.Background()
	drv := startProvisionedNeo4j(t, ctx)

	labels := []string{
		"Application", "Repository", "Image", "Package", "Deployment",
		"Vulnerability", "MergeRequest", "Pipeline", "Control",
	}
	for _, label := range labels {
		e := brain.EntitySnapshot{
			Label: label, Key: "k-" + label, ScopeID: "scope-1",
			Props: map[string]string{"name": "n-" + label},
		}
		projectEntity(t, ctx, drv, e)
		// Idempotence: the same sighting twice is one node.
		projectEntity(t, ctx, drv, e)

		recs := runWrite(t, ctx, drv,
			"MATCH (n {key: $key}) RETURN labels(n) AS labels, n.name AS name, count(n) AS n",
			map[string]any{"key": "k-" + label})
		if len(recs) != 1 {
			t.Fatalf("label %q merged %d nodes, want 1 — re-projection must converge", label, len(recs))
		}
		l, _ := recs[0].Get("labels")
		names, _ := l.([]any)
		if len(names) != 1 || names[0] != label {
			t.Errorf("label %q stored as %v — the parameter must become the label name", label, names)
		}
		if got, _ := recs[0].Get("name"); got != "n-"+label {
			t.Errorf("label %q property = %v", label, got)
		}
	}
}

// TestLifecycleEntityEnrichesInPlace: a later sighting of the same (label, key)
// overlays its properties onto the node the graph already has, which is what
// makes the graph additive across missions rather than duplicative.
func TestLifecycleEntityEnrichesInPlace(t *testing.T) {
	ctx := context.Background()
	drv := startProvisionedNeo4j(t, ctx)

	projectEntity(t, ctx, drv, brain.EntitySnapshot{
		Label: "Image", Key: "sha256:abc", Props: map[string]string{"tag": "v1"},
	})
	projectEntity(t, ctx, drv, brain.EntitySnapshot{
		Label: "Image", Key: "sha256:abc", Props: map[string]string{"registry": "gitlab"},
	})

	recs := runWrite(t, ctx, drv,
		"MATCH (i:Image {key: 'sha256:abc'}) RETURN i.tag AS tag, i.registry AS registry", nil)
	if len(recs) != 1 {
		t.Fatalf("want 1 Image, got %d", len(recs))
	}
	if tag, _ := recs[0].Get("tag"); tag != "v1" {
		t.Errorf("the first sighting's property was lost: tag = %v", tag)
	}
	if reg, _ := recs[0].Get("registry"); reg != "gitlab" {
		t.Errorf("the second sighting did not enrich the node: registry = %v", reg)
	}
}

// TestLifecycleEdgeTypesMaterialiseAndDoNotDuplicate: an edge type travels as
// data and becomes a relationship TYPE, and re-projection adds no second edge.
func TestLifecycleEdgeTypesMaterialiseAndDoNotDuplicate(t *testing.T) {
	ctx := context.Background()
	drv := startProvisionedNeo4j(t, ctx)

	e := brain.EntitySnapshot{
		Label: "Application", Key: "customer-portal",
		Edges: []brain.EntityEdge{
			{Type: "HAS_REPOSITORY", TargetLabel: "Repository", TargetKey: "gitlab.com/examplebank/customer-portal"},
			{Type: "HAS_DEPLOYMENT", TargetLabel: "Deployment", TargetKey: "examplebank/customer-portal"},
		},
	}
	projectEntity(t, ctx, drv, e)
	projectEntity(t, ctx, drv, e)

	recs := runWrite(t, ctx, drv,
		"MATCH (a:Application {key: 'customer-portal'})-[r]->(t) "+
			"RETURN type(r) AS type, labels(t)[0] AS target ORDER BY type(r)", nil)
	if len(recs) != 2 {
		t.Fatalf("want 2 edges after two passes, got %d — re-projection duplicated", len(recs))
	}
	var got []string
	for _, rec := range recs {
		ty, _ := rec.Get("type")
		target, _ := rec.Get("target")
		got = append(got, ty.(string)+"->"+target.(string))
	}
	sort.Strings(got)
	want := []string{"HAS_DEPLOYMENT->Deployment", "HAS_REPOSITORY->Repository"}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("edge %d = %q, want %q", i, got[i], want[i])
		}
	}
}

// TestOneCveAcrossTwoApplicationsIsOneVulnerabilityNode is the shared-knowledge
// property: two Findings naming the same CVE, in two different Applications,
// project as two Findings and ONE Vulnerability with two INSTANCE_OF edges.
func TestOneCveAcrossTwoApplicationsIsOneVulnerabilityNode(t *testing.T) {
	ctx := context.Background()
	drv := startProvisionedNeo4j(t, ctx)

	for _, f := range []brain.FindingSnapshot{
		{
			ID: "f-portal", Title: "vulnerable lodash", Severity: "high",
			ScopeID: "s", Status: brain.FindingStatusOpen, VulnerabilityID: "CVE-2025-1234",
		},
		{
			ID: "f-ledger", Title: "vulnerable lodash", Severity: "high",
			ScopeID: "s", Status: brain.FindingStatusOpen, VulnerabilityID: "CVE-2025-1234",
		},
	} {
		runWrite(t, ctx, drv, upsertFindingCypher, findingUpsertParams(f))
	}

	recs := runWrite(t, ctx, drv,
		"MATCH (v:Vulnerability {key: 'CVE-2025-1234'}) "+
			"OPTIONAL MATCH (f:Finding)-[:INSTANCE_OF]->(v) "+
			"RETURN count(DISTINCT v) AS vulns, count(DISTINCT f) AS findings", nil)
	if len(recs) != 1 {
		t.Fatalf("want 1 row, got %d", len(recs))
	}
	if n, _ := recs[0].Get("vulns"); n != int64(1) {
		t.Errorf("one CVE across two Applications must be %v Vulnerability node, want 1", n)
	}
	if n, _ := recs[0].Get("findings"); n != int64(2) {
		t.Errorf("INSTANCE_OF edges = %v, want 2 — each occurrence is its own Finding", n)
	}
}

// TestFindingStatusUpdatesInPlace: a status change lands on the Finding the
// graph already has. The node is never duplicated and the status is never
// empty, so the report page can count by status.
func TestFindingStatusUpdatesInPlace(t *testing.T) {
	ctx := context.Background()
	drv := startProvisionedNeo4j(t, ctx)

	f := brain.FindingSnapshot{
		ID: "f1", Title: "vulnerable lodash", Severity: "high", ScopeID: "s",
		Status: brain.FindingStatusOpen, VulnerabilityID: "CVE-2025-1234",
	}
	runWrite(t, ctx, drv, upsertFindingCypher, findingUpsertParams(f))

	for _, status := range []string{
		brain.FindingStatusFixing, brain.FindingStatusFixed, brain.FindingStatusVerified,
	} {
		f.Status = status
		runWrite(t, ctx, drv, upsertFindingCypher, findingUpsertParams(f))

		recs := runWrite(t, ctx, drv,
			"MATCH (f:Finding {brain_id: 'f1'}) RETURN f.status AS status, count(f) AS n", nil)
		if len(recs) != 1 {
			t.Fatalf("status %q produced %d Finding nodes, want 1", status, len(recs))
		}
		if got, _ := recs[0].Get("status"); got != status {
			t.Errorf("status = %v, want %q", got, status)
		}
	}

	// A Finding with no shared identity projects without a Vulnerability, and
	// creates no empty-keyed node for one.
	runWrite(t, ctx, drv, upsertFindingCypher, findingUpsertParams(brain.FindingSnapshot{
		ID: "f2", Title: "hardcoded secret", Severity: "high", ScopeID: "s",
	}))
	recs := runWrite(t, ctx, drv, "MATCH (v:Vulnerability) RETURN count(v) AS n", nil)
	if n, _ := recs[0].Get("n"); n != int64(1) {
		t.Errorf("Vulnerability nodes = %v, want 1 — a Finding with no CVE must merge none", n)
	}
	statusRecs := runWrite(t, ctx, drv,
		"MATCH (f:Finding {brain_id: 'f2'}) RETURN f.status AS status", nil)
	if got, _ := statusRecs[0].Get("status"); got != brain.FindingStatusOpen {
		t.Errorf("a Finding with no status projected as %v, want open", got)
	}
}

// TestLifecycleLabelIsDataNotCypher: the injection property, over the real
// entity query. A label made of Cypher is stored as a bad name, never executed.
func TestLifecycleLabelIsDataNotCypher(t *testing.T) {
	ctx := context.Background()
	drv := startProvisionedNeo4j(t, ctx)

	runWrite(t, ctx, drv, "CREATE (:Canary {id: 1})", nil)

	// entityUpsertParams refuses an out-of-taxonomy label, so the injection can
	// only be attempted by going around it — which is exactly what the server
	// side must survive on its own.
	params, err := entityUpsertParams(brain.EntitySnapshot{Label: "Application", Key: "k1"})
	if err != nil {
		t.Fatalf("entityUpsertParams: %v", err)
	}
	const injected = "Application; MATCH (n) DETACH DELETE n //"
	params["label"] = injected
	// Identity travels as the $ident map, not a bare $key (gibson#1669), so the
	// node has to be addressed the way the query actually merges it.
	params["ident"] = map[string]any{"key": "injected"}
	runWrite(t, ctx, drv, upsertEntityCypher, params)

	recs := runWrite(t, ctx, drv, "MATCH (n {key: 'injected'}) RETURN labels(n) AS labels", nil)
	if len(recs) != 1 {
		t.Fatalf("merged %d nodes for the injected label, want 1", len(recs))
	}
	l, _ := recs[0].Get("labels")
	got, _ := l.([]any)
	if len(got) != 1 || got[0] != injected {
		t.Errorf("labels = %v, want the literal [%q]", got, injected)
	}

	canary := runWrite(t, ctx, drv, "MATCH (c:Canary) RETURN count(c) AS n", nil)
	if n, _ := canary[0].Get("n"); n != int64(1) {
		t.Fatalf("the canary node is gone (count %v): the label was executed as Cypher", n)
	}
}

// TestAnAgentEnrichesTheFindingItMeantRatherThanCreatingASecondOne is the
// regression gibson#1669 named. The entity path merged everything on `key`
// while a raised Finding merges on `brain_id`, so an agent writing a priority
// onto a Finding created a SECOND :Finding beside the real one — and the
// priority, the status and any TOUCHES edge landed on a node nothing else
// references. A triage pass would then read its own writes back as missing.
func TestAnAgentEnrichesTheFindingItMeantRatherThanCreatingASecondOne(t *testing.T) {
	ctx := context.Background()
	drv := startProvisionedNeo4j(t, ctx)

	// A Finding raised the normal way.
	runWrite(t, ctx, drv, upsertFindingCypher, findingUpsertParams(brain.FindingSnapshot{
		ID: "f1", Title: "vulnerable lodash", Severity: "high", ScopeID: "s",
		Status: brain.FindingStatusOpen, VulnerabilityID: "CVE-2025-1234",
	}))

	// An agent annotates it, naming it the only way it can know it: by the
	// brain_id every read surface hands back.
	projectEntity(t, ctx, drv, brain.EntitySnapshot{
		Label: "Finding", Key: "f1", ScopeID: "s",
		Props: map[string]string{"priority": "P1", "priority_rule": "R01"},
		Edges: []brain.EntityEdge{
			{Type: "TOUCHES", TargetLabel: "Control", TargetKey: "PCI-DSS-6.3.3"},
		},
	})

	recs := runWrite(t, ctx, drv, "MATCH (f:Finding) RETURN count(f) AS n", nil)
	if n, _ := recs[0].Get("n"); n != int64(1) {
		t.Fatalf("Finding nodes = %v, want 1 — the agent's write created a second node", n)
	}

	recs = runWrite(t, ctx, drv, `
MATCH (f:Finding {brain_id: 'f1'})
OPTIONAL MATCH (f)-[:TOUCHES]->(c:Control)
RETURN f.priority AS priority, f.title AS title, f.status AS status, c.key AS control`, nil)
	if len(recs) != 1 {
		t.Fatalf("want one row, got %d", len(recs))
	}
	if got, _ := recs[0].Get("priority"); got != "P1" {
		t.Errorf("priority = %v, want P1 on the Finding the agent meant", got)
	}
	// The enrichment must not erase what raised the Finding.
	if got, _ := recs[0].Get("title"); got != "vulnerable lodash" {
		t.Errorf("title = %v, want the raised title preserved", got)
	}
	if got, _ := recs[0].Get("status"); got != brain.FindingStatusOpen {
		t.Errorf("status = %v, want open preserved", got)
	}
	if got, _ := recs[0].Get("control"); got != "PCI-DSS-6.3.3" {
		t.Errorf("control = %v, want the TOUCHES edge on the real Finding", got)
	}
}

// TestFindingInstantsSurviveReprojection: time to fix is only measurable if the
// instants it is measured between hold still (gibson#1671).
//
// A Finding is re-projected on every pass of the projector, so an instant written
// by a plain SET moves every time a scan runs. Measuring from one of those would
// mean "time since the last scan touched it", which shrinks as the fleet works —
// the harder failure, because it produces a number rather than an error.
func TestFindingInstantsSurviveReprojection(t *testing.T) {
	ctx := context.Background()
	drv := startProvisionedNeo4j(t, ctx)

	// toString on the server side, because a datetime read back into Go carries a
	// location pointer that makes two identical instants compare unequal with !=.
	// Canonicalising in the database compares the instant, which is the claim.
	read := func(id string) (created, verified any) {
		recs := runWrite(t, ctx, drv,
			"MATCH (f:Finding {brain_id: $id}) RETURN toString(f.created_at) AS c, toString(f.verified_at) AS v",
			map[string]any{"id": id})
		if len(recs) != 1 {
			t.Fatalf("matched %d Finding nodes for %s, want 1", len(recs), id)
		}
		c, _ := recs[0].Get("c")
		v, _ := recs[0].Get("v")
		return c, v
	}

	open := brain.FindingSnapshot{
		ID: "f-instants", Title: "outdated dependency", Severity: "high",
		ScopeID: "s", Status: brain.FindingStatusOpen,
	}
	runWrite(t, ctx, drv, upsertFindingCypher, findingUpsertParams(open))

	created, verified := read(open.ID)
	if created == nil {
		t.Fatal("a projected Finding must record when it was first seen")
	}
	if verified != nil {
		t.Fatalf("an open Finding must not carry a verified instant, got %v", verified)
	}

	// The projector runs again with the Finding unchanged, which is the common
	// case: a rescan that finds the same thing.
	time.Sleep(5 * time.Millisecond)
	runWrite(t, ctx, drv, upsertFindingCypher, findingUpsertParams(open))
	reCreated, _ := read(open.ID)
	if reCreated != created {
		t.Errorf("created_at moved on re-projection: %v -> %v", created, reCreated)
	}

	// The fix lands and the rescan verifies it.
	fixed := open
	fixed.Status = brain.FindingStatusVerified
	runWrite(t, ctx, drv, upsertFindingCypher, findingUpsertParams(fixed))

	stillCreated, verifiedAt := read(open.ID)
	if stillCreated != created {
		t.Errorf("created_at moved when the status changed: %v -> %v", created, stillCreated)
	}
	if verifiedAt == nil {
		t.Fatal("reaching verified must record when it happened")
	}

	// Every later pass re-asserts verified. The instant it first happened is the
	// one that measures time to fix, so it must not follow the last scan.
	time.Sleep(5 * time.Millisecond)
	runWrite(t, ctx, drv, upsertFindingCypher, findingUpsertParams(fixed))
	finalCreated, finalVerified := read(open.ID)
	if finalCreated != created {
		t.Errorf("created_at moved on a later pass: %v -> %v", created, finalCreated)
	}
	if finalVerified != verifiedAt {
		t.Errorf("verified_at moved on a later pass: %v -> %v", verifiedAt, finalVerified)
	}
}

// TestFindingCreatedAtIsTemporalNotAnEpochInteger: the dashboard's time series
// does `date(f.created_at)` and compares against `datetime()`, which an integer
// cannot answer. updated_at is deliberately still an epoch integer — this pins
// the difference so a later edit does not "tidy" them into agreement and
// silently empty the time series (gibson#1671).
func TestFindingCreatedAtIsTemporalNotAnEpochInteger(t *testing.T) {
	ctx := context.Background()
	drv := startProvisionedNeo4j(t, ctx)

	f := brain.FindingSnapshot{ID: "f-temporal", Severity: "low", ScopeID: "s"}
	runWrite(t, ctx, drv, upsertFindingCypher, findingUpsertParams(f))

	recs := runWrite(t, ctx, drv, `
MATCH (f:Finding {brain_id: 'f-temporal'})
RETURN date(f.created_at) AS d,
       f.created_at > datetime() - duration({days: 1}) AS recent`, nil)
	if len(recs) != 1 {
		t.Fatalf("matched %d nodes, want 1", len(recs))
	}
	if d, _ := recs[0].Get("d"); d == nil {
		t.Error("date(created_at) returned nothing — the dashboard time series would be empty")
	}
	if recent, _ := recs[0].Get("recent"); recent != true {
		t.Errorf("created_at is not within the last day: %v", recent)
	}
}
