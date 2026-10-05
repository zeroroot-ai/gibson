// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package daemon

import (
	"context"
	"errors"
	"log/slog"
	"regexp"
	"strings"
	"testing"

	"github.com/zeroroot-ai/gibson/internal/engine/taxonomy"
	"github.com/zeroroot-ai/gibson/internal/infra/types"
)

// gibson#550: a :Target node, so "what did we learn about target X" is one
// traversal. The join key already existed — Finding.scope and a fan-out
// instance's target_id both hold the target UUID — but there was no node to
// traverse from.

// TestBootstrap_WritesATargetNodePerResolvedTarget: the whole resolved set, not
// just the primary. A fan-out instance names its own target, so every target in
// the set needs a node or the join covers less than the run did.
func TestBootstrap_WritesATargetNodePerResolvedTarget(t *testing.T) {
	m, run := bootstrapFixture(t)
	def := forEachDef(0)
	targets := []forEachTarget{
		fanTarget("11111111-1111-1111-1111-111111111111", "a", "https://10.0.0.1:6443"),
		fanTarget("22222222-2222-2222-2222-222222222222", "b", "https://10.0.0.2:6443"),
	}

	proj, origins, err := missionDefinitionToProjected(def, "", targets)
	if err != nil {
		t.Fatalf("project: %v", err)
	}

	client := &recordingGraphClient{}
	writer := newFakeGraphWriter()
	b := NewGraphBootstrapper(client, writer, slog.New(slog.DiscardHandler))
	if _, err := b.Bootstrap(context.Background(), m.TenantID, m, def, run, proj, origins, targets); err != nil {
		t.Fatalf("bootstrap: %v", err)
	}

	got := writer.targets[m.TenantID]
	if len(got) != len(targets) {
		t.Fatalf("wrote %d :Target projections, want %d (one per resolved target)", len(got), len(targets))
	}
	byID := map[string]TargetProjection{}
	for _, p := range got {
		byID[p.ID] = p
	}
	for _, want := range targets {
		p, ok := byID[want.ID]
		if !ok {
			t.Fatalf("no :Target for %s; wrote %v", want.ID, got)
		}
		if p.Name != want.Target.Name {
			t.Errorf("target %s name = %q, want %q", want.ID, p.Name, want.Target.Name)
		}
		// Every Target must name the mission, or the TARGETS edge is not drawn
		// and the node is unreachable from the run that produced it.
		if p.MissionID != m.ID.String() {
			t.Errorf("target %s MissionID = %q, want %q", want.ID, p.MissionID, m.ID)
		}
	}

	// The bootstrap must not write a :Target itself — the projector is the sole
	// writer of a graph node (ADR-0112), same rule as :Mission in gibson#551.
	for _, w := range client.writes {
		if targetNodeWritePattern.MatchString(w.cypher) {
			t.Errorf("the bootstrap wrote a :Target node itself:\n%s", w.cypher)
		}
	}
}

// targetNodeWritePattern matches a statement that CREATEs or MERGEs a :Target.
var targetNodeWritePattern = regexp.MustCompile(`(?i)(MERGE|CREATE)\s*\(\s*\w*\s*:Target\b`)

// TestBootstrap_SkipsATargetThatDidNotResolve: a nil Target in the set is not a
// reason to fail the run, because the projection already refused a run whose
// target set would not resolve. Writing a node with a UUID and nothing else
// would be worse than writing none.
func TestBootstrap_SkipsATargetThatDidNotResolve(t *testing.T) {
	m, run := bootstrapFixture(t)
	def := forEachDef(0)
	resolved := fanTarget("11111111-1111-1111-1111-111111111111", "a", "https://10.0.0.1:6443")
	targets := []forEachTarget{resolved, {ID: "22222222-2222-2222-2222-222222222222"}}

	proj, origins, err := missionDefinitionToProjected(def, "", []forEachTarget{resolved})
	if err != nil {
		t.Fatalf("project: %v", err)
	}

	writer := newFakeGraphWriter()
	b := NewGraphBootstrapper(&recordingGraphClient{}, writer, slog.New(slog.DiscardHandler))
	if _, err := b.Bootstrap(context.Background(), m.TenantID, m, def, run, proj, origins, targets); err != nil {
		t.Fatalf("bootstrap: %v", err)
	}

	got := writer.targets[m.TenantID]
	if len(got) != 1 {
		t.Fatalf("wrote %d :Target projections, want 1 — the unresolved one must be skipped", len(got))
	}
	if got[0].ID != resolved.ID {
		t.Errorf("wrote target %q, want the resolved one %q", got[0].ID, resolved.ID)
	}
}

// TestUpsertTargetCypher_MatchesTheMissionAndNeverMergesIt: :Mission has one
// writer. Merging it here would re-create the second writer gibson#551 removed,
// on a third MERGE key.
func TestUpsertTargetCypher_MatchesTheMissionAndNeverMergesIt(t *testing.T) {
	if !strings.Contains(upsertTargetCypher, "OPTIONAL MATCH (m:Mission") {
		t.Error("the Cypher does not OPTIONAL MATCH the Mission")
	}
	if missionNodeWritePattern.MatchString(upsertTargetCypher) {
		t.Errorf("the target upsert MERGEs or CREATEs a :Mission:\n%s", upsertTargetCypher)
	}
	// The TARGETS edge must be conditional on the Mission existing, or the
	// FOREACH writes an edge from null.
	if !strings.Contains(upsertTargetCypher, "CASE WHEN m IS NULL") {
		t.Error("the TARGETS edge is not guarded on the Mission existing")
	}
}

// TestUpsertTargetCypher_KeepsAStoredValueWhenAParameterIsEmpty: a Target is
// written on every run, and a run may know less about it than a previous one.
func TestUpsertTargetCypher_KeepsAStoredValueWhenAParameterIsEmpty(t *testing.T) {
	setClause := setClauseOf(t, upsertTargetCypher)
	for _, prop := range []string{"name", "type", "url", "status"} {
		if !strings.Contains(setClause, "CASE WHEN $"+prop+" ") {
			t.Errorf("m.%s is assigned unconditionally; an empty parameter would erase the stored value", prop)
		}
	}
}

// TestTargetUpsertParams_CoverEveryParameterTheCypherReferences: a $param with
// no map key is a Neo4j ParameterMissing at runtime.
func TestTargetUpsertParams_CoverEveryParameterTheCypherReferences(t *testing.T) {
	want := map[string]bool{}
	for _, mt := range cypherParamPattern.FindAllStringSubmatch(upsertTargetCypher, -1) {
		want[mt[1]] = true
	}
	if len(want) == 0 {
		t.Fatal("the Cypher references no parameters; the regex is wrong")
	}
	got := targetUpsertParams("tenant-a", TargetProjection{ID: "t1"})
	for p := range want {
		if _, ok := got[p]; !ok {
			t.Errorf("the Cypher reads $%s and the param map does not supply it", p)
		}
	}
	for p := range got {
		if !want[p] {
			t.Errorf("the param map supplies %q and the Cypher never reads it", p)
		}
	}
}

// TestUpsertFindingCypher_ReachesTheTargetItWasFoundOn is the acceptance
// criterion: a finding is reachable from its target. Finding.scope already
// holds the target UUID, set server-side, so the edge needs no new producer.
func TestUpsertFindingCypher_ReachesTheTargetItWasFoundOn(t *testing.T) {
	if !strings.Contains(upsertFindingCypher, "OPTIONAL MATCH (tg:Target {id: $scope})") {
		t.Fatal("the finding upsert does not look for the Target its scope names")
	}
	if !strings.Contains(upsertFindingCypher, "MERGE (f)-[:FOUND_ON]->(tg)") {
		t.Error("the FOUND_ON edge is not drawn")
	}
	// OPTIONAL, not MATCH: a scope that is not a target UUID (a mission id, as
	// several producers still send) must not drop the Finding write entirely.
	if targetNodeWritePattern.MatchString(upsertFindingCypher) {
		t.Error("the finding upsert MERGEs a :Target; a scope that is not a target UUID would mint a junk node")
	}
	if !strings.Contains(upsertFindingCypher, "CASE WHEN tg IS NULL") {
		t.Error("the FOUND_ON edge is not guarded on the Target existing")
	}
}

// TestBootstrapVocabularyIsInTheTaxonomy: the per-run writes are a SECOND
// writer, which the projector's own drift check cannot see. That is how
// MissionNode came to be MERGEd on every run from outside the Taxonomy.
func TestBootstrapVocabularyIsInTheTaxonomy(t *testing.T) {
	if drift := vocabularyDrift(taxonomy.Global, bootstrapNodeLabels, bootstrapRelationshipTypes); len(drift) > 0 {
		t.Errorf("the bootstrap writes shapes the Taxonomy does not admit: %v", drift)
	}
	// And the guard must be able to fail, or it is decoration.
	if drift := vocabularyDrift(taxonomy.Global, []string{"NotPromoted"}, nil); len(drift) == 0 {
		t.Error("vocabularyDrift accepted an unpromoted label")
	}
}

// TestTheMissionGraphLabelsCarryAUniquenessConstraintOnTheirMergeKey is the
// point of promoting them. Before this, MissionNode was MERGEd on `id` on every
// run with no constraint behind it, so the derived identity gibson#528
// introduced was convention rather than enforcement.
func TestTheMissionGraphLabelsCarryAUniquenessConstraintOnTheirMergeKey(t *testing.T) {
	ddl := strings.Join(constraintStatements(taxonomy.Global), "\n")
	for _, label := range []string{"MissionNode", "MissionRun", "Target"} {
		want := "FOR (n:" + label + ") REQUIRE n.id IS UNIQUE"
		if !strings.Contains(ddl, want) {
			t.Errorf("no uniqueness constraint on %s.id; the DDL is:\n%s", label, ddl)
		}
		// The property has to be the one the writer keys on. `key` is the
		// default for an unlisted label, and a constraint on `key` would cover
		// no node any of these writers creates.
		if id := identityForLabel(label); id.props[0] != "id" {
			t.Errorf("identityForLabel(%q) keys on %q, but the writer MERGEs on id", label, id.props[0])
		}
	}
}

// TestAnEntityWriteCannotAddressTheMissionGraphOrATarget: an agent must not be
// able to invent a run's structure or a registered target.
func TestAnEntityWriteCannotAddressTheMissionGraphOrATarget(t *testing.T) {
	for _, label := range []string{"MissionNode", "MissionRun", "Target"} {
		if _, err := entityIdentity(label, "k"); err == nil {
			t.Errorf("an entity write addressed %s; it must be refused", label)
		}
	}
	// A label that IS agent-writable still is.
	if _, err := entityIdentity("Vulnerability", "CVE-2026-1"); err != nil {
		t.Errorf("entityIdentity refused Vulnerability, which agents do write: %v", err)
	}
}

// TestTheRefusalReasonIsSpecificToTheLabel: the refusal used to tell every
// caller its label "is identified by a composite key", which is false for three
// of the six and sends the reader looking for a composite that does not exist.
func TestTheRefusalReasonIsSpecificToTheLabel(t *testing.T) {
	_, err := entityIdentity("Target", "t1")
	if err == nil {
		t.Fatal("Target was not refused")
	}
	if strings.Contains(err.Error(), "composite") {
		t.Errorf("Target is keyed on id, not a composite, but the refusal says composite: %v", err)
	}
	_, err = entityIdentity("Port", "p1")
	if err == nil {
		t.Fatal("Port was not refused")
	}
	if !strings.Contains(err.Error(), "brain_host_id") {
		t.Errorf("Port's refusal does not name its real key: %v", err)
	}
}

// bootstrapTargetFixture keeps the type assertion honest: forEachTarget's
// Target is a *types.Target, and runTargetRef reads URL then Connection["url"]
// then Name, which is the precedence a run already uses for its target_ref.
func TestTargetProjection_URLFollowsTheRunsOwnPrecedence(t *testing.T) {
	cases := []struct {
		name   string
		target types.Target
		want   string
	}{
		{"URL wins", types.Target{Name: "n", URL: "https://u"}, "https://u"},
		{"then Connection", types.Target{Name: "n", Connection: map[string]any{"url": "https://c"}}, "https://c"},
		{"then the name", types.Target{Name: "n"}, "n"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := runTargetRef(&c.target); got != c.want {
				t.Errorf("runTargetRef = %q, want %q", got, c.want)
			}
		})
	}
}

// failingTargetWriter is a fakeGraphWriter whose target upsert always fails.
type failingTargetWriter struct {
	*fakeGraphWriter
}

func (failingTargetWriter) UpsertTarget(context.Context, string, TargetProjection) error {
	return errors.New("neo4j is down")
}

// TestBootstrap_ATargetWriteFailureFailsTheRun: unlike the projection tick,
// which is best-effort and self-heals, the bootstrap runs once before the
// harness is built. A missing :Target means the FOUND_ON edge never lands for
// this run and no later pass repairs it, so the run fails rather than producing
// a graph that quietly answers "nothing" for that target.
func TestBootstrap_ATargetWriteFailureFailsTheRun(t *testing.T) {
	m, run := bootstrapFixture(t)
	def := forEachDef(0)
	targets := []forEachTarget{fanTarget("11111111-1111-1111-1111-111111111111", "a", "https://10.0.0.1:6443")}

	proj, origins, err := missionDefinitionToProjected(def, "", targets)
	if err != nil {
		t.Fatalf("project: %v", err)
	}

	b := NewGraphBootstrapper(&recordingGraphClient{},
		failingTargetWriter{fakeGraphWriter: newFakeGraphWriter()}, slog.New(slog.DiscardHandler))
	_, err = b.Bootstrap(context.Background(), m.TenantID, m, def, run, proj, origins, targets)
	if err == nil {
		t.Fatal("bootstrap succeeded with a failing target write")
	}
	if !strings.Contains(err.Error(), targets[0].ID) {
		t.Errorf("the error does not name the target that failed: %v", err)
	}
}

// TestMustMatchTaxonomy_PanicsOnDrift: the guard both writers call at wiring
// time has to be able to fire, and its message has to say which writer drifted
// — there are two, and they declare different vocabularies.
func TestMustMatchTaxonomy_PanicsOnDrift(t *testing.T) {
	defer func() {
		r := recover()
		if r == nil {
			t.Fatal("mustMatchTaxonomy accepted an unpromoted label")
		}
		msg, ok := r.(string)
		if !ok {
			t.Fatalf("panicked with %T, want a string", r)
		}
		if !strings.Contains(msg, "test writer") {
			t.Errorf("the panic does not name the writer: %q", msg)
		}
		if !strings.Contains(msg, "NotPromoted") {
			t.Errorf("the panic does not name the offending label: %q", msg)
		}
	}()
	mustMatchTaxonomy("test writer", taxonomy.Global, []string{"NotPromoted"}, nil)
}

// TestMustMatchTaxonomy_AcceptsThePromotedVocabulary is the other half: the
// guard must not fire on either writer's real declaration, or the daemon cannot
// start.
func TestMustMatchTaxonomy_AcceptsThePromotedVocabulary(_ *testing.T) {
	mustMatchTaxonomy("graph projector", taxonomy.Global, projectedNodeLabels, projectedRelationshipTypes)
	mustMatchTaxonomy("graph bootstrap", taxonomy.Global, bootstrapNodeLabels, bootstrapRelationshipTypes)
}
