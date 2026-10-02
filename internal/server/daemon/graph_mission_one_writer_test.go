// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package daemon

import (
	"context"
	"log/slog"
	"regexp"
	"sort"
	"strings"
	"testing"
	"time"

	missionpb "github.com/zeroroot-ai/sdk/api/gen/gibson/mission/v1"
)

// gibson#551: a :Mission node has ONE writer. The per-run graph bootstrap used
// to MERGE its own on {id} alone, while the projector MERGEs on
// {id, tenant_id}. That is not a cosmetic duplication: when the bootstrap ran
// first its CREATE produced a node with no tenant_id, which the projector's
// MERGE then could not match, so the tenant ended up with two :Mission nodes
// carrying the same id — and the one its tenant-scoped reads could see was not
// the one the MissionRun hung off.

// TestBootstrap_WritesTheMissionNodeThroughTheSoleWriter is the regression: the
// bootstrap must not issue a :Mission statement of its own, and the projection
// it hands the writer must carry everything the retired writer used to set.
func TestBootstrap_WritesTheMissionNodeThroughTheSoleWriter(t *testing.T) {
	m, run := bootstrapFixture(t)
	m.Description = "Sweep the fleet. Then report."
	m.MissionDefinitionJSON = `{"name":"fanout"}`
	def := forEachDef(0)
	def.Description = "Sweep the fleet. Then report."

	targets := []forEachTarget{
		fanTarget("11111111-1111-1111-1111-111111111111", "a", "https://10.0.0.1:6443"),
	}
	proj, origins, err := missionDefinitionToProjected(def, "", targets)
	if err != nil {
		t.Fatalf("project: %v", err)
	}

	client := &recordingGraphClient{}
	writer := newFakeGraphWriter()
	b := NewGraphBootstrapper(client, writer, slog.New(slog.DiscardHandler))
	if _, err := b.Bootstrap(context.Background(), m.TenantID, m, def, run, proj, origins); err != nil {
		t.Fatalf("bootstrap: %v", err)
	}

	// The bootstrap's own client must not CREATE or MERGE a :Mission node. It
	// may still MATCH one — that is how a MissionRun and a MissionNode attach.
	for _, w := range client.writes {
		if loc := missionNodeWritePattern.FindString(w.cypher); loc != "" {
			t.Errorf("the bootstrap wrote a :Mission node itself (%q):\n%s", loc, w.cypher)
		}
	}

	got := writer.missions[m.TenantID]
	if len(got) != 1 {
		t.Fatalf("writer received %d mission upserts, want exactly 1", len(got))
	}
	p := got[0]
	if p.ID != m.ID.String() {
		t.Errorf("ID = %q, want %q", p.ID, m.ID)
	}
	if p.Name != "fanout" {
		t.Errorf("Name = %q, want %q", p.Name, "fanout")
	}
	if p.TargetID != m.TargetID.String() {
		t.Errorf("TargetID = %q, want %q", p.TargetID, m.TargetID)
	}
	if p.Description != "Sweep the fleet. Then report." {
		t.Errorf("Description = %q, want the mission's full description", p.Description)
	}
	// The objective is the first sentence, not the whole description.
	if p.Objective != "Sweep the fleet." {
		t.Errorf("Objective = %q, want the first sentence only", p.Objective)
	}
	if p.YAMLSource != `{"name":"fanout"}` {
		t.Errorf("YAMLSource = %q, want the stored definition", p.YAMLSource)
	}
	// The bootstrap runs because the mission is starting.
	if p.Status != "running" {
		t.Errorf("Status = %q, want running", p.Status)
	}
	if p.StartedAt == nil {
		t.Error("StartedAt is nil; the bootstrap knows the run is starting")
	}
}

// TestBootstrap_WithoutAGraphWriter_Fails: a missing writer must fail the run,
// not be skipped. Skipping would leave the MissionRun and every MissionNode
// MATCHing a :Mission that does not exist, so the whole graph for that run
// would be silently empty.
func TestBootstrap_WithoutAGraphWriter_Fails(t *testing.T) {
	m, run := bootstrapFixture(t)
	def := forEachDef(0)
	targets := []forEachTarget{
		fanTarget("11111111-1111-1111-1111-111111111111", "a", "https://10.0.0.1:6443"),
	}
	proj, origins, err := missionDefinitionToProjected(def, "", targets)
	if err != nil {
		t.Fatalf("project: %v", err)
	}

	b := NewGraphBootstrapper(&recordingGraphClient{}, nil, slog.New(slog.DiscardHandler))
	_, err = b.Bootstrap(context.Background(), m.TenantID, m, def, run, proj, origins)
	if err == nil {
		t.Fatal("bootstrap succeeded with no graph writer; the run's :Mission node would never exist")
	}
	if !strings.Contains(err.Error(), m.ID.String()) {
		t.Errorf("error does not name the mission: %v", err)
	}
}

// missionNodeWritePattern matches a statement that CREATEs or MERGEs a
// :Mission node. A MATCH on one is fine: a MissionRun and a MissionNode both
// attach to a :Mission the sole writer already made.
var missionNodeWritePattern = regexp.MustCompile(`(?i)(MERGE|CREATE)\s*\(\s*\w*\s*:Mission\b`)

// setClauseOf returns everything from the unconditional SET onward. It fails
// the test when the marker is absent rather than slicing from a -1 index, so a
// reshaped Cypher is a loud failure and not a silently empty assertion.
func setClauseOf(t *testing.T, cypher string) string {
	t.Helper()
	i := strings.Index(cypher, "\nSET ")
	if i < 0 {
		t.Fatal("the Cypher has no unconditional SET clause; it was reshaped and these assertions no longer apply")
	}
	return cypher[i:]
}

// setParamPattern finds each `m.<prop> = ...` assignment in the SET clause.
var setParamPattern = regexp.MustCompile(`m\.([a-z_]+)\s+=\s+([^,\n]+)`)

// cypherParamPattern finds every `$param` reference.
var cypherParamPattern = regexp.MustCompile(`\$([a-z_]+)`)

// TestUpsertMissionCypher_KeepsAStoredValueWhenAParameterIsEmpty pins the
// property that makes one writer with two callers safe. The CreateMission RPC
// upserts from a goroutine and the run bootstrap upserts inline, so either can
// land second. If a SET assigned its parameter unconditionally, the later write
// would erase what the earlier one knew — the RPC does not know the objective
// or the definition, and the bootstrap does not know the creating principal.
func TestUpsertMissionCypher_KeepsAStoredValueWhenAParameterIsEmpty(t *testing.T) {
	setClause := setClauseOf(t, upsertMissionCypher)
	matches := setParamPattern.FindAllStringSubmatch(setClause, -1)
	if len(matches) < 9 {
		t.Fatalf("found %d SET assignments, want every MissionProjection field; the regex or the Cypher changed shape", len(matches))
	}

	// created_at/updated_at are the writer's own timestamps, not caller data.
	timestamps := map[string]bool{"created_at": true, "updated_at": true}
	guarded := 0
	for _, mt := range matches {
		prop, rhs := mt[1], mt[2]
		if timestamps[prop] {
			continue
		}
		if !strings.HasPrefix(strings.TrimSpace(rhs), "CASE WHEN") {
			t.Errorf("m.%s is assigned unconditionally (%s); an empty parameter would erase the stored value", prop, strings.TrimSpace(rhs))
			continue
		}
		if !strings.Contains(rhs, "THEN m."+prop) {
			t.Errorf("m.%s is guarded but does not fall back to m.%s: %s", prop, prop, strings.TrimSpace(rhs))
		}
		guarded++
	}
	if guarded == 0 {
		t.Fatal("no guarded assignment found at all")
	}
}

// TestUpsertMissionCypher_CreatedAtIsSetOnCreateOnly: `created_at` used to be
// re-stamped on every merge, so the graph recorded the last merge time and
// could not answer when a mission was created.
func TestUpsertMissionCypher_CreatedAtIsSetOnCreateOnly(t *testing.T) {
	if !strings.Contains(upsertMissionCypher, "ON CREATE SET m.created_at = datetime()") {
		t.Error("created_at is not set ON CREATE")
	}
	setClause := setClauseOf(t, upsertMissionCypher)
	if strings.Contains(setClause, "m.created_at") {
		t.Error("created_at is re-stamped in the unconditional SET clause")
	}
}

// TestMissionUpsertParams_CoverEveryParameterTheCypherReferences catches the
// failure the Cypher cannot: a parameter named in the query with no key in the
// map is a Neo4j ParameterMissing error at runtime, on a write that is
// best-effort from the RPC and so would be logged and forgotten.
func TestMissionUpsertParams_CoverEveryParameterTheCypherReferences(t *testing.T) {
	want := map[string]bool{}
	for _, mt := range cypherParamPattern.FindAllStringSubmatch(upsertMissionCypher, -1) {
		want[mt[1]] = true
	}
	if len(want) == 0 {
		t.Fatal("the Cypher references no parameters; the regex is wrong")
	}

	started := time.Now()
	got := missionUpsertParams("tenant-a", MissionProjection{ID: "m1", StartedAt: &started})

	var missing []string
	for p := range want {
		if _, ok := got[p]; !ok {
			missing = append(missing, p)
		}
	}
	sort.Strings(missing)
	if len(missing) > 0 {
		t.Errorf("the Cypher references parameters the param map does not supply: %v", missing)
	}

	var extra []string
	for p := range got {
		if !want[p] {
			extra = append(extra, p)
		}
	}
	sort.Strings(extra)
	if len(extra) > 0 {
		t.Errorf("the param map supplies parameters the Cypher never reads: %v", extra)
	}
}

// TestMissionUpsertParams_NilStartedAtStaysNil: a nil StartedAt must reach
// Neo4j as a nil parameter, which is what the Cypher's IS NULL guard reads as
// "leave the stored value alone". An empty string would not match IS NULL and
// datetime("") would fail the write.
func TestMissionUpsertParams_NilStartedAtStaysNil(t *testing.T) {
	got := missionUpsertParams("tenant-a", MissionProjection{ID: "m1"})
	if got["started_at"] != nil {
		t.Errorf("started_at = %#v, want nil", got["started_at"])
	}
}

// TestMissionObjective takes the first sentence, which is what a graph reader
// sees as the mission's goal.
func TestMissionObjective(t *testing.T) {
	cases := []struct{ in, want string }{
		{"Sweep the fleet. Then report.", "Sweep the fleet."},
		{"No sentence boundary here", "No sentence boundary here"},
		{"", ""},
		{".leading dot", ".leading dot"},
		{"Trailing space.   And more.", "Trailing space."},
	}
	for _, c := range cases {
		if got := missionObjective(&missionpb.MissionDefinition{Description: c.in}); got != c.want {
			t.Errorf("missionObjective(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

// TestMissionYAMLSource falls back to an empty JSON object, so a reader that
// parses the property never has to special-case an empty string.
func TestMissionYAMLSource(t *testing.T) {
	m, _ := bootstrapFixture(t)
	if got := missionYAMLSource(m); got != "{}" {
		t.Errorf("empty definition = %q, want {}", got)
	}
	m.MissionDefinitionJSON = `{"name":"x"}`
	if got := missionYAMLSource(m); got != `{"name":"x"}` {
		t.Errorf("stored definition = %q", got)
	}
}
