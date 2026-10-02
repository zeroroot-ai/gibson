// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package daemon

import (
	"context"
	"log/slog"
	"strings"
	"testing"

	"github.com/zeroroot-ai/gibson/internal/engine/graphrag/graph"
	"github.com/zeroroot-ai/gibson/internal/engine/mission"
	"github.com/zeroroot-ai/gibson/internal/infra/types"
)

// recordingGraphClient captures every Cypher statement and its parameters, so a
// test can assert what the bootstrap WROTE rather than that it did not error.
// Every query returns one record, which is what the queries package reads to
// confirm the Mission exists.
type recordingGraphClient struct {
	graph.GraphClient
	writes []recordedWrite
}

type recordedWrite struct {
	cypher string
	params map[string]any
}

func (c *recordingGraphClient) Query(_ context.Context, cypher string, params map[string]any) (graph.QueryResult, error) {
	c.writes = append(c.writes, recordedWrite{cypher: cypher, params: params})
	return graph.QueryResult{Records: []map[string]any{{"id": params["id"]}}}, nil
}

// missionNodeWrites returns the parameters of every :MissionNode write, keyed by
// the node name the bootstrap recorded.
func (c *recordingGraphClient) missionNodeWrites() map[string]map[string]any {
	out := map[string]map[string]any{}
	for _, w := range c.writes {
		if !strings.Contains(w.cypher, "MERGE (n:MissionNode") {
			continue
		}
		name, _ := w.params["name"].(string)
		out[name] = w.params
	}
	return out
}

// dependencyWriteCount counts the DEPENDS_ON edge writes.
func (c *recordingGraphClient) dependencyWriteCount() int {
	n := 0
	for _, w := range c.writes {
		if strings.Contains(w.cypher, "DEPENDS_ON") {
			n++
		}
	}
	return n
}

func bootstrapFixture(t *testing.T) (*mission.Mission, *mission.MissionRun) {
	t.Helper()
	missionID := types.NewID()
	return &mission.Mission{
			ID:       missionID,
			Name:     "fanout",
			TenantID: "tenant-a",
			TargetID: types.NewID(),
			Status:   mission.MissionStatusRunning,
		}, &mission.MissionRun{
			ID:        types.NewID(),
			MissionID: missionID,
			RunNumber: 1,
		}
}

// The whole of gibson#528: a two-target fan-out writes one graph node per
// instance, each naming the target it ran against. Before this, the graph was
// written from def.GetNodes() — one node for the for_each, no instances, no
// target — so "what did we learn about target X" had no answer.
func TestBootstrap_WritesOneNodePerFanOutInstanceWithItsTarget(t *testing.T) {
	m, run := bootstrapFixture(t)
	targets := []forEachTarget{
		fanTarget("11111111-1111-1111-1111-111111111111", "a", "https://10.0.0.1:6443"),
		fanTarget("22222222-2222-2222-2222-222222222222", "b", "https://10.0.0.2:6443"),
	}
	def := forEachDef(0)

	proj, origins, err := missionDefinitionToProjected(def, "", targets)
	if err != nil {
		t.Fatalf("project: %v", err)
	}

	client := &recordingGraphClient{}
	b := NewGraphBootstrapper(client, slog.New(slog.DiscardHandler))
	if _, err := b.Bootstrap(context.Background(), m, def, run, proj, origins); err != nil {
		t.Fatalf("bootstrap: %v", err)
	}

	nodes := client.missionNodeWrites()
	for _, tgt := range targets {
		name := "scan#" + tgt.ID
		params, ok := nodes[name]
		if !ok {
			t.Fatalf("no graph node for instance %q; wrote %v", name, nodeNames(nodes))
		}
		if got := params["target_id"]; got != tgt.ID {
			t.Errorf("instance %q target_id = %v, want %q", name, got, tgt.ID)
		}
		if got := params["is_dynamic"]; got != true {
			t.Errorf("instance %q is_dynamic = %v, want true — an instance is spawned at runtime", name, got)
		}
		if got := params["spawned_by"]; got != "each" {
			t.Errorf("instance %q spawned_by = %v, want the for_each node %q", name, got, "each")
		}
		if got := params["tool_name"]; got != "nmap" {
			t.Errorf("instance %q tool_name = %v, want the template's tool", name, got)
		}
	}

	// Neither the for_each nor the bare template is work, so neither is a graph
	// node: the graph records what ran.
	for _, absent := range []string{"each", "scan"} {
		if _, ok := nodes[absent]; ok {
			t.Errorf("node %q was written, but it is not a unit of work", absent)
		}
	}
}

// The identity is derived, so running the same mission again MERGEs onto the
// nodes already there. It used to be types.NewID() per call, so every run wrote a
// second node for the same step and a uniqueness constraint on `id` would have
// covered nothing a reader could use.
func TestBootstrap_NodeIdentityIsStableAcrossRuns(t *testing.T) {
	m, run := bootstrapFixture(t)
	targets := []forEachTarget{
		fanTarget("11111111-1111-1111-1111-111111111111", "a", "https://10.0.0.1:6443"),
	}
	def := forEachDef(0)
	proj, origins, err := missionDefinitionToProjected(def, "", targets)
	if err != nil {
		t.Fatalf("project: %v", err)
	}

	ids := func() map[string]any {
		client := &recordingGraphClient{}
		b := NewGraphBootstrapper(client, slog.New(slog.DiscardHandler))
		if _, err := b.Bootstrap(context.Background(), m, def, run, proj, origins); err != nil {
			t.Fatalf("bootstrap: %v", err)
		}
		out := map[string]any{}
		for name, params := range client.missionNodeWrites() {
			out[name] = params["id"]
		}
		return out
	}

	first, second := ids(), ids()
	if len(first) == 0 {
		t.Fatal("no nodes written")
	}
	for name, id := range first {
		if second[name] != id {
			t.Errorf("node %q got id %v then %v; re-running must MERGE onto the same node", name, id, second[name])
		}
	}
}

// Two instances of one template are distinct nodes. A derivation that ignored the
// target would collapse a whole fan-out onto one node — the defect, restated.
func TestBootstrap_InstancesOfOneTemplateGetDistinctIdentities(t *testing.T) {
	missionID := types.NewID()
	a := missionNodeGraphID(missionID, "scan#11111111-1111-1111-1111-111111111111")
	b := missionNodeGraphID(missionID, "scan#22222222-2222-2222-2222-222222222222")
	if a == b {
		t.Fatalf("two instances derived the same id %q", a)
	}
	if err := a.Validate(); err != nil {
		t.Errorf("derived id is not a valid UUID, so it cannot be a types.ID: %v", err)
	}
	// The same inputs under a different mission are a different node.
	if missionNodeGraphID(types.NewID(), "scan#11111111-1111-1111-1111-111111111111") == a {
		t.Error("the mission is not part of the derivation; two missions' nodes would collide")
	}
}

// Dependencies come from the projection's resolved DependsOn, so an edge the
// author expressed through `edges` or a join's `wait_for` is recorded. Reading
// each node's own `dependencies` list, as before, recorded none of those.
func TestBootstrap_DependenciesComeFromTheResolvedProjection(t *testing.T) {
	m, run := bootstrapFixture(t)
	targets := []forEachTarget{
		fanTarget("11111111-1111-1111-1111-111111111111", "a", "https://10.0.0.1:6443"),
		fanTarget("22222222-2222-2222-2222-222222222222", "b", "https://10.0.0.2:6443"),
	}
	def := forEachDef(0)
	// `after` depends on the join, which waits on the for_each. Its dependencies
	// list names "report", a node that is never work — so the only way the edge
	// reaches the graph is through the projection's resolution.
	def.Nodes["after"] = agentNode("writer", "report")

	proj, origins, err := missionDefinitionToProjected(def, "", targets)
	if err != nil {
		t.Fatalf("project: %v", err)
	}

	client := &recordingGraphClient{}
	b := NewGraphBootstrapper(client, slog.New(slog.DiscardHandler))
	if _, err := b.Bootstrap(context.Background(), m, def, run, proj, origins); err != nil {
		t.Fatalf("bootstrap: %v", err)
	}

	// `after` waits on both instances, so two edges — one per target.
	if got := client.dependencyWriteCount(); got != 2 {
		t.Errorf("wrote %d dependency edges, want 2 (one per fan-out instance)", got)
	}
}

// A mission with no for_each is written exactly as a mission without fan-out
// should be: no node marked dynamic, no target on any node, no spawned_by.
func TestBootstrap_AMissionWithoutFanOutIsUnchangedInShape(t *testing.T) {
	m, run := bootstrapFixture(t)
	def := forEachDef(0)
	delete(def.Nodes, "each")
	delete(def.Nodes, "report")
	def.Nodes["scan"] = agentNode("nmap-agent")

	proj, origins, err := missionDefinitionToProjected(def, "", nil)
	if err != nil {
		t.Fatalf("project: %v", err)
	}
	if len(origins) != 0 {
		t.Fatalf("a mission with no for_each produced %d fan-out origins", len(origins))
	}

	client := &recordingGraphClient{}
	b := NewGraphBootstrapper(client, slog.New(slog.DiscardHandler))
	if _, err := b.Bootstrap(context.Background(), m, def, run, proj, origins); err != nil {
		t.Fatalf("bootstrap: %v", err)
	}

	nodes := client.missionNodeWrites()
	if _, ok := nodes["scan"]; !ok {
		t.Fatalf("the ordinary node was not written; wrote %v", nodeNames(nodes))
	}
	for name, params := range nodes {
		if params["is_dynamic"] != false {
			t.Errorf("node %q is marked dynamic in a mission with no fan-out", name)
		}
		if params["target_id"] != "" {
			t.Errorf("node %q carries target_id %v; an unbound node has no target", name, params["target_id"])
		}
		if params["spawned_by"] != "" {
			t.Errorf("node %q carries spawned_by %v", name, params["spawned_by"])
		}
	}
}

// nodeNames reports what was written, so a failure says which nodes exist rather
// than only which one was missing.
func nodeNames(nodes map[string]map[string]any) []string {
	out := make([]string, 0, len(nodes))
	for name := range nodes {
		out = append(out, name)
	}
	return out
}
