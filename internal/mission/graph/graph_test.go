package graph_test

import (
	"reflect"
	"testing"

	"github.com/zeroroot-ai/gibson/internal/mission/graph"
	daemonpb "github.com/zeroroot-ai/sdk/api/gen/gibson/daemon/v1"
	missionv1 "github.com/zeroroot-ai/sdk/api/gen/gibson/mission/v1"
)

// --- fixture builders ---------------------------------------------------

func agent(id, name string) *missionv1.MissionNode {
	return &missionv1.MissionNode{
		Id:     id,
		Type:   missionv1.NodeType_NODE_TYPE_AGENT,
		Config: &missionv1.MissionNode_AgentConfig{AgentConfig: &missionv1.AgentNodeConfig{AgentName: name}},
	}
}

func tool(id, name string) *missionv1.MissionNode {
	return &missionv1.MissionNode{
		Id:     id,
		Type:   missionv1.NodeType_NODE_TYPE_TOOL,
		Config: &missionv1.MissionNode_ToolConfig{ToolConfig: &missionv1.ToolNodeConfig{ToolName: name}},
	}
}

func nodeByID(g *daemonpb.MissionGraph, id string) (*daemonpb.MissionGraphNode, bool) {
	for _, n := range g.GetNodes() {
		if n.GetId() == id {
			return n, true
		}
	}
	return nil, false
}

func mustProject(t *testing.T, def *missionv1.MissionDefinition, layout *daemonpb.MissionLayout) *daemonpb.MissionGraph {
	t.Helper()
	g, err := graph.Project(def, layout)
	if err != nil {
		t.Fatalf("Project() unexpected error: %v", err)
	}
	return g
}

// --- tests --------------------------------------------------------------

func TestProject_LinearMission(t *testing.T) {
	def := &missionv1.MissionDefinition{
		Nodes: map[string]*missionv1.MissionNode{
			"scan":   agent("scan", "nmap-agent"),
			"enrich": agent("enrich", "shodan-agent"),
		},
		Edges:       []*missionv1.MissionEdge{{From: "scan", To: "enrich"}},
		EntryPoints: []string{"scan"},
		ExitPoints:  []string{"enrich"},
	}
	g := mustProject(t, def, nil)

	if len(g.GetNodes()) != 2 || len(g.GetEdges()) != 1 {
		t.Fatalf("want 2 nodes / 1 edge, got %d / %d", len(g.GetNodes()), len(g.GetEdges()))
	}
	scan, _ := nodeByID(g, "scan")
	enrich, _ := nodeByID(g, "enrich")
	if scan.GetKind() != "agent" || scan.GetSummary() != "nmap-agent" {
		t.Errorf("scan: kind=%q summary=%q", scan.GetKind(), scan.GetSummary())
	}
	if !scan.GetIsEntry() || scan.GetIsExit() {
		t.Errorf("scan should be entry-only")
	}
	if !enrich.GetIsExit() || enrich.GetIsEntry() {
		t.Errorf("enrich should be exit-only")
	}
	if scan.GetRank() != 0 || enrich.GetRank() != 1 {
		t.Errorf("ranks: scan=%d enrich=%d, want 0 and 1", scan.GetRank(), enrich.GetRank())
	}
}

func TestProject_AllNodeKinds(t *testing.T) {
	plugin := &missionv1.MissionNode{
		Id: "plug", Type: missionv1.NodeType_NODE_TYPE_PLUGIN,
		Config: &missionv1.MissionNode_PluginConfig{PluginConfig: &missionv1.PluginNodeConfig{PluginName: "trivy", Method: "scan"}},
	}
	cond := &missionv1.MissionNode{
		Id: "cond", Type: missionv1.NodeType_NODE_TYPE_CONDITION,
		Config: &missionv1.MissionNode_ConditionConfig{ConditionConfig: &missionv1.ConditionNodeConfig{Expression: "result.ok"}},
	}
	join := &missionv1.MissionNode{
		Id: "join", Type: missionv1.NodeType_NODE_TYPE_JOIN,
		Config: &missionv1.MissionNode_JoinConfig{JoinConfig: &missionv1.JoinNodeConfig{WaitFor: []string{"a"}}},
	}
	cases := []struct {
		node              *missionv1.MissionNode
		wantKind, wantSum string
	}{
		{agent("a", "scanner"), "agent", "scanner"},
		{tool("t", "nmap"), "tool", "nmap"},
		{plugin, "plugin", "trivy.scan"},
		{cond, "condition", "result.ok"},
		{join, "join", "a"},
	}
	def := &missionv1.MissionDefinition{
		Nodes: map[string]*missionv1.MissionNode{},
		Edges: []*missionv1.MissionEdge{{From: "a", To: "t"}, {From: "t", To: "plug"}, {From: "plug", To: "cond"}},
	}
	for _, c := range cases {
		def.Nodes[c.node.GetId()] = c.node
	}
	g := mustProject(t, def, nil)
	for _, c := range cases {
		n, ok := nodeByID(g, c.node.GetId())
		if !ok {
			t.Fatalf("node %q missing", c.node.GetId())
		}
		if n.GetKind() != c.wantKind || n.GetSummary() != c.wantSum {
			t.Errorf("%s: kind=%q summary=%q want %q/%q", n.GetId(), n.GetKind(), n.GetSummary(), c.wantKind, c.wantSum)
		}
	}
}

func TestProject_ConditionBranchRoles(t *testing.T) {
	def := &missionv1.MissionDefinition{
		Nodes: map[string]*missionv1.MissionNode{
			"check": {
				Id: "check", Type: missionv1.NodeType_NODE_TYPE_CONDITION,
				Config: &missionv1.MissionNode_ConditionConfig{ConditionConfig: &missionv1.ConditionNodeConfig{
					Expression: "found", TrueBranch: []string{"exploit"}, FalseBranch: []string{"report"},
				}},
			},
			"exploit": agent("exploit", "exploit-agent"),
			"report":  agent("report", "report-agent"),
		},
		EntryPoints: []string{"check"},
	}
	g := mustProject(t, def, nil)
	roles := map[string]string{}
	for _, e := range g.GetEdges() {
		if e.GetFrom() == "check" {
			roles[e.GetTo()] = e.GetRole()
		}
	}
	if roles["exploit"] != "true" || roles["report"] != "false" {
		t.Errorf("branch roles = %+v, want exploit:true report:false", roles)
	}
}

func TestProject_ParallelJoinDiamondIsAcyclic(t *testing.T) {
	def := &missionv1.MissionDefinition{
		Nodes: map[string]*missionv1.MissionNode{
			"fan": {
				Id: "fan", Type: missionv1.NodeType_NODE_TYPE_PARALLEL,
				Config: &missionv1.MissionNode_ParallelConfig{ParallelConfig: &missionv1.ParallelNodeConfig{
					MaxConcurrency: 2,
					SubNodes:       []*missionv1.MissionNode{agent("p1", "a1"), agent("p2", "a2")},
				}},
			},
			"join": {
				Id: "join", Type: missionv1.NodeType_NODE_TYPE_JOIN,
				Config: &missionv1.MissionNode_JoinConfig{JoinConfig: &missionv1.JoinNodeConfig{WaitFor: []string{"p1", "p2"}}},
			},
		},
		EntryPoints: []string{"fan"},
		ExitPoints:  []string{"join"},
	}
	g := mustProject(t, def, nil)
	for _, id := range []string{"fan", "p1", "p2", "join"} {
		if _, ok := nodeByID(g, id); !ok {
			t.Fatalf("node %q missing — sub-node flattening failed", id)
		}
	}
	fan, _ := nodeByID(g, "fan")
	p1, _ := nodeByID(g, "p1")
	join, _ := nodeByID(g, "join")
	if !(fan.GetRank() < p1.GetRank() && p1.GetRank() < join.GetRank()) {
		t.Errorf("ranks not increasing: fan=%d p1=%d join=%d", fan.GetRank(), p1.GetRank(), join.GetRank())
	}
	if fan.GetSummary() != "max_concurrency=2" {
		t.Errorf("parallel summary = %q", fan.GetSummary())
	}
}

func TestProject_DerivedEntryExitWhenOmitted(t *testing.T) {
	def := &missionv1.MissionDefinition{
		Nodes: map[string]*missionv1.MissionNode{"a": agent("a", "x"), "b": agent("b", "y"), "c": agent("c", "z")},
		Edges: []*missionv1.MissionEdge{{From: "a", To: "b"}, {From: "b", To: "c"}},
	}
	g := mustProject(t, def, nil)
	if !reflect.DeepEqual(g.GetEntryPoints(), []string{"a"}) {
		t.Errorf("entry = %v, want [a]", g.GetEntryPoints())
	}
	if !reflect.DeepEqual(g.GetExitPoints(), []string{"c"}) {
		t.Errorf("exit = %v, want [c]", g.GetExitPoints())
	}
}

func TestProject_SavedLayoutOverridesAuto(t *testing.T) {
	def := &missionv1.MissionDefinition{
		Nodes:       map[string]*missionv1.MissionNode{"pinned": agent("pinned", "x"), "auto": agent("auto", "y")},
		Edges:       []*missionv1.MissionEdge{{From: "pinned", To: "auto"}},
		EntryPoints: []string{"pinned"},
	}
	layout := &daemonpb.MissionLayout{
		MissionDefinitionId: "def-1",
		Nodes:               []*daemonpb.NodePosition{{NodeId: "pinned", X: 999, Y: 111}},
		Viewport:            &daemonpb.MissionGraphViewport{Zoom: 1.5},
	}
	g := mustProject(t, def, layout)

	p, _ := nodeByID(g, "pinned")
	if p.GetLayoutSource() != "saved" || p.GetX() != 999 || p.GetY() != 111 {
		t.Errorf("pinned: source=%q (%v,%v), want saved (999,111)", p.GetLayoutSource(), p.GetX(), p.GetY())
	}
	a, _ := nodeByID(g, "auto")
	if a.GetLayoutSource() != "auto" {
		t.Errorf("auto node should be auto, got %q", a.GetLayoutSource())
	}
	if g.GetViewport().GetZoom() != 1.5 {
		t.Errorf("viewport zoom = %v, want 1.5", g.GetViewport().GetZoom())
	}
}

func TestProject_Validation_DanglingEdge(t *testing.T) {
	def := &missionv1.MissionDefinition{
		Nodes: map[string]*missionv1.MissionNode{"a": agent("a", "x")},
		Edges: []*missionv1.MissionEdge{{From: "a", To: "ghost"}},
	}
	_, err := graph.Project(def, nil)
	ve, ok := err.(*graph.ValidationError)
	if !ok || len(ve.DanglingEdges) != 1 || ve.DanglingEdges[0].Missing != "ghost" {
		t.Fatalf("want dangling ghost, got %T %v", err, err)
	}
}

func TestProject_Validation_Orphan(t *testing.T) {
	def := &missionv1.MissionDefinition{
		Nodes:       map[string]*missionv1.MissionNode{"a": agent("a", "x"), "b": agent("b", "y"), "island": agent("island", "z")},
		Edges:       []*missionv1.MissionEdge{{From: "a", To: "b"}},
		EntryPoints: []string{"a"},
	}
	_, err := graph.Project(def, nil)
	ve, ok := err.(*graph.ValidationError)
	if !ok || !reflect.DeepEqual(ve.OrphanNodes, []string{"island"}) {
		t.Fatalf("want orphan [island], got %T %v", err, err)
	}
}

func TestProject_Validation_Cycle(t *testing.T) {
	def := &missionv1.MissionDefinition{
		Nodes: map[string]*missionv1.MissionNode{"a": agent("a", "x"), "b": agent("b", "y"), "c": agent("c", "z")},
		Edges: []*missionv1.MissionEdge{{From: "a", To: "b"}, {From: "b", To: "c"}, {From: "c", To: "a"}},
	}
	_, err := graph.Project(def, nil)
	ve, ok := err.(*graph.ValidationError)
	if !ok || len(ve.Cycles) != 1 || !reflect.DeepEqual(ve.Cycles[0], []string{"a", "b", "c"}) {
		t.Fatalf("want cycle [a b c], got %T %v", err, err)
	}
}

func TestProject_NilDefinition(t *testing.T) {
	_, err := graph.Project(nil, nil)
	if ve, ok := err.(*graph.ValidationError); !ok || !ve.Empty {
		t.Fatalf("nil def: want Empty ValidationError, got %T %v", err, err)
	}
}

func TestProject_DeterministicAndTopologicallySound(t *testing.T) {
	build := func() *missionv1.MissionDefinition {
		return &missionv1.MissionDefinition{
			Nodes: map[string]*missionv1.MissionNode{
				"a": agent("a", "x"), "b": agent("b", "y"), "c": agent("c", "z"), "d": agent("d", "w"),
			},
			Edges: []*missionv1.MissionEdge{
				{From: "a", To: "b"}, {From: "a", To: "c"}, {From: "b", To: "d"}, {From: "c", To: "d"},
			},
			EntryPoints: []string{"a"},
			ExitPoints:  []string{"d"},
		}
	}
	g1 := mustProject(t, build(), nil)
	g2 := mustProject(t, build(), nil)
	if !reflect.DeepEqual(g1.String(), g2.String()) {
		t.Fatalf("Project() not deterministic")
	}
	rank := map[string]int32{}
	for _, n := range g1.GetNodes() {
		rank[n.GetId()] = n.GetRank()
	}
	for _, e := range g1.GetEdges() {
		if rank[e.GetFrom()] >= rank[e.GetTo()] {
			t.Errorf("edge %s(%d)->%s(%d) not forward in rank", e.GetFrom(), rank[e.GetFrom()], e.GetTo(), rank[e.GetTo()])
		}
	}
}
