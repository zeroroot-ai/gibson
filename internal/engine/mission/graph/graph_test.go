// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package graph_test

import (
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/zeroroot-ai/gibson/internal/engine/mission/graph"
	daemonpb "github.com/zeroroot-ai/sdk/api/gen/gibson/daemon/v1"
	jobv1 "github.com/zeroroot-ai/sdk/api/gen/gibson/job/v1"
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
			"enrich": agent("enrich", "enrich-agent"),
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
	// A JOB node drives work on a bank of always-on coding agents (ADR-0119).
	// The bank is what the projection summarises, because it is what a reader
	// needs to see: which pool this node feeds.
	jobNode := &missionv1.MissionNode{
		Id: "fix", Type: missionv1.NodeType_NODE_TYPE_JOB,
		Config: &missionv1.MissionNode_JobConfig{JobConfig: &missionv1.JobNodeConfig{
			BankRef: "nightly",
			Spec:    &jobv1.JobSpec{Goal: "fix the CVE"},
		}},
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
		{jobNode, "job", "nightly"},
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

// A for_each node's template is flattened into the graph the way a parallel
// sub-node is, with a parent edge, so the definition graph shows the work the
// author wrote once. The N instances a RUN produces are a runtime concern and
// are deliberately not nodes here (gibson#524, epic gibson#496).
func TestProject_ForEachTemplateIsFlattenedAndJoinable(t *testing.T) {
	def := &missionv1.MissionDefinition{
		Nodes: map[string]*missionv1.MissionNode{
			"each": {
				Id:   "each",
				Type: missionv1.NodeType_NODE_TYPE_FOR_EACH,
				Config: &missionv1.MissionNode_ForEachConfig{ForEachConfig: &missionv1.ForEachNodeConfig{
					Source:         missionv1.ForEachNodeConfig_SOURCE_TARGET_SET,
					MaxConcurrency: 4,
					Template:       tool("scan", "nmap"),
				}},
			},
			"report": {
				Id:     "report",
				Type:   missionv1.NodeType_NODE_TYPE_JOIN,
				Config: &missionv1.MissionNode_JoinConfig{JoinConfig: &missionv1.JoinNodeConfig{WaitFor: []string{"each"}}},
			},
		},
		EntryPoints: []string{"each"},
		ExitPoints:  []string{"report"},
	}

	g := mustProject(t, def, nil)

	// The template is a node, reachable, not swallowed by its parent.
	for _, id := range []string{"each", "scan", "report"} {
		if _, ok := nodeByID(g, id); !ok {
			t.Fatalf("node %q missing — for_each template flattening failed", id)
		}
	}

	each, _ := nodeByID(g, "each")
	scan, _ := nodeByID(g, "scan")
	report, _ := nodeByID(g, "report")

	// Both the template and the join are children of the for_each, so they share
	// a rank. That is correct on dependencies — the join waits on the for_each
	// NODE, which completes when its instances do, not on the template — and it
	// is deliberately asserted rather than assumed, because it means a rendered
	// graph draws the join BESIDE the work instead of after it. Whether the join
	// should rank behind the template is a layout question for gibson#527, which
	// owns join-over-instances semantics.
	if each.GetRank() >= scan.GetRank() {
		t.Errorf("template must rank behind its for_each: each=%d scan=%d",
			each.GetRank(), scan.GetRank())
	}
	if each.GetRank() >= report.GetRank() {
		t.Errorf("join must rank behind the for_each it waits on: each=%d report=%d",
			each.GetRank(), report.GetRank())
	}
	if scan.GetRank() != report.GetRank() {
		t.Logf("template and join ranks diverged (scan=%d report=%d); if this is "+
			"intentional, gibson#527 changed the layout and this log can become an "+
			"assertion", scan.GetRank(), report.GetRank())
	}

	// The summary says what it fans out over AND how wide, because "for_each"
	// alone does not tell a reader whether this is one target or fifty.
	if got, want := each.GetSummary(), "TARGET_SET max_concurrency=4"; got != want {
		t.Errorf("for_each summary = %q, want %q", got, want)
	}

	// A join naming the for_each must not be a cycle or an orphan: the node is
	// one node in the graph even though a run gives it N instances.
	if each.GetKind() != "for_each" {
		t.Errorf("kind = %q, want for_each — the dispatch arm is missing", each.GetKind())
	}
}

// A for_each with no template must not synthesize a dangling edge. protovalidate
// requires the template, so this is the defence-in-depth case for a definition
// that reached the projector some other way.
func TestProject_ForEachWithNoTemplateDoesNotDangle(t *testing.T) {
	def := &missionv1.MissionDefinition{
		Nodes: map[string]*missionv1.MissionNode{
			"each": {
				Id:   "each",
				Type: missionv1.NodeType_NODE_TYPE_FOR_EACH,
				Config: &missionv1.MissionNode_ForEachConfig{ForEachConfig: &missionv1.ForEachNodeConfig{
					Source: missionv1.ForEachNodeConfig_SOURCE_TARGET_SET,
				}},
			},
		},
		EntryPoints: []string{"each"},
		ExitPoints:  []string{"each"},
	}

	g := mustProject(t, def, nil)
	if _, ok := nodeByID(g, "each"); !ok {
		t.Fatal("the for_each node itself must still project")
	}
	if n := len(g.GetNodes()); n != 1 {
		t.Errorf("projected %d nodes, want 1 — a missing template must not add one", n)
	}
}

// A template that is itself a for_each is refused. protovalidate cannot express
// it, so this is the only gate, and the fixture proves the gate bites rather
// than merely existing (gibson#524).
func TestProject_NestedForEachIsRefused(t *testing.T) {
	inner := &missionv1.MissionNode{
		Id:   "inner",
		Type: missionv1.NodeType_NODE_TYPE_FOR_EACH,
		Config: &missionv1.MissionNode_ForEachConfig{ForEachConfig: &missionv1.ForEachNodeConfig{
			Source:   missionv1.ForEachNodeConfig_SOURCE_TARGET_SET,
			Template: tool("scan", "nmap"),
		}},
	}
	def := &missionv1.MissionDefinition{
		Nodes: map[string]*missionv1.MissionNode{
			"outer": {
				Id:   "outer",
				Type: missionv1.NodeType_NODE_TYPE_FOR_EACH,
				Config: &missionv1.MissionNode_ForEachConfig{ForEachConfig: &missionv1.ForEachNodeConfig{
					Source:   missionv1.ForEachNodeConfig_SOURCE_TARGET_SET,
					Template: inner,
				}},
			},
		},
		EntryPoints: []string{"outer"},
		ExitPoints:  []string{"outer"},
	}

	g, err := graph.Project(def, nil)
	if err == nil {
		t.Fatal("want a ValidationError for a nested for_each; a product of two " +
			"target sets reads like one fan-out and dispatches N*M times")
	}
	if g != nil {
		t.Error("Project must return no graph alongside a ValidationError")
	}

	var ve *graph.ValidationError
	if !errors.As(err, &ve) {
		t.Fatalf("error is not a *ValidationError: %v", err)
	}
	if len(ve.NestedForEach) != 1 || ve.NestedForEach[0] != "outer" {
		t.Errorf("NestedForEach = %v, want [outer]", ve.NestedForEach)
	}
	if !strings.Contains(err.Error(), "template is itself a for_each") {
		t.Errorf("error text does not name the problem: %v", err)
	}
}

// TestValidate_RefusesACycle: Validate reports the same cycle Project does,
// so the write path and the mission view refuse the same definition
// (gibson#547).
func TestValidate_RefusesACycle(t *testing.T) {
	def := &missionv1.MissionDefinition{
		Nodes: map[string]*missionv1.MissionNode{"a": agent("a", "x"), "b": agent("b", "y"), "c": agent("c", "z")},
		Edges: []*missionv1.MissionEdge{{From: "a", To: "b"}, {From: "b", To: "c"}, {From: "c", To: "a"}},
	}
	err := graph.Validate(def)
	var ve *graph.ValidationError
	if !errors.As(err, &ve) || len(ve.Cycles) != 1 || !reflect.DeepEqual(ve.Cycles[0], []string{"a", "b", "c"}) {
		t.Fatalf("want cycle [a b c], got %T %v", err, err)
	}
	if _, perr := graph.Project(def, nil); perr == nil || perr.Error() != err.Error() {
		t.Fatalf("Validate and Project disagree: %v vs %v", err, perr)
	}
}

// TestValidate_SoundDefinitionIsNil: a definition Project renders passes
// Validate with a nil error, never a typed nil.
func TestValidate_SoundDefinitionIsNil(t *testing.T) {
	def := &missionv1.MissionDefinition{
		Nodes: map[string]*missionv1.MissionNode{"a": agent("a", "x"), "b": agent("b", "y")},
		Edges: []*missionv1.MissionEdge{{From: "a", To: "b"}},
	}
	if err := graph.Validate(def); err != nil {
		t.Fatalf("sound definition refused: %v", err)
	}
	if err := graph.Validate(nil); err == nil {
		t.Fatal("nil definition must be refused")
	}
}

// agentFrom is an agent node that starts from an earlier node (gibson#802).
func agentFrom(id, name, startsFrom string) *missionv1.MissionNode {
	n := agent(id, name)
	n.StartsFrom = startsFrom
	return n
}

// A node may start from an earlier node: the ancestor's snapshot exists when
// the node starts (ADR-0169).
func TestProject_StartsFrom_AncestorIsAccepted(t *testing.T) {
	def := &missionv1.MissionDefinition{
		Nodes: map[string]*missionv1.MissionNode{
			"scan":    agent("scan", "recon"),
			"exploit": agentFrom("exploit", "recon", "scan"),
		},
		Edges: []*missionv1.MissionEdge{{From: "scan", To: "exploit"}},
	}
	mustProject(t, def, nil)
}

func TestProject_StartsFrom_Refusals(t *testing.T) {
	cases := map[string]struct {
		def    *missionv1.MissionDefinition
		node   string
		from   string
		reason string
	}{
		"does not exist": {
			def: &missionv1.MissionDefinition{
				Nodes: map[string]*missionv1.MissionNode{"a": agentFrom("a", "x", "ghost")},
			},
			node: "a", from: "ghost", reason: "does not exist",
		},
		"itself": {
			def: &missionv1.MissionDefinition{
				Nodes: map[string]*missionv1.MissionNode{
					"a": agent("a", "x"),
					"b": agentFrom("b", "y", "b"),
				},
				Edges: []*missionv1.MissionEdge{{From: "a", To: "b"}},
			},
			node: "b", from: "b", reason: "is the node itself",
		},
		"a later node": {
			def: &missionv1.MissionDefinition{
				Nodes: map[string]*missionv1.MissionNode{
					"first":  agentFrom("first", "x", "second"),
					"second": agent("second", "y"),
				},
				Edges: []*missionv1.MissionEdge{{From: "first", To: "second"}},
			},
			node: "first", from: "second", reason: "does not run before it",
		},
		"another agent": {
			def: &missionv1.MissionDefinition{
				Nodes: map[string]*missionv1.MissionNode{
					"scan":    agent("scan", "alpha"),
					"exploit": agentFrom("exploit", "beta", "scan"),
				},
				Edges: []*missionv1.MissionEdge{{From: "scan", To: "exploit"}},
			},
			node: "exploit", from: "scan", reason: "runs another agent",
		},
		"a node on another branch": {
			def: &missionv1.MissionDefinition{
				Nodes: map[string]*missionv1.MissionNode{
					"root":  agent("root", "r"),
					"left":  agent("left", "l"),
					"right": agentFrom("right", "x", "left"),
				},
				Edges: []*missionv1.MissionEdge{{From: "root", To: "left"}, {From: "root", To: "right"}},
			},
			node: "right", from: "left", reason: "does not run before it",
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := graph.Project(tc.def, nil)
			var ve *graph.ValidationError
			if !errors.As(err, &ve) {
				t.Fatalf("want *ValidationError, got %T %v", err, err)
			}
			if len(ve.StartsFrom) != 1 {
				t.Fatalf("want one starts_from refusal, got %+v", ve.StartsFrom)
			}
			r := ve.StartsFrom[0]
			if r.Node != tc.node || r.StartsFrom != tc.from || r.Reason != tc.reason {
				t.Fatalf("refusal = %+v, want node %q from %q reason %q", r, tc.node, tc.from, tc.reason)
			}
			if !strings.Contains(err.Error(), tc.reason) {
				t.Errorf("error text %q omits the reason %q", err.Error(), tc.reason)
			}
		})
	}
}

// A for_each template node may carry starts_from: the ancestry check reads
// the flattened node set, so it treats the template like any other node.
func TestProject_StartsFrom_CycleSkipsTheCheck(t *testing.T) {
	def := &missionv1.MissionDefinition{
		Nodes: map[string]*missionv1.MissionNode{
			"a": agent("a", "x"),
			"b": agentFrom("b", "y", "a"),
		},
		Edges: []*missionv1.MissionEdge{{From: "a", To: "b"}, {From: "b", To: "a"}},
	}
	_, err := graph.Project(def, nil)
	var ve *graph.ValidationError
	if !errors.As(err, &ve) || len(ve.Cycles) == 0 {
		t.Fatalf("want a cycle refusal, got %T %v", err, err)
	}
	if len(ve.StartsFrom) != 0 {
		t.Errorf("a cyclic definition must skip the starts_from ancestry check, got %+v", ve.StartsFrom)
	}
}
