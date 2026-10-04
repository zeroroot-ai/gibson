// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

// Package graph projects a gibson.mission.v1 MissionDefinition into the
// renderable gibson.daemon.v1 MissionGraph returned by GetMissionGraph.
//
// The mission definition is the pure work DAG (nodes + edges + entry/exit).
// This package derives the flow-chart projection from it — typed boxes,
// data-flow edges, derived entry/exit, structural validation, and a
// deterministic auto-layout — and overlays a saved layout (per-node positions
// from the layout store) so hand-arranged positions win. The daemon owns this
// so the dashboard is a pure renderer and never re-derives topology.
//
// Project is pure and deterministic: identical input yields identical output.
package graph

import (
	"sort"
	"strconv"
	"strings"

	daemonpb "github.com/zeroroot-ai/sdk/api/gen/gibson/daemon/v1"
	missionv1 "github.com/zeroroot-ai/sdk/api/gen/gibson/mission/v1"
)

// Node kind strings (mirror the MissionGraphNode.kind contract in daemon.proto).
const (
	kindAgent     = "agent"
	kindTool      = "tool"
	kindPlugin    = "plugin"
	kindCondition = "condition"
	kindParallel  = "parallel"
	kindJoin      = "join"
	kindJob       = "job"
	kindForEach   = "for_each"
	kindUnknown   = "unknown"
)

// Edge role strings (mirror MissionGraphEdge.role).
const (
	roleDefault        = ""
	roleConditionTrue  = "true"
	roleConditionFalse = "false"
)

// Layout source strings (mirror MissionGraphNode.layout_source).
const (
	layoutSaved = "saved"
	layoutAuto  = "auto"
)

// Auto-layout spacing in abstract canvas units.
const (
	rankSpacingX = 240.0
	rankSpacingY = 120.0
)

// edge is the internal representation used by the graph algorithms before the
// final daemonpb assembly.
type edge struct {
	from      string
	to        string
	condition string
	role      string
}

// analysis is what Validate and Project share: the indexed node set, the edge
// set, the derived endpoints, and every structural problem found. One
// implementation, so the write path and the mission view cannot disagree.
type analysis struct {
	nodes map[string]*missionv1.MissionNode
	edges []edge
	entry []string
	exit  []string
}

// analyse indexes def and runs the structural checks. It returns a typed
// *ValidationError enumerating every problem, or nil with the analysis.
func analyse(def *missionv1.MissionDefinition) (*analysis, *ValidationError) {
	if def == nil {
		return nil, &ValidationError{Empty: true}
	}

	// 1. Index top-level nodes, flattening inline parallel sub-nodes so they
	//    are never silently dropped.
	nodes := map[string]*missionv1.MissionNode{}
	var synthesized []edge
	for _, id := range sortedNodeKeys(def.GetNodes()) {
		collectNode(id, def.GetNodes()[id], nodes, &synthesized)
	}

	// 2. Build the edge set (explicit + synthesized) and report dangling ends.
	edges, dangling := buildEdges(def, nodes, synthesized)

	// 3. Derive entry/exit (honor declared, else derive from degree).
	inDeg, outDeg := degrees(nodes, edges)
	entry := deriveEndpoints(def.GetEntryPoints(), nodes, inDeg)
	exit := deriveEndpoints(def.GetExitPoints(), nodes, outDeg)

	// 4. Structural analysis.
	cycles := findCycles(nodes, edges)
	orphans := findOrphans(nodes, edges, entry)
	// The fan-out refusals come from the same finder the run path calls, so the
	// mission view and a submitted run cannot disagree about what is supported.
	nested := findNestedForEach(nodes)
	if len(dangling) > 0 || len(orphans) > 0 || len(cycles) > 0 || len(nested) > 0 {
		return nil, &ValidationError{
			DanglingEdges: dangling,
			OrphanNodes:   orphans,
			Cycles:        cycles,
			NestedForEach: nested,
		}
	}
	return &analysis{nodes: nodes, edges: edges, entry: entry, exit: exit}, nil
}

// Validate reports every structural problem in def: dangling edges, orphan
// nodes, cycles, and the fan-out declarations the daemon does not support. Nil
// means the definition is sound. The write path calls it before a definition
// is stored (gibson#547); before that, these checks ran only in the mission
// view, so a cyclic definition was accepted, stored and run, where the
// scheduler dispatched none of its nodes and the mission settled as completed.
//
// It is the same analysis Project performs. A second implementation of the
// same rule would be the defect, not the fix.
func Validate(def *missionv1.MissionDefinition) error {
	if _, verr := analyse(def); verr != nil {
		return verr // typed nil never escapes: verr is checked before return
	}
	return nil
}

// Project derives the renderable MissionGraph from def, overlaying saved
// positions from layout (may be nil). On any structural problem (dangling
// edges, orphan nodes, illegal cycles) it returns a nil graph and a typed
// *ValidationError enumerating every problem.
func Project(def *missionv1.MissionDefinition, layout *daemonpb.MissionLayout) (*daemonpb.MissionGraph, error) {
	a, verr := analyse(def)
	if verr != nil {
		return nil, verr
	}
	nodes, edges, entry, exit := a.nodes, a.edges, a.entry, a.exit

	// 5. Rank + lay out.
	ranks := layerNodes(nodes, edges)
	positions := autoPositions(nodes, ranks)
	saved := savedPositions(layout)

	g := &daemonpb.MissionGraph{
		EntryPoints: entry,
		ExitPoints:  exit,
	}
	entrySet := toSet(entry)
	exitSet := toSet(exit)
	for _, id := range sortedNodeKeys(nodes) {
		n := nodes[id]
		gn := &daemonpb.MissionGraphNode{
			Id:           id,
			Kind:         kindOf(n.GetType()),
			Name:         displayName(n),
			Summary:      summarize(n),
			IsEntry:      entrySet[id],
			IsExit:       exitSet[id],
			Rank:         int32(ranks[id]),
			X:            positions[id].x,
			Y:            positions[id].y,
			LayoutSource: layoutAuto,
		}
		if pos, ok := saved[id]; ok {
			gn.X = pos.x
			gn.Y = pos.y
			gn.LayoutSource = layoutSaved
		}
		g.Nodes = append(g.Nodes, gn)
	}
	for _, e := range edges {
		g.Edges = append(g.Edges, &daemonpb.MissionGraphEdge{
			From:      e.from,
			To:        e.to,
			Condition: e.condition,
			Role:      e.role,
		})
	}
	// Viewport: saved layout's viewport wins; else the definition carries none.
	if layout != nil && layout.GetViewport() != nil {
		v := layout.GetViewport()
		g.Viewport = &daemonpb.MissionGraphViewport{X: v.GetX(), Y: v.GetY(), Zoom: v.GetZoom()}
	}
	return g, nil
}

type xy struct{ x, y float64 }

func savedPositions(layout *daemonpb.MissionLayout) map[string]xy {
	out := map[string]xy{}
	if layout == nil {
		return out
	}
	for _, p := range layout.GetNodes() {
		out[p.GetNodeId()] = xy{x: p.GetX(), y: p.GetY()}
	}
	return out
}

// collectNode adds n to the flat node index and recursively flattens inline
// parallel sub-nodes, synthesizing a parent→child edge for each.
func collectNode(id string, n *missionv1.MissionNode, into map[string]*missionv1.MissionNode, synth *[]edge) {
	if n == nil || id == "" {
		return
	}
	into[id] = n
	if p := n.GetParallelConfig(); p != nil {
		for _, child := range p.GetSubNodes() {
			cid := child.GetId()
			if cid == "" {
				continue
			}
			*synth = append(*synth, edge{from: id, to: cid})
			collectNode(cid, child, into, synth)
		}
	}
	// A for_each's template is flattened the same way a parallel sub-node is,
	// so it appears in the index and carries a parent edge. ONE template, not a
	// list: a for_each runs one node per item in its source, where parallel runs
	// N different declared nodes. The N instances a run produces are a runtime
	// concern and are not nodes in the definition graph (gibson#524).
	if f := n.GetForEachConfig(); f != nil {
		if tpl := f.GetTemplate(); tpl != nil {
			if tid := tpl.GetId(); tid != "" {
				*synth = append(*synth, edge{from: id, to: tid})
				collectNode(tid, tpl, into, synth)
			}
		}
	}
}

// RefuseUnsupportedFanOut reports the fan-out declarations the daemon does not
// support, over an already-indexed node set. Nil means nothing to refuse.
//
// It exists so the authoring path and the run path refuse the same thing from
// one implementation. Project calls it, and so does the daemon's mission
// projection: a refusal that only the mission view performs is a guard that
// cannot fail on the path that matters (gibson#527).
//
// It covers cross-node and nested-message properties only, which is exactly
// what protovalidate cannot express. Graph topology — cycles, orphans, dangling
// edges — stays in Project, because refusing those on the run path would change
// how already-stored definitions behave and that is not this function's call to
// make.
func RefuseUnsupportedFanOut(nodes map[string]*missionv1.MissionNode) error {
	nested := findNestedForEach(nodes)
	if len(nested) == 0 {
		return nil // a nil literal, so no caller meets a typed nil in an error
	}
	return &ValidationError{NestedForEach: nested}
}

// findNestedForEach names every for_each whose template is itself a for_each.
//
// protovalidate cannot express "this nested MissionNode's config is not this
// variant", so this is the only place the refusal can live, and the proto's
// field comment says as much rather than leaving it to look like an omission.
//
// Sorted, because a validation message that reorders between runs is a diff
// nobody can review.
func findNestedForEach(nodes map[string]*missionv1.MissionNode) []string {
	var out []string
	for id, n := range nodes {
		f := n.GetForEachConfig()
		if f == nil {
			continue
		}
		if f.GetTemplate().GetForEachConfig() != nil {
			out = append(out, id)
		}
	}
	sort.Strings(out)
	return out
}

// buildEdges assembles the deterministic edge list and reports dangling
// endpoints. Explicit MissionEdges win; synthesized edges (parallel children,
// condition branches, join wait_for) are added only when the (from,to) pair is
// not already explicit. Condition branch membership tags edge roles.
func buildEdges(def *missionv1.MissionDefinition, nodes map[string]*missionv1.MissionNode, synthesized []edge) ([]edge, []DanglingEdge) {
	seen := map[[2]string]int{}
	var out []edge
	var dangling []DanglingEdge

	add := func(e edge, src string) {
		key := [2]string{e.from, e.to}
		if _, ok := seen[key]; ok {
			return
		}
		if _, ok := nodes[e.from]; !ok {
			dangling = append(dangling, DanglingEdge{From: e.from, To: e.to, Missing: e.from, Source: src})
			return
		}
		if _, ok := nodes[e.to]; !ok {
			dangling = append(dangling, DanglingEdge{From: e.from, To: e.to, Missing: e.to, Source: src})
			return
		}
		seen[key] = len(out)
		out = append(out, e)
	}

	for _, e := range def.GetEdges() {
		add(edge{from: e.GetFrom(), to: e.GetTo(), condition: e.GetCondition()}, "edge")
	}
	for _, e := range synthesized {
		add(e, "parallel")
	}
	for _, id := range sortedNodeKeys(nodes) {
		c := nodes[id].GetConditionConfig()
		if c == nil {
			continue
		}
		for _, t := range c.GetTrueBranch() {
			add(edge{from: id, to: t, role: roleConditionTrue}, "condition.true")
			tagRole(out, seen, id, t, roleConditionTrue)
		}
		for _, f := range c.GetFalseBranch() {
			add(edge{from: id, to: f, role: roleConditionFalse}, "condition.false")
			tagRole(out, seen, id, f, roleConditionFalse)
		}
	}
	for _, id := range sortedNodeKeys(nodes) {
		j := nodes[id].GetJoinConfig()
		if j == nil {
			continue
		}
		for _, up := range j.GetWaitFor() {
			add(edge{from: up, to: id}, "join.wait_for")
		}
	}

	sort.SliceStable(out, func(i, k int) bool {
		if out[i].from != out[k].from {
			return out[i].from < out[k].from
		}
		if out[i].to != out[k].to {
			return out[i].to < out[k].to
		}
		return out[i].role < out[k].role
	})
	return out, dangling
}

func tagRole(out []edge, seen map[[2]string]int, from, to, role string) {
	if idx, ok := seen[[2]string{from, to}]; ok {
		if out[idx].role == roleDefault {
			out[idx].role = role
		}
	}
}

func degrees(nodes map[string]*missionv1.MissionNode, edges []edge) (in, out map[string]int) {
	in = map[string]int{}
	out = map[string]int{}
	for id := range nodes {
		in[id] = 0
		out[id] = 0
	}
	for _, e := range edges {
		out[e.from]++
		in[e.to]++
	}
	return in, out
}

func deriveEndpoints(declared []string, nodes map[string]*missionv1.MissionNode, deg map[string]int) []string {
	var out []string
	if len(declared) > 0 {
		for _, id := range declared {
			if _, ok := nodes[id]; ok {
				out = append(out, id)
			}
		}
	} else {
		for id := range nodes {
			if deg[id] == 0 {
				out = append(out, id)
			}
		}
	}
	sort.Strings(out)
	return dedupe(out)
}

func kindOf(t missionv1.NodeType) string {
	switch t {
	case missionv1.NodeType_NODE_TYPE_AGENT:
		return kindAgent
	case missionv1.NodeType_NODE_TYPE_TOOL:
		return kindTool
	case missionv1.NodeType_NODE_TYPE_PLUGIN:
		return kindPlugin
	case missionv1.NodeType_NODE_TYPE_CONDITION:
		return kindCondition
	case missionv1.NodeType_NODE_TYPE_PARALLEL:
		return kindParallel
	case missionv1.NodeType_NODE_TYPE_JOIN:
		return kindJoin
	case missionv1.NodeType_NODE_TYPE_JOB:
		return kindJob
	case missionv1.NodeType_NODE_TYPE_FOR_EACH:
		return kindForEach
	default:
		return kindUnknown
	}
}

func displayName(n *missionv1.MissionNode) string {
	if name := strings.TrimSpace(n.GetName()); name != "" {
		return name
	}
	return n.GetId()
}

func summarize(n *missionv1.MissionNode) string {
	switch {
	case n.GetAgentConfig() != nil:
		return n.GetAgentConfig().GetAgentName()
	case n.GetToolConfig() != nil:
		return n.GetToolConfig().GetToolName()
	case n.GetPluginConfig() != nil:
		p := n.GetPluginConfig()
		if m := p.GetMethod(); m != "" {
			return p.GetPluginName() + "." + m
		}
		return p.GetPluginName()
	case n.GetConditionConfig() != nil:
		return n.GetConditionConfig().GetExpression()
	case n.GetParallelConfig() != nil:
		if c := n.GetParallelConfig().GetMaxConcurrency(); c > 0 {
			return "max_concurrency=" + strconv.Itoa(int(c))
		}
		return ""
	case n.GetForEachConfig() != nil:
		f := n.GetForEachConfig()
		detail := strings.TrimPrefix(f.GetSource().String(), "SOURCE_")
		if c := f.GetMaxConcurrency(); c > 0 {
			detail += " max_concurrency=" + strconv.Itoa(int(c))
		}
		return detail
	case n.GetJoinConfig() != nil:
		return strings.Join(n.GetJoinConfig().GetWaitFor(), ", ")
	case n.GetJobConfig() != nil:
		// The bank is what a reader needs to see: it says which pool of
		// always-on agents this node drives (ADR-0019).
		return n.GetJobConfig().GetBankRef()
	default:
		return ""
	}
}
