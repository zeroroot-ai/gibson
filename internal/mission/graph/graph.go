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

// Project derives the renderable MissionGraph from def, overlaying saved
// positions from layout (may be nil). On any structural problem (dangling
// edges, orphan nodes, illegal cycles) it returns a nil graph and a typed
// *ValidationError enumerating every problem.
func Project(def *missionv1.MissionDefinition, layout *daemonpb.MissionLayout) (*daemonpb.MissionGraph, error) {
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
	if len(dangling) > 0 || len(orphans) > 0 || len(cycles) > 0 {
		return nil, &ValidationError{DanglingEdges: dangling, OrphanNodes: orphans, Cycles: cycles}
	}

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
	case n.GetJoinConfig() != nil:
		return strings.Join(n.GetJoinConfig().GetWaitFor(), ", ")
	default:
		return ""
	}
}
