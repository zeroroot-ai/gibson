package graph

import (
	"fmt"
	"sort"
	"strings"

	missionv1 "github.com/zeroroot-ai/sdk/api/gen/gibson/mission/v1"
)

// DanglingEdge describes an edge whose endpoint references a node that does not
// exist in the mission.
type DanglingEdge struct {
	From    string
	To      string
	Missing string // the endpoint (From or To) that does not resolve to a node
	Source  string // "edge" | "parallel" | "condition.true" | "condition.false" | "join.wait_for"
}

// ValidationError enumerates every structural problem found in a mission. A
// non-nil ValidationError means Project returned no graph.
type ValidationError struct {
	Empty         bool
	DanglingEdges []DanglingEdge
	OrphanNodes   []string
	Cycles        [][]string
}

func (e *ValidationError) Error() string {
	if e.Empty {
		return "mission graph: nil definition"
	}
	var parts []string
	for _, d := range e.DanglingEdges {
		parts = append(parts, fmt.Sprintf("dangling edge %s->%s (missing node %q, from %s)", d.From, d.To, d.Missing, d.Source))
	}
	if len(e.OrphanNodes) > 0 {
		parts = append(parts, "orphan nodes: "+strings.Join(e.OrphanNodes, ", "))
	}
	for _, c := range e.Cycles {
		parts = append(parts, "cycle: "+strings.Join(c, "->"))
	}
	return "mission graph: " + strings.Join(parts, "; ")
}

func adjacency(edges []edge) map[string][]string {
	adj := map[string][]string{}
	for _, e := range edges {
		adj[e.from] = append(adj[e.from], e.to)
	}
	for k := range adj {
		sort.Strings(adj[k])
	}
	return adj
}

// findCycles returns illegal cycles via DFS. Acyclic constructs (including
// parallel→…→join fan-out/fan-in diamonds) produce none. Each cycle is reported
// once, canonicalized to start at its lexicographically smallest member.
func findCycles(nodes map[string]*missionv1.MissionNode, edges []edge) [][]string {
	adj := adjacency(edges)
	const (
		white = 0
		gray  = 1
		black = 2
	)
	color := map[string]int{}
	var stack []string
	seen := map[string]bool{}
	var cycles [][]string

	var dfs func(u string)
	dfs = func(u string) {
		color[u] = gray
		stack = append(stack, u)
		for _, v := range adj[u] {
			switch color[v] {
			case white:
				dfs(v)
			case gray:
				start := 0
				for i, n := range stack {
					if n == v {
						start = i
						break
					}
				}
				cyc := canonicalCycle(stack[start:])
				key := strings.Join(cyc, "\x00")
				if !seen[key] {
					seen[key] = true
					cycles = append(cycles, cyc)
				}
			}
		}
		stack = stack[:len(stack)-1]
		color[u] = black
	}

	for _, id := range sortedNodeKeys(nodes) {
		if color[id] == white {
			dfs(id)
		}
	}
	sort.Slice(cycles, func(i, k int) bool {
		return strings.Join(cycles[i], "\x00") < strings.Join(cycles[k], "\x00")
	})
	return cycles
}

func canonicalCycle(path []string) []string {
	if len(path) == 0 {
		return nil
	}
	min := 0
	for i := 1; i < len(path); i++ {
		if path[i] < path[min] {
			min = i
		}
	}
	out := make([]string, 0, len(path))
	out = append(out, path[min:]...)
	out = append(out, path[:min]...)
	return out
}

// findOrphans returns nodes unreachable from any entry point (sorted). With no
// entry points (e.g. a fully cyclic graph) every node is an orphan, surfacing
// alongside the cycle report.
func findOrphans(nodes map[string]*missionv1.MissionNode, edges []edge, entry []string) []string {
	adj := adjacency(edges)
	reach := map[string]bool{}
	var dfs func(u string)
	dfs = func(u string) {
		if reach[u] {
			return
		}
		reach[u] = true
		for _, v := range adj[u] {
			dfs(v)
		}
	}
	for _, e := range entry {
		dfs(e)
	}
	var orphans []string
	for id := range nodes {
		if !reach[id] {
			orphans = append(orphans, id)
		}
	}
	sort.Strings(orphans)
	return orphans
}

// layerNodes assigns each node a topological rank: 0 for roots, otherwise one
// past the maximum rank of its predecessors (longest-path layering). Inputs are
// assumed acyclic (cycles are rejected before layering).
func layerNodes(nodes map[string]*missionv1.MissionNode, edges []edge) map[string]int {
	indeg := map[string]int{}
	for id := range nodes {
		indeg[id] = 0
	}
	adj := adjacency(edges)
	for _, vs := range adj {
		for _, v := range vs {
			indeg[v]++
		}
	}
	rank := map[string]int{}
	var queue []string
	for _, id := range sortedNodeKeys(nodes) {
		if indeg[id] == 0 {
			rank[id] = 0
			queue = append(queue, id)
		}
	}
	for len(queue) > 0 {
		u := queue[0]
		queue = queue[1:]
		for _, v := range adj[u] {
			if r := rank[u] + 1; r > rank[v] {
				rank[v] = r
			}
			indeg[v]--
			if indeg[v] == 0 {
				queue = append(queue, v)
				sort.Strings(queue)
			}
		}
	}
	return rank
}

// autoPositions converts ranks into deterministic canvas coordinates: x by
// rank (depth), y by stable order within the rank.
func autoPositions(nodes map[string]*missionv1.MissionNode, ranks map[string]int) map[string]xy {
	byRank := map[int][]string{}
	for _, id := range sortedNodeKeys(nodes) {
		byRank[ranks[id]] = append(byRank[ranks[id]], id)
	}
	pos := map[string]xy{}
	for r, ids := range byRank {
		sort.Strings(ids)
		for i, id := range ids {
			pos[id] = xy{x: float64(r) * rankSpacingX, y: float64(i) * rankSpacingY}
		}
	}
	return pos
}

// --- small deterministic helpers ---

func sortedNodeKeys(m map[string]*missionv1.MissionNode) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func toSet(ss []string) map[string]bool {
	m := make(map[string]bool, len(ss))
	for _, s := range ss {
		m[s] = true
	}
	return m
}

func dedupe(ss []string) []string {
	if len(ss) == 0 {
		return ss
	}
	out := ss[:1]
	for _, s := range ss[1:] {
		if s != out[len(out)-1] {
			out = append(out, s)
		}
	}
	return out
}
