// Package definitionutil provides pure, stateless helper functions
// over the canonical generated proto type
// `*missionv1.MissionDefinition`. These replace the methods that
// previously hung off the hand-written mirror at
// `internal/mission/definition.go`.
//
// Spec: mission-schema-canonicalization Requirement 1.
package definitionutil

import (
	missionv1 "github.com/zero-day-ai/sdk/api/gen/gibson/mission/v1"
)

// GetNode returns the node with the given ID and a found flag.
// Returns (nil, false) for nil definitions, missions with no nodes,
// or missing IDs. Never panics.
func GetNode(def *missionv1.MissionDefinition, id string) (*missionv1.MissionNode, bool) {
	if def == nil || def.Nodes == nil {
		return nil, false
	}
	n, ok := def.Nodes[id]
	return n, ok
}

// EntryNodeIDs returns the node IDs designated as entry points to
// the mission. If `def.EntryPoints` is set, those IDs are returned
// in order. If unset, IDs are computed from the edges (nodes with
// no incoming edges).
//
// Returns an empty slice (never nil) for nil definitions or
// missions with no nodes.
func EntryNodeIDs(def *missionv1.MissionDefinition) []string {
	if def == nil || len(def.Nodes) == 0 {
		return []string{}
	}
	if len(def.EntryPoints) > 0 {
		out := make([]string, 0, len(def.EntryPoints))
		for _, id := range def.EntryPoints {
			if _, ok := def.Nodes[id]; ok {
				out = append(out, id)
			}
		}
		return out
	}
	return computeEntryByEdges(def)
}

// ExitNodeIDs returns the node IDs designated as exit points from
// the mission. If `def.ExitPoints` is set, those IDs are returned
// in order. If unset, IDs are computed from the edges (nodes with
// no outgoing edges).
//
// Returns an empty slice (never nil) for nil definitions or
// missions with no nodes.
func ExitNodeIDs(def *missionv1.MissionDefinition) []string {
	if def == nil || len(def.Nodes) == 0 {
		return []string{}
	}
	if len(def.ExitPoints) > 0 {
		out := make([]string, 0, len(def.ExitPoints))
		for _, id := range def.ExitPoints {
			if _, ok := def.Nodes[id]; ok {
				out = append(out, id)
			}
		}
		return out
	}
	return computeExitByEdges(def)
}

// EntryNodes returns the nodes designated as entry points.
// Convenience wrapper over EntryNodeIDs that resolves IDs to nodes.
// Missing IDs (entries in EntryPoints not present in Nodes) are
// silently skipped.
func EntryNodes(def *missionv1.MissionDefinition) []*missionv1.MissionNode {
	ids := EntryNodeIDs(def)
	out := make([]*missionv1.MissionNode, 0, len(ids))
	for _, id := range ids {
		if n, ok := def.Nodes[id]; ok {
			out = append(out, n)
		}
	}
	return out
}

// ExitNodes returns the nodes designated as exit points. Same
// semantics as EntryNodes.
func ExitNodes(def *missionv1.MissionDefinition) []*missionv1.MissionNode {
	ids := ExitNodeIDs(def)
	out := make([]*missionv1.MissionNode, 0, len(ids))
	for _, id := range ids {
		if n, ok := def.Nodes[id]; ok {
			out = append(out, n)
		}
	}
	return out
}

// computeEntryByEdges returns node IDs that have no incoming edges.
// Order: stable map-iteration order is not guaranteed by Go; the
// result is sorted for determinism.
func computeEntryByEdges(def *missionv1.MissionDefinition) []string {
	hasIncoming := make(map[string]bool, len(def.Nodes))
	for _, e := range def.Edges {
		if e == nil {
			continue
		}
		hasIncoming[e.To] = true
	}
	out := make([]string, 0)
	for id := range def.Nodes {
		if !hasIncoming[id] {
			out = append(out, id)
		}
	}
	sortStrings(out)
	return out
}

// computeExitByEdges returns node IDs that have no outgoing edges.
func computeExitByEdges(def *missionv1.MissionDefinition) []string {
	hasOutgoing := make(map[string]bool, len(def.Nodes))
	for _, e := range def.Edges {
		if e == nil {
			continue
		}
		hasOutgoing[e.From] = true
	}
	out := make([]string, 0)
	for id := range def.Nodes {
		if !hasOutgoing[id] {
			out = append(out, id)
		}
	}
	sortStrings(out)
	return out
}

// sortStrings sorts in place via insertion sort. Pulled inline to
// avoid a dependency on the sort package for a function that only
// runs on small slices.
func sortStrings(xs []string) {
	for i := 1; i < len(xs); i++ {
		for j := i; j > 0 && xs[j-1] > xs[j]; j-- {
			xs[j-1], xs[j] = xs[j], xs[j-1]
		}
	}
}
