// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package graphrag

import (
	"time"

	"github.com/neo4j/neo4j-go-driver/v5/neo4j/dbtype"
	"github.com/zeroroot-ai/gibson/internal/infra/types"
)

// Decoding Neo4j rows back into graphrag types.
//
// A row that cannot be decoded is SKIPPED, never returned half-built. A node
// with an unparseable id cannot be joined to anything, related to anything, or
// asked for again — handing it back would put a value into a caller's knowledge
// graph that no later call can resolve. Silence about one malformed row is the
// lesser harm; the row is malformed because something else already went wrong.

// recordsToNodes decodes rows shaped `RETURN n`.
func recordsToNodes(records []map[string]any) []GraphNode {
	nodes := make([]GraphNode, 0, len(records))
	for _, rec := range records {
		raw, ok := rec["n"]
		if !ok {
			continue
		}
		neoNode, ok := raw.(dbtype.Node)
		if !ok {
			continue
		}
		node, ok := decodeNode(neoNode)
		if !ok {
			continue
		}
		nodes = append(nodes, node)
	}
	return nodes
}

func decodeNode(n dbtype.Node) (GraphNode, bool) {
	idStr, _ := n.Props["id"].(string)
	id, err := types.ParseID(idStr)
	if err != nil {
		return GraphNode{}, false
	}

	labels := make([]NodeType, 0, len(n.Labels))
	for _, l := range n.Labels {
		labels = append(labels, NodeType(l))
	}

	props := make(map[string]any, len(n.Props))
	for k, v := range n.Props {
		props[k] = v
	}

	node := GraphNode{
		ID:         id,
		Labels:     labels,
		Properties: props,
		CreatedAt:  parseTimeProp(n.Props["created_at"]),
		UpdatedAt:  parseTimeProp(n.Props["updated_at"]),
	}
	if missionID, mErr := types.ParseID(stringProp(n.Props["mission_id"])); mErr == nil {
		node.MissionID = &missionID
	}
	return node, true
}

// recordsToRelationships decodes rows shaped
// `RETURN a.id AS from_id, b.id AS to_id, type(r) AS rel_type, r AS rel`.
func recordsToRelationships(records []map[string]any) []Relationship {
	rels := make([]Relationship, 0, len(records))
	for _, rec := range records {
		fromID, err := types.ParseID(stringProp(rec["from_id"]))
		if err != nil {
			continue
		}
		toID, err := types.ParseID(stringProp(rec["to_id"]))
		if err != nil {
			continue
		}

		rel := Relationship{
			FromID:     fromID,
			ToID:       toID,
			Type:       RelationType(stringProp(rec["rel_type"])),
			Properties: map[string]any{},
		}
		if neoRel, ok := rec["rel"].(dbtype.Relationship); ok {
			for k, v := range neoRel.Props {
				rel.Properties[k] = v
			}
			rel.Weight = floatProp(neoRel.Props["weight"])
			rel.CreatedAt = parseTimeProp(neoRel.Props["created_at"])
		}
		rels = append(rels, rel)
	}
	return rels
}

func stringProp(v any) string {
	s, _ := v.(string)
	return s
}

func floatProp(v any) float64 {
	switch f := v.(type) {
	case float64:
		return f
	case int64:
		return float64(f)
	default:
		return 0
	}
}

// parseTimeProp reads a timestamp property, accepting both the RFC3339 strings
// this provider writes and the native temporal types a node written by another
// path may carry. An unreadable timestamp yields the zero time rather than
// "now" — a made-up timestamp is worse than an obviously absent one.
func parseTimeProp(v any) time.Time {
	switch t := v.(type) {
	case string:
		parsed, err := time.Parse(time.RFC3339, t)
		if err != nil {
			return time.Time{}
		}
		return parsed
	case time.Time:
		return t
	case dbtype.LocalDateTime:
		return t.Time()
	default:
		return time.Time{}
	}
}
