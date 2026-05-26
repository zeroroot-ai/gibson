package graphrag

import (
	"github.com/zeroroot-ai/gibson/internal/types"
)

// MissionScope defines the scope for mission filtering in GraphRAG queries.
// Used by both GraphRAGQuery (semantic + structured queries) and NodeQuery
// (direct property lookup).
type MissionScope string

const (
	ScopeCurrentRun  MissionScope = "current_run"  // Only data from current mission run
	ScopeSameMission MissionScope = "same_mission" // All runs of the same mission
	ScopeAll         MissionScope = "all"          // All missions (no filtering)
)

// NodeQuery represents a query for specific nodes by properties.
// Used for exact lookups rather than similarity search.
type NodeQuery struct {
	NodeTypes  []NodeType     `json:"node_types,omitempty"`
	Properties map[string]any `json:"properties,omitempty"`
	MissionID  *types.ID      `json:"mission_id,omitempty"`
	Limit      int            `json:"limit,omitempty"`

	// Mission-scoped query fields (Phase 2)
	// Scope determines what data is visible: current run, all runs of mission, or global
	Scope MissionScope `json:"scope,omitempty"`
	// MissionRunID is set by harness for mission-run scoped queries (default scope)
	MissionRunID string `json:"mission_run_id,omitempty"`
	// MissionName is used for ScopeMission queries to find all runs with same name
	MissionName string `json:"mission_name,omitempty"`
}

// NewNodeQuery creates a new NodeQuery.
func NewNodeQuery() *NodeQuery {
	return &NodeQuery{
		Properties: make(map[string]any),
		Limit:      100,
	}
}

// WithNodeTypes filters by node types.
func (nq *NodeQuery) WithNodeTypes(types ...NodeType) *NodeQuery {
	nq.NodeTypes = types
	return nq
}

// WithProperty adds a property filter.
func (nq *NodeQuery) WithProperty(key string, value any) *NodeQuery {
	nq.Properties[key] = value
	return nq
}

// WithMission filters by mission ID.
func (nq *NodeQuery) WithMission(missionID types.ID) *NodeQuery {
	nq.MissionID = &missionID
	return nq
}

// WithLimit sets the maximum number of results.
func (nq *NodeQuery) WithLimit(limit int) *NodeQuery {
	nq.Limit = limit
	return nq
}

// WithScope sets the mission scope for the query.
func (nq *NodeQuery) WithScope(scope MissionScope) *NodeQuery {
	nq.Scope = scope
	return nq
}

// WithMissionRunID sets the mission run ID for mission-run scoped queries.
func (nq *NodeQuery) WithMissionRunID(runID string) *NodeQuery {
	nq.MissionRunID = runID
	return nq
}

// WithMissionName sets the mission name for same-mission scoped queries.
func (nq *NodeQuery) WithMissionName(name string) *NodeQuery {
	nq.MissionName = name
	return nq
}

// TraversalFilters contains filters for graph traversal.
// Controls which relationships and nodes to include during traversal.
type TraversalFilters struct {
	AllowedRelations []RelationType `json:"allowed_relations,omitempty"`  // Only traverse these relations
	BlockedRelations []RelationType `json:"blocked_relations,omitempty"`  // Never traverse these relations
	AllowedNodeTypes []NodeType     `json:"allowed_node_types,omitempty"` // Only include these node types
	BlockedNodeTypes []NodeType     `json:"blocked_node_types,omitempty"` // Never include these node types
	MinWeight        float64        `json:"min_weight,omitempty"`         // Minimum relationship weight
	MaxDepth         int            `json:"max_depth,omitempty"`          // Override query max_hops
}
