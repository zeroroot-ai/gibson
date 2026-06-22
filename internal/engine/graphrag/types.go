package graphrag

import (
	"fmt"
	"time"

	"github.com/zeroroot-ai/gibson/internal/infra/types"
)

// NodeType represents the type of node in the graph.
// Different node types represent different entities in the security knowledge graph.
// Node types should match those defined in the taxonomy YAML configuration.
type NodeType string

// String returns the string representation of NodeType.
func (nt NodeType) String() string {
	return string(nt)
}

// RelationType represents the type of relationship between nodes.
// Relationships capture semantic connections in the security knowledge graph.
// Relationship types should match those defined in the taxonomy YAML configuration.
type RelationType string

// String returns the string representation of RelationType.
func (rt RelationType) String() string {
	return string(rt)
}

// GraphNode represents a node in the knowledge graph.
// Nodes can have embeddings for vector search and are associated with missions.
type GraphNode struct {
	ID         types.ID       `json:"id"`
	Labels     []NodeType     `json:"labels"`     // Node can have multiple labels
	Properties map[string]any `json:"properties"` // Flexible property storage
	Embedding  []float64      `json:"embedding,omitempty"`
	CreatedAt  time.Time      `json:"created_at"`
	UpdatedAt  time.Time      `json:"updated_at"`
	MissionID  *types.ID      `json:"mission_id,omitempty"`
}

// NewGraphNode creates a new GraphNode with the given ID and labels.
func NewGraphNode(id types.ID, labels ...NodeType) *GraphNode {
	now := time.Now()
	return &GraphNode{
		ID:         id,
		Labels:     labels,
		Properties: make(map[string]any),
		CreatedAt:  now,
		UpdatedAt:  now,
	}
}

// WithProperty adds a property to the node.
// Returns the node for method chaining.
func (n *GraphNode) WithProperty(key string, value any) *GraphNode {
	n.Properties[key] = value
	n.UpdatedAt = time.Now()
	return n
}

// WithProperties sets multiple properties on the node.
// Returns the node for method chaining.
func (n *GraphNode) WithProperties(props map[string]any) *GraphNode {
	for k, v := range props {
		n.Properties[k] = v
	}
	n.UpdatedAt = time.Now()
	return n
}

// WithEmbedding sets the embedding vector for the node.
// Returns the node for method chaining.
func (n *GraphNode) WithEmbedding(embedding []float64) *GraphNode {
	n.Embedding = embedding
	n.UpdatedAt = time.Now()
	return n
}

// WithMission sets the mission ID for the node.
// Returns the node for method chaining.
func (n *GraphNode) WithMission(missionID types.ID) *GraphNode {
	n.MissionID = &missionID
	n.UpdatedAt = time.Now()
	return n
}

// HasLabel checks if the node has the given label.
func (n *GraphNode) HasLabel(label NodeType) bool {
	for _, l := range n.Labels {
		if l == label {
			return true
		}
	}
	return false
}

// GetProperty retrieves a property value by key.
// Returns nil if the property doesn't exist.
func (n *GraphNode) GetProperty(key string) any {
	return n.Properties[key]
}

// GetStringProperty retrieves a string property value by key.
// Returns empty string if the property doesn't exist or isn't a string.
func (n *GraphNode) GetStringProperty(key string) string {
	if val, ok := n.Properties[key].(string); ok {
		return val
	}
	return ""
}

// WithMissionName sets the mission_name property.
// Returns the node for method chaining.
func (n *GraphNode) WithMissionName(name string) *GraphNode {
	return n.WithProperty("mission_name", name)
}

// WithRunNumber sets the run_number property.
// Returns the node for method chaining.
func (n *GraphNode) WithRunNumber(runNumber int) *GraphNode {
	return n.WithProperty("run_number", runNumber)
}

// WithCreatedInRun sets the created_in_run property (original discovery run ID).
// Returns the node for method chaining.
func (n *GraphNode) WithCreatedInRun(runID string) *GraphNode {
	return n.WithProperty("created_in_run", runID)
}

// WithUpdatedInRun sets the updated_in_run property (most recent update run ID).
// Returns the node for method chaining.
func (n *GraphNode) WithUpdatedInRun(runID string) *GraphNode {
	return n.WithProperty("updated_in_run", runID)
}

// WithLastSeenInRun sets the last_seen_in_run property (for re-discovery tracking).
// Returns the node for method chaining.
func (n *GraphNode) WithLastSeenInRun(runID string) *GraphNode {
	return n.WithProperty("last_seen_in_run", runID)
}

// GetMissionName returns the mission_name property.
func (n *GraphNode) GetMissionName() string {
	return n.GetStringProperty("mission_name")
}

// GetRunNumber returns the run_number property.
// Handles both int and float64 types for JSON compatibility.
func (n *GraphNode) GetRunNumber() int {
	if v, ok := n.Properties["run_number"].(int); ok {
		return v
	}
	if v, ok := n.Properties["run_number"].(float64); ok {
		return int(v)
	}
	return 0
}

// RunMetadata contains run provenance information for a graph node.
type RunMetadata struct {
	MissionName  string    `json:"mission_name"`
	RunNumber    int       `json:"run_number"`
	DiscoveredAt time.Time `json:"discovered_at"`
}

// GetRunMetadata extracts run metadata from node properties.
// Returns nil if no mission_name is set (backwards compatibility).
func (n *GraphNode) GetRunMetadata() *RunMetadata {
	name := n.GetMissionName()
	if name == "" {
		return nil
	}
	return &RunMetadata{
		MissionName:  name,
		RunNumber:    n.GetRunNumber(),
		DiscoveredAt: n.CreatedAt,
	}
}

// Validate validates the GraphNode fields.
func (n *GraphNode) Validate() error {
	if err := n.ID.Validate(); err != nil {
		return fmt.Errorf("invalid node ID: %w", err)
	}
	if len(n.Labels) == 0 {
		return fmt.Errorf("node must have at least one label")
	}
	return nil
}

// Relationship represents an edge between two nodes in the graph.
type Relationship struct {
	ID         types.ID       `json:"id"`
	FromID     types.ID       `json:"from_id"`
	ToID       types.ID       `json:"to_id"`
	Type       RelationType   `json:"type"`
	Properties map[string]any `json:"properties,omitempty"`
	Weight     float64        `json:"weight,omitempty"` // Relationship strength/confidence
	CreatedAt  time.Time      `json:"created_at"`
}

// NewRelationship creates a new Relationship between two nodes.
func NewRelationship(fromID, toID types.ID, relType RelationType) *Relationship {
	return &Relationship{
		ID:         types.NewID(),
		FromID:     fromID,
		ToID:       toID,
		Type:       relType,
		Properties: make(map[string]any),
		Weight:     1.0, // Default weight
		CreatedAt:  time.Now(),
	}
}

// WithProperty adds a property to the relationship.
// Returns the relationship for method chaining.
func (r *Relationship) WithProperty(key string, value any) *Relationship {
	r.Properties[key] = value
	return r
}

// WithWeight sets the weight/confidence for the relationship.
// Returns the relationship for method chaining.
func (r *Relationship) WithWeight(weight float64) *Relationship {
	r.Weight = weight
	return r
}

// Validate validates the Relationship fields.
func (r *Relationship) Validate() error {
	if err := r.ID.Validate(); err != nil {
		return fmt.Errorf("invalid relationship ID: %w", err)
	}
	if err := r.FromID.Validate(); err != nil {
		return fmt.Errorf("invalid from_id: %w", err)
	}
	if err := r.ToID.Validate(); err != nil {
		return fmt.Errorf("invalid to_id: %w", err)
	}
	if r.Weight < 0.0 || r.Weight > 1.0 {
		return fmt.Errorf("relationship weight must be between 0.0 and 1.0, got %f", r.Weight)
	}
	return nil
}

// AttackPattern represents an attack pattern node in the graph.
// This is a specialized node type for MITRE ATT&CK patterns.
type AttackPattern struct {
	ID          types.ID  `json:"id"`
	TechniqueID string    `json:"technique_id"` // e.g., "T1566"
	Name        string    `json:"name"`
	Description string    `json:"description"`
	Tactics     []string  `json:"tactics"`   // e.g., ["Initial Access", "Execution"]
	Platforms   []string  `json:"platforms"` // e.g., ["Windows", "Linux"]
	DataSources []string  `json:"data_sources,omitempty"`
	References  []string  `json:"references,omitempty"`
	Embedding   []float64 `json:"embedding,omitempty"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// NewAttackPattern creates a new AttackPattern.
func NewAttackPattern(techniqueID, name, description string) *AttackPattern {
	now := time.Now()
	return &AttackPattern{
		ID:          types.NewID(),
		TechniqueID: techniqueID,
		Name:        name,
		Description: description,
		Tactics:     []string{},
		Platforms:   []string{},
		DataSources: []string{},
		References:  []string{},
		CreatedAt:   now,
		UpdatedAt:   now,
	}
}

// ToGraphNode converts the AttackPattern to a GraphNode.
func (ap *AttackPattern) ToGraphNode() *GraphNode {
	node := NewGraphNode(ap.ID, NodeType("attack_pattern"))
	node.WithProperties(map[string]any{
		"technique_id": ap.TechniqueID,
		"name":         ap.Name,
		"description":  ap.Description,
		"tactics":      ap.Tactics,
		"platforms":    ap.Platforms,
		"data_sources": ap.DataSources,
		"references":   ap.References,
	})
	if len(ap.Embedding) > 0 {
		node.WithEmbedding(ap.Embedding)
	}
	node.CreatedAt = ap.CreatedAt
	node.UpdatedAt = ap.UpdatedAt
	return node
}

// FindingNode represents a security finding node in the graph.
// This connects findings to the knowledge graph for contextual analysis.
type FindingNode struct {
	ID          types.ID  `json:"id"`
	Title       string    `json:"title"`
	Description string    `json:"description"`
	Severity    string    `json:"severity"`
	Category    string    `json:"category"`
	Confidence  float64   `json:"confidence"`
	MissionID   types.ID  `json:"mission_id"`
	TargetID    *types.ID `json:"target_id,omitempty"`
	Embedding   []float64 `json:"embedding,omitempty"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// NewFindingNode creates a new FindingNode.
func NewFindingNode(id types.ID, title, description string, missionID types.ID) *FindingNode {
	now := time.Now()
	return &FindingNode{
		ID:          id,
		Title:       title,
		Description: description,
		MissionID:   missionID,
		Confidence:  1.0,
		CreatedAt:   now,
		UpdatedAt:   now,
	}
}

// ToGraphNode converts the FindingNode to a GraphNode.
func (fn *FindingNode) ToGraphNode() *GraphNode {
	node := NewGraphNode(fn.ID, NodeType("finding"))
	node.WithProperties(map[string]any{
		"title":       fn.Title,
		"description": fn.Description,
		"severity":    fn.Severity,
		"category":    fn.Category,
		"confidence":  fn.Confidence,
	})
	if fn.TargetID != nil {
		node.WithProperty("target_id", fn.TargetID.String())
	}
	node.WithMission(fn.MissionID)
	if len(fn.Embedding) > 0 {
		node.WithEmbedding(fn.Embedding)
	}
	node.CreatedAt = fn.CreatedAt
	node.UpdatedAt = fn.UpdatedAt
	return node
}

// TechniqueNode represents a MITRE technique/tactic node.
type TechniqueNode struct {
	ID          types.ID  `json:"id"`
	TechniqueID string    `json:"technique_id"` // e.g., "T1566.001" (with sub-technique)
	Name        string    `json:"name"`
	Description string    `json:"description"`
	Tactic      string    `json:"tactic"` // Primary tactic
	Platform    string    `json:"platform,omitempty"`
	Embedding   []float64 `json:"embedding,omitempty"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// NewTechniqueNode creates a new TechniqueNode.
func NewTechniqueNode(techniqueID, name, description, tactic string) *TechniqueNode {
	now := time.Now()
	return &TechniqueNode{
		ID:          types.NewID(),
		TechniqueID: techniqueID,
		Name:        name,
		Description: description,
		Tactic:      tactic,
		CreatedAt:   now,
		UpdatedAt:   now,
	}
}

// ToGraphNode converts the TechniqueNode to a GraphNode.
func (tn *TechniqueNode) ToGraphNode() *GraphNode {
	node := NewGraphNode(tn.ID, NodeType("technique"))
	node.WithProperties(map[string]any{
		"technique_id": tn.TechniqueID,
		"name":         tn.Name,
		"description":  tn.Description,
		"tactic":       tn.Tactic,
		"platform":     tn.Platform,
	})
	if len(tn.Embedding) > 0 {
		node.WithEmbedding(tn.Embedding)
	}
	node.CreatedAt = tn.CreatedAt
	node.UpdatedAt = tn.UpdatedAt
	return node
}
