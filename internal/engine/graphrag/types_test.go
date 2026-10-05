// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package graphrag

import (
	"testing"
	"time"

	"github.com/zeroroot-ai/gibson/internal/infra/types"
)

func TestNodeType_String(t *testing.T) {
	tests := []struct {
		name     string
		nodeType NodeType
		want     string
	}{
		{
			name:     "finding",
			nodeType: NodeType("finding"),
			want:     "finding",
		},
		{
			name:     "attack_pattern",
			nodeType: NodeType("attack_pattern"),
			want:     "attack_pattern",
		},
		{
			name:     "technique",
			nodeType: NodeType("technique"),
			want:     "technique",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.nodeType.String(); got != tt.want {
				t.Errorf("NodeType.String() = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestNodeType_IsValid has been removed because node type validation
// is now handled by the taxonomy system, not hardcoded constants.

func TestRelationType_String(t *testing.T) {
	tests := []struct {
		name         string
		relationType RelationType
		want         string
	}{
		{
			name:         "exploits",
			relationType: RelationType("exploits"),
			want:         "exploits",
		},
		{
			name:         "similar_to",
			relationType: RelationType("similar_to"),
			want:         "similar_to",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.relationType.String(); got != tt.want {
				t.Errorf("RelationType.String() = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestRelationType_IsValid has been removed because relationship type validation
// is now handled by the taxonomy system, not hardcoded constants.

func TestNewGraphNode(t *testing.T) {
	id := types.NewID()
	node := NewGraphNode(id, NodeType("finding"), NodeType("entity"))

	if node.ID != id {
		t.Errorf("NewGraphNode() ID = %v, want %v", node.ID, id)
	}
	if len(node.Labels) != 2 {
		t.Errorf("NewGraphNode() Labels count = %v, want 2", len(node.Labels))
	}
	if node.Labels[0] != NodeType("finding") {
		t.Errorf("NewGraphNode() Labels[0] = %v, want %v", node.Labels[0], NodeType("finding"))
	}
	if node.Properties == nil {
		t.Error("NewGraphNode() Properties should not be nil")
	}
	if node.CreatedAt.IsZero() {
		t.Error("NewGraphNode() CreatedAt should not be zero")
	}
}

func TestGraphNode_WithProperty(t *testing.T) {
	node := NewGraphNode(types.NewID(), NodeType("finding"))
	result := node.WithProperty("key", "value")

	if result != node {
		t.Error("WithProperty() should return the same node for chaining")
	}
	if node.Properties["key"] != "value" {
		t.Errorf("WithProperty() property = %v, want 'value'", node.Properties["key"])
	}
}

func TestGraphNode_WithProperties(t *testing.T) {
	node := NewGraphNode(types.NewID(), NodeType("finding"))
	props := map[string]any{
		"key1": "value1",
		"key2": 42,
	}
	result := node.WithProperties(props)

	if result != node {
		t.Error("WithProperties() should return the same node for chaining")
	}
	if node.Properties["key1"] != "value1" {
		t.Errorf("WithProperties() key1 = %v, want 'value1'", node.Properties["key1"])
	}
	if node.Properties["key2"] != 42 {
		t.Errorf("WithProperties() key2 = %v, want 42", node.Properties["key2"])
	}
}

func TestGraphNode_WithEmbedding(t *testing.T) {
	node := NewGraphNode(types.NewID(), NodeType("finding"))
	embedding := []float64{0.1, 0.2, 0.3}
	result := node.WithEmbedding(embedding)

	if result != node {
		t.Error("WithEmbedding() should return the same node for chaining")
	}
	if len(node.Embedding) != 3 {
		t.Errorf("WithEmbedding() embedding length = %v, want 3", len(node.Embedding))
	}
}

func TestGraphNode_WithMission(t *testing.T) {
	node := NewGraphNode(types.NewID(), NodeType("finding"))
	missionID := types.NewID()
	result := node.WithMission(missionID)

	if result != node {
		t.Error("WithMission() should return the same node for chaining")
	}
	if node.MissionID == nil {
		t.Error("WithMission() MissionID should not be nil")
	}
	if *node.MissionID != missionID {
		t.Errorf("WithMission() MissionID = %v, want %v", *node.MissionID, missionID)
	}
}

func TestGraphNode_HasLabel(t *testing.T) {
	node := NewGraphNode(types.NewID(), NodeType("finding"), NodeType("entity"))

	tests := []struct {
		name  string
		label NodeType
		want  bool
	}{
		{
			name:  "has label - Finding",
			label: NodeType("finding"),
			want:  true,
		},
		{
			name:  "has label - Entity",
			label: NodeType("entity"),
			want:  true,
		},
		{
			name:  "does not have label - Technique",
			label: NodeType("technique"),
			want:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := node.HasLabel(tt.label); got != tt.want {
				t.Errorf("HasLabel() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestGraphNode_GetProperty(t *testing.T) {
	node := NewGraphNode(types.NewID(), NodeType("finding"))
	node.WithProperty("key", "value")

	tests := []struct {
		name string
		key  string
		want any
	}{
		{
			name: "existing property",
			key:  "key",
			want: "value",
		},
		{
			name: "non-existent property",
			key:  "nonexistent",
			want: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := node.GetProperty(tt.key)
			if got != tt.want {
				t.Errorf("GetProperty() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestGraphNode_GetStringProperty(t *testing.T) {
	node := NewGraphNode(types.NewID(), NodeType("finding"))
	node.WithProperty("string_key", "string_value")
	node.WithProperty("int_key", 42)

	tests := []struct {
		name string
		key  string
		want string
	}{
		{
			name: "string property",
			key:  "string_key",
			want: "string_value",
		},
		{
			name: "non-string property",
			key:  "int_key",
			want: "",
		},
		{
			name: "non-existent property",
			key:  "nonexistent",
			want: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := node.GetStringProperty(tt.key)
			if got != tt.want {
				t.Errorf("GetStringProperty() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestGraphNode_Validate(t *testing.T) {
	tests := []struct {
		name    string
		node    *GraphNode
		wantErr bool
	}{
		{
			name:    "valid node",
			node:    NewGraphNode(types.NewID(), NodeType("finding")),
			wantErr: false,
		},
		{
			name: "invalid - no labels",
			node: &GraphNode{
				ID:         types.NewID(),
				Labels:     []NodeType{},
				Properties: make(map[string]any),
			},
			wantErr: true,
		},
		{
			name: "valid - taxonomy type (host)",
			node: &GraphNode{
				ID:         types.NewID(),
				Labels:     []NodeType{NodeType("host")},
				Properties: make(map[string]any),
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.node.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestGraphNode_UpdatedAt(t *testing.T) {
	node := NewGraphNode(types.NewID(), NodeType("finding"))
	originalTime := node.UpdatedAt

	// Sleep briefly to ensure time difference
	time.Sleep(10 * time.Millisecond)

	node.WithProperty("key", "value")

	if !node.UpdatedAt.After(originalTime) {
		t.Error("UpdatedAt should be updated after WithProperty()")
	}
}
