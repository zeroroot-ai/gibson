package mission

import (
	"testing"
)

// TestValidateInlineTarget_ValidConfig tests validation of a valid inline target config.
func TestValidateInlineTarget_ValidConfig(t *testing.T) {
	config := &InlineTarget{
		Seeds: []*TargetSeed{
			{Value: "example.com", Type: "domain", Scope: "in_scope"},
			{Value: "192.168.1.0/24", Type: "cidr", Scope: "expand"},
		},
		Profile: "balanced",
		Depth:   3,
	}

	err := ValidateInlineTarget(config)
	if err != nil {
		t.Errorf("expected no error, got: %v", err)
	}
}

// TestValidateInlineTarget_NilConfig tests validation with nil config.
func TestValidateInlineTarget_NilConfig(t *testing.T) {
	err := ValidateInlineTarget(nil)
	if err == nil {
		t.Error("expected error for nil config, got nil")
	}
	if err.Error() != "inline target config is required" {
		t.Errorf("unexpected error message: %v", err)
	}
}

// TestValidateInlineTarget_EmptyTargetSeeds tests validation with no seeds.
func TestValidateInlineTarget_EmptyTargetSeeds(t *testing.T) {
	config := &InlineTarget{
		Seeds:   []*TargetSeed{},
		Profile: "balanced",
		Depth:   3,
	}

	err := ValidateInlineTarget(config)
	if err == nil {
		t.Error("expected error for empty seeds, got nil")
	}
	if err.Error() != "at least one seed is required" {
		t.Errorf("unexpected error message: %v", err)
	}
}

// TestValidateInlineTarget_InvalidTargetSeedType tests validation with invalid seed type.
func TestValidateInlineTarget_InvalidTargetSeedType(t *testing.T) {
	tests := []struct {
		name     string
		seedType string
	}{
		{"empty type", ""},
		{"invalid type", "invalid_type"},
		{"unknown type", "url"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := &InlineTarget{
				Seeds: []*TargetSeed{
					{Value: "example.com", Type: tt.seedType},
				},
				Profile: "balanced",
				Depth:   3,
			}

			err := ValidateInlineTarget(config)
			if err == nil {
				t.Errorf("expected error for seed type '%s', got nil", tt.seedType)
			}
		})
	}
}

// TestValidateInlineTarget_EmptyTargetSeedValue tests validation with empty seed value.
func TestValidateInlineTarget_EmptyTargetSeedValue(t *testing.T) {
	config := &InlineTarget{
		Seeds: []*TargetSeed{
			{Value: "", Type: "domain"},
		},
		Profile: "balanced",
		Depth:   3,
	}

	err := ValidateInlineTarget(config)
	if err == nil {
		t.Error("expected error for empty seed value, got nil")
	}
}

// TestValidateInlineTarget_InvalidProfile tests validation with invalid profiles.
func TestValidateInlineTarget_InvalidProfile(t *testing.T) {
	tests := []struct {
		name    string
		profile string
	}{
		{"empty profile", ""},
		{"invalid profile", "super_fast"},
		{"unknown profile", "turbo"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := &InlineTarget{
				Seeds: []*TargetSeed{
					{Value: "example.com", Type: "domain"},
				},
				Profile: tt.profile,
				Depth:   3,
			}

			err := ValidateInlineTarget(config)
			if err == nil {
				t.Errorf("expected error for profile '%s', got nil", tt.profile)
			}
		})
	}
}

// TestValidateInlineTarget_ValidProfiles tests all valid profiles.
func TestValidateInlineTarget_ValidProfiles(t *testing.T) {
	profiles := []string{"aggressive", "balanced", "stealth"}

	for _, profile := range profiles {
		t.Run(profile, func(t *testing.T) {
			config := &InlineTarget{
				Seeds: []*TargetSeed{
					{Value: "example.com", Type: "domain"},
				},
				Profile: profile,
				Depth:   3,
			}

			err := ValidateInlineTarget(config)
			if err != nil {
				t.Errorf("expected no error for profile '%s', got: %v", profile, err)
			}
		})
	}
}

// TestValidateInlineTarget_InvalidDepth tests validation with invalid depths.
func TestValidateInlineTarget_InvalidDepth(t *testing.T) {
	tests := []struct {
		name  string
		depth int32
	}{
		{"depth too low", 0},
		{"depth negative", -1},
		{"depth too high", 6},
		{"depth way too high", 100},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := &InlineTarget{
				Seeds: []*TargetSeed{
					{Value: "example.com", Type: "domain"},
				},
				Profile: "balanced",
				Depth:   tt.depth,
			}

			err := ValidateInlineTarget(config)
			if err == nil {
				t.Errorf("expected error for depth %d, got nil", tt.depth)
			}
		})
	}
}

// TestValidateInlineTarget_ValidDepths tests all valid depths.
func TestValidateInlineTarget_ValidDepths(t *testing.T) {
	for depth := int32(1); depth <= 5; depth++ {
		t.Run(string(rune('0'+depth)), func(t *testing.T) {
			config := &InlineTarget{
				Seeds: []*TargetSeed{
					{Value: "example.com", Type: "domain"},
				},
				Profile: "balanced",
				Depth:   depth,
			}

			err := ValidateInlineTarget(config)
			if err != nil {
				t.Errorf("expected no error for depth %d, got: %v", depth, err)
			}
		})
	}
}

// TestValidateInlineTarget_ValidTargetSeedTypes tests all valid seed types.
func TestValidateInlineTarget_ValidTargetSeedTypes(t *testing.T) {
	seedTypes := []struct {
		seedType string
		value    string
	}{
		{"domain", "example.com"},
		{"host", "192.168.1.1"},
		{"cidr", "192.168.1.0/24"},
		{"org", "Example Corp"},
		{"asn", "AS12345"},
	}

	for _, st := range seedTypes {
		t.Run(st.seedType, func(t *testing.T) {
			config := &InlineTarget{
				Seeds: []*TargetSeed{
					{Value: st.value, Type: st.seedType},
				},
				Profile: "balanced",
				Depth:   3,
			}

			err := ValidateInlineTarget(config)
			if err != nil {
				t.Errorf("expected no error for seed type '%s', got: %v", st.seedType, err)
			}
		})
	}
}

// TestValidateInlineTarget_InvalidTargetSeedScope tests validation with invalid seed scope.
func TestValidateInlineTarget_InvalidTargetSeedScope(t *testing.T) {
	config := &InlineTarget{
		Seeds: []*TargetSeed{
			{Value: "example.com", Type: "domain", Scope: "invalid_scope"},
		},
		Profile: "balanced",
		Depth:   3,
	}

	err := ValidateInlineTarget(config)
	if err == nil {
		t.Error("expected error for invalid seed scope, got nil")
	}
}

// TestValidateInlineWorkflow_ValidConfig tests validation of a valid inline workflow config.
func TestValidateInlineWorkflow_ValidConfig(t *testing.T) {
	config := &InlineWorkflow{
		Name: "test-workflow",
		Nodes: []*WorkflowNode{
			{
				ID:   "node1",
				Type: "agent",
				Name: "recon-agent",
			},
			{
				ID:        "node2",
				Type:      "tool",
				Name:      "nmap",
				DependsOn: []string{"node1"},
			},
		},
	}

	err := ValidateInlineWorkflow(config)
	if err != nil {
		t.Errorf("expected no error, got: %v", err)
	}
}

// TestValidateInlineWorkflow_NilConfig tests validation with nil config.
func TestValidateInlineWorkflow_NilConfig(t *testing.T) {
	err := ValidateInlineWorkflow(nil)
	if err == nil {
		t.Error("expected error for nil config, got nil")
	}
}

// TestValidateInlineWorkflow_EmptyNodes tests validation with no nodes.
func TestValidateInlineWorkflow_EmptyNodes(t *testing.T) {
	config := &InlineWorkflow{
		Name:  "test-workflow",
		Nodes: []*WorkflowNode{},
	}

	err := ValidateInlineWorkflow(config)
	if err == nil {
		t.Error("expected error for empty nodes, got nil")
	}
}

// TestValidateInlineWorkflow_InvalidNodeType tests validation with invalid node types.
func TestValidateInlineWorkflow_InvalidNodeType(t *testing.T) {
	config := &InlineWorkflow{
		Nodes: []*WorkflowNode{
			{
				ID:   "node1",
				Type: "invalid_type",
				Name: "test-node",
			},
		},
	}

	err := ValidateInlineWorkflow(config)
	if err == nil {
		t.Error("expected error for invalid node type, got nil")
	}
}

// TestValidateInlineWorkflow_ValidNodeTypes tests all valid node types.
func TestValidateInlineWorkflow_ValidNodeTypes(t *testing.T) {
	nodeTypes := []string{"agent", "tool", "plugin", "condition", "parallel", "join"}

	for _, nodeType := range nodeTypes {
		t.Run(nodeType, func(t *testing.T) {
			config := &InlineWorkflow{
				Nodes: []*WorkflowNode{
					{
						ID:   "node1",
						Type: nodeType,
						Name: "test-node",
					},
				},
			}

			err := ValidateInlineWorkflow(config)
			if err != nil {
				t.Errorf("expected no error for node type '%s', got: %v", nodeType, err)
			}
		})
	}
}

// TestValidateInlineWorkflow_DuplicateNodeID tests validation with duplicate node IDs.
func TestValidateInlineWorkflow_DuplicateNodeID(t *testing.T) {
	config := &InlineWorkflow{
		Nodes: []*WorkflowNode{
			{ID: "node1", Type: "agent", Name: "agent1"},
			{ID: "node1", Type: "tool", Name: "tool1"},
		},
	}

	err := ValidateInlineWorkflow(config)
	if err == nil {
		t.Error("expected error for duplicate node ID, got nil")
	}
}

// TestValidateInlineWorkflow_NonExistentDependency tests validation with non-existent dependency.
func TestValidateInlineWorkflow_NonExistentDependency(t *testing.T) {
	config := &InlineWorkflow{
		Nodes: []*WorkflowNode{
			{
				ID:        "node1",
				Type:      "agent",
				Name:      "agent1",
				DependsOn: []string{"non_existent_node"},
			},
		},
	}

	err := ValidateInlineWorkflow(config)
	if err == nil {
		t.Error("expected error for non-existent dependency, got nil")
	}
}

// TestValidateInlineWorkflow_CircularDependency tests circular dependency detection.
func TestValidateInlineWorkflow_CircularDependency(t *testing.T) {
	tests := []struct {
		name  string
		nodes []*WorkflowNode
	}{
		{
			name: "simple cycle",
			nodes: []*WorkflowNode{
				{ID: "node1", Type: "agent", Name: "agent1", DependsOn: []string{"node2"}},
				{ID: "node2", Type: "tool", Name: "tool1", DependsOn: []string{"node1"}},
			},
		},
		{
			name: "self cycle",
			nodes: []*WorkflowNode{
				{ID: "node1", Type: "agent", Name: "agent1", DependsOn: []string{"node1"}},
			},
		},
		{
			name: "three node cycle",
			nodes: []*WorkflowNode{
				{ID: "node1", Type: "agent", Name: "agent1", DependsOn: []string{"node2"}},
				{ID: "node2", Type: "tool", Name: "tool1", DependsOn: []string{"node3"}},
				{ID: "node3", Type: "plugin", Name: "plugin1", DependsOn: []string{"node1"}},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := &InlineWorkflow{
				Nodes: tt.nodes,
			}

			err := ValidateInlineWorkflow(config)
			if err == nil {
				t.Error("expected error for circular dependency, got nil")
			}
		})
	}
}

// TestValidateInlineWorkflow_ComplexValidDAG tests a complex valid DAG.
func TestValidateInlineWorkflow_ComplexValidDAG(t *testing.T) {
	config := &InlineWorkflow{
		Nodes: []*WorkflowNode{
			{ID: "start", Type: "agent", Name: "recon"},
			{ID: "scan1", Type: "tool", Name: "nmap", DependsOn: []string{"start"}},
			{ID: "scan2", Type: "tool", Name: "nuclei", DependsOn: []string{"start"}},
			{ID: "analyze", Type: "agent", Name: "analyzer", DependsOn: []string{"scan1", "scan2"}},
			{ID: "report", Type: "plugin", Name: "reporter", DependsOn: []string{"analyze"}},
		},
	}

	err := ValidateInlineWorkflow(config)
	if err != nil {
		t.Errorf("expected no error for valid complex DAG, got: %v", err)
	}
}

// TestValidateInlineWorkflow_EmptyNodeID tests validation with empty node ID.
func TestValidateInlineWorkflow_EmptyNodeID(t *testing.T) {
	config := &InlineWorkflow{
		Nodes: []*WorkflowNode{
			{ID: "", Type: "agent", Name: "test"},
		},
	}

	err := ValidateInlineWorkflow(config)
	if err == nil {
		t.Error("expected error for empty node ID, got nil")
	}
}

// TestValidateInlineWorkflow_EmptyNodeName tests validation with empty node name.
func TestValidateInlineWorkflow_EmptyNodeName(t *testing.T) {
	config := &InlineWorkflow{
		Nodes: []*WorkflowNode{
			{ID: "node1", Type: "agent", Name: ""},
		},
	}

	err := ValidateInlineWorkflow(config)
	if err == nil {
		t.Error("expected error for empty node name, got nil")
	}
}

// TestValidateInlineWorkflow_ValidEdges tests validation with explicit edges.
func TestValidateInlineWorkflow_ValidEdges(t *testing.T) {
	config := &InlineWorkflow{
		Nodes: []*WorkflowNode{
			{ID: "node1", Type: "agent", Name: "agent1"},
			{ID: "node2", Type: "tool", Name: "tool1"},
		},
		Edges: []*WorkflowEdge{
			{From: "node1", To: "node2"},
		},
	}

	err := ValidateInlineWorkflow(config)
	if err != nil {
		t.Errorf("expected no error for valid edges, got: %v", err)
	}
}

// TestValidateInlineWorkflow_InvalidEdge tests validation with invalid edges.
func TestValidateInlineWorkflow_InvalidEdge(t *testing.T) {
	tests := []struct {
		name  string
		edges []*WorkflowEdge
	}{
		{
			name: "empty from",
			edges: []*WorkflowEdge{
				{From: "", To: "node2"},
			},
		},
		{
			name: "empty to",
			edges: []*WorkflowEdge{
				{From: "node1", To: ""},
			},
		},
		{
			name: "non-existent from",
			edges: []*WorkflowEdge{
				{From: "non_existent", To: "node2"},
			},
		},
		{
			name: "non-existent to",
			edges: []*WorkflowEdge{
				{From: "node1", To: "non_existent"},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := &InlineWorkflow{
				Nodes: []*WorkflowNode{
					{ID: "node1", Type: "agent", Name: "agent1"},
					{ID: "node2", Type: "tool", Name: "tool1"},
				},
				Edges: tt.edges,
			}

			err := ValidateInlineWorkflow(config)
			if err == nil {
				t.Errorf("expected error for %s, got nil", tt.name)
			}
		})
	}
}
