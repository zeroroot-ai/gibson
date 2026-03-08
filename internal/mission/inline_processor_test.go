package mission

import (
	"context"
	"errors"
	"testing"

	"github.com/zero-day-ai/gibson/internal/types"
)

// mockTargetCreator is a mock implementation of TargetCreator for testing.
type mockTargetCreator struct {
	createFunc  func(ctx context.Context, target *types.Target) error
	lastCreated *types.Target
}

func (m *mockTargetCreator) Create(ctx context.Context, target *types.Target) error {
	m.lastCreated = target
	if m.createFunc != nil {
		return m.createFunc(ctx, target)
	}
	return nil
}

// mockWorkflowCreator is a mock implementation of WorkflowCreator for testing.
type mockWorkflowCreator struct {
	createFunc  func(ctx context.Context, def *MissionDefinition) error
	lastCreated *MissionDefinition
}

func (m *mockWorkflowCreator) CreateDefinition(ctx context.Context, def *MissionDefinition) error {
	m.lastCreated = def
	if m.createFunc != nil {
		return m.createFunc(ctx, def)
	}
	return nil
}

func TestNewInlineConfigProcessor(t *testing.T) {
	targetCreator := &mockTargetCreator{}
	workflowCreator := &mockWorkflowCreator{}

	processor := NewInlineConfigProcessor(targetCreator, workflowCreator)

	if processor == nil {
		t.Fatal("expected non-nil processor")
	}
	if processor.targetCreator != targetCreator {
		t.Error("target creator not set correctly")
	}
	if processor.workflowCreator != workflowCreator {
		t.Error("workflow creator not set correctly")
	}
}

func TestProcessInlineTarget_Success(t *testing.T) {
	targetCreator := &mockTargetCreator{}
	workflowCreator := &mockWorkflowCreator{}
	processor := NewInlineConfigProcessor(targetCreator, workflowCreator)

	config := &InlineTarget{
		Seeds: []*TargetSeed{
			{Value: "example.com", Type: "domain", Scope: "in_scope"},
		},
		Profile: "balanced",
		Depth:   3,
	}

	targetID, err := processor.ProcessInlineTarget(context.Background(), config)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Check target ID format
	if targetID == "" {
		t.Error("expected non-empty target ID")
	}
	if !isValidInlineTargetID(string(targetID)) {
		t.Errorf("target ID should have inline-target- prefix: %s", targetID)
	}

	// Check target was created
	if targetCreator.lastCreated == nil {
		t.Fatal("target was not created")
	}

	// Check target fields
	target := targetCreator.lastCreated
	if target.ID != targetID {
		t.Errorf("target ID mismatch: got %s, want %s", target.ID, targetID)
	}
	if target.Status != types.TargetStatusActive {
		t.Errorf("expected active status, got %s", target.Status)
	}

	// Check metadata
	if target.Config == nil {
		t.Fatal("target config is nil")
	}
	if source, ok := target.Config["source"].(string); !ok || source != "inline" {
		t.Error("expected source:inline in config")
	}
	if profile, ok := target.Config["profile"].(string); !ok || profile != "balanced" {
		t.Errorf("expected profile:balanced in config, got %v", target.Config["profile"])
	}
}

func TestProcessInlineTarget_ValidationError(t *testing.T) {
	targetCreator := &mockTargetCreator{}
	workflowCreator := &mockWorkflowCreator{}
	processor := NewInlineConfigProcessor(targetCreator, workflowCreator)

	// Empty config should fail validation
	config := &InlineTarget{
		Seeds:   []*TargetSeed{},
		Profile: "balanced",
		Depth:   3,
	}

	_, err := processor.ProcessInlineTarget(context.Background(), config)

	if err == nil {
		t.Error("expected validation error for empty seeds")
	}
}

func TestProcessInlineTarget_CreateError(t *testing.T) {
	createErr := errors.New("database error")
	targetCreator := &mockTargetCreator{
		createFunc: func(ctx context.Context, target *types.Target) error {
			return createErr
		},
	}
	workflowCreator := &mockWorkflowCreator{}
	processor := NewInlineConfigProcessor(targetCreator, workflowCreator)

	config := &InlineTarget{
		Seeds: []*TargetSeed{
			{Value: "example.com", Type: "domain", Scope: "in_scope"},
		},
		Profile: "balanced",
		Depth:   3,
	}

	_, err := processor.ProcessInlineTarget(context.Background(), config)

	if err == nil {
		t.Error("expected create error")
	}
	if !errors.Is(err, createErr) && !containsString(err.Error(), "database error") {
		t.Errorf("expected error to contain 'database error', got: %v", err)
	}
}

func TestProcessInlineWorkflow_Success(t *testing.T) {
	targetCreator := &mockTargetCreator{}
	workflowCreator := &mockWorkflowCreator{}
	processor := NewInlineConfigProcessor(targetCreator, workflowCreator)

	config := &InlineWorkflow{
		Name: "test-workflow",
		Nodes: []*WorkflowNode{
			{ID: "node1", Type: "agent", Name: "recon-agent"},
			{ID: "node2", Type: "tool", Name: "nmap", DependsOn: []string{"node1"}},
		},
	}

	workflowID, err := processor.ProcessInlineWorkflow(context.Background(), config)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Check workflow ID format
	if workflowID == "" {
		t.Error("expected non-empty workflow ID")
	}
	if !isValidInlineWorkflowID(string(workflowID)) {
		t.Errorf("workflow ID should have inline-workflow- prefix: %s", workflowID)
	}

	// Check workflow was created
	if workflowCreator.lastCreated == nil {
		t.Fatal("workflow was not created")
	}

	// Check workflow fields
	def := workflowCreator.lastCreated
	if def.ID != workflowID {
		t.Errorf("workflow ID mismatch: got %s, want %s", def.ID, workflowID)
	}
	if def.Name != "test-workflow" {
		t.Errorf("expected name 'test-workflow', got %s", def.Name)
	}

	// Check metadata
	if def.Metadata == nil {
		t.Fatal("workflow metadata is nil")
	}
	if source, ok := def.Metadata["source"].(string); !ok || source != "inline" {
		t.Error("expected source:inline in metadata")
	}
	if nodeCount, ok := def.Metadata["node_count"].(int); !ok || nodeCount != 2 {
		t.Errorf("expected node_count:2 in metadata, got %v", def.Metadata["node_count"])
	}
}

func TestProcessInlineWorkflow_ValidationError(t *testing.T) {
	targetCreator := &mockTargetCreator{}
	workflowCreator := &mockWorkflowCreator{}
	processor := NewInlineConfigProcessor(targetCreator, workflowCreator)

	// Empty nodes should fail validation
	config := &InlineWorkflow{
		Name:  "test-workflow",
		Nodes: []*WorkflowNode{},
	}

	_, err := processor.ProcessInlineWorkflow(context.Background(), config)

	if err == nil {
		t.Error("expected validation error for empty nodes")
	}
}

func TestProcessInlineWorkflow_CreateError(t *testing.T) {
	createErr := errors.New("storage error")
	targetCreator := &mockTargetCreator{}
	workflowCreator := &mockWorkflowCreator{
		createFunc: func(ctx context.Context, def *MissionDefinition) error {
			return createErr
		},
	}
	processor := NewInlineConfigProcessor(targetCreator, workflowCreator)

	config := &InlineWorkflow{
		Name: "test-workflow",
		Nodes: []*WorkflowNode{
			{ID: "node1", Type: "agent", Name: "recon-agent"},
		},
	}

	_, err := processor.ProcessInlineWorkflow(context.Background(), config)

	if err == nil {
		t.Error("expected create error")
	}
	if !containsString(err.Error(), "storage error") {
		t.Errorf("expected error to contain 'storage error', got: %v", err)
	}
}

func TestProcessInlineWorkflow_AutoGenerateName(t *testing.T) {
	targetCreator := &mockTargetCreator{}
	workflowCreator := &mockWorkflowCreator{}
	processor := NewInlineConfigProcessor(targetCreator, workflowCreator)

	// No name provided - should auto-generate
	config := &InlineWorkflow{
		Nodes: []*WorkflowNode{
			{ID: "node1", Type: "agent", Name: "recon-agent"},
		},
	}

	_, err := processor.ProcessInlineWorkflow(context.Background(), config)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if workflowCreator.lastCreated == nil {
		t.Fatal("workflow was not created")
	}

	// Check auto-generated name has inline-workflow prefix
	name := workflowCreator.lastCreated.Name
	if !containsString(name, "inline-workflow-") {
		t.Errorf("expected auto-generated name with inline-workflow- prefix, got: %s", name)
	}
}

func TestProcessInlineTarget_WithMetadata(t *testing.T) {
	targetCreator := &mockTargetCreator{}
	workflowCreator := &mockWorkflowCreator{}
	processor := NewInlineConfigProcessor(targetCreator, workflowCreator)

	config := &InlineTarget{
		Seeds: []*TargetSeed{
			{Value: "example.com", Type: "domain", Scope: "in_scope"},
		},
		Profile: "balanced",
		Depth:   3,
		Metadata: map[string]any{
			"project": "test-project",
			"owner":   "test-team",
		},
	}

	_, err := processor.ProcessInlineTarget(context.Background(), config)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	target := targetCreator.lastCreated
	if target.Config == nil {
		t.Fatal("target config is nil")
	}

	// Check that user metadata is merged
	if project, ok := target.Config["project"].(string); !ok || project != "test-project" {
		t.Errorf("expected project in config, got %v", target.Config["project"])
	}
	if owner, ok := target.Config["owner"].(string); !ok || owner != "test-team" {
		t.Errorf("expected owner in config, got %v", target.Config["owner"])
	}
}

func TestProcessInlineWorkflow_WithMetadata(t *testing.T) {
	targetCreator := &mockTargetCreator{}
	workflowCreator := &mockWorkflowCreator{}
	processor := NewInlineConfigProcessor(targetCreator, workflowCreator)

	config := &InlineWorkflow{
		Name: "test-workflow",
		Nodes: []*WorkflowNode{
			{ID: "node1", Type: "agent", Name: "recon-agent"},
		},
		Metadata: map[string]any{
			"version":  "2.0",
			"category": "recon",
		},
	}

	_, err := processor.ProcessInlineWorkflow(context.Background(), config)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	def := workflowCreator.lastCreated
	if def.Metadata == nil {
		t.Fatal("workflow metadata is nil")
	}

	// Check that user metadata is merged
	if version, ok := def.Metadata["version"].(string); !ok || version != "2.0" {
		t.Errorf("expected version in metadata, got %v", def.Metadata["version"])
	}
	if category, ok := def.Metadata["category"].(string); !ok || category != "recon" {
		t.Errorf("expected category in metadata, got %v", def.Metadata["category"])
	}
}

func TestProcessInlineWorkflow_WithEdges(t *testing.T) {
	targetCreator := &mockTargetCreator{}
	workflowCreator := &mockWorkflowCreator{}
	processor := NewInlineConfigProcessor(targetCreator, workflowCreator)

	config := &InlineWorkflow{
		Name: "test-workflow",
		Nodes: []*WorkflowNode{
			{ID: "node1", Type: "agent", Name: "recon-agent"},
			{ID: "node2", Type: "tool", Name: "nmap"},
		},
		Edges: []*WorkflowEdge{
			{From: "node1", To: "node2", Condition: "success"},
		},
	}

	_, err := processor.ProcessInlineWorkflow(context.Background(), config)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	def := workflowCreator.lastCreated
	if def.Metadata == nil {
		t.Fatal("workflow metadata is nil")
	}

	// Check that edges are stored in metadata
	edges, ok := def.Metadata["inline_edges"]
	if !ok {
		t.Error("expected inline_edges in metadata")
	}
	edgesList, ok := edges.([]map[string]string)
	if !ok || len(edgesList) != 1 {
		t.Errorf("expected 1 edge in metadata, got %v", edges)
	}
}

// Helper functions

func isValidInlineTargetID(id string) bool {
	return len(id) > 14 && id[:14] == "inline-target-"
}

func isValidInlineWorkflowID(id string) bool {
	return len(id) > 16 && id[:16] == "inline-workflow-"
}

func containsString(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
