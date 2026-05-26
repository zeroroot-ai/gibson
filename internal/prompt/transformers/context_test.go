package transformers

import (
	"strings"
	"testing"

	"github.com/zeroroot-ai/gibson/internal/prompt"
)

func TestNewContextInjector(t *testing.T) {
	injector := NewContextInjector()

	if injector == nil {
		t.Fatal("NewContextInjector() returned nil")
	}

	if !injector.IncludeMemory {
		t.Error("Expected IncludeMemory to be true by default")
	}

	if !injector.IncludeConstraints {
		t.Error("Expected IncludeConstraints to be true by default")
	}
}

func TestContextInjector_Name(t *testing.T) {
	injector := NewContextInjector()

	if injector.Name() != "ContextInjector" {
		t.Errorf("Expected name 'ContextInjector', got '%s'", injector.Name())
	}
}

func TestContextInjector_Transform_BasicContext(t *testing.T) {
	injector := NewContextInjector()

	ctx := &prompt.RelayContext{
		SourceAgent: "ParentAgent",
		TargetAgent: "ChildAgent",
		Task:        "Process data",
		Constraints: []string{"Use safe mode", "Log all actions"},
	}

	prompts := []prompt.Prompt{
		{
			ID:       "original1",
			Position: prompt.PositionSystem,
			Content:  "Original prompt",
		},
	}

	result, err := injector.Transform(ctx, prompts)
	if err != nil {
		t.Fatalf("Transform() failed: %v", err)
	}

	// Should have added one context prompt
	if len(result) != 2 {
		t.Fatalf("Expected 2 prompts, got %d", len(result))
	}

	// First prompt should be the context
	contextPrompt := result[0]

	if contextPrompt.Position != prompt.PositionSystemPrefix {
		t.Errorf("Expected position system_prefix, got %s", contextPrompt.Position)
	}

	if contextPrompt.Priority != 1 {
		t.Errorf("Expected priority 1, got %d", contextPrompt.Priority)
	}

	// Check content contains expected information
	if !strings.Contains(contextPrompt.Content, "ParentAgent") {
		t.Errorf("Context should contain source agent name, got: %s", contextPrompt.Content)
	}

	if !strings.Contains(contextPrompt.Content, "Process data") {
		t.Errorf("Context should contain task description, got: %s", contextPrompt.Content)
	}

	if !strings.Contains(contextPrompt.Content, "Use safe mode") {
		t.Errorf("Context should contain constraints, got: %s", contextPrompt.Content)
	}

	// Check metadata
	if contextPrompt.Metadata["relay"] != true {
		t.Error("Expected relay metadata to be true")
	}

	if contextPrompt.Metadata["source_agent"] != "ParentAgent" {
		t.Errorf("Expected source_agent metadata, got: %v", contextPrompt.Metadata["source_agent"])
	}

	// Original prompt should be second
	if result[1].ID != "original1" {
		t.Errorf("Expected original prompt to be preserved, got ID: %s", result[1].ID)
	}
}

func TestContextInjector_Transform_WithMemory(t *testing.T) {
	injector := NewContextInjector()
	injector.IncludeMemory = true

	ctx := &prompt.RelayContext{
		SourceAgent: "ParentAgent",
		TargetAgent: "ChildAgent",
		Task:        "Process data",
		Memory: map[string]any{
			"key1": "value1",
			"key2": 42,
		},
	}

	prompts := []prompt.Prompt{
		{ID: "test1", Position: prompt.PositionSystem, Content: "content"},
	}

	result, err := injector.Transform(ctx, prompts)
	if err != nil {
		t.Fatalf("Transform() failed: %v", err)
	}

	contextPrompt := result[0]

	if !strings.Contains(contextPrompt.Content, "Shared Context") {
		t.Errorf("Expected memory reference in content, got: %s", contextPrompt.Content)
	}

	if !strings.Contains(contextPrompt.Content, "2 items") {
		t.Errorf("Expected item count in content, got: %s", contextPrompt.Content)
	}
}

func TestContextInjector_Transform_WithoutMemory(t *testing.T) {
	injector := NewContextInjector()
	injector.IncludeMemory = false

	ctx := &prompt.RelayContext{
		SourceAgent: "ParentAgent",
		TargetAgent: "ChildAgent",
		Task:        "Process data",
		Memory: map[string]any{
			"key1": "value1",
		},
	}

	prompts := []prompt.Prompt{
		{ID: "test1", Position: prompt.PositionSystem, Content: "content"},
	}

	result, err := injector.Transform(ctx, prompts)
	if err != nil {
		t.Fatalf("Transform() failed: %v", err)
	}

	contextPrompt := result[0]

	if strings.Contains(contextPrompt.Content, "Shared Context") {
		t.Errorf("Should not include memory when IncludeMemory=false, got: %s", contextPrompt.Content)
	}
}

func TestContextInjector_Transform_WithoutConstraints(t *testing.T) {
	injector := NewContextInjector()
	injector.IncludeConstraints = false

	ctx := &prompt.RelayContext{
		SourceAgent: "ParentAgent",
		TargetAgent: "ChildAgent",
		Task:        "Process data",
		Constraints: []string{"constraint1", "constraint2"},
	}

	prompts := []prompt.Prompt{
		{ID: "test1", Position: prompt.PositionSystem, Content: "content"},
	}

	result, err := injector.Transform(ctx, prompts)
	if err != nil {
		t.Fatalf("Transform() failed: %v", err)
	}

	contextPrompt := result[0]

	if strings.Contains(contextPrompt.Content, "Constraints:") {
		t.Errorf("Should not include constraints when IncludeConstraints=false, got: %s", contextPrompt.Content)
	}
}

func TestContextInjector_Transform_CustomTemplate(t *testing.T) {
	injector := NewContextInjector()
	injector.ContextTemplate = "From: {SourceAgent}\nTo: {TargetAgent}\nTask: {Task}\nLimits: {Constraints}"

	ctx := &prompt.RelayContext{
		SourceAgent: "ParentAgent",
		TargetAgent: "ChildAgent",
		Task:        "Process data",
		Constraints: []string{"constraint1", "constraint2"},
	}

	prompts := []prompt.Prompt{
		{ID: "test1", Position: prompt.PositionSystem, Content: "content"},
	}

	result, err := injector.Transform(ctx, prompts)
	if err != nil {
		t.Fatalf("Transform() failed: %v", err)
	}

	contextPrompt := result[0]

	if !strings.Contains(contextPrompt.Content, "From: ParentAgent") {
		t.Errorf("Custom template not applied correctly, got: %s", contextPrompt.Content)
	}

	if !strings.Contains(contextPrompt.Content, "To: ChildAgent") {
		t.Errorf("Custom template not applied correctly, got: %s", contextPrompt.Content)
	}

	if !strings.Contains(contextPrompt.Content, "Task: Process data") {
		t.Errorf("Custom template not applied correctly, got: %s", contextPrompt.Content)
	}

	if !strings.Contains(contextPrompt.Content, "constraint1, constraint2") {
		t.Errorf("Custom template constraints not applied correctly, got: %s", contextPrompt.Content)
	}
}

func TestContextInjector_Transform_EmptyPrompts(t *testing.T) {
	injector := NewContextInjector()

	ctx := &prompt.RelayContext{
		SourceAgent: "ParentAgent",
		TargetAgent: "ChildAgent",
		Task:        "Process data",
	}

	result, err := injector.Transform(ctx, []prompt.Prompt{})
	if err != nil {
		t.Fatalf("Transform() failed: %v", err)
	}

	// Should still add context prompt even with no original prompts
	if len(result) != 1 {
		t.Errorf("Expected 1 prompt (context only), got %d", len(result))
	}

	if result[0].Position != prompt.PositionSystemPrefix {
		t.Errorf("Expected system_prefix position, got %s", result[0].Position)
	}
}

func TestContextInjector_Transform_MultiplePrompts(t *testing.T) {
	injector := NewContextInjector()

	ctx := &prompt.RelayContext{
		SourceAgent: "ParentAgent",
		TargetAgent: "ChildAgent",
		Task:        "Process data",
	}

	prompts := []prompt.Prompt{
		{ID: "test1", Position: prompt.PositionSystem, Content: "content1"},
		{ID: "test2", Position: prompt.PositionUser, Content: "content2"},
		{ID: "test3", Position: prompt.PositionContext, Content: "content3"},
	}

	result, err := injector.Transform(ctx, prompts)
	if err != nil {
		t.Fatalf("Transform() failed: %v", err)
	}

	// Should have context + 3 original prompts
	if len(result) != 4 {
		t.Errorf("Expected 4 prompts, got %d", len(result))
	}

	// Context should be first
	if result[0].Position != prompt.PositionSystemPrefix {
		t.Errorf("Expected first prompt to be context at system_prefix")
	}

	// Original prompts should follow in order
	if result[1].ID != "test1" || result[2].ID != "test2" || result[3].ID != "test3" {
		t.Error("Original prompts not preserved in correct order")
	}
}

func TestContextInjector_Transform_Immutability(t *testing.T) {
	injector := NewContextInjector()

	originalPrompts := []prompt.Prompt{
		{
			ID:       "test1",
			Position: prompt.PositionSystem,
			Content:  "original content",
			Priority: 5,
		},
	}

	ctx := &prompt.RelayContext{
		SourceAgent: "ParentAgent",
		TargetAgent: "ChildAgent",
		Task:        "Process data",
	}

	result, err := injector.Transform(ctx, originalPrompts)
	if err != nil {
		t.Fatalf("Transform() failed: %v", err)
	}

	// Modify result
	result[0].Content = "modified"
	result[1].Content = "also modified"

	// Original should be unchanged
	if originalPrompts[0].Content != "original content" {
		t.Errorf("Original prompts were modified!")
	}

	if originalPrompts[0].Priority != 5 {
		t.Errorf("Original prompt priority was modified!")
	}
}

func TestContextInjector_Transform_NoConstraints(t *testing.T) {
	injector := NewContextInjector()

	ctx := &prompt.RelayContext{
		SourceAgent: "ParentAgent",
		TargetAgent: "ChildAgent",
		Task:        "Process data",
		Constraints: []string{}, // Empty constraints
	}

	prompts := []prompt.Prompt{
		{ID: "test1", Position: prompt.PositionSystem, Content: "content"},
	}

	result, err := injector.Transform(ctx, prompts)
	if err != nil {
		t.Fatalf("Transform() failed: %v", err)
	}

	contextPrompt := result[0]

	// Should still work, just without constraints section
	if !strings.Contains(contextPrompt.Content, "ParentAgent") {
		t.Errorf("Context should still contain basic info, got: %s", contextPrompt.Content)
	}
}
