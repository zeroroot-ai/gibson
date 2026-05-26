package transformers

import (
	"testing"

	"github.com/zeroroot-ai/gibson/internal/prompt"
)

func TestNewScopeNarrower(t *testing.T) {
	narrower := NewScopeNarrower()

	if narrower == nil {
		t.Fatal("NewScopeNarrower() returned nil")
	}

	if len(narrower.AllowedPositions) != 0 {
		t.Error("Expected empty AllowedPositions by default")
	}

	if len(narrower.ExcludeIDs) != 0 {
		t.Error("Expected empty ExcludeIDs by default")
	}

	if len(narrower.KeywordFilter) != 0 {
		t.Error("Expected empty KeywordFilter by default")
	}
}

func TestScopeNarrower_Name(t *testing.T) {
	narrower := NewScopeNarrower()

	if narrower.Name() != "ScopeNarrower" {
		t.Errorf("Expected name 'ScopeNarrower', got '%s'", narrower.Name())
	}
}

func TestScopeNarrower_Transform_NoFilters(t *testing.T) {
	narrower := NewScopeNarrower()

	ctx := &prompt.RelayContext{
		SourceAgent: "parent",
		TargetAgent: "child",
		Task:        "test",
	}

	prompts := []prompt.Prompt{
		{ID: "test1", Position: prompt.PositionSystem, Content: "content1"},
		{ID: "test2", Position: prompt.PositionUser, Content: "content2"},
		{ID: "test3", Position: prompt.PositionContext, Content: "content3"},
	}

	result, err := narrower.Transform(ctx, prompts)
	if err != nil {
		t.Fatalf("Transform() failed: %v", err)
	}

	// With no filters, all prompts should pass through
	if len(result) != 3 {
		t.Errorf("Expected 3 prompts, got %d", len(result))
	}
}

func TestScopeNarrower_Transform_PositionFilter(t *testing.T) {
	narrower := NewScopeNarrower()
	narrower.AllowedPositions = []prompt.Position{
		prompt.PositionSystem,
		prompt.PositionUser,
	}

	ctx := &prompt.RelayContext{
		SourceAgent: "parent",
		TargetAgent: "child",
		Task:        "test",
	}

	prompts := []prompt.Prompt{
		{ID: "test1", Position: prompt.PositionSystem, Content: "content1"},
		{ID: "test2", Position: prompt.PositionUser, Content: "content2"},
		{ID: "test3", Position: prompt.PositionContext, Content: "content3"},
		{ID: "test4", Position: prompt.PositionTools, Content: "content4"},
	}

	result, err := narrower.Transform(ctx, prompts)
	if err != nil {
		t.Fatalf("Transform() failed: %v", err)
	}

	// Should only include system and user positions
	if len(result) != 2 {
		t.Errorf("Expected 2 prompts, got %d", len(result))
	}

	// Verify correct prompts were kept
	if result[0].ID != "test1" || result[1].ID != "test2" {
		t.Errorf("Wrong prompts filtered. Got IDs: %s, %s", result[0].ID, result[1].ID)
	}
}

func TestScopeNarrower_Transform_IDExclusion(t *testing.T) {
	narrower := NewScopeNarrower()
	narrower.ExcludeIDs = []string{"test2", "test4"}

	ctx := &prompt.RelayContext{
		SourceAgent: "parent",
		TargetAgent: "child",
		Task:        "test",
	}

	prompts := []prompt.Prompt{
		{ID: "test1", Position: prompt.PositionSystem, Content: "content1"},
		{ID: "test2", Position: prompt.PositionUser, Content: "content2"},
		{ID: "test3", Position: prompt.PositionContext, Content: "content3"},
		{ID: "test4", Position: prompt.PositionTools, Content: "content4"},
	}

	result, err := narrower.Transform(ctx, prompts)
	if err != nil {
		t.Fatalf("Transform() failed: %v", err)
	}

	// Should exclude test2 and test4
	if len(result) != 2 {
		t.Errorf("Expected 2 prompts, got %d", len(result))
	}

	// Verify correct prompts were kept
	if result[0].ID != "test1" || result[1].ID != "test3" {
		t.Errorf("Wrong prompts filtered. Got IDs: %s, %s", result[0].ID, result[1].ID)
	}
}

func TestScopeNarrower_Transform_KeywordFilter(t *testing.T) {
	narrower := NewScopeNarrower()
	narrower.KeywordFilter = []string{"security", "authentication"}

	ctx := &prompt.RelayContext{
		SourceAgent: "parent",
		TargetAgent: "child",
		Task:        "test",
	}

	prompts := []prompt.Prompt{
		{ID: "test1", Position: prompt.PositionSystem, Content: "Handle security protocols"},
		{ID: "test2", Position: prompt.PositionUser, Content: "Process data"},
		{ID: "test3", Position: prompt.PositionContext, Content: "Implement authentication"},
		{ID: "test4", Position: prompt.PositionTools, Content: "Log events"},
	}

	result, err := narrower.Transform(ctx, prompts)
	if err != nil {
		t.Fatalf("Transform() failed: %v", err)
	}

	// Should only include prompts with security or authentication keywords
	if len(result) != 2 {
		t.Errorf("Expected 2 prompts, got %d", len(result))
	}

	// Verify correct prompts were kept
	if result[0].ID != "test1" || result[1].ID != "test3" {
		t.Errorf("Wrong prompts filtered. Got IDs: %s, %s", result[0].ID, result[1].ID)
	}
}

func TestScopeNarrower_Transform_KeywordFilter_CaseInsensitive(t *testing.T) {
	narrower := NewScopeNarrower()
	narrower.KeywordFilter = []string{"SECURITY"}

	ctx := &prompt.RelayContext{
		SourceAgent: "parent",
		TargetAgent: "child",
		Task:        "test",
	}

	prompts := []prompt.Prompt{
		{ID: "test1", Position: prompt.PositionSystem, Content: "Handle security protocols"},
		{ID: "test2", Position: prompt.PositionUser, Content: "Process data"},
	}

	result, err := narrower.Transform(ctx, prompts)
	if err != nil {
		t.Fatalf("Transform() failed: %v", err)
	}

	// Should match case-insensitively
	if len(result) != 1 {
		t.Errorf("Expected 1 prompt, got %d", len(result))
	}

	if result[0].ID != "test1" {
		t.Errorf("Wrong prompt filtered. Got ID: %s", result[0].ID)
	}
}

func TestScopeNarrower_Transform_CombinedFilters(t *testing.T) {
	narrower := NewScopeNarrower()
	narrower.AllowedPositions = []prompt.Position{
		prompt.PositionSystem,
		prompt.PositionUser,
		prompt.PositionContext,
	}
	narrower.ExcludeIDs = []string{"test2"}
	narrower.KeywordFilter = []string{"security"}

	ctx := &prompt.RelayContext{
		SourceAgent: "parent",
		TargetAgent: "child",
		Task:        "test",
	}

	prompts := []prompt.Prompt{
		{ID: "test1", Position: prompt.PositionSystem, Content: "Handle security"},   // Pass all
		{ID: "test2", Position: prompt.PositionUser, Content: "Security check"},      // Excluded by ID
		{ID: "test3", Position: prompt.PositionContext, Content: "Process data"},     // Fail keyword
		{ID: "test4", Position: prompt.PositionTools, Content: "Security protocols"}, // Fail position
	}

	result, err := narrower.Transform(ctx, prompts)
	if err != nil {
		t.Fatalf("Transform() failed: %v", err)
	}

	// Only test1 should pass all filters
	if len(result) != 1 {
		t.Errorf("Expected 1 prompt, got %d", len(result))
	}

	if len(result) > 0 && result[0].ID != "test1" {
		t.Errorf("Wrong prompt filtered. Got ID: %s", result[0].ID)
	}
}

func TestScopeNarrower_Transform_EmptyResult(t *testing.T) {
	narrower := NewScopeNarrower()
	narrower.KeywordFilter = []string{"nonexistent"}

	ctx := &prompt.RelayContext{
		SourceAgent: "parent",
		TargetAgent: "child",
		Task:        "test",
	}

	prompts := []prompt.Prompt{
		{ID: "test1", Position: prompt.PositionSystem, Content: "content1"},
		{ID: "test2", Position: prompt.PositionUser, Content: "content2"},
	}

	result, err := narrower.Transform(ctx, prompts)
	if err != nil {
		t.Fatalf("Transform() failed: %v", err)
	}

	// No prompts should match
	if len(result) != 0 {
		t.Errorf("Expected 0 prompts, got %d", len(result))
	}
}

func TestScopeNarrower_Transform_EmptyInput(t *testing.T) {
	narrower := NewScopeNarrower()
	narrower.AllowedPositions = []prompt.Position{prompt.PositionSystem}

	ctx := &prompt.RelayContext{
		SourceAgent: "parent",
		TargetAgent: "child",
		Task:        "test",
	}

	result, err := narrower.Transform(ctx, []prompt.Prompt{})
	if err != nil {
		t.Fatalf("Transform() failed: %v", err)
	}

	// Empty input should produce empty output
	if len(result) != 0 {
		t.Errorf("Expected 0 prompts, got %d", len(result))
	}
}

func TestScopeNarrower_Transform_Immutability(t *testing.T) {
	narrower := NewScopeNarrower()
	narrower.KeywordFilter = []string{"keep"}

	ctx := &prompt.RelayContext{
		SourceAgent: "parent",
		TargetAgent: "child",
		Task:        "test",
	}

	originalPrompts := []prompt.Prompt{
		{ID: "test1", Position: prompt.PositionSystem, Content: "keep this", Priority: 5},
		{ID: "test2", Position: prompt.PositionUser, Content: "remove this", Priority: 3},
	}

	result, err := narrower.Transform(ctx, originalPrompts)
	if err != nil {
		t.Fatalf("Transform() failed: %v", err)
	}

	// Modify result
	if len(result) > 0 {
		result[0].Content = "modified"
		result[0].Priority = 999
	}

	// Original should be unchanged
	if originalPrompts[0].Content != "keep this" {
		t.Errorf("Original prompt content was modified!")
	}

	if originalPrompts[0].Priority != 5 {
		t.Errorf("Original prompt priority was modified!")
	}
}

func TestScopeNarrower_Transform_MultipleKeywords(t *testing.T) {
	narrower := NewScopeNarrower()
	narrower.KeywordFilter = []string{"security", "auth", "encrypt"}

	ctx := &prompt.RelayContext{
		SourceAgent: "parent",
		TargetAgent: "child",
		Task:        "test",
	}

	prompts := []prompt.Prompt{
		{ID: "test1", Position: prompt.PositionSystem, Content: "Handle security"},
		{ID: "test2", Position: prompt.PositionUser, Content: "Process auth"},
		{ID: "test3", Position: prompt.PositionContext, Content: "Data logging"},
		{ID: "test4", Position: prompt.PositionTools, Content: "Encrypt data"},
	}

	result, err := narrower.Transform(ctx, prompts)
	if err != nil {
		t.Fatalf("Transform() failed: %v", err)
	}

	// Should include all prompts with any of the keywords
	if len(result) != 3 {
		t.Errorf("Expected 3 prompts, got %d", len(result))
	}
}

func TestScopeNarrower_Transform_AllPositions(t *testing.T) {
	narrower := NewScopeNarrower()
	narrower.AllowedPositions = []prompt.Position{
		prompt.PositionSystemPrefix,
		prompt.PositionSystem,
		prompt.PositionSystemSuffix,
		prompt.PositionContext,
		prompt.PositionTools,
		prompt.PositionPlugins,
		prompt.PositionAgents,
		prompt.PositionConstraints,
		prompt.PositionExamples,
		prompt.PositionUserPrefix,
		prompt.PositionUser,
		prompt.PositionUserSuffix,
	}

	ctx := &prompt.RelayContext{
		SourceAgent: "parent",
		TargetAgent: "child",
		Task:        "test",
	}

	prompts := []prompt.Prompt{
		{ID: "test1", Position: prompt.PositionSystem, Content: "content1"},
		{ID: "test2", Position: prompt.PositionUser, Content: "content2"},
		{ID: "test3", Position: prompt.PositionContext, Content: "content3"},
	}

	result, err := narrower.Transform(ctx, prompts)
	if err != nil {
		t.Fatalf("Transform() failed: %v", err)
	}

	// All prompts should pass
	if len(result) != 3 {
		t.Errorf("Expected 3 prompts, got %d", len(result))
	}
}
