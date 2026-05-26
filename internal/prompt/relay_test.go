package prompt

import (
	"testing"

	"github.com/zeroroot-ai/gibson/internal/types"
)

// mockTransformer is a simple transformer for testing.
type mockTransformer struct {
	name      string
	transform func(*RelayContext, []Prompt) ([]Prompt, error)
}

func (m *mockTransformer) Name() string {
	return m.name
}

func (m *mockTransformer) Transform(ctx *RelayContext, prompts []Prompt) ([]Prompt, error) {
	return m.transform(ctx, prompts)
}

func TestNewPromptRelay(t *testing.T) {
	relay := NewPromptRelay()
	if relay == nil {
		t.Fatal("NewPromptRelay() returned nil")
	}

	if _, ok := relay.(*DefaultPromptRelay); !ok {
		t.Errorf("NewPromptRelay() returned wrong type: %T", relay)
	}
}

func TestDefaultPromptRelay_Relay_EmptyTransformers(t *testing.T) {
	relay := NewPromptRelay()
	ctx := &RelayContext{
		SourceAgent: "parent",
		TargetAgent: "child",
		Task:        "test task",
		Prompts: []Prompt{
			{
				ID:       "test1",
				Position: PositionSystem,
				Content:  "test content",
			},
		},
	}

	result, err := relay.Relay(ctx)
	if err != nil {
		t.Fatalf("Relay() with no transformers failed: %v", err)
	}

	if len(result) != 1 {
		t.Errorf("Expected 1 prompt, got %d", len(result))
	}

	if result[0].ID != "test1" {
		t.Errorf("Expected prompt ID 'test1', got '%s'", result[0].ID)
	}
}

func TestDefaultPromptRelay_Relay_SingleTransformer(t *testing.T) {
	relay := NewPromptRelay()

	// Create a transformer that adds a priority field
	transformer := &mockTransformer{
		name: "PriorityAdder",
		transform: func(ctx *RelayContext, prompts []Prompt) ([]Prompt, error) {
			result := make([]Prompt, len(prompts))
			for i, p := range prompts {
				p.Priority = 10
				result[i] = p
			}
			return result, nil
		},
	}

	ctx := &RelayContext{
		SourceAgent: "parent",
		TargetAgent: "child",
		Task:        "test task",
		Prompts: []Prompt{
			{
				ID:       "test1",
				Position: PositionSystem,
				Content:  "test content",
				Priority: 0,
			},
		},
	}

	result, err := relay.Relay(ctx, transformer)
	if err != nil {
		t.Fatalf("Relay() failed: %v", err)
	}

	if len(result) != 1 {
		t.Errorf("Expected 1 prompt, got %d", len(result))
	}

	if result[0].Priority != 10 {
		t.Errorf("Expected priority 10, got %d", result[0].Priority)
	}
}

func TestDefaultPromptRelay_Relay_MultipleTransformers(t *testing.T) {
	relay := NewPromptRelay()

	// First transformer adds priority
	transformer1 := &mockTransformer{
		name: "PriorityAdder",
		transform: func(ctx *RelayContext, prompts []Prompt) ([]Prompt, error) {
			result := make([]Prompt, len(prompts))
			for i, p := range prompts {
				p.Priority = 10
				result[i] = p
			}
			return result, nil
		},
	}

	// Second transformer adds a prompt
	transformer2 := &mockTransformer{
		name: "PromptAdder",
		transform: func(ctx *RelayContext, prompts []Prompt) ([]Prompt, error) {
			newPrompt := Prompt{
				ID:       "added",
				Position: PositionSystemPrefix,
				Content:  "added content",
				Priority: 20,
			}
			return append([]Prompt{newPrompt}, prompts...), nil
		},
	}

	ctx := &RelayContext{
		SourceAgent: "parent",
		TargetAgent: "child",
		Task:        "test task",
		Prompts: []Prompt{
			{
				ID:       "test1",
				Position: PositionSystem,
				Content:  "test content",
				Priority: 0,
			},
		},
	}

	result, err := relay.Relay(ctx, transformer1, transformer2)
	if err != nil {
		t.Fatalf("Relay() failed: %v", err)
	}

	if len(result) != 2 {
		t.Errorf("Expected 2 prompts, got %d", len(result))
	}

	// Check that transformers were applied in order
	if result[0].ID != "added" {
		t.Errorf("Expected first prompt ID 'added', got '%s'", result[0].ID)
	}

	if result[0].Priority != 20 {
		t.Errorf("Expected first prompt priority 20, got %d", result[0].Priority)
	}

	if result[1].Priority != 10 {
		t.Errorf("Expected second prompt priority 10, got %d", result[1].Priority)
	}
}

func TestDefaultPromptRelay_Relay_Immutability(t *testing.T) {
	relay := NewPromptRelay()

	// Transformer that modifies prompts
	transformer := &mockTransformer{
		name: "Modifier",
		transform: func(ctx *RelayContext, prompts []Prompt) ([]Prompt, error) {
			result := make([]Prompt, len(prompts))
			for i, p := range prompts {
				p.Content = "modified"
				p.Priority = 999
				result[i] = p
			}
			return result, nil
		},
	}

	originalPrompt := Prompt{
		ID:       "test1",
		Position: PositionSystem,
		Content:  "original content",
		Priority: 5,
	}

	ctx := &RelayContext{
		SourceAgent: "parent",
		TargetAgent: "child",
		Task:        "test task",
		Prompts:     []Prompt{originalPrompt},
	}

	result, err := relay.Relay(ctx, transformer)
	if err != nil {
		t.Fatalf("Relay() failed: %v", err)
	}

	// Check that original prompt in context was not modified
	if ctx.Prompts[0].Content != "original content" {
		t.Errorf("Original prompt was modified! Content: %s", ctx.Prompts[0].Content)
	}

	if ctx.Prompts[0].Priority != 5 {
		t.Errorf("Original prompt was modified! Priority: %d", ctx.Prompts[0].Priority)
	}

	// Check that result has modified values
	if result[0].Content != "modified" {
		t.Errorf("Expected modified content, got: %s", result[0].Content)
	}

	if result[0].Priority != 999 {
		t.Errorf("Expected priority 999, got: %d", result[0].Priority)
	}
}

func TestDefaultPromptRelay_Relay_TransformerError(t *testing.T) {
	relay := NewPromptRelay()

	// Transformer that returns an error
	transformer := &mockTransformer{
		name: "ErrorTransformer",
		transform: func(ctx *RelayContext, prompts []Prompt) ([]Prompt, error) {
			return nil, NewInvalidPromptError("transformer error")
		},
	}

	ctx := &RelayContext{
		SourceAgent: "parent",
		TargetAgent: "child",
		Task:        "test task",
		Prompts: []Prompt{
			{
				ID:       "test1",
				Position: PositionSystem,
				Content:  "test content",
			},
		},
	}

	_, err := relay.Relay(ctx, transformer)
	if err == nil {
		t.Fatal("Expected error from transformer, got nil")
	}

	// Check that error is wrapped with relay context
	if !containsErrorCode(err, ErrCodeRelayFailed) {
		t.Errorf("Expected ErrCodeRelayFailed in error chain, got: %v", err)
	}
}

func TestDeepCopyPrompts(t *testing.T) {
	original := []Prompt{
		{
			ID:       "test1",
			Position: PositionSystem,
			Content:  "content1",
			Priority: 5,
			Metadata: map[string]any{
				"key1": "value1",
				"key2": 42,
			},
			Variables: []VariableDef{
				{
					Name:     "var1",
					Required: true,
					Default:  "default",
				},
			},
		},
	}

	copied, err := deepCopyPrompts(original)
	if err != nil {
		t.Fatalf("deepCopyPrompts() failed: %v", err)
	}

	// Modify the copy
	copied[0].Content = "modified"
	copied[0].Priority = 999
	copied[0].Metadata["key1"] = "modified"
	copied[0].Variables[0].Name = "modified"

	// Check original was not modified
	if original[0].Content != "content1" {
		t.Errorf("Original content was modified")
	}

	if original[0].Priority != 5 {
		t.Errorf("Original priority was modified")
	}

	if original[0].Metadata["key1"] != "value1" {
		t.Errorf("Original metadata was modified")
	}

	if original[0].Variables[0].Name != "var1" {
		t.Errorf("Original variables were modified")
	}
}

func TestRelayContext_ComplexData(t *testing.T) {
	relay := NewPromptRelay()

	ctx := &RelayContext{
		SourceAgent: "parent",
		TargetAgent: "child",
		Task:        "complex task",
		Memory: map[string]any{
			"key1": "value1",
			"key2": 42,
			"nested": map[string]any{
				"inner": "value",
			},
		},
		Constraints: []string{
			"constraint1",
			"constraint2",
		},
		Prompts: []Prompt{
			{
				ID:       "test1",
				Position: PositionSystem,
				Content:  "test content",
			},
		},
	}

	// Transformer that accesses context data
	transformer := &mockTransformer{
		name: "ContextReader",
		transform: func(ctx *RelayContext, prompts []Prompt) ([]Prompt, error) {
			if ctx.SourceAgent != "parent" {
				t.Errorf("Expected SourceAgent 'parent', got '%s'", ctx.SourceAgent)
			}
			if ctx.TargetAgent != "child" {
				t.Errorf("Expected TargetAgent 'child', got '%s'", ctx.TargetAgent)
			}
			if len(ctx.Constraints) != 2 {
				t.Errorf("Expected 2 constraints, got %d", len(ctx.Constraints))
			}
			if len(ctx.Memory) != 3 {
				t.Errorf("Expected 3 memory entries, got %d", len(ctx.Memory))
			}
			return prompts, nil
		},
	}

	_, err := relay.Relay(ctx, transformer)
	if err != nil {
		t.Fatalf("Relay() failed: %v", err)
	}
}

// Helper function to check if an error contains a specific error code
func containsErrorCode(err error, code types.ErrorCode) bool {
	if err == nil {
		return false
	}
	// Simple string contains check for error code
	return containsStr(err.Error(), string(code))
}

// Helper function to check if a string contains a substring
func containsStr(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(substr) == 0 ||
		(len(s) > 0 && len(substr) > 0 && findSubstring(s, substr)))
}

func findSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
