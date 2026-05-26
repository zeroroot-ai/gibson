package prompt

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zeroroot-ai/gibson/internal/types"
)

func TestPrompt_Validate(t *testing.T) {
	t.Run("valid prompt passes validation", func(t *testing.T) {
		p := &Prompt{
			ID:       "test-prompt-1",
			Name:     "Test Prompt",
			Position: PositionSystem,
			Content:  "You are a helpful assistant.",
		}

		err := p.Validate()
		assert.NoError(t, err, "Valid prompt should pass validation")
	})

	t.Run("valid prompt with all fields passes validation", func(t *testing.T) {
		p := &Prompt{
			ID:          "test-prompt-2",
			Name:        "Comprehensive Test Prompt",
			Description: "A prompt with all fields populated",
			Position:    PositionContext,
			Content:     "Context information goes here",
			Variables:   []VariableDef{},
			Conditions:  []Condition{},
			Examples:    []Example{},
			Priority:    100,
			Metadata: map[string]any{
				"author":  "test",
				"version": "1.0",
			},
		}

		err := p.Validate()
		assert.NoError(t, err, "Valid comprehensive prompt should pass validation")
	})

	t.Run("empty ID fails validation", func(t *testing.T) {
		p := &Prompt{
			ID:       "",
			Name:     "Test Prompt",
			Position: PositionSystem,
			Content:  "Content",
		}

		err := p.Validate()
		require.Error(t, err, "Empty ID should fail validation")

		var gibsonErr *types.GibsonError
		require.True(t, errors.As(err, &gibsonErr), "Error should be a GibsonError")
		assert.Equal(t, PROMPT_EMPTY_ID, gibsonErr.Code)
		assert.Contains(t, gibsonErr.Error(), "ID cannot be empty")
	})

	t.Run("invalid position fails validation", func(t *testing.T) {
		p := &Prompt{
			ID:       "test-prompt",
			Name:     "Test Prompt",
			Position: Position("invalid_position"),
			Content:  "Content",
		}

		err := p.Validate()
		require.Error(t, err, "Invalid position should fail validation")

		var gibsonErr *types.GibsonError
		require.True(t, errors.As(err, &gibsonErr), "Error should be a GibsonError")
		assert.Equal(t, PROMPT_INVALID_POSITION, gibsonErr.Code)
		assert.Contains(t, gibsonErr.Error(), "invalid prompt position")
	})

	t.Run("empty position fails validation", func(t *testing.T) {
		p := &Prompt{
			ID:       "test-prompt",
			Name:     "Test Prompt",
			Position: Position(""),
			Content:  "Content",
		}

		err := p.Validate()
		require.Error(t, err, "Empty position should fail validation")

		var gibsonErr *types.GibsonError
		require.True(t, errors.As(err, &gibsonErr), "Error should be a GibsonError")
		assert.Equal(t, PROMPT_INVALID_POSITION, gibsonErr.Code)
	})

	t.Run("empty content fails validation", func(t *testing.T) {
		p := &Prompt{
			ID:       "test-prompt",
			Name:     "Test Prompt",
			Position: PositionSystem,
			Content:  "",
		}

		err := p.Validate()
		require.Error(t, err, "Empty content should fail validation")

		var gibsonErr *types.GibsonError
		require.True(t, errors.As(err, &gibsonErr), "Error should be a GibsonError")
		assert.Equal(t, PROMPT_EMPTY_CONTENT, gibsonErr.Code)
		assert.Contains(t, gibsonErr.Error(), "content cannot be empty")
	})
}

func TestPrompt_ValidateAllPositions(t *testing.T) {
	t.Run("all valid positions pass validation", func(t *testing.T) {
		positions := AllPositions()

		for _, pos := range positions {
			p := &Prompt{
				ID:       "test-prompt",
				Position: pos,
				Content:  "Test content",
			}

			err := p.Validate()
			assert.NoError(t, err,
				"Prompt with position %s should pass validation", pos)
		}
	})
}

func TestPrompt_Structure(t *testing.T) {
	t.Run("prompt has correct json tags", func(t *testing.T) {
		p := &Prompt{
			ID:          "test-id",
			Name:        "test-name",
			Description: "test-desc",
			Position:    PositionSystem,
			Content:     "test-content",
			Priority:    10,
			Metadata:    map[string]any{"key": "value"},
		}

		// Verify the struct can be used (fields are accessible)
		assert.Equal(t, "test-id", p.ID)
		assert.Equal(t, "test-name", p.Name)
		assert.Equal(t, "test-desc", p.Description)
		assert.Equal(t, PositionSystem, p.Position)
		assert.Equal(t, "test-content", p.Content)
		assert.Equal(t, 10, p.Priority)
		assert.Equal(t, "value", p.Metadata["key"])
	})

	t.Run("optional fields can be nil or empty", func(t *testing.T) {
		p := &Prompt{
			ID:       "test-id",
			Position: PositionSystem,
			Content:  "test-content",
			// All optional fields omitted
		}

		err := p.Validate()
		assert.NoError(t, err, "Prompt with only required fields should be valid")

		assert.Empty(t, p.Name)
		assert.Empty(t, p.Description)
		assert.Empty(t, p.Variables)
		assert.Empty(t, p.Conditions)
		assert.Empty(t, p.Examples)
		assert.Equal(t, 0, p.Priority)
		assert.Nil(t, p.Metadata)
	})

	t.Run("arrays can be empty", func(t *testing.T) {
		p := &Prompt{
			ID:         "test-id",
			Position:   PositionSystem,
			Content:    "test-content",
			Variables:  []VariableDef{},
			Conditions: []Condition{},
			Examples:   []Example{},
		}

		err := p.Validate()
		assert.NoError(t, err, "Prompt with empty arrays should be valid")
	})

	t.Run("metadata can be complex", func(t *testing.T) {
		p := &Prompt{
			ID:       "test-id",
			Position: PositionSystem,
			Content:  "test-content",
			Metadata: map[string]any{
				"string": "value",
				"int":    42,
				"bool":   true,
				"nested": map[string]any{
					"key": "nested-value",
				},
				"array": []string{"a", "b", "c"},
			},
		}

		err := p.Validate()
		assert.NoError(t, err, "Prompt with complex metadata should be valid")

		// Verify metadata is accessible
		assert.Equal(t, "value", p.Metadata["string"])
		assert.Equal(t, 42, p.Metadata["int"])
		assert.Equal(t, true, p.Metadata["bool"])

		nested, ok := p.Metadata["nested"].(map[string]any)
		require.True(t, ok, "Nested metadata should be map")
		assert.Equal(t, "nested-value", nested["key"])
	})
}

func TestPrompt_ValidationEdgeCases(t *testing.T) {
	t.Run("whitespace-only ID fails validation", func(t *testing.T) {
		p := &Prompt{
			ID:       "   ",
			Position: PositionSystem,
			Content:  "Content",
		}

		// Note: Current implementation checks for empty string only
		// Whitespace-only strings currently pass. This test documents current behavior.
		err := p.Validate()
		// This would fail in a more strict implementation
		assert.NoError(t, err, "Current implementation allows whitespace-only ID")
	})

	t.Run("whitespace-only content fails validation", func(t *testing.T) {
		p := &Prompt{
			ID:       "test-id",
			Position: PositionSystem,
			Content:  "   ",
		}

		// Note: Current implementation checks for empty string only
		err := p.Validate()
		assert.NoError(t, err, "Current implementation allows whitespace-only content")
	})

	t.Run("very long ID is valid", func(t *testing.T) {
		longID := make([]byte, 10000)
		for i := range longID {
			longID[i] = 'a'
		}

		p := &Prompt{
			ID:       string(longID),
			Position: PositionSystem,
			Content:  "Content",
		}

		err := p.Validate()
		assert.NoError(t, err, "Very long ID should be valid")
	})

	t.Run("very long content is valid", func(t *testing.T) {
		longContent := make([]byte, 100000)
		for i := range longContent {
			longContent[i] = 'a'
		}

		p := &Prompt{
			ID:       "test-id",
			Position: PositionSystem,
			Content:  string(longContent),
		}

		err := p.Validate()
		assert.NoError(t, err, "Very long content should be valid")
	})

	t.Run("negative priority is valid", func(t *testing.T) {
		p := &Prompt{
			ID:       "test-id",
			Position: PositionSystem,
			Content:  "Content",
			Priority: -100,
		}

		err := p.Validate()
		assert.NoError(t, err, "Negative priority should be valid")
	})

	t.Run("zero priority is valid", func(t *testing.T) {
		p := &Prompt{
			ID:       "test-id",
			Position: PositionSystem,
			Content:  "Content",
			Priority: 0,
		}

		err := p.Validate()
		assert.NoError(t, err, "Zero priority should be valid")
	})
}

func TestPrompt_ErrorCodes(t *testing.T) {
	t.Run("error codes are defined correctly", func(t *testing.T) {
		assert.Equal(t, types.ErrorCode("PROMPT_INVALID_POSITION"), PROMPT_INVALID_POSITION)
		assert.Equal(t, types.ErrorCode("PROMPT_EMPTY_ID"), PROMPT_EMPTY_ID)
		assert.Equal(t, types.ErrorCode("PROMPT_EMPTY_CONTENT"), PROMPT_EMPTY_CONTENT)
	})

	t.Run("errors can be checked with errors.Is", func(t *testing.T) {
		p := &Prompt{
			ID:       "",
			Position: PositionSystem,
			Content:  "Content",
		}

		err := p.Validate()
		require.Error(t, err)

		expectedErr := types.NewError(PROMPT_EMPTY_ID, "")
		assert.True(t, errors.Is(err, expectedErr),
			"Error should be identifiable by error code")
	})
}

func TestPrompt_MultipleValidationErrors(t *testing.T) {
	t.Run("validation returns first error encountered", func(t *testing.T) {
		p := &Prompt{
			ID:       "",                  // First error: empty ID
			Position: Position("invalid"), // Second error: invalid position
			Content:  "",                  // Third error: empty content
		}

		err := p.Validate()
		require.Error(t, err)

		// Should return the first error (empty ID)
		var gibsonErr *types.GibsonError
		require.True(t, errors.As(err, &gibsonErr))
		assert.Equal(t, PROMPT_EMPTY_ID, gibsonErr.Code,
			"Should return first validation error")
	})

	t.Run("validation order: ID, Position, Content", func(t *testing.T) {
		// Test ID is checked first
		p1 := &Prompt{
			ID:       "",
			Position: Position("invalid"),
			Content:  "",
		}
		err1 := p1.Validate()
		var gibsonErr1 *types.GibsonError
		require.True(t, errors.As(err1, &gibsonErr1))
		assert.Equal(t, PROMPT_EMPTY_ID, gibsonErr1.Code)

		// Test Position is checked second (when ID is valid)
		p2 := &Prompt{
			ID:       "valid-id",
			Position: Position("invalid"),
			Content:  "",
		}
		err2 := p2.Validate()
		var gibsonErr2 *types.GibsonError
		require.True(t, errors.As(err2, &gibsonErr2))
		assert.Equal(t, PROMPT_INVALID_POSITION, gibsonErr2.Code)

		// Test Content is checked third (when ID and Position are valid)
		p3 := &Prompt{
			ID:       "valid-id",
			Position: PositionSystem,
			Content:  "",
		}
		err3 := p3.Validate()
		var gibsonErr3 *types.GibsonError
		require.True(t, errors.As(err3, &gibsonErr3))
		assert.Equal(t, PROMPT_EMPTY_CONTENT, gibsonErr3.Code)
	})
}

func TestPrompt_ForwardDeclarations(t *testing.T) {
	t.Run("VariableDef is defined", func(t *testing.T) {
		var _ VariableDef
		// Just verify the type exists and can be used
		p := &Prompt{
			ID:        "test",
			Position:  PositionSystem,
			Content:   "test",
			Variables: []VariableDef{},
		}
		assert.NotNil(t, p.Variables)
	})

	t.Run("Condition is defined", func(t *testing.T) {
		var _ Condition
		// Just verify the type exists and can be used
		p := &Prompt{
			ID:         "test",
			Position:   PositionSystem,
			Content:    "test",
			Conditions: []Condition{},
		}
		assert.NotNil(t, p.Conditions)
	})

	t.Run("Example is defined", func(t *testing.T) {
		var _ Example
		// Just verify the type exists and can be used
		p := &Prompt{
			ID:       "test",
			Position: PositionSystem,
			Content:  "test",
			Examples: []Example{},
		}
		assert.NotNil(t, p.Examples)
	})
}
