package agent

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zeroroot-ai/gibson/internal/infra/types"
)

// TestTaskJSONSerialization verifies that Task struct serializes correctly
// with goal and context as top-level JSON fields.
func TestTaskJSONSerialization(t *testing.T) {
	// Create a task with goal and context
	taskID := types.NewID()
	missionID := types.NewID()
	targetID := types.NewID()

	task := Task{
		ID:          taskID,
		Name:        "test-task",
		Description: "Test task for serialization",
		Goal:        "Achieve test objective",
		Context: map[string]any{
			"phase":    "init",
			"priority": 1,
			"data":     "test-value",
		},
		Input: map[string]any{
			"legacy": "input",
		},
		Timeout:   30 * time.Minute,
		MissionID: &missionID,
		TargetID:  &targetID,
		CreatedAt: time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC),
		Priority:  5,
		Tags:      []string{"test", "serialization"},
	}

	// Marshal to JSON
	jsonData, err := json.Marshal(task)
	require.NoError(t, err, "Failed to marshal task to JSON")

	// Unmarshal to map to verify structure
	var jsonMap map[string]any
	err = json.Unmarshal(jsonData, &jsonMap)
	require.NoError(t, err, "Failed to unmarshal JSON to map")

	// Verify goal is at top level
	assert.Contains(t, jsonMap, "goal", "JSON should contain top-level 'goal' field")
	assert.Equal(t, "Achieve test objective", jsonMap["goal"], "Goal should be serialized correctly")

	// Verify context is at top level
	assert.Contains(t, jsonMap, "context", "JSON should contain top-level 'context' field")
	contextMap, ok := jsonMap["context"].(map[string]any)
	require.True(t, ok, "Context should be a map")
	assert.Equal(t, "init", contextMap["phase"], "Context phase should be serialized correctly")
	assert.Equal(t, float64(1), contextMap["priority"], "Context priority should be serialized correctly")
	assert.Equal(t, "test-value", contextMap["data"], "Context data should be serialized correctly")

	// Verify input is still at top level (backward compatibility)
	assert.Contains(t, jsonMap, "input", "JSON should contain top-level 'input' field for backward compatibility")
	inputMap, ok := jsonMap["input"].(map[string]any)
	require.True(t, ok, "Input should be a map")
	assert.Equal(t, "input", inputMap["legacy"], "Input should be serialized correctly")

	// Verify other fields
	assert.Equal(t, taskID.String(), jsonMap["id"], "ID should be serialized correctly")
	assert.Equal(t, "test-task", jsonMap["name"], "Name should be serialized correctly")
	assert.Equal(t, "Test task for serialization", jsonMap["description"], "Description should be serialized correctly")
	assert.Equal(t, float64(5), jsonMap["priority"], "Priority should be serialized correctly")

	// Verify tags
	tags, ok := jsonMap["tags"].([]any)
	require.True(t, ok, "Tags should be an array")
	assert.Len(t, tags, 2, "Should have 2 tags")
	assert.Equal(t, "test", tags[0], "First tag should be 'test'")
	assert.Equal(t, "serialization", tags[1], "Second tag should be 'serialization'")
}

// TestTaskJSONRoundTrip verifies that Task can be marshaled and unmarshaled
// without losing data (round-trip test).
func TestTaskJSONRoundTrip(t *testing.T) {
	// Create original task
	originalTask := Task{
		ID:          types.NewID(),
		Name:        "round-trip-task",
		Description: "Task for round-trip testing",
		Goal:        "Complete round-trip test",
		Context: map[string]any{
			"phase":    "analyze",
			"findings": []string{"finding1", "finding2"},
			"nested":   map[string]any{"key": "value"},
		},
		Input: map[string]any{
			"param1": "value1",
			"param2": 42,
		},
		Timeout:   15 * time.Minute,
		CreatedAt: time.Now().UTC().Truncate(time.Second), // Truncate to second for comparison
		Priority:  3,
		Tags:      []string{"round-trip", "test"},
	}

	// Marshal to JSON
	jsonData, err := json.Marshal(originalTask)
	require.NoError(t, err, "Failed to marshal task")

	// Unmarshal back to Task
	var unmarshaledTask Task
	err = json.Unmarshal(jsonData, &unmarshaledTask)
	require.NoError(t, err, "Failed to unmarshal task")

	// Compare fields
	assert.Equal(t, originalTask.ID, unmarshaledTask.ID, "ID should match")
	assert.Equal(t, originalTask.Name, unmarshaledTask.Name, "Name should match")
	assert.Equal(t, originalTask.Description, unmarshaledTask.Description, "Description should match")
	assert.Equal(t, originalTask.Goal, unmarshaledTask.Goal, "Goal should match")
	assert.Equal(t, originalTask.Priority, unmarshaledTask.Priority, "Priority should match")
	assert.Equal(t, originalTask.Tags, unmarshaledTask.Tags, "Tags should match")

	// Compare Context (need to compare as JSON due to map[string]any conversions)
	originalContextJSON, _ := json.Marshal(originalTask.Context)
	unmarshaledContextJSON, _ := json.Marshal(unmarshaledTask.Context)
	assert.JSONEq(t, string(originalContextJSON), string(unmarshaledContextJSON), "Context should match")

	// Compare Input
	originalInputJSON, _ := json.Marshal(originalTask.Input)
	unmarshaledInputJSON, _ := json.Marshal(unmarshaledTask.Input)
	assert.JSONEq(t, string(originalInputJSON), string(unmarshaledInputJSON), "Input should match")

	// Compare time (truncated to seconds for JSON precision)
	assert.True(t, originalTask.CreatedAt.Equal(unmarshaledTask.CreatedAt), "CreatedAt should match")
}

// TestTaskJSONWithEmptyGoalAndContext verifies that Task serialization
// handles empty/nil goal and context correctly with omitempty behavior.
func TestTaskJSONWithEmptyGoalAndContext(t *testing.T) {
	// Create task with empty goal and nil context
	task := Task{
		ID:          types.NewID(),
		Name:        "minimal-task",
		Description: "Task with no goal or context",
		Goal:        "",  // Empty goal - will be omitted due to omitempty tag
		Context:     nil, // Nil context - will be omitted due to omitempty tag
		Input: map[string]any{
			"test": "value",
		},
		Timeout:   10 * time.Minute,
		CreatedAt: time.Now().UTC(),
		Priority:  0,
		Tags:      []string{},
	}

	// Marshal to JSON
	jsonData, err := json.Marshal(task)
	require.NoError(t, err, "Failed to marshal task")

	// Unmarshal to map to verify structure
	var jsonMap map[string]any
	err = json.Unmarshal(jsonData, &jsonMap)
	require.NoError(t, err, "Failed to unmarshal JSON to map")

	// Verify goal is omitted when empty (due to omitempty tag)
	_, hasGoal := jsonMap["goal"]
	assert.False(t, hasGoal, "Empty goal should be omitted from JSON (omitempty tag)")

	// Verify context is omitted when nil (due to omitempty tag)
	_, hasContext := jsonMap["context"]
	assert.False(t, hasContext, "Nil context should be omitted from JSON (omitempty tag)")

	// Verify input is still present
	assert.Contains(t, jsonMap, "input", "JSON should contain 'input' field")
}

// TestTaskJSONWithComplexContext verifies that Task serialization handles
// complex nested context structures correctly.
func TestTaskJSONWithComplexContext(t *testing.T) {
	// Create task with complex nested context
	task := Task{
		ID:          types.NewID(),
		Name:        "complex-context-task",
		Description: "Task with complex context",
		Goal:        "Test complex context serialization",
		Context: map[string]any{
			"phase": "final",
			"previous_findings": []any{
				map[string]any{"severity": "high", "title": "XSS"},
				map[string]any{"severity": "medium", "title": "CSRF"},
			},
			"metadata": map[string]any{
				"timestamp": "2024-01-01T00:00:00Z",
				"agent":     "test-agent",
				"nested": map[string]any{
					"level1": map[string]any{
						"level2": "deep-value",
					},
				},
			},
		},
		Input:     map[string]any{},
		Timeout:   20 * time.Minute,
		CreatedAt: time.Now().UTC(),
		Priority:  1,
		Tags:      []string{},
	}

	// Marshal to JSON
	jsonData, err := json.Marshal(task)
	require.NoError(t, err, "Failed to marshal task")

	// Unmarshal to map to verify structure
	var jsonMap map[string]any
	err = json.Unmarshal(jsonData, &jsonMap)
	require.NoError(t, err, "Failed to unmarshal JSON to map")

	// Verify complex context structure
	contextMap, ok := jsonMap["context"].(map[string]any)
	require.True(t, ok, "Context should be a map")

	assert.Equal(t, "final", contextMap["phase"], "Context phase should be correct")

	// Verify previous_findings array
	findings, ok := contextMap["previous_findings"].([]any)
	require.True(t, ok, "previous_findings should be an array")
	assert.Len(t, findings, 2, "Should have 2 findings")

	// Verify metadata nested structure
	metadata, ok := contextMap["metadata"].(map[string]any)
	require.True(t, ok, "metadata should be a map")
	assert.Equal(t, "test-agent", metadata["agent"], "metadata.agent should be correct")

	nested, ok := metadata["nested"].(map[string]any)
	require.True(t, ok, "nested should be a map")
	level1, ok := nested["level1"].(map[string]any)
	require.True(t, ok, "level1 should be a map")
	assert.Equal(t, "deep-value", level1["level2"], "Deep nested value should be correct")

	// Round-trip test
	var unmarshaledTask Task
	err = json.Unmarshal(jsonData, &unmarshaledTask)
	require.NoError(t, err, "Failed to unmarshal task")

	// Verify the nested structure is preserved
	previousFindings, ok := unmarshaledTask.Context["previous_findings"].([]any)
	require.True(t, ok, "previous_findings should unmarshal as slice")
	assert.Len(t, previousFindings, 2, "Should preserve 2 findings")
}
