package llm

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestExtractJSON_DecisionWithMarkdown tests that ParseDecision-style JSON
// can be extracted from markdown code blocks
func TestExtractJSON_DecisionWithMarkdown(t *testing.T) {
	// Simulate an LLM response with a Decision wrapped in markdown
	response := `Based on the mission state, here's my decision:

` + "```json" + `
{
  "reasoning": "Execute recon agent",
  "action": "execute_agent",
  "target_node_id": "recon-1",
  "confidence": 0.9
}
` + "```" + `

This should proceed with the reconnaissance phase.`

	// Extract the JSON
	result, err := ExtractJSON(response)
	require.NoError(t, err)

	// Verify it's valid JSON that can be unmarshaled
	type Decision struct {
		Reasoning    string  `json:"reasoning"`
		Action       string  `json:"action"`
		TargetNodeID string  `json:"target_node_id"`
		Confidence   float64 `json:"confidence"`
	}

	decision, err := ExtractJSONAs[Decision](response)
	require.NoError(t, err)
	assert.Equal(t, "Execute recon agent", decision.Reasoning)
	assert.Equal(t, "execute_agent", decision.Action)
	assert.Equal(t, "recon-1", decision.TargetNodeID)
	assert.Equal(t, 0.9, decision.Confidence)

	// Verify the extracted JSON contains the expected fields
	assert.Contains(t, result, `"reasoning"`)
	assert.Contains(t, result, `"action"`)
	assert.Contains(t, result, `"target_node_id"`)
	assert.Contains(t, result, `"confidence"`)
}

// TestExtractJSON_PlanGenerationWithMarkdown tests that plan generation JSON
// can be extracted from markdown code blocks
func TestExtractJSON_PlanGenerationWithMarkdown(t *testing.T) {
	// Simulate an LLM response with execution plan wrapped in markdown
	response := `Here's the execution plan for the reconnaissance task:

` + "```json" + `
{
  "steps": [
    {
      "name": "port_scan",
      "description": "Scan target for open ports",
      "type": "tool",
      "tool_name": "nmap",
      "tool_input": {"target": "192.168.1.1"}
    },
    {
      "name": "service_detection",
      "description": "Detect services on open ports",
      "type": "tool",
      "tool_name": "nmap",
      "tool_input": {"target": "192.168.1.1", "service_scan": true},
      "depends_on": ["port_scan"]
    }
  ]
}
` + "```" + `

This plan covers the initial reconnaissance phase.`

	// Extract the JSON
	result, err := ExtractJSON(response)
	require.NoError(t, err)

	// Verify it's valid JSON
	type ExecutionPlan struct {
		Steps []struct {
			Name        string         `json:"name"`
			Description string         `json:"description"`
			Type        string         `json:"type"`
			ToolName    string         `json:"tool_name"`
			ToolInput   map[string]any `json:"tool_input"`
			DependsOn   []string       `json:"depends_on,omitempty"`
		} `json:"steps"`
	}

	plan, err := ExtractJSONAs[ExecutionPlan](response)
	require.NoError(t, err)
	assert.Len(t, plan.Steps, 2)
	assert.Equal(t, "port_scan", plan.Steps[0].Name)
	assert.Equal(t, "service_detection", plan.Steps[1].Name)
	assert.Equal(t, []string{"port_scan"}, plan.Steps[1].DependsOn)

	// Verify the extracted JSON contains the expected fields
	assert.Contains(t, result, `"steps"`)
	assert.Contains(t, result, `"port_scan"`)
	assert.Contains(t, result, `"service_detection"`)
}

// TestExtractJSON_FindingClassificationWithMarkdown tests finding classification JSON extraction
func TestExtractJSON_FindingClassificationWithMarkdown(t *testing.T) {
	// Simulate an LLM response with finding classification wrapped in markdown
	response := `After analyzing the security finding, here's my classification:

` + "```json" + `
{
  "category": "prompt_injection",
  "subcategory": "direct_injection",
  "confidence": 0.95,
  "rationale": "The input contains clear attempts to override system instructions"
}
` + "```" + `

This represents a high-confidence classification.`

	// Extract the JSON
	result, err := ExtractJSON(response)
	require.NoError(t, err)

	// Verify it's valid JSON
	type Classification struct {
		Category    string  `json:"category"`
		Subcategory string  `json:"subcategory"`
		Confidence  float64 `json:"confidence"`
		Rationale   string  `json:"rationale"`
	}

	classification, err := ExtractJSONAs[Classification](response)
	require.NoError(t, err)
	assert.Equal(t, "prompt_injection", classification.Category)
	assert.Equal(t, "direct_injection", classification.Subcategory)
	assert.Equal(t, 0.95, classification.Confidence)
	assert.Contains(t, classification.Rationale, "override system instructions")

	// Verify the extracted JSON contains the expected fields
	assert.Contains(t, result, `"category"`)
	assert.Contains(t, result, `"confidence"`)
	assert.Contains(t, result, `"rationale"`)
}

// TestExtractJSON_BackwardCompatibility verifies that raw JSON still works
func TestExtractJSON_BackwardCompatibility(t *testing.T) {
	tests := []struct {
		name     string
		response string
		wantErr  bool
	}{
		{
			name:     "raw JSON object",
			response: `{"key": "value", "number": 42}`,
			wantErr:  false,
		},
		{
			name:     "raw JSON array",
			response: `[{"id": 1}, {"id": 2}]`,
			wantErr:  false,
		},
		{
			name:     "JSON with whitespace",
			response: `  {"key": "value"}  `,
			wantErr:  false,
		},
		{
			name:     "no JSON",
			response: `This is just text`,
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ExtractJSON(tt.response)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}
