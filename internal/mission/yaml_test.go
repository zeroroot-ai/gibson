package mission

import (
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLoadFromReader_ValidConfig(t *testing.T) {
	yamlContent := `
name: test-mission
description: Test mission description
target:
  reference: target-1
workflow:
  reference: workflow-1
constraints:
  max_duration: 1h30m
  max_findings: 100
  max_cost: 10.50
  severity_threshold: high
  require_approval: true
`

	config, err := LoadFromReader(strings.NewReader(yamlContent))
	require.NoError(t, err)
	assert.Equal(t, "test-mission", config.Name)
	assert.Equal(t, "Test mission description", config.Description)
	assert.Equal(t, "target-1", config.Target.Reference)
	assert.Equal(t, "workflow-1", config.Workflow.Reference)
	assert.NotNil(t, config.Constraints)
	assert.Equal(t, "1h30m", config.Constraints.MaxDuration)
	assert.Equal(t, 100, *config.Constraints.MaxFindings)
	assert.Equal(t, 10.50, *config.Constraints.MaxCost)
}

func TestLoadFromReader_InlineTarget(t *testing.T) {
	yamlContent := `
name: test-mission
description: Test mission
target:
  inline:
    type: llm
    provider: openai
    model: gpt-4
workflow:
  reference: workflow-1
`

	config, err := LoadFromReader(strings.NewReader(yamlContent))
	require.NoError(t, err)
	assert.NotNil(t, config.Target.Inline)
	assert.Equal(t, "llm", config.Target.Inline.Type)
	assert.Equal(t, "openai", config.Target.Inline.Provider)
	assert.Equal(t, "gpt-4", config.Target.Inline.Model)
}

func TestLoadFromReader_InlineWorkflow(t *testing.T) {
	yamlContent := `
name: test-mission
description: Test mission
target:
  reference: target-1
workflow:
  inline:
    agents:
      - agent-1
      - agent-2
`

	config, err := LoadFromReader(strings.NewReader(yamlContent))
	require.NoError(t, err)
	assert.NotNil(t, config.Workflow.Inline)
	assert.Equal(t, 2, len(config.Workflow.Inline.Agents))
}

func TestLoadFromReader_EnvVarInterpolation(t *testing.T) {
	// Set test environment variable
	os.Setenv("TEST_TARGET", "test-target-id")
	defer os.Unsetenv("TEST_TARGET")

	yamlContent := `
name: test-mission
description: Test mission
target:
  reference: ${TEST_TARGET}
workflow:
  reference: workflow-1
`

	config, err := LoadFromReader(strings.NewReader(yamlContent))
	require.NoError(t, err)
	assert.Equal(t, "test-target-id", config.Target.Reference)
}

func TestLoadFromReader_ValidationErrors(t *testing.T) {
	tests := []struct {
		name    string
		yaml    string
		wantErr string
	}{
		{
			name: "missing name",
			yaml: `
description: Test mission
target:
  reference: target-1
workflow:
  reference: workflow-1
`,
			wantErr: "mission name is required",
		},
		{
			name: "missing target",
			yaml: `
name: test-mission
workflow:
  reference: workflow-1
`,
			wantErr: "target must specify either 'reference' or 'inline'",
		},
		{
			name: "both target reference and inline",
			yaml: `
name: test-mission
target:
  reference: target-1
  inline:
    type: llm
    provider: openai
workflow:
  reference: workflow-1
`,
			wantErr: "target cannot specify both 'reference' and 'inline'",
		},
		{
			name: "invalid max_duration",
			yaml: `
name: test-mission
target:
  reference: target-1
workflow:
  reference: workflow-1
constraints:
  max_duration: invalid
`,
			wantErr: "invalid max_duration format",
		},
		{
			name: "invalid max_findings",
			yaml: `
name: test-mission
target:
  reference: target-1
workflow:
  reference: workflow-1
constraints:
  max_findings: -1
`,
			wantErr: "max_findings must be greater than 0",
		},
		{
			name: "invalid severity_threshold",
			yaml: `
name: test-mission
target:
  reference: target-1
workflow:
  reference: workflow-1
constraints:
  severity_threshold: invalid
`,
			wantErr: "invalid severity_threshold",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := LoadFromReader(strings.NewReader(tt.yaml))
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.wantErr)
		})
	}
}

func TestMissionConstraintsConfig_ToConstraints(t *testing.T) {
	maxFindings := 100
	maxCost := 10.50
	severityThreshold := "high"
	requireApproval := true

	config := &MissionConstraintsConfig{
		MaxDuration:       "1h30m",
		MaxFindings:       &maxFindings,
		MaxCost:           &maxCost,
		SeverityThreshold: &severityThreshold,
		RequireApproval:   &requireApproval,
	}

	constraints, err := config.ToConstraints()
	require.NoError(t, err)
	assert.NotZero(t, constraints.MaxDuration)
	assert.Equal(t, maxFindings, constraints.MaxFindings)
	assert.Equal(t, maxCost, constraints.MaxCost)
	assert.Equal(t, severityThreshold, string(constraints.SeverityThreshold))
}

func TestLoadFromFile(t *testing.T) {
	// Create temporary YAML file
	tmpFile, err := os.CreateTemp("", "mission-*.yaml")
	require.NoError(t, err)
	defer os.Remove(tmpFile.Name())

	yamlContent := `
name: test-mission
description: Test mission from file
target:
  reference: target-1
workflow:
  reference: workflow-1
`

	_, err = tmpFile.WriteString(yamlContent)
	require.NoError(t, err)
	tmpFile.Close()

	config, err := LoadFromFile(tmpFile.Name())
	require.NoError(t, err)
	assert.Equal(t, "test-mission", config.Name)
}

func TestLoadFromFile_NonExistent(t *testing.T) {
	_, err := LoadFromFile("/nonexistent/file.yaml")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to open file")
}

func TestParseYAML_ValidInput(t *testing.T) {
	yamlContent := []byte(`
name: test-mission
description: Test mission description
target:
  reference: target-1
workflow:
  reference: workflow-1
constraints:
  max_duration: 1h30m
  max_findings: 100
  max_cost: 10.50
  severity_threshold: high
`)

	config, err := ParseYAML(yamlContent)
	require.NoError(t, err)
	assert.NotNil(t, config)
	assert.Equal(t, "test-mission", config.Name)
	assert.Equal(t, "Test mission description", config.Description)
	assert.Equal(t, "target-1", config.Target.Reference)
	assert.Equal(t, "workflow-1", config.Workflow.Reference)
	assert.NotNil(t, config.Constraints)
	assert.Equal(t, "1h30m", config.Constraints.MaxDuration)
	assert.Equal(t, 100, *config.Constraints.MaxFindings)
	assert.Equal(t, 10.50, *config.Constraints.MaxCost)
	assert.Equal(t, "high", *config.Constraints.SeverityThreshold)
}

func TestParseYAML_MinimalValidInput(t *testing.T) {
	yamlContent := []byte(`
name: minimal-mission
target:
  reference: target-1
workflow:
  reference: workflow-1
`)

	config, err := ParseYAML(yamlContent)
	require.NoError(t, err)
	assert.NotNil(t, config)
	assert.Equal(t, "minimal-mission", config.Name)
	assert.Equal(t, "target-1", config.Target.Reference)
	assert.Equal(t, "workflow-1", config.Workflow.Reference)
	assert.Nil(t, config.Constraints)
	assert.Nil(t, config.Guardrails)
	assert.Nil(t, config.Reporting)
}

func TestParseYAML_InlineTarget(t *testing.T) {
	yamlContent := []byte(`
name: test-mission
target:
  inline:
    type: llm
    provider: openai
    model: gpt-4
    endpoint: https://api.openai.com
workflow:
  reference: workflow-1
`)

	config, err := ParseYAML(yamlContent)
	require.NoError(t, err)
	assert.NotNil(t, config.Target.Inline)
	assert.Equal(t, "llm", config.Target.Inline.Type)
	assert.Equal(t, "openai", config.Target.Inline.Provider)
	assert.Equal(t, "gpt-4", config.Target.Inline.Model)
	assert.Equal(t, "https://api.openai.com", config.Target.Inline.Endpoint)
}

func TestParseYAML_InlineWorkflow(t *testing.T) {
	yamlContent := []byte(`
name: test-mission
target:
  reference: target-1
workflow:
  inline:
    agents:
      - agent-1
      - agent-2
      - agent-3
`)

	config, err := ParseYAML(yamlContent)
	require.NoError(t, err)
	assert.NotNil(t, config.Workflow.Inline)
	assert.Equal(t, 3, len(config.Workflow.Inline.Agents))
	assert.Equal(t, "agent-1", config.Workflow.Inline.Agents[0])
	assert.Equal(t, "agent-2", config.Workflow.Inline.Agents[1])
	assert.Equal(t, "agent-3", config.Workflow.Inline.Agents[2])
}

func TestParseYAML_InvalidYAMLSyntax(t *testing.T) {
	tests := []struct {
		name    string
		yaml    []byte
		wantErr string
	}{
		{
			name: "malformed YAML structure",
			yaml: []byte(`
name: test-mission
target:
  reference: target-1
  this is not valid yaml syntax
workflow:
  reference: workflow-1
`),
			wantErr: "YAML parsing failed",
		},
		{
			name: "incorrect indentation",
			yaml: []byte(`
name: test-mission
target:
reference: target-1
workflow:
  reference: workflow-1
`),
			wantErr: "YAML validation failed",
		},
		{
			name: "invalid field type",
			yaml: []byte(`
name: test-mission
target:
  reference: target-1
workflow:
  reference: workflow-1
constraints:
  max_findings: "not a number"
`),
			wantErr: "YAML validation failed",
		},
		{
			name: "unknown field (strict mode)",
			yaml: []byte(`
name: test-mission
target:
  reference: target-1
workflow:
  reference: workflow-1
unknown_field: should fail
`),
			wantErr: "YAML validation failed",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ParseYAML(tt.yaml)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.wantErr)
		})
	}
}

func TestParseYAML_EmptyInput(t *testing.T) {
	tests := []struct {
		name       string
		input      []byte
		wantErrAny []string // Accept any of these error messages
	}{
		{
			name:       "empty byte slice",
			input:      []byte{},
			wantErrAny: []string{"failed to parse YAML", "EOF"},
		},
		{
			name:       "nil byte slice",
			input:      nil,
			wantErrAny: []string{"failed to parse YAML", "EOF"},
		},
		{
			name:       "whitespace only",
			input:      []byte("   \n\t   "),
			wantErrAny: []string{"YAML parsing failed", "cannot start any token"},
		},
		{
			name:       "empty YAML document",
			input:      []byte("---"),
			wantErrAny: []string{"mission name is required"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ParseYAML(tt.input)
			require.Error(t, err)

			// Check if error contains any of the expected strings
			errStr := err.Error()
			found := false
			for _, wantErr := range tt.wantErrAny {
				if strings.Contains(errStr, wantErr) {
					found = true
					break
				}
			}
			assert.True(t, found, "error %q does not contain any of %v", errStr, tt.wantErrAny)
		})
	}
}

func TestParseYAML_MissingRequiredFields(t *testing.T) {
	tests := []struct {
		name    string
		yaml    []byte
		wantErr string
	}{
		{
			name: "missing name",
			yaml: []byte(`
description: Test mission
target:
  reference: target-1
workflow:
  reference: workflow-1
`),
			wantErr: "mission name is required",
		},
		{
			name: "missing target",
			yaml: []byte(`
name: test-mission
workflow:
  reference: workflow-1
`),
			wantErr: "target must specify either 'reference' or 'inline'",
		},
		{
			name: "missing workflow",
			yaml: []byte(`
name: test-mission
target:
  reference: target-1
`),
			wantErr: "workflow must specify either 'reference' or 'inline'",
		},
		{
			name: "missing target reference and inline",
			yaml: []byte(`
name: test-mission
target: {}
workflow:
  reference: workflow-1
`),
			wantErr: "target must specify either 'reference' or 'inline'",
		},
		{
			name: "missing workflow reference and inline",
			yaml: []byte(`
name: test-mission
target:
  reference: target-1
workflow: {}
`),
			wantErr: "workflow must specify either 'reference' or 'inline'",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ParseYAML(tt.yaml)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.wantErr)
		})
	}
}

func TestParseYAML_InvalidConstraints(t *testing.T) {
	tests := []struct {
		name    string
		yaml    []byte
		wantErr string
	}{
		{
			name: "invalid max_duration format",
			yaml: []byte(`
name: test-mission
target:
  reference: target-1
workflow:
  reference: workflow-1
constraints:
  max_duration: invalid
`),
			wantErr: "invalid max_duration format",
		},
		{
			name: "negative max_findings",
			yaml: []byte(`
name: test-mission
target:
  reference: target-1
workflow:
  reference: workflow-1
constraints:
  max_findings: -1
`),
			wantErr: "max_findings must be greater than 0",
		},
		{
			name: "zero max_findings",
			yaml: []byte(`
name: test-mission
target:
  reference: target-1
workflow:
  reference: workflow-1
constraints:
  max_findings: 0
`),
			wantErr: "max_findings must be greater than 0",
		},
		{
			name: "negative max_cost",
			yaml: []byte(`
name: test-mission
target:
  reference: target-1
workflow:
  reference: workflow-1
constraints:
  max_cost: -10.50
`),
			wantErr: "max_cost must be greater than 0",
		},
		{
			name: "invalid severity_threshold",
			yaml: []byte(`
name: test-mission
target:
  reference: target-1
workflow:
  reference: workflow-1
constraints:
  severity_threshold: invalid
`),
			wantErr: "invalid severity_threshold",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ParseYAML(tt.yaml)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.wantErr)
		})
	}
}

func TestParseYAML_EnvVarExpansion(t *testing.T) {
	// Set test environment variables
	os.Setenv("TEST_MISSION_NAME", "env-mission")
	os.Setenv("TEST_TARGET_REF", "env-target")
	os.Setenv("TEST_WORKFLOW_REF", "env-workflow")
	defer func() {
		os.Unsetenv("TEST_MISSION_NAME")
		os.Unsetenv("TEST_TARGET_REF")
		os.Unsetenv("TEST_WORKFLOW_REF")
	}()

	yamlContent := []byte(`
name: ${TEST_MISSION_NAME}
description: Mission with env vars
target:
  reference: ${TEST_TARGET_REF}
workflow:
  reference: ${TEST_WORKFLOW_REF}
`)

	config, err := ParseYAML(yamlContent)
	require.NoError(t, err)
	assert.Equal(t, "env-mission", config.Name)
	assert.Equal(t, "env-target", config.Target.Reference)
	assert.Equal(t, "env-workflow", config.Workflow.Reference)
}

func TestParseYAML_BothReferenceAndInline(t *testing.T) {
	tests := []struct {
		name    string
		yaml    []byte
		wantErr string
	}{
		{
			name: "target with both reference and inline",
			yaml: []byte(`
name: test-mission
target:
  reference: target-1
  inline:
    type: llm
    provider: openai
workflow:
  reference: workflow-1
`),
			wantErr: "target cannot specify both 'reference' and 'inline'",
		},
		{
			name: "workflow with both reference and inline",
			yaml: []byte(`
name: test-mission
target:
  reference: target-1
workflow:
  reference: workflow-1
  inline:
    agents:
      - agent-1
`),
			wantErr: "workflow cannot specify both 'reference' and 'inline'",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ParseYAML(tt.yaml)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.wantErr)
		})
	}
}

func TestParseYAML_CompleteConfiguration(t *testing.T) {
	maxFindings := 50
	maxCost := 25.75
	severityThreshold := "medium"
	requireApproval := true
	maxTokens := int64(10000)
	rateLimitRPS := 100
	requireConfirmation := false

	yamlContent := []byte(`
name: complete-mission
description: Mission with all optional fields
target:
  reference: target-1
workflow:
  reference: workflow-1
constraints:
  max_duration: 2h
  max_findings: 50
  max_cost: 25.75
  severity_threshold: medium
  require_approval: true
guardrails:
  max_tokens: 10000
  rate_limit_rps: 100
  allowed_agents:
    - agent-1
    - agent-2
  blocked_agents:
    - bad-agent
  require_confirmation: false
reporting:
  formats:
    - json
    - html
  output_path: /tmp/reports
  email_to:
    - admin@example.com
  webhooks:
    - https://webhook.example.com/mission
`)

	config, err := ParseYAML(yamlContent)
	require.NoError(t, err)
	assert.NotNil(t, config)

	// Basic fields
	assert.Equal(t, "complete-mission", config.Name)
	assert.Equal(t, "Mission with all optional fields", config.Description)
	assert.Equal(t, "target-1", config.Target.Reference)
	assert.Equal(t, "workflow-1", config.Workflow.Reference)

	// Constraints
	assert.NotNil(t, config.Constraints)
	assert.Equal(t, "2h", config.Constraints.MaxDuration)
	assert.Equal(t, maxFindings, *config.Constraints.MaxFindings)
	assert.Equal(t, maxCost, *config.Constraints.MaxCost)
	assert.Equal(t, severityThreshold, *config.Constraints.SeverityThreshold)
	assert.Equal(t, requireApproval, *config.Constraints.RequireApproval)

	// Guardrails
	assert.NotNil(t, config.Guardrails)
	assert.Equal(t, maxTokens, *config.Guardrails.MaxTokens)
	assert.Equal(t, rateLimitRPS, *config.Guardrails.RateLimitRPS)
	assert.Equal(t, 2, len(config.Guardrails.AllowedAgents))
	assert.Equal(t, 1, len(config.Guardrails.BlockedAgents))
	assert.Equal(t, requireConfirmation, *config.Guardrails.RequireConfirmation)

	// Reporting
	assert.NotNil(t, config.Reporting)
	assert.Equal(t, 2, len(config.Reporting.Formats))
	assert.Equal(t, "/tmp/reports", config.Reporting.OutputPath)
	assert.Equal(t, 1, len(config.Reporting.EmailTo))
	assert.Equal(t, 1, len(config.Reporting.Webhooks))
}

func TestParseYAML_InlineTargetValidation(t *testing.T) {
	tests := []struct {
		name    string
		yaml    []byte
		wantErr string
	}{
		{
			name: "inline target missing type",
			yaml: []byte(`
name: test-mission
target:
  inline:
    provider: openai
    model: gpt-4
workflow:
  reference: workflow-1
`),
			wantErr: "inline target must specify 'type'",
		},
		{
			name: "inline target missing provider",
			yaml: []byte(`
name: test-mission
target:
  inline:
    type: llm
    model: gpt-4
workflow:
  reference: workflow-1
`),
			wantErr: "inline target must specify 'provider'",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ParseYAML(tt.yaml)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.wantErr)
		})
	}
}

func TestParseYAML_InlineWorkflowValidation(t *testing.T) {
	yamlContent := []byte(`
name: test-mission
target:
  reference: target-1
workflow:
  inline:
    agents: []
    phases: []
`)

	_, err := ParseYAML(yamlContent)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "inline workflow must specify either 'agents' or 'phases'")
}
