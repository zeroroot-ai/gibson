package mission

import (
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/zero-day-ai/gibson/internal/agent"
	"gopkg.in/yaml.v3"
)

// MissionConfig represents a mission configuration loaded from YAML.
type MissionConfig struct {
	// Name is the mission name
	Name string `yaml:"name"`

	// Description describes what the mission does
	Description string `yaml:"description"`

	// Target specifies the target configuration
	Target MissionTargetConfig `yaml:"target"`

	// Workflow specifies the workflow configuration
	Workflow MissionWorkflowConfig `yaml:"workflow"`

	// Constraints defines execution constraints
	Constraints *MissionConstraintsConfig `yaml:"constraints,omitempty"`

	// Guardrails defines safety guardrails
	Guardrails *GuardrailConfig `yaml:"guardrails,omitempty"`

	// Reporting defines reporting options
	Reporting *ReportingConfig `yaml:"reporting,omitempty"`
}

// MissionTargetConfig specifies target configuration.
// Either Reference or Inline must be specified, not both.
type MissionTargetConfig struct {
	// Reference is a reference to an existing target by name or ID
	Reference string `yaml:"reference,omitempty"`

	// Inline defines an inline target configuration
	Inline *InlineTargetConfig `yaml:"inline,omitempty"`
}

// InlineTargetConfig defines an inline target configuration.
type InlineTargetConfig struct {
	Seeds    []*TargetSeedConfig `yaml:"seeds"`
	Profile  string              `yaml:"profile"`
	Depth    int32               `yaml:"depth"`
	Excluded []string            `yaml:"excluded,omitempty"`
	Metadata map[string]string   `yaml:"metadata,omitempty"`
}

// TargetSeedConfig defines a target seed for inline targets.
type TargetSeedConfig struct {
	Value string `yaml:"value"`
	Type  string `yaml:"type"`
	Scope string `yaml:"scope,omitempty"`
}

// ToInlineTarget converts InlineTargetConfig to InlineTarget.
func (c *InlineTargetConfig) ToInlineTarget() *InlineTarget {
	if c == nil {
		return nil
	}
	seeds := make([]*TargetSeed, len(c.Seeds))
	for i, s := range c.Seeds {
		seeds[i] = &TargetSeed{
			Value: s.Value,
			Type:  s.Type,
			Scope: s.Scope,
		}
	}
	// Convert string map to any map for Metadata
	var metadata map[string]any
	if len(c.Metadata) > 0 {
		metadata = make(map[string]any, len(c.Metadata))
		for k, v := range c.Metadata {
			metadata[k] = v
		}
	}
	return &InlineTarget{
		Seeds:    seeds,
		Profile:  c.Profile,
		Depth:    c.Depth,
		Excluded: c.Excluded,
		Metadata: metadata,
	}
}

// MissionWorkflowConfig specifies workflow configuration.
// Either Reference or Inline must be specified, not both.
type MissionWorkflowConfig struct {
	// Reference is a reference to an existing workflow by name or ID
	Reference string `yaml:"reference,omitempty"`

	// Inline defines an inline workflow configuration
	Inline *InlineWorkflowConfig `yaml:"inline,omitempty"`
}

// InlineWorkflowConfig defines an inline workflow configuration.
type InlineWorkflowConfig struct {
	Name     string                `yaml:"name,omitempty"`
	Nodes    []*WorkflowNodeConfig `yaml:"nodes"`
	Edges    []*WorkflowEdgeConfig `yaml:"edges,omitempty"`
	Metadata map[string]string     `yaml:"metadata,omitempty"`
}

// WorkflowNodeConfig defines a workflow node for inline workflows.
type WorkflowNodeConfig struct {
	ID        string            `yaml:"id"`
	Type      string            `yaml:"type"`
	Name      string            `yaml:"name"`
	DependsOn []string          `yaml:"depends_on,omitempty"`
	Config    map[string]string `yaml:"config,omitempty"`
}

// WorkflowEdgeConfig defines a workflow edge for inline workflows.
type WorkflowEdgeConfig struct {
	From      string `yaml:"from"`
	To        string `yaml:"to"`
	Condition string `yaml:"condition,omitempty"`
}

// ToInlineWorkflow converts InlineWorkflowConfig to InlineWorkflow.
func (c *InlineWorkflowConfig) ToInlineWorkflow() *InlineWorkflow {
	if c == nil {
		return nil
	}
	nodes := make([]*WorkflowNode, len(c.Nodes))
	for i, n := range c.Nodes {
		// Convert string map to any map for Config
		var config map[string]any
		if len(n.Config) > 0 {
			config = make(map[string]any, len(n.Config))
			for k, v := range n.Config {
				config[k] = v
			}
		}
		nodes[i] = &WorkflowNode{
			ID:        n.ID,
			Type:      n.Type,
			Name:      n.Name,
			DependsOn: n.DependsOn,
			Config:    config,
		}
	}
	edges := make([]*WorkflowEdge, len(c.Edges))
	for i, e := range c.Edges {
		edges[i] = &WorkflowEdge{
			From:      e.From,
			To:        e.To,
			Condition: e.Condition,
		}
	}
	// Convert string map to any map for Metadata
	var metadata map[string]any
	if len(c.Metadata) > 0 {
		metadata = make(map[string]any, len(c.Metadata))
		for k, v := range c.Metadata {
			metadata[k] = v
		}
	}
	return &InlineWorkflow{
		Name:     c.Name,
		Nodes:    nodes,
		Edges:    edges,
		Metadata: metadata,
	}
}

// MissionConstraintsConfig defines execution constraints.
type MissionConstraintsConfig struct {
	MaxDuration       string   `yaml:"max_duration,omitempty"`
	MaxFindings       *int     `yaml:"max_findings,omitempty"`
	MaxCost           *float64 `yaml:"max_cost,omitempty"`
	SeverityThreshold *string  `yaml:"severity_threshold,omitempty"`
	RequireApproval   *bool    `yaml:"require_approval,omitempty"`
}

// GuardrailConfig defines safety guardrails.
type GuardrailConfig struct {
	MaxTokens           *int64   `yaml:"max_tokens,omitempty"`
	RateLimitRPS        *int     `yaml:"rate_limit_rps,omitempty"`
	AllowedAgents       []string `yaml:"allowed_agents,omitempty"`
	BlockedAgents       []string `yaml:"blocked_agents,omitempty"`
	RequireConfirmation *bool    `yaml:"require_confirmation,omitempty"`
}

// ReportingConfig defines reporting options.
type ReportingConfig struct {
	Formats    []string `yaml:"formats,omitempty"`
	OutputPath string   `yaml:"output_path,omitempty"`
	EmailTo    []string `yaml:"email_to,omitempty"`
	Webhooks   []string `yaml:"webhooks,omitempty"`
}

// LoadFromFile loads a mission configuration from a YAML file.
// Supports both .yaml and .yml extensions.
// Performs environment variable interpolation using ${VAR} syntax.
func LoadFromFile(path string) (*MissionConfig, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("failed to open file: %w", err)
	}
	defer file.Close()

	return LoadFromReader(file)
}

// LoadFromReader loads a mission configuration from an io.Reader.
// This is useful for testing and reading from non-file sources.
func LoadFromReader(reader io.Reader) (*MissionConfig, error) {
	// Read the entire content
	data, err := io.ReadAll(reader)
	if err != nil {
		return nil, fmt.Errorf("failed to read content: %w", err)
	}

	// Use ParseYAML to parse the bytes
	return ParseYAML(data)
}

// ParseYAML parses a mission configuration from raw YAML bytes.
// This function is useful for parsing mission YAML from sources other than files,
// such as network requests or embedded data.
//
// The parser performs:
// - Environment variable expansion using ${VAR} syntax
// - Strict YAML parsing (fails on unknown fields)
// - Comprehensive validation of required fields and constraints
//
// Parameters:
//   - data: Raw YAML bytes containing the mission configuration
//
// Returns:
//   - *MissionConfig: The parsed and validated mission configuration
//   - error: Detailed error with validation messages, or nil on success
//
// Example usage:
//
//	yamlData := []byte(`
//	name: Example Mission
//	target:
//	  reference: my-target
//	workflow:
//	  reference: my-workflow
//	`)
//	config, err := ParseYAML(yamlData)
func ParseYAML(data []byte) (*MissionConfig, error) {
	// Expand environment variables
	content := expandEnvVars(string(data))

	// Parse YAML
	var config MissionConfig
	decoder := yaml.NewDecoder(strings.NewReader(content))
	decoder.KnownFields(true) // Strict mode - fail on unknown fields

	if err := decoder.Decode(&config); err != nil {
		return nil, formatYAMLError(err)
	}

	// Validate configuration
	if err := validateConfig(&config); err != nil {
		return nil, err
	}

	return &config, nil
}

// expandEnvVars expands environment variables in the format ${VAR} or $VAR.
func expandEnvVars(content string) string {
	return os.ExpandEnv(content)
}

// validateConfig validates the mission configuration.
func validateConfig(config *MissionConfig) error {
	if config.Name == "" {
		return NewValidationError("mission name is required")
	}

	// Validate target configuration
	if config.Target.Reference == "" && config.Target.Inline == nil {
		return NewValidationError("target must specify either 'reference' or 'inline'")
	}

	if config.Target.Reference != "" && config.Target.Inline != nil {
		return NewValidationError("target cannot specify both 'reference' and 'inline'")
	}

	// Validate inline target if specified
	if config.Target.Inline != nil {
		if len(config.Target.Inline.Seeds) == 0 {
			return NewValidationError("inline target must specify at least one seed")
		}
		if config.Target.Inline.Profile == "" {
			return NewValidationError("inline target must specify 'profile'")
		}
	}

	// Validate workflow configuration
	if config.Workflow.Reference == "" && config.Workflow.Inline == nil {
		return NewValidationError("workflow must specify either 'reference' or 'inline'")
	}

	if config.Workflow.Reference != "" && config.Workflow.Inline != nil {
		return NewValidationError("workflow cannot specify both 'reference' and 'inline'")
	}

	// Validate inline workflow if specified
	if config.Workflow.Inline != nil {
		if len(config.Workflow.Inline.Nodes) == 0 {
			return NewValidationError("inline workflow must specify at least one node")
		}
	}

	// Validate constraints if specified
	if config.Constraints != nil {
		if err := validateConstraints(config.Constraints); err != nil {
			return err
		}
	}

	return nil
}

// validateConstraints validates constraint configuration.
func validateConstraints(constraints *MissionConstraintsConfig) error {
	// Validate max_duration if specified
	if constraints.MaxDuration != "" {
		_, err := time.ParseDuration(constraints.MaxDuration)
		if err != nil {
			return NewValidationError(fmt.Sprintf("invalid max_duration format: %v (use format like '1h30m')", err))
		}
	}

	// Validate max_findings if specified
	if constraints.MaxFindings != nil && *constraints.MaxFindings <= 0 {
		return NewValidationError("max_findings must be greater than 0")
	}

	// Validate max_cost if specified
	if constraints.MaxCost != nil && *constraints.MaxCost <= 0 {
		return NewValidationError("max_cost must be greater than 0")
	}

	// Validate severity_threshold if specified
	if constraints.SeverityThreshold != nil {
		validSeverities := []string{"info", "low", "medium", "high", "critical"}
		valid := false
		for _, s := range validSeverities {
			if strings.ToLower(*constraints.SeverityThreshold) == s {
				valid = true
				break
			}
		}
		if !valid {
			return NewValidationError(fmt.Sprintf("invalid severity_threshold: %s (must be one of: %s)",
				*constraints.SeverityThreshold, strings.Join(validSeverities, ", ")))
		}
	}

	return nil
}

// formatYAMLError formats YAML parsing errors with line numbers.
func formatYAMLError(err error) error {
	// Extract line number from yaml.TypeError if available
	var typeErr *yaml.TypeError
	if yamlErr, ok := err.(*yaml.TypeError); ok {
		typeErr = yamlErr
	}

	if typeErr != nil && len(typeErr.Errors) > 0 {
		// Format with line-specific errors
		var errMsgs []string
		for _, e := range typeErr.Errors {
			errMsgs = append(errMsgs, e)
		}
		return NewValidationError(fmt.Sprintf("YAML validation failed:\n  %s", strings.Join(errMsgs, "\n  ")))
	}

	// For other errors, try to extract line number from error message
	errMsg := err.Error()
	if strings.Contains(errMsg, "line") {
		return NewValidationError(fmt.Sprintf("YAML parsing failed: %s", errMsg))
	}

	return NewValidationError(fmt.Sprintf("failed to parse YAML: %v", err))
}

// ToConstraints converts MissionConstraintsConfig to MissionConstraints.
func (c *MissionConstraintsConfig) ToConstraints() (*MissionConstraints, error) {
	constraints := &MissionConstraints{}

	if c.MaxDuration != "" {
		duration, err := time.ParseDuration(c.MaxDuration)
		if err != nil {
			return nil, fmt.Errorf("invalid max_duration: %w", err)
		}
		constraints.MaxDuration = duration
	}

	if c.MaxFindings != nil {
		constraints.MaxFindings = *c.MaxFindings
	}

	if c.MaxCost != nil {
		constraints.MaxCost = *c.MaxCost
	}

	if c.SeverityThreshold != nil {
		// Convert string to FindingSeverity
		// This is a simplified conversion - in production, use proper validation
		constraints.SeverityThreshold = agent.FindingSeverity(*c.SeverityThreshold)
	}

	// RequireApproval doesn't exist in MissionConstraints, removed

	return constraints, nil
}
