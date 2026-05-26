package plan

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/zeroroot-ai/gibson/internal/harness"
	"github.com/zeroroot-ai/gibson/internal/llm"
	"github.com/zeroroot-ai/gibson/internal/types"
)

// LLMPlanGenerator generates execution plans using an LLM to analyze tasks
// and available resources (tools, plugins, agents) to create optimal execution strategies.
type LLMPlanGenerator struct {
	slot         string
	riskAssessor *RiskAssessor
	maxRetries   int
}

// LLMGeneratorOption is a functional option for configuring an LLMPlanGenerator.
type LLMGeneratorOption func(*LLMPlanGenerator)

// NewLLMPlanGenerator creates a new LLM-based plan generator with the specified options.
// Default configuration:
//   - slot: "planner"
//   - maxRetries: 3
//   - riskAssessor: NewRiskAssessor(WithDefaultRules())
func NewLLMPlanGenerator(opts ...LLMGeneratorOption) *LLMPlanGenerator {
	gen := &LLMPlanGenerator{
		slot:         "planner",
		riskAssessor: NewRiskAssessor(WithDefaultRules()),
		maxRetries:   3,
	}

	for _, opt := range opts {
		opt(gen)
	}

	return gen
}

// WithSlot sets the LLM slot to use for plan generation.
func WithSlot(slot string) LLMGeneratorOption {
	return func(g *LLMPlanGenerator) {
		g.slot = slot
	}
}

// WithRiskAssessor sets the risk assessor to use for evaluating generated steps.
func WithRiskAssessor(assessor *RiskAssessor) LLMGeneratorOption {
	return func(g *LLMPlanGenerator) {
		g.riskAssessor = assessor
	}
}

// WithMaxRetries sets the maximum number of retries for plan generation on parse errors.
func WithMaxRetries(n int) LLMGeneratorOption {
	return func(g *LLMPlanGenerator) {
		g.maxRetries = n
	}
}

// Generate creates an execution plan based on the provided input and harness.
// The method performs the following steps:
//
//  1. Validates the input to ensure required fields are present
//  2. Builds a system prompt describing available tools, plugins, and agents
//  3. Builds a user prompt with the task description and constraints
//  4. Calls the LLM via harness.Complete() to generate a plan
//  5. Parses the JSON response into an ExecutionPlan structure
//  6. Validates that the plan has at least one step
//  7. Assesses risk for each step using the risk assessor
//  8. Retries on parse errors up to maxRetries times
//
// Parameters:
//   - ctx: Context for cancellation and timeout control
//   - input: Input parameters including task, available resources, and constraints
//   - h: Agent harness providing access to AI capabilities for plan generation
//
// Returns:
//   - *ExecutionPlan: The generated and validated execution plan
//   - error: Any error encountered during plan generation or validation
func (g *LLMPlanGenerator) Generate(ctx context.Context, input GenerateInput, h harness.AgentHarness) (*ExecutionPlan, error) {
	// Validate input
	if err := input.Validate(); err != nil {
		return nil, fmt.Errorf("invalid input: %w", err)
	}

	// Build prompts
	systemPrompt := buildSystemPrompt(input)
	userPrompt := buildUserPrompt(input)

	messages := []llm.Message{
		llm.NewSystemMessage(systemPrompt),
		llm.NewUserMessage(userPrompt),
	}

	// Try to generate and parse the plan with retries
	var plan *ExecutionPlan
	var lastErr error

	for attempt := 0; attempt <= g.maxRetries; attempt++ {
		// Call LLM to generate plan
		resp, err := h.Complete(ctx, g.slot, messages)
		if err != nil {
			return nil, fmt.Errorf("failed to generate plan: %w", err)
		}

		// Parse the response
		plan, err = parseGeneratedPlan(resp.Message.Content)
		if err != nil {
			lastErr = err
			if attempt < g.maxRetries {
				// Add feedback to retry with corrections
				messages = append(messages,
					llm.NewAssistantMessage(resp.Message.Content),
					llm.NewUserMessage(fmt.Sprintf("The plan could not be parsed: %v. Please provide a valid JSON response following the exact schema specified.", err)),
				)
				continue
			}
			return nil, fmt.Errorf("failed to parse plan after %d attempts: %w", g.maxRetries+1, lastErr)
		}

		// Successfully parsed
		break
	}

	// Validate plan has at least one step
	if len(plan.Steps) == 0 {
		return nil, fmt.Errorf("generated plan has no steps")
	}

	// Set plan metadata
	plan.ID = types.NewID()
	if input.Task.MissionID != nil {
		plan.MissionID = *input.Task.MissionID
	}
	plan.AgentName = h.Mission().CurrentAgent
	plan.Status = PlanStatusDraft
	plan.CreatedAt = time.Now()
	plan.UpdatedAt = time.Now()

	// Assess risk for each step
	mission := h.Mission()
	target := h.Target()
	riskCtx := RiskContext{
		Mission: &mission,
		Target:  &target,
	}

	for i := range plan.Steps {
		step := &plan.Steps[i]

		// Generate step ID if not present
		if step.ID == "" {
			step.ID = types.NewID()
		}

		// Set sequence number
		step.Sequence = i + 1
		step.Status = StepStatusPending

		// Assess risk
		assessment := g.riskAssessor.AssessStep(step, riskCtx)

		// Update step with risk assessment
		step.RiskLevel = assessment.Level
		step.RequiresApproval = assessment.RequiresApproval
		step.RiskRationale = assessment.Rationale
	}

	// Create plan risk summary
	planAssessment := g.riskAssessor.AssessPlan(plan, riskCtx)
	plan.RiskSummary = &planAssessment

	return plan, nil
}

// buildSystemPrompt creates the system prompt that instructs the LLM on how to generate plans.
// It describes the available resources (tools, plugins, agents) and the expected output format.
func buildSystemPrompt(input GenerateInput) string {
	var sb strings.Builder

	sb.WriteString("You are an expert mission planning AI for cybersecurity operations. ")
	sb.WriteString("Your task is to analyze the given mission task and create a detailed, step-by-step execution plan.\n\n")

	sb.WriteString("# Available Resources\n\n")

	// Document available tools
	if len(input.AvailableTools) > 0 {
		sb.WriteString("## Tools\n")
		sb.WriteString("The following tools are available for use:\n\n")
		for _, tool := range input.AvailableTools {
			sb.WriteString(fmt.Sprintf("- **%s**: %s\n", tool.Name, tool.Description))
			if len(tool.Tags) > 0 {
				sb.WriteString(fmt.Sprintf("  Tags: %s\n", strings.Join(tool.Tags, ", ")))
			}
		}
		sb.WriteString("\n")
	}

	// Document available plugins
	if len(input.AvailablePlugins) > 0 {
		sb.WriteString("## Plugins\n")
		sb.WriteString("The following plugins are available for use:\n\n")
		for _, plugin := range input.AvailablePlugins {
			sb.WriteString(fmt.Sprintf("- **%s** (v%s): Available methods:\n", plugin.Name, plugin.Version))
			for _, method := range plugin.Methods {
				sb.WriteString(fmt.Sprintf("  - `%s`: %s\n", method.Name, method.Description))
			}
		}
		sb.WriteString("\n")
	}

	// Document available agents
	if len(input.AvailableAgents) > 0 {
		sb.WriteString("## Agents\n")
		sb.WriteString("The following specialized agents are available for delegation:\n\n")
		for _, agent := range input.AvailableAgents {
			sb.WriteString(fmt.Sprintf("- **%s**: %s\n", agent.Name, agent.Description))
			if len(agent.Capabilities) > 0 {
				sb.WriteString(fmt.Sprintf("  Capabilities: %s\n", strings.Join(agent.Capabilities, ", ")))
			}
		}
		sb.WriteString("\n")
	}

	// Output format specification
	sb.WriteString("# Output Format\n\n")
	sb.WriteString("You MUST respond with a valid JSON object following this exact schema:\n\n")
	sb.WriteString("```json\n")
	sb.WriteString("{\n")
	sb.WriteString("  \"steps\": [\n")
	sb.WriteString("    {\n")
	sb.WriteString("      \"name\": \"step name\",\n")
	sb.WriteString("      \"description\": \"what this step does\",\n")
	sb.WriteString("      \"type\": \"tool|plugin|agent\",\n")
	sb.WriteString("      \"tool_name\": \"for tool type\",\n")
	sb.WriteString("      \"tool_input\": {},\n")
	sb.WriteString("      \"plugin_name\": \"for plugin type\",\n")
	sb.WriteString("      \"plugin_method\": \"method name\",\n")
	sb.WriteString("      \"plugin_params\": {},\n")
	sb.WriteString("      \"agent_name\": \"for agent type\",\n")
	sb.WriteString("      \"depends_on\": []\n")
	sb.WriteString("    }\n")
	sb.WriteString("  ]\n")
	sb.WriteString("}\n")
	sb.WriteString("```\n\n")

	sb.WriteString("## Step Types\n\n")
	sb.WriteString("- **tool**: Execute a tool. Requires `tool_name` and `tool_input` fields.\n")
	sb.WriteString("- **plugin**: Call a plugin method. Requires `plugin_name`, `plugin_method`, and `plugin_params` fields.\n")
	sb.WriteString("- **agent**: Delegate to another agent. Requires `agent_name` field.\n\n")

	sb.WriteString("## Dependencies\n\n")
	sb.WriteString("The `depends_on` field is an array of step names that must complete before this step can execute. ")
	sb.WriteString("Use this to create sequential or parallel execution flows.\n\n")

	sb.WriteString("## Planning Guidelines\n\n")
	sb.WriteString("- Break complex tasks into smaller, manageable steps\n")
	sb.WriteString("- Use the most appropriate resource type (tool, plugin, or agent) for each step\n")
	sb.WriteString("- Consider dependencies and execution order\n")
	sb.WriteString("- Be specific in step descriptions and inputs\n")
	sb.WriteString("- Optimize for parallel execution where possible\n")
	sb.WriteString("- Ensure each step has a clear, measurable outcome\n")

	return sb.String()
}

// buildUserPrompt creates the user prompt containing the task details and constraints.
func buildUserPrompt(input GenerateInput) string {
	var sb strings.Builder

	sb.WriteString("# Mission Task\n\n")
	sb.WriteString(fmt.Sprintf("**Task Name**: %s\n\n", input.Task.Name))
	sb.WriteString(fmt.Sprintf("**Description**: %s\n\n", input.Task.Description))

	// Include task input parameters
	if len(input.Task.Input) > 0 {
		sb.WriteString("**Input Parameters**:\n")
		for key, value := range input.Task.Input {
			sb.WriteString(fmt.Sprintf("- %s: %v\n", key, value))
		}
		sb.WriteString("\n")
	}

	// Include constraints if present
	if len(input.Constraints) > 0 {
		sb.WriteString("# Constraints\n\n")
		sb.WriteString("The execution plan MUST respect the following constraints:\n\n")
		for _, constraint := range input.Constraints {
			sb.WriteString(fmt.Sprintf("- %s\n", constraint))
		}
		sb.WriteString("\n")
	}

	sb.WriteString("Please generate a detailed execution plan for this task using the available resources. ")
	sb.WriteString("Respond ONLY with the JSON object - no additional explanation or formatting.")

	return sb.String()
}

// parseGeneratedPlan parses the LLM's JSON response into an ExecutionPlan structure.
// Supports both raw JSON and markdown-wrapped JSON (```json ... ```).
func parseGeneratedPlan(response string) (*ExecutionPlan, error) {
	// Extract JSON from markdown code blocks if present
	extractedJSON, err := llm.ExtractJSON(response)
	if err != nil {
		return nil, fmt.Errorf("failed to extract JSON from response: %w", err)
	}

	// Parse the JSON structure
	var parsed struct {
		Steps []struct {
			Name         string         `json:"name"`
			Description  string         `json:"description"`
			Type         string         `json:"type"`
			ToolName     string         `json:"tool_name,omitempty"`
			ToolInput    map[string]any `json:"tool_input,omitempty"`
			PluginName   string         `json:"plugin_name,omitempty"`
			PluginMethod string         `json:"plugin_method,omitempty"`
			PluginParams map[string]any `json:"plugin_params,omitempty"`
			AgentName    string         `json:"agent_name,omitempty"`
			DependsOn    []string       `json:"depends_on,omitempty"`
		} `json:"steps"`
	}

	if err := json.Unmarshal([]byte(extractedJSON), &parsed); err != nil {
		return nil, fmt.Errorf("failed to unmarshal JSON: %w", err)
	}

	// Convert to ExecutionPlan
	plan := &ExecutionPlan{
		Steps: make([]ExecutionStep, 0, len(parsed.Steps)),
	}

	// Create a map of step names to IDs for dependency resolution
	stepNameToID := make(map[string]types.ID)
	for i, stepData := range parsed.Steps {
		stepID := types.NewID()
		stepNameToID[stepData.Name] = stepID

		step := ExecutionStep{
			ID:          stepID,
			Sequence:    i + 1,
			Type:        StepType(stepData.Type),
			Name:        stepData.Name,
			Description: stepData.Description,
			Status:      StepStatusPending,
		}

		// Set type-specific fields
		switch StepType(stepData.Type) {
		case StepTypeTool:
			step.ToolName = stepData.ToolName
			step.ToolInput = stepData.ToolInput
			if step.ToolInput == nil {
				step.ToolInput = make(map[string]any)
			}

		case StepTypePlugin:
			step.PluginName = stepData.PluginName
			step.PluginMethod = stepData.PluginMethod
			step.PluginParams = stepData.PluginParams
			if step.PluginParams == nil {
				step.PluginParams = make(map[string]any)
			}

		case StepTypeAgent:
			step.AgentName = stepData.AgentName
		}

		plan.Steps = append(plan.Steps, step)
	}

	// Resolve dependencies after all steps are created
	for i, stepData := range parsed.Steps {
		if len(stepData.DependsOn) > 0 {
			dependencyIDs := make([]types.ID, 0, len(stepData.DependsOn))
			for _, depName := range stepData.DependsOn {
				if depID, exists := stepNameToID[depName]; exists {
					dependencyIDs = append(dependencyIDs, depID)
				}
			}
			plan.Steps[i].DependsOn = dependencyIDs
		}
	}

	return plan, nil
}
