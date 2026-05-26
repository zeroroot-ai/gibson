package plan

import (
	"context"
	"fmt"
	"sync"

	"github.com/zeroroot-ai/gibson/internal/agent"
	"github.com/zeroroot-ai/gibson/internal/guardrail"
	"github.com/zeroroot-ai/gibson/internal/harness"
	"github.com/zeroroot-ai/gibson/internal/types"
)

// executeTool executes a tool step.
// It calls the tool through the harness using CallToolProto and returns the output.
// Tools don't produce findings directly.
func (e *PlanExecutor) executeTool(ctx context.Context, step *ExecutionStep, h harness.AgentHarness) (map[string]any, []agent.Finding, error) {
	if step.ToolName == "" {
		return nil, nil, fmt.Errorf("tool name is required for tool step")
	}

	e.logger.Debug("executing tool step",
		"tool_name", step.ToolName,
		"step_id", step.ID,
	)

	// Get tool descriptor to determine proto types
	toolDesc, err := h.GetToolDescriptor(ctx, step.ToolName)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get tool descriptor: %w", err)
	}

	// Check if tool supports proto execution
	if toolDesc.InputProtoType == "" || toolDesc.OutputProtoType == "" {
		return nil, nil, fmt.Errorf("tool %s does not support proto execution", step.ToolName)
	}

	e.logger.Debug("tool proto types",
		"tool_name", step.ToolName,
		"input_type", toolDesc.InputProtoType,
		"output_type", toolDesc.OutputProtoType,
	)

	// Convert step.ToolInput (map[string]any) to proto request
	inputMsg, err := mapToProtoMessage(step.ToolInput, toolDesc.InputProtoType)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to convert input to proto: %w", err)
	}

	// Create output proto message
	outputMsg, err := createProtoMessage(toolDesc.OutputProtoType)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create output proto: %w", err)
	}

	// Call the tool through the harness using CallToolProto
	err = h.CallToolProto(ctx, step.ToolName, inputMsg, outputMsg)
	if err != nil {
		return nil, nil, fmt.Errorf("tool execution failed: %w", err)
	}

	// Convert proto response back to map[string]any for mission output
	output, err := protoMessageToMap(outputMsg)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to convert output from proto: %w", err)
	}

	// Tools don't produce findings directly
	return output, []agent.Finding{}, nil
}

// executePlugin executes a plugin step.
// It calls the plugin method through the harness and converts the result to a map.
// Plugins don't produce findings directly.
func (e *PlanExecutor) executePlugin(ctx context.Context, step *ExecutionStep, h harness.AgentHarness) (map[string]any, []agent.Finding, error) {
	if step.PluginName == "" {
		return nil, nil, fmt.Errorf("plugin name is required for plugin step")
	}
	if step.PluginMethod == "" {
		return nil, nil, fmt.Errorf("plugin method is required for plugin step")
	}

	e.logger.Debug("executing plugin step",
		"plugin_name", step.PluginName,
		"method", step.PluginMethod,
		"step_id", step.ID,
	)

	// Call the plugin method through the harness
	result, err := h.QueryPlugin(ctx, step.PluginName, step.PluginMethod, step.PluginParams)
	if err != nil {
		return nil, nil, fmt.Errorf("plugin execution failed: %w", err)
	}

	// Convert result to map[string]any
	output := make(map[string]any)
	if result != nil {
		// If result is already a map, use it directly
		if resultMap, ok := result.(map[string]any); ok {
			output = resultMap
		} else {
			// Otherwise, wrap it
			output["result"] = result
		}
	}

	// Plugins don't produce findings directly
	return output, []agent.Finding{}, nil
}

// executeAgent executes an agent delegation step.
// It delegates the task to another agent through the harness and extracts findings
// from the agent result.
func (e *PlanExecutor) executeAgent(ctx context.Context, step *ExecutionStep, h harness.AgentHarness) (map[string]any, []agent.Finding, error) {
	if step.AgentName == "" {
		return nil, nil, fmt.Errorf("agent name is required for agent step")
	}
	if step.AgentTask == nil {
		return nil, nil, fmt.Errorf("agent task is required for agent step")
	}

	e.logger.Debug("executing agent delegation step",
		"agent_name", step.AgentName,
		"step_id", step.ID,
	)

	// Delegate to the agent through the harness
	result, err := h.DelegateToAgent(ctx, step.AgentName, *step.AgentTask)
	if err != nil {
		return nil, nil, fmt.Errorf("agent delegation failed: %w", err)
	}

	// Extract findings from agent result
	findings := result.Findings

	// Convert agent output to map[string]any
	output := make(map[string]any)
	if result.Output != nil {
		output = result.Output
	}

	// Add agent result metadata
	output["agent_status"] = string(result.Status)
	output["agent_task_id"] = result.TaskID.String()

	return output, findings, nil
}

// executeCondition executes a condition step.
// It evaluates the condition expression and returns the result.
// For now, this uses simple string matching. A production implementation
// would use a proper expression evaluator.
func (e *PlanExecutor) executeCondition(ctx context.Context, step *ExecutionStep, results map[types.ID]*StepResult) (map[string]any, error) {
	if step.Condition == nil {
		return nil, fmt.Errorf("condition is required for condition step")
	}

	e.logger.Debug("executing condition step",
		"step_id", step.ID,
	)

	// Simple string match evaluation for now
	// In a real implementation, this would use a proper expression evaluator
	expression := step.Condition.Expression

	// For now, just check if the expression is non-empty as a simple boolean
	// A production implementation would parse and evaluate the expression properly
	result := expression != "" && expression != "false"

	output := make(map[string]any)
	output["result"] = result
	if result {
		output["branch"] = "true"
	} else {
		output["branch"] = "false"
	}
	output["expression"] = expression

	return output, nil
}

// executeParallel executes parallel steps concurrently.
// It spawns goroutines for each parallel step, waits for all to complete,
// and aggregates the results and findings.
func (e *PlanExecutor) executeParallel(ctx context.Context, step *ExecutionStep, h harness.AgentHarness) (map[string]any, []agent.Finding, error) {
	if len(step.ParallelSteps) == 0 {
		return nil, nil, fmt.Errorf("parallel steps are required for parallel step")
	}

	e.logger.Debug("executing parallel step",
		"step_id", step.ID,
		"parallel_steps", len(step.ParallelSteps),
	)

	var wg sync.WaitGroup
	resultsChan := make(chan *StepResult, len(step.ParallelSteps))
	errorsChan := make(chan error, len(step.ParallelSteps))

	// Execute each parallel step concurrently
	for i := range step.ParallelSteps {
		wg.Add(1)
		go func(parallelStep *ExecutionStep) {
			defer wg.Done()

			result, err := e.executeStep(ctx, parallelStep, h)
			if err != nil {
				errorsChan <- fmt.Errorf("parallel step %s failed: %w", parallelStep.Name, err)
				return
			}
			resultsChan <- result
		}(&step.ParallelSteps[i])
	}

	// Wait for all goroutines to complete
	wg.Wait()
	close(resultsChan)
	close(errorsChan)

	// Check for errors
	var errors []error
	for err := range errorsChan {
		errors = append(errors, err)
	}
	if len(errors) > 0 {
		return nil, nil, fmt.Errorf("parallel execution had %d error(s): %v", len(errors), errors[0])
	}

	// Collect results and aggregate findings
	var allFindings []agent.Finding
	outputs := make(map[string]any)
	stepResults := make([]map[string]any, 0, len(step.ParallelSteps))

	for result := range resultsChan {
		allFindings = append(allFindings, result.Findings...)
		stepResults = append(stepResults, map[string]any{
			"step_id":  result.StepID.String(),
			"status":   string(result.Status),
			"output":   result.Output,
			"duration": result.Duration.Milliseconds(),
		})
	}

	outputs["parallel_results"] = stepResults
	outputs["total_findings"] = len(allFindings)

	return outputs, allFindings, nil
}

// runInputGuardrails runs input guardrails on a step before execution.
// It builds a GuardrailInput from the step data and processes it through
// the configured input guardrail pipeline.
func (e *PlanExecutor) runInputGuardrails(ctx context.Context, step *ExecutionStep, h harness.AgentHarness) error {
	if e.guardrails == nil {
		return nil
	}

	// Build GuardrailInput from step data
	input := guardrail.GuardrailInput{
		Content:  step.Description,
		Metadata: make(map[string]any),
	}

	// Add step-specific metadata
	input.Metadata["step_id"] = step.ID.String()
	input.Metadata["step_type"] = string(step.Type)
	input.Metadata["step_name"] = step.Name

	// Add type-specific fields
	switch step.Type {
	case StepTypeTool:
		input.ToolName = step.ToolName
		input.ToolInput = step.ToolInput
	case StepTypeAgent:
		input.AgentName = step.AgentName
	}

	// Get mission context from harness
	missionCtx := h.Mission()
	input.MissionContext = &missionCtx

	// Get target info from harness
	targetInfo := h.Target()
	input.TargetInfo = &targetInfo

	// Process input through guardrails
	_, err := e.guardrails.ProcessInput(ctx, input)
	if err != nil {
		return fmt.Errorf("input guardrail check failed: %w", err)
	}

	return nil
}

// runOutputGuardrails runs output guardrails on a step's output after execution.
// It builds a GuardrailOutput from the step output and processes it through
// the configured output guardrail pipeline.
func (e *PlanExecutor) runOutputGuardrails(ctx context.Context, step *ExecutionStep, output map[string]any, h harness.AgentHarness) error {
	if e.guardrails == nil {
		return nil
	}

	// Build GuardrailOutput from step output
	guardrailOutput := guardrail.GuardrailOutput{
		Content:    fmt.Sprintf("%v", output),
		ToolOutput: output,
		Metadata:   make(map[string]any),
	}

	// Add step-specific metadata
	guardrailOutput.Metadata["step_id"] = step.ID.String()
	guardrailOutput.Metadata["step_type"] = string(step.Type)
	guardrailOutput.Metadata["step_name"] = step.Name

	// Process output through guardrails
	_, err := e.guardrails.ProcessOutput(ctx, guardrailOutput)
	if err != nil {
		return fmt.Errorf("output guardrail check failed: %w", err)
	}

	return nil
}
