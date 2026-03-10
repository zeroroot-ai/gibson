package payload

import (
	"context"
	"fmt"
	"time"

	"github.com/zero-day-ai/gibson/internal/agent"
	"github.com/zero-day-ai/gibson/internal/finding"
	"github.com/zero-day-ai/gibson/internal/registry"
	"github.com/zero-day-ai/gibson/internal/types"
)

// PayloadExecutor orchestrates the execution of payloads against targets
type PayloadExecutor interface {
	// Execute runs a payload against a target and returns the result
	Execute(ctx context.Context, req *ExecutionRequest) (*ExecutionResult, error)

	// ExecuteDryRun validates and simulates payload execution without actually running it
	ExecuteDryRun(ctx context.Context, req *ExecutionRequest) (*DryRunResult, error)

	// ValidateParameters checks if provided parameters match the payload's requirements
	ValidateParameters(payload *Payload, params map[string]interface{}) error
}

// ExecutorConfig holds configuration for the payload executor
type ExecutorConfig struct {
	DefaultTimeout    time.Duration
	CreateFindings    bool // Whether to create findings on successful attacks
	StoreExecutions   bool // Whether to store execution records
	MaxResponseLength int  // Maximum length of response to store (0 = unlimited)
}

// DefaultExecutorConfig returns the default executor configuration
func DefaultExecutorConfig() ExecutorConfig {
	return ExecutorConfig{
		DefaultTimeout:    5 * time.Minute,
		CreateFindings:    true,
		StoreExecutions:   true,
		MaxResponseLength: 10000, // 10KB
	}
}

// payloadExecutor implements PayloadExecutor
type payloadExecutor struct {
	config         ExecutorConfig
	substitutor    ParameterSubstitutor
	matcher        IndicatorMatcher
	registry       PayloadRegistry
	executionStore ExecutionStore
	findingStore   finding.FindingStore
	discovery      registry.ComponentDiscovery
}

// NewPayloadExecutor creates a new payload executor
func NewPayloadExecutor(
	registry PayloadRegistry,
	executionStore ExecutionStore,
	findingStore finding.FindingStore,
	discovery registry.ComponentDiscovery,
	config ExecutorConfig,
) PayloadExecutor {
	return &payloadExecutor{
		config:         config,
		substitutor:    NewParameterSubstitutor(),
		matcher:        NewIndicatorMatcher(),
		registry:       registry,
		executionStore: executionStore,
		findingStore:   findingStore,
		discovery:      discovery,
	}
}

// NewPayloadExecutorWithDefaults creates a new payload executor with default configuration
func NewPayloadExecutorWithDefaults(
	registry PayloadRegistry,
	executionStore ExecutionStore,
	findingStore finding.FindingStore,
	discovery registry.ComponentDiscovery,
) PayloadExecutor {
	return NewPayloadExecutor(registry, executionStore, findingStore, discovery, DefaultExecutorConfig())
}

// Execute runs a payload against a target
func (e *payloadExecutor) Execute(ctx context.Context, req *ExecutionRequest) (*ExecutionResult, error) {
	// Validate request
	if req == nil {
		return nil, fmt.Errorf("execution request cannot be nil")
	}
	if req.PayloadID == "" {
		return nil, fmt.Errorf("payload ID is required")
	}
	if req.TargetID == "" {
		return nil, fmt.Errorf("target ID is required")
	}

	// Get payload
	payload, err := e.registry.Get(ctx, req.PayloadID)
	if err != nil {
		return nil, fmt.Errorf("failed to get payload: %w", err)
	}

	// Check if payload is enabled
	if !payload.Enabled {
		return nil, fmt.Errorf("payload %s is disabled", payload.ID)
	}

	// Create execution record
	execution := NewExecution(req.PayloadID, req.TargetID, req.AgentID)
	execution.MissionID = req.MissionID
	execution.Parameters = req.Parameters
	if req.Metadata != nil {
		execution.Metadata = req.Metadata
	}

	// Set agent ID if specified in request
	if req.AgentID == "" {
		// Use default agent if not specified
		execution.AgentID = types.ID("default-agent")
	}

	// Apply timeout if specified
	execCtx := ctx
	if req.Timeout > 0 {
		var cancel context.CancelFunc
		execCtx, cancel = context.WithTimeout(ctx, req.Timeout)
		defer cancel()
	} else if e.config.DefaultTimeout > 0 {
		var cancel context.CancelFunc
		execCtx, cancel = context.WithTimeout(ctx, e.config.DefaultTimeout)
		defer cancel()
	}

	// Validate and instantiate parameters
	if err := e.ValidateParameters(payload, req.Parameters); err != nil {
		execution.Status = ExecutionStatusFailed
		execution.ErrorMessage = fmt.Sprintf("Parameter validation failed: %v", err)
		execution.CompletedAt = timePtr(time.Now())
		if e.config.StoreExecutions {
			_ = e.executionStore.Save(ctx, execution)
		}
		return nil, fmt.Errorf("parameter validation failed: %w", err)
	}

	// Substitute parameters in template
	instantiatedText, err := e.substitutor.Substitute(payload.Template, req.Parameters, payload.Parameters)
	if err != nil {
		execution.Status = ExecutionStatusFailed
		execution.ErrorMessage = fmt.Sprintf("Parameter substitution failed: %v", err)
		execution.CompletedAt = timePtr(time.Now())
		if e.config.StoreExecutions {
			_ = e.executionStore.Save(ctx, execution)
		}
		return nil, fmt.Errorf("parameter substitution failed: %w", err)
	}
	execution.InstantiatedText = instantiatedText

	// Mark execution as running
	startTime := time.Now()
	execution.Status = ExecutionStatusRunning
	execution.StartedAt = &startTime

	// Execute the payload using the agent
	// For now, we'll create a simple interaction since full agent integration
	// may require more setup
	response, responseTimeMs, err := e.executePayloadWithAgent(execCtx, execution.AgentID, instantiatedText, req)

	// Calculate execution time
	endTime := time.Now()
	execution.CompletedAt = &endTime
	execution.ResponseTime = responseTimeMs

	// Handle execution errors
	if err != nil {
		// Check if it was a timeout
		if ctx.Err() == context.DeadlineExceeded {
			execution.Status = ExecutionStatusTimeout
			execution.ErrorMessage = "Execution timed out"
		} else if ctx.Err() == context.Canceled {
			execution.Status = ExecutionStatusCancelled
			execution.ErrorMessage = "Execution was cancelled"
		} else {
			execution.Status = ExecutionStatusFailed
			execution.ErrorMessage = fmt.Sprintf("Execution failed: %v", err)
		}

		if e.config.StoreExecutions {
			_ = e.executionStore.Save(ctx, execution)
		}

		// Create result
		result := NewExecutionResult(execution.ID)
		result.Status = execution.Status
		result.Success = false
		result.ErrorMessage = execution.ErrorMessage
		result.WithError(err)
		return result, err
	}

	// Store response (truncate if necessary)
	execution.Response = response
	if e.config.MaxResponseLength > 0 && len(response) > e.config.MaxResponseLength {
		execution.Response = response[:e.config.MaxResponseLength]
		if execution.Metadata == nil {
			execution.Metadata = make(map[string]interface{})
		}
		execution.Metadata["response_truncated"] = true
		execution.Metadata["original_response_length"] = len(response)
	}

	// Evaluate success using indicators
	success, confidenceScore, matchedIndicators, err := e.matcher.Match(response, payload.SuccessIndicators)
	if err != nil {
		execution.ErrorMessage = fmt.Sprintf("Indicator matching failed: %v", err)
		// Don't fail the execution, just note the error
	} else {
		execution.Success = success
		execution.ConfidenceScore = confidenceScore
		execution.IndicatorsMatched = matchedIndicators
		execution.MatchDetails = make(map[string]interface{})
		execution.MatchDetails["matched_count"] = len(matchedIndicators)
	}

	// Mark execution as completed
	execution.Status = ExecutionStatusCompleted

	// Create finding if successful and configured to do so
	if execution.Success && e.config.CreateFindings && e.findingStore != nil {
		findingID, err := e.createFinding(ctx, payload, execution, response)
		if err != nil {
			// Log error but don't fail the execution
			execution.ErrorMessage = fmt.Sprintf("Failed to create finding: %v", err)
		} else {
			execution.FindingID = &findingID
			execution.FindingCreated = true
		}
	}

	// Store execution record
	if e.config.StoreExecutions && e.executionStore != nil {
		if err := e.executionStore.Save(ctx, execution); err != nil {
			// Log error but don't fail
			// In production, this would be logged
		}
	}

	// Create result
	result := NewExecutionResult(execution.ID)
	result.Status = execution.Status
	result.Success = execution.Success
	result.ConfidenceScore = execution.ConfidenceScore
	result.Response = execution.Response
	result.InstantiatedText = execution.InstantiatedText
	result.IndicatorsMatched = execution.IndicatorsMatched
	result.MatchDetails = execution.MatchDetails
	result.TokensUsed = execution.TokensUsed
	result.Cost = execution.Cost
	result.ResponseTime = time.Duration(execution.ResponseTime) * time.Millisecond
	if execution.StartedAt != nil {
		result.StartedAt = *execution.StartedAt
	}
	if execution.CompletedAt != nil {
		result.CompletedAt = *execution.CompletedAt
		result.Duration = execution.CompletedAt.Sub(*execution.StartedAt)
	}

	return result, nil
}

// ExecuteDryRun validates and simulates execution without actually running the payload
func (e *payloadExecutor) ExecuteDryRun(ctx context.Context, req *ExecutionRequest) (*DryRunResult, error) {
	// Validate request
	if req == nil {
		return nil, fmt.Errorf("execution request cannot be nil")
	}
	if req.PayloadID == "" {
		return nil, fmt.Errorf("payload ID is required")
	}
	if req.TargetID == "" {
		return nil, fmt.Errorf("target ID is required")
	}

	// Get payload
	payload, err := e.registry.Get(ctx, req.PayloadID)
	if err != nil {
		return nil, fmt.Errorf("failed to get payload: %w", err)
	}

	result := NewDryRunResult()

	// Check if payload is enabled
	if !payload.Enabled {
		result.AddWarning(fmt.Sprintf("Payload %s is disabled", payload.Name))
	}

	// Validate parameters
	if err := e.ValidateParameters(payload, req.Parameters); err != nil {
		result.AddValidationError(fmt.Sprintf("Parameter validation failed: %v", err))
		return result, nil
	}

	// Try to substitute parameters
	instantiatedText, err := e.substitutor.Substitute(payload.Template, req.Parameters, payload.Parameters)
	if err != nil {
		result.AddValidationError(fmt.Sprintf("Parameter substitution failed: %v", err))
		return result, nil
	}

	result.InstantiatedText = instantiatedText

	// Estimate tokens (rough estimate: ~4 chars per token)
	result.EstimatedTokens = len(instantiatedText) / 4

	// Check for potential issues
	if len(instantiatedText) == 0 {
		result.AddWarning("Instantiated text is empty")
	}

	if len(instantiatedText) > 10000 {
		result.AddWarning(fmt.Sprintf("Instantiated text is very long (%d characters)", len(instantiatedText)))
	}

	// Validate target exists (if possible)
	// This would require target store integration

	return result, nil
}

// ValidateParameters checks if provided parameters match the payload's requirements
func (e *payloadExecutor) ValidateParameters(payload *Payload, params map[string]interface{}) error {
	if payload == nil {
		return fmt.Errorf("payload cannot be nil")
	}

	return e.substitutor.Validate(params, payload.Parameters)
}

// executePayloadWithAgent executes the payload using the specified agent
func (e *payloadExecutor) executePayloadWithAgent(
	ctx context.Context,
	agentID types.ID,
	payloadText string,
	req *ExecutionRequest,
) (string, int64, error) {
	// This is a simplified implementation
	// In a full implementation, this would:
	// 1. Get the agent from the registry
	// 2. Create a task for the agent
	// 3. Execute the task
	// 4. Return the response

	// For now, we'll simulate an execution
	// In real usage, this would integrate with the agent system

	startTime := time.Now()

	// Simulate execution delay
	time.Sleep(100 * time.Millisecond)

	// Return simulated response
	response := fmt.Sprintf("Simulated response to: %s", payloadText[:min(50, len(payloadText))])
	responseTimeMs := time.Since(startTime).Milliseconds()

	return response, responseTimeMs, nil
}

// createFinding creates a finding from a successful payload execution
func (e *payloadExecutor) createFinding(
	ctx context.Context,
	payload *Payload,
	execution *Execution,
	response string,
) (types.ID, error) {
	// Create base finding
	findingID := types.NewID()
	targetIDPtr := &execution.TargetID

	baseFinding := &agent.Finding{
		ID:          findingID,
		TargetID:    targetIDPtr,
		Title:       fmt.Sprintf("%s - %s", payload.Name, string(payload.Categories[0])),
		Description: payload.Description,
		Severity:    payload.Severity,
		Category:    string(payload.Categories[0]),
		Confidence:  execution.ConfidenceScore,
		Evidence: []agent.Evidence{
			{
				Type:        "payload_execution",
				Description: fmt.Sprintf("Successful execution of payload: %s", payload.Name),
				Data: map[string]any{
					"payload_text": execution.InstantiatedText,
					"payload_id":   string(payload.ID),
				},
				Timestamp: execution.CreatedAt,
			},
			{
				Type:        "response",
				Description: "Response from target",
				Data: map[string]any{
					"response_text":   response,
					"response_length": len(response),
				},
				Timestamp: *execution.CompletedAt,
			},
		},
		Metadata: map[string]interface{}{
			"payload_id":         string(payload.ID),
			"payload_name":       payload.Name,
			"payload_version":    payload.Version,
			"execution_id":       string(execution.ID),
			"confidence_score":   execution.ConfidenceScore,
			"indicators_matched": execution.IndicatorsMatched,
		},
		CreatedAt: time.Now(),
	}

	// Add MITRE mappings if available
	if len(payload.MitreTechniques) > 0 {
		if baseFinding.Metadata == nil {
			baseFinding.Metadata = make(map[string]interface{})
		}
		baseFinding.Metadata["mitre_techniques"] = payload.MitreTechniques
	}

	// Create enhanced finding for storage
	// This requires converting to EnhancedFinding type
	enhancedFinding := finding.EnhancedFinding{
		Finding:         *baseFinding,
		MissionID:       types.ID(""), // No mission for now
		AgentName:       "payload-executor",
		Subcategory:     "",
		Status:          finding.StatusOpen,
		RiskScore:       mapSeverityToRiskScore(payload.Severity),
		Remediation:     fmt.Sprintf("Review and address the vulnerability exploited by payload: %s", payload.Name),
		References:      payload.Metadata.References,
		OccurrenceCount: 1,
		UpdatedAt:       time.Now(),
	}

	// Add MITRE ATLAS mappings if available - store in Metadata
	if len(payload.MitreTechniques) > 0 {
		mappings := make([]finding.SimpleMitreMapping, 0, len(payload.MitreTechniques))
		for _, technique := range payload.MitreTechniques {
			mappings = append(mappings, finding.SimpleMitreMapping{
				TechniqueID:   technique,
				TechniqueName: "", // Would need mapping
			})
		}
		if enhancedFinding.Metadata == nil {
			enhancedFinding.Metadata = make(map[string]any)
		}
		enhancedFinding.Metadata["mitre_atlas"] = mappings
	}

	// If we have a mission ID, set it
	if execution.MissionID != nil {
		enhancedFinding.MissionID = *execution.MissionID
	}

	// Store the finding
	if err := e.findingStore.Store(ctx, enhancedFinding); err != nil {
		return "", fmt.Errorf("failed to store finding: %w", err)
	}

	return findingID, nil
}

// mapSeverityToRiskScore maps finding severity to a CVSS-like risk score (0-10)
func mapSeverityToRiskScore(severity agent.FindingSeverity) float64 {
	switch severity {
	case agent.SeverityCritical:
		return 9.5
	case agent.SeverityHigh:
		return 7.5
	case agent.SeverityMedium:
		return 5.0
	case agent.SeverityLow:
		return 2.5
	case agent.SeverityInfo:
		return 0.5
	default:
		return 5.0
	}
}

// Helper functions

func timePtr(t time.Time) *time.Time {
	return &t
}
