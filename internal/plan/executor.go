package plan

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"

	"github.com/zero-day-ai/gibson/internal/agent"
	"github.com/zero-day-ai/gibson/internal/guardrail"
	"github.com/zero-day-ai/gibson/internal/harness"
	"github.com/zero-day-ai/gibson/internal/types"
)

// PlanExecutor executes execution plans with guardrails and approval missions.
// It orchestrates the execution of plan steps, handles dependencies, enforces
// approval requirements, and aggregates results.
type PlanExecutor struct {
	guardrails      *guardrail.GuardrailPipeline
	approvalService ApprovalService
	logger          *slog.Logger
	tracer          trace.Tracer
	stepTimeout     time.Duration
}

// ExecutorOption is a functional option for configuring PlanExecutor.
type ExecutorOption func(*PlanExecutor)

// WithGuardrails configures the guardrail pipeline for the executor.
func WithGuardrails(g *guardrail.GuardrailPipeline) ExecutorOption {
	return func(e *PlanExecutor) {
		e.guardrails = g
	}
}

// WithApprovalService configures the approval service for the executor.
func WithApprovalService(s ApprovalService) ExecutorOption {
	return func(e *PlanExecutor) {
		e.approvalService = s
	}
}

// WithExecutorLogger configures the logger for the executor.
func WithExecutorLogger(l *slog.Logger) ExecutorOption {
	return func(e *PlanExecutor) {
		e.logger = l
	}
}

// WithExecutorTracer configures the tracer for the executor.
func WithExecutorTracer(t trace.Tracer) ExecutorOption {
	return func(e *PlanExecutor) {
		e.tracer = t
	}
}

// WithStepTimeout configures the default timeout for step execution.
func WithStepTimeout(d time.Duration) ExecutorOption {
	return func(e *PlanExecutor) {
		e.stepTimeout = d
	}
}

// NewPlanExecutor creates a new PlanExecutor with the given options.
// Default values:
//   - stepTimeout: 5 minutes
//   - logger: slog.Default()
func NewPlanExecutor(opts ...ExecutorOption) *PlanExecutor {
	executor := &PlanExecutor{
		stepTimeout: 5 * time.Minute,
		logger:      slog.Default(),
	}

	for _, opt := range opts {
		opt(executor)
	}

	return executor
}

// Execute executes the given execution plan using the provided harness.
// It validates the plan status, handles step dependencies, manages approvals,
// and aggregates results and findings.
//
// The execution process:
//  1. Validates plan is in "approved" status
//  2. Updates plan status to "executing"
//  3. Iterates through steps in sequence order
//  4. Checks dependencies before executing each step
//  5. Requests approval for high-risk steps if required
//  6. Executes each step via executeStep()
//  7. Collects results and aggregates findings
//  8. Updates final plan status (completed/failed)
//
// Returns:
//   - PlanResult containing all step results and aggregated findings
//   - Error if plan validation fails, approval is denied, or execution fails
func (e *PlanExecutor) Execute(ctx context.Context, plan *ExecutionPlan, h harness.AgentHarness) (*PlanResult, error) {
	// Validate plan status
	if plan.Status != PlanStatusApproved {
		return nil, NewPlanError(
			ErrPlanNotApproved,
			fmt.Sprintf("plan must be approved before execution, current status: %s", plan.Status),
			nil,
		)
	}

	// Create parent span for plan execution if tracer is configured
	var span trace.Span
	if e.tracer != nil {
		ctx, span = e.tracer.Start(ctx, "plan.execute",
			trace.WithAttributes(
				attribute.String("plan.id", plan.ID.String()),
				attribute.String("plan.mission_id", plan.MissionID.String()),
				attribute.String("plan.agent", plan.AgentName),
				attribute.Int("plan.steps", len(plan.Steps)),
			),
		)
		defer span.End()
	}

	e.logger.Info("starting plan execution",
		"plan_id", plan.ID,
		"mission_id", plan.MissionID,
		"agent", plan.AgentName,
		"steps", len(plan.Steps),
	)

	// Update plan status to executing
	plan.Status = PlanStatusExecuting
	now := time.Now()
	plan.StartedAt = &now
	plan.UpdatedAt = now

	// Initialize result tracking
	result := &PlanResult{
		PlanID:      plan.ID,
		Status:      PlanStatusExecuting,
		StepResults: make([]StepResult, 0, len(plan.Steps)),
		Findings:    make([]agent.Finding, 0),
	}
	stepResults := make(map[types.ID]*StepResult)
	executionStart := time.Now()

	// Execute steps in sequence order
	for i := range plan.Steps {
		step := &plan.Steps[i]

		// Check if we can execute this step (dependencies satisfied)
		if !e.canExecuteStep(step, stepResults) {
			e.logger.Warn("skipping step due to unsatisfied dependencies",
				"step_id", step.ID,
				"step_name", step.Name,
				"sequence", step.Sequence,
			)
			stepResult := &StepResult{
				StepID:      step.ID,
				Status:      StepStatusSkipped,
				StartedAt:   time.Now(),
				CompletedAt: time.Now(),
				Duration:    0,
			}
			result.StepResults = append(result.StepResults, *stepResult)
			stepResults[step.ID] = stepResult
			continue
		}

		// Handle approval if required
		if step.RequiresApproval {
			e.logger.Info("requesting approval for high-risk step",
				"step_id", step.ID,
				"step_name", step.Name,
				"risk_level", step.RiskLevel,
			)

			approvalReq := ApprovalRequest{
				ID:          types.NewID(),
				PlanID:      plan.ID,
				StepID:      step.ID,
				StepDetails: *step,
				RiskAssessment: RiskAssessment{
					Level:            step.RiskLevel,
					RequiresApproval: step.RequiresApproval,
					Rationale:        step.RiskRationale,
				},
				PlanContext: PlanContext{
					PlanID:      plan.ID,
					AgentName:   plan.AgentName,
					MissionID:   plan.MissionID,
					TotalSteps:  len(plan.Steps),
					CurrentStep: step.Sequence,
				},
				RequestedAt: time.Now(),
				ExpiresAt:   time.Now().Add(30 * time.Minute), // 30 minute approval timeout
			}

			if e.approvalService != nil {
				decision, err := e.approvalService.RequestApproval(ctx, approvalReq)
				if err != nil {
					plan.Status = PlanStatusFailed
					result.Status = PlanStatusFailed
					result.Error = NewPlanError(ErrApprovalTimeout, "approval request timed out", err)
					result.Error.StepID = &step.ID

					if span != nil {
						span.SetStatus(codes.Error, "approval timeout")
						span.RecordError(err)
					}

					e.logger.Error("approval request failed",
						"step_id", step.ID,
						"error", err,
					)

					return result, result.Error
				}

				if !decision.IsApproved() {
					plan.Status = PlanStatusFailed
					result.Status = PlanStatusFailed
					result.Error = NewPlanError(
						ErrApprovalDenied,
						fmt.Sprintf("step approval denied: %s", decision.Reason),
						nil,
					)
					result.Error.StepID = &step.ID

					if span != nil {
						span.SetStatus(codes.Error, "approval denied")
						span.AddEvent("approval_denied",
							trace.WithAttributes(
								attribute.String("step_id", step.ID.String()),
								attribute.String("reason", decision.Reason),
								attribute.String("approver_id", decision.ApproverID),
							),
						)
					}

					e.logger.Warn("step approval denied",
						"step_id", step.ID,
						"approver", decision.ApproverID,
						"reason", decision.Reason,
					)

					return result, result.Error
				}

				e.logger.Info("step approved",
					"step_id", step.ID,
					"approver", decision.ApproverID,
				)
			}
		}

		// Execute the step
		e.logger.Info("executing step",
			"step_id", step.ID,
			"step_name", step.Name,
			"sequence", step.Sequence,
			"type", step.Type,
		)

		stepResult, err := e.executeStep(ctx, step, h)
		if err != nil {
			plan.Status = PlanStatusFailed
			result.Status = PlanStatusFailed
			result.Error = NewPlanError(
				ErrStepExecutionFailed,
				fmt.Sprintf("step execution failed: %s", step.Name),
				err,
			)
			result.Error.StepID = &step.ID

			if span != nil {
				span.SetStatus(codes.Error, "step execution failed")
				span.RecordError(err)
			}

			e.logger.Error("step execution failed",
				"step_id", step.ID,
				"step_name", step.Name,
				"error", err,
			)

			// Add the failed step result
			result.StepResults = append(result.StepResults, *stepResult)
			stepResults[step.ID] = stepResult

			return result, result.Error
		}

		// Store step result
		result.StepResults = append(result.StepResults, *stepResult)
		stepResults[step.ID] = stepResult

		// Aggregate findings from this step
		if len(stepResult.Findings) > 0 {
			result.Findings = append(result.Findings, stepResult.Findings...)
		}

		e.logger.Info("step completed",
			"step_id", step.ID,
			"status", stepResult.Status,
			"duration", stepResult.Duration,
			"findings", len(stepResult.Findings),
		)
	}

	// All steps completed successfully
	plan.Status = PlanStatusCompleted
	result.Status = PlanStatusCompleted
	result.TotalDuration = time.Since(executionStart)
	completedAt := time.Now()
	plan.CompletedAt = &completedAt
	plan.UpdatedAt = completedAt

	if span != nil {
		span.SetStatus(codes.Ok, "plan execution completed")
		span.SetAttributes(
			attribute.Int("plan.findings", len(result.Findings)),
			attribute.Int64("plan.duration_ms", result.TotalDuration.Milliseconds()),
		)
	}

	e.logger.Info("plan execution completed",
		"plan_id", plan.ID,
		"status", result.Status,
		"duration", result.TotalDuration,
		"findings", len(result.Findings),
		"steps_executed", len(result.StepResults),
	)

	return result, nil
}

// canExecuteStep checks if a step can be executed based on its dependencies.
// Returns true if all dependencies have completed successfully.
func (e *PlanExecutor) canExecuteStep(step *ExecutionStep, results map[types.ID]*StepResult) bool {
	// If step has no dependencies, it can be executed
	if len(step.DependsOn) == 0 {
		return true
	}

	// Check all dependencies
	for _, depID := range step.DependsOn {
		depResult, exists := results[depID]
		if !exists {
			// Dependency has not been executed yet
			return false
		}

		if depResult.Status != StepStatusCompleted {
			// Dependency did not complete successfully
			return false
		}
	}

	// All dependencies completed successfully
	return true
}

// executeStep executes a single step in the plan with guardrails and tracing.
// It handles different step types (tool, plugin, agent, condition, parallel)
// and integrates input/output guardrail checking.
//
// The execution flow:
//  1. Run input guardrails if configured
//  2. Execute step based on type (tool, plugin, agent, condition, parallel)
//  3. Run output guardrails if configured
//  4. Return StepResult with output, findings, and timing
func (e *PlanExecutor) executeStep(ctx context.Context, step *ExecutionStep, h harness.AgentHarness) (*StepResult, error) {
	// Create step-scoped context with timeout
	stepCtx, cancel := context.WithTimeout(ctx, e.stepTimeout)
	defer cancel()

	// Create span for step execution if tracer is configured
	var span trace.Span
	if e.tracer != nil {
		stepCtx, span = e.tracer.Start(stepCtx, "step.execute",
			trace.WithAttributes(
				attribute.String("step.id", step.ID.String()),
				attribute.String("step.name", step.Name),
				attribute.String("step.type", string(step.Type)),
				attribute.Int("step.sequence", step.Sequence),
			),
		)
		defer span.End()
	}

	startTime := time.Now()
	result := &StepResult{
		StepID:    step.ID,
		Status:    StepStatusRunning,
		StartedAt: startTime,
		Output:    make(map[string]any),
		Findings:  make([]agent.Finding, 0),
		Metadata:  make(map[string]any),
	}

	// Update step status
	step.Status = StepStatusRunning

	// Run step through input guardrails if configured
	if err := e.runInputGuardrails(stepCtx, step, h); err != nil {
		if span != nil {
			span.SetStatus(codes.Error, "input guardrails blocked")
			span.RecordError(err)
		}
		step.Status = StepStatusFailed
		return &StepResult{
			StepID:      step.ID,
			Status:      StepStatusFailed,
			StartedAt:   startTime,
			CompletedAt: time.Now(),
			Duration:    time.Since(startTime),
			Error: &StepError{
				Code:    string(ErrGuardrailBlocked),
				Message: "input guardrails blocked step execution",
				Cause:   err,
			},
		}, err
	}

	// Execute step based on type
	var output map[string]any
	var findings []agent.Finding
	var err error

	switch step.Type {
	case StepTypeTool:
		output, findings, err = e.executeTool(stepCtx, step, h)
	case StepTypePlugin:
		output, findings, err = e.executePlugin(stepCtx, step, h)
	case StepTypeAgent:
		output, findings, err = e.executeAgent(stepCtx, step, h)
	case StepTypeCondition:
		output, err = e.executeCondition(stepCtx, step, nil)
		findings = []agent.Finding{}
	case StepTypeParallel:
		output, findings, err = e.executeParallel(stepCtx, step, h)
	default:
		err = fmt.Errorf("unsupported step type: %s", step.Type)
	}

	if err != nil {
		if span != nil {
			span.SetStatus(codes.Error, "step execution failed")
			span.RecordError(err)
		}
		step.Status = StepStatusFailed
		return &StepResult{
			StepID:      step.ID,
			Status:      StepStatusFailed,
			StartedAt:   startTime,
			CompletedAt: time.Now(),
			Duration:    time.Since(startTime),
			Error: &StepError{
				Code:    string(ErrStepExecutionFailed),
				Message: fmt.Sprintf("step execution failed: %s", step.Name),
				Cause:   err,
			},
		}, err
	}

	// Run output through output guardrails if configured
	if err := e.runOutputGuardrails(stepCtx, step, output, h); err != nil {
		if span != nil {
			span.SetStatus(codes.Error, "output guardrails blocked")
			span.RecordError(err)
		}
		step.Status = StepStatusFailed
		return &StepResult{
			StepID:      step.ID,
			Status:      StepStatusFailed,
			StartedAt:   startTime,
			CompletedAt: time.Now(),
			Duration:    time.Since(startTime),
			Error: &StepError{
				Code:    string(ErrGuardrailBlocked),
				Message: "output guardrails blocked step execution",
				Cause:   err,
			},
		}, err
	}

	// Mark step as completed
	result.Status = StepStatusCompleted
	result.Output = output
	result.Findings = findings
	result.CompletedAt = time.Now()
	result.Duration = time.Since(startTime)
	step.Status = StepStatusCompleted

	if span != nil {
		span.SetStatus(codes.Ok, "step completed")
		span.SetAttributes(
			attribute.Int64("step.duration_ms", result.Duration.Milliseconds()),
			attribute.Int("step.findings", len(result.Findings)),
		)
	}

	return result, nil
}
