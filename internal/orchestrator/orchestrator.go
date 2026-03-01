package orchestrator

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/zero-day-ai/gibson/internal/events"
	"github.com/zero-day-ai/gibson/internal/graphrag/schema"
	"github.com/zero-day-ai/gibson/internal/harness"
	"github.com/zero-day-ai/gibson/internal/registry"
	"github.com/zero-day-ai/gibson/internal/types"
	"go.opentelemetry.io/otel/trace"
)

// OrchestratorStatus represents the final status of an orchestration run.
type OrchestratorStatus string

const (
	// StatusCompleted indicates the mission completed successfully
	StatusCompleted OrchestratorStatus = "completed"

	// StatusFailed indicates the mission failed with an error
	StatusFailed OrchestratorStatus = "failed"

	// StatusMaxIterations indicates max iterations were reached
	StatusMaxIterations OrchestratorStatus = "max_iterations"

	// StatusTimeout indicates the orchestrator timed out
	StatusTimeout OrchestratorStatus = "timeout"

	// StatusCancelled indicates the context was cancelled
	StatusCancelled OrchestratorStatus = "cancelled"

	// StatusBudgetExceeded indicates token budget was exhausted
	StatusBudgetExceeded OrchestratorStatus = "budget_exceeded"

	// StatusConcurrencyLimit indicates max concurrent executions reached
	StatusConcurrencyLimit OrchestratorStatus = "concurrency_limit"
)

// String returns the string representation of OrchestratorStatus
func (s OrchestratorStatus) String() string {
	return string(s)
}

// Event type constants matching observability.EventType
const (
	// EventTypeDecision represents orchestrator decision events
	EventTypeDecision = "decision"
)

// DecisionEventData captures orchestrator decision-making information.
// This matches observability.DecisionEventData to avoid circular dependencies.
type DecisionEventData struct {
	Action       string  `json:"action"`
	TargetNodeID string  `json:"target_node_id,omitempty"`
	Confidence   float64 `json:"confidence"`
	Reasoning    string  `json:"reasoning"`
}

// Logger defines the interface for structured logging with event support.
// This interface is implemented by observability.Logger to avoid circular dependencies.
type Logger interface {
	Debug(ctx context.Context, msg string, args ...any)
	Info(ctx context.Context, msg string, args ...any)
	Warn(ctx context.Context, msg string, args ...any)
	Error(ctx context.Context, msg string, args ...any)
	Event(ctx context.Context, eventType string, msg string, data any)
	Slog() *slog.Logger // Returns the underlying slog.Logger for advanced usage
}

// slogAdapter adapts slog.Logger to the Logger interface for backward compatibility.
// This provides a default logger when observability.Logger is not available.
type slogAdapter struct {
	slog *slog.Logger
}

func (s *slogAdapter) Debug(ctx context.Context, msg string, args ...any) {
	s.slog.DebugContext(ctx, msg, args...)
}

func (s *slogAdapter) Info(ctx context.Context, msg string, args ...any) {
	s.slog.InfoContext(ctx, msg, args...)
}

func (s *slogAdapter) Warn(ctx context.Context, msg string, args ...any) {
	s.slog.WarnContext(ctx, msg, args...)
}

func (s *slogAdapter) Error(ctx context.Context, msg string, args ...any) {
	s.slog.ErrorContext(ctx, msg, args...)
}

func (s *slogAdapter) Event(ctx context.Context, eventType string, msg string, data any) {
	// For slog adapter, just log as info with event_type and event_data
	s.slog.InfoContext(ctx, msg, "event_type", eventType, "event_data", data)
}

func (s *slogAdapter) Slog() *slog.Logger {
	return s.slog
}

// WrapSlogLogger wraps a *slog.Logger to implement the Logger interface.
// Use this when you have a slog.Logger but need to pass it to orchestrator components.
func WrapSlogLogger(logger *slog.Logger) Logger {
	if logger == nil {
		logger = slog.Default()
	}
	return &slogAdapter{slog: logger}
}

// OrchestratorObserver defines the interface for observing mission state.
type OrchestratorObserver interface {
	Observe(ctx context.Context, missionID string) (*ObservationState, error)
}

// OrchestratorThinker defines the interface for making orchestration decisions.
type OrchestratorThinker interface {
	Think(ctx context.Context, state *ObservationState) (*ThinkResult, error)
}

// OrchestratorActor defines the interface for executing orchestration decisions.
type OrchestratorActor interface {
	Act(ctx context.Context, decision *Decision, missionID string) (*ActionResult, error)
}

// Orchestrator implements the main Observe → Think → Act control loop.
// It coordinates the observer, thinker, and actor components to autonomously
// execute mission workflows based on LLM reasoning.
type Orchestrator struct {
	observer         OrchestratorObserver
	thinker          OrchestratorThinker
	actor            OrchestratorActor
	eventBus         EventBus
	logger           Logger
	tracer           trace.Tracer
	logWriter        DecisionLogWriter
	inventoryBuilder *InventoryBuilder       // Component discovery for validation
	metrics          harness.MetricsRecorder // Metrics recorder for observability

	// Configuration options
	maxIterations int
	budget        int // Total token budget (0 = unlimited)
	maxConcurrent int // Max concurrent node executions
	timeout       time.Duration
	runMode       RunMode // Error handling behavior mode
}

// EventBus defines the interface for emitting orchestrator events.
type EventBus interface {
	Publish(event events.Event)
}

// DecisionLogWriter defines the interface for logging decisions to external systems.
// This is typically implemented by Langfuse or similar observability platforms.
type DecisionLogWriter interface {
	// LogDecision writes a decision and its outcome to the external log
	LogDecision(ctx context.Context, decision *Decision, result *ThinkResult, iteration int, missionID string) error

	// LogAction writes an action result to the external log
	LogAction(ctx context.Context, action *ActionResult, iteration int, missionID string) error
}

// OrchestratorOption is a functional option for configuring the Orchestrator.
type OrchestratorOption func(*Orchestrator)

// WithMaxIterations sets the maximum number of orchestration iterations.
// Default: 100
func WithMaxIterations(n int) OrchestratorOption {
	return func(o *Orchestrator) {
		if n > 0 {
			o.maxIterations = n
		}
	}
}

// WithBudget sets the total token budget for the orchestration run.
// When the budget is exceeded, orchestration stops.
// Default: 0 (unlimited)
func WithBudget(tokens int) OrchestratorOption {
	return func(o *Orchestrator) {
		if tokens >= 0 {
			o.budget = tokens
		}
	}
}

// WithMaxConcurrent sets the maximum number of concurrent node executions.
// Default: 10
func WithMaxConcurrent(n int) OrchestratorOption {
	return func(o *Orchestrator) {
		if n > 0 {
			o.maxConcurrent = n
		}
	}
}

// WithTimeout sets the overall timeout for the orchestration run.
// Default: 0 (no timeout)
func WithTimeout(d time.Duration) OrchestratorOption {
	return func(o *Orchestrator) {
		if d > 0 {
			o.timeout = d
		}
	}
}

// WithLogger sets the logger for orchestrator operations.
func WithLogger(logger Logger) OrchestratorOption {
	return func(o *Orchestrator) {
		if logger != nil {
			o.logger = logger
		}
	}
}

// WithTracer sets the OpenTelemetry tracer for distributed tracing.
func WithTracer(tracer trace.Tracer) OrchestratorOption {
	return func(o *Orchestrator) {
		if tracer != nil {
			o.tracer = tracer
		}
	}
}

// WithEventBus sets the event bus for emitting orchestration events.
func WithEventBus(bus EventBus) OrchestratorOption {
	return func(o *Orchestrator) {
		if bus != nil {
			o.eventBus = bus
		}
	}
}

// WithDecisionLogWriter sets the decision log writer for external observability.
func WithDecisionLogWriter(writer DecisionLogWriter) OrchestratorOption {
	return func(o *Orchestrator) {
		if writer != nil {
			o.logWriter = writer
		}
	}
}

// WithComponentDiscovery sets the component discovery for inventory building and validation.
// This enables the orchestrator to validate spawned agents against the registry.
func WithComponentDiscovery(discovery registry.ComponentDiscovery) OrchestratorOption {
	return func(o *Orchestrator) {
		if discovery != nil {
			o.inventoryBuilder = NewInventoryBuilder(discovery)
		}
	}
}

// WithMetricsRecorder sets the metrics recorder for mission observability.
// Metrics include mission status, duration, node counts, and iteration counts.
func WithMetricsRecorder(recorder harness.MetricsRecorder) OrchestratorOption {
	return func(o *Orchestrator) {
		if recorder != nil {
			o.metrics = recorder
		}
	}
}

// NewOrchestrator creates a new Orchestrator with the specified components and options.
//
// Required components:
//   - observer: Gathers execution state from the graph (implements OrchestratorObserver)
//   - thinker: Makes decisions using LLM reasoning (implements OrchestratorThinker)
//   - actor: Executes decisions and updates graph state (implements OrchestratorActor)
//
// The orchestrator coordinates these components in a loop until the mission
// completes, fails, or hits resource limits.
//
// Run mode is determined by the following precedence:
//  1. Explicit WithRunMode() option
//  2. GIBSON_RUN_MODE environment variable
//  3. Default: RunModeProduction
func NewOrchestrator(observer OrchestratorObserver, thinker OrchestratorThinker, actor OrchestratorActor, options ...OrchestratorOption) *Orchestrator {
	// Read run mode from environment variable (can be overridden by options)
	envRunMode := GetRunModeFromEnv()

	o := &Orchestrator{
		observer:      observer,
		thinker:       thinker,
		actor:         actor,
		maxIterations: 100,                              // Reasonable default to prevent infinite loops
		maxConcurrent: 10,                               // Default concurrency limit
		budget:        0,                                // Unlimited by default
		timeout:       0,                                // No timeout by default
		runMode:       envRunMode,                       // Default from environment or production
		logger:        &slogAdapter{slog: slog.Default()},
		tracer:        trace.NewNoopTracerProvider().Tracer("orchestrator"),
		metrics:       harness.NewNoOpMetricsRecorder(), // Default to no-op
	}

	// Apply functional options (can override environment variable)
	for _, opt := range options {
		opt(o)
	}

	return o
}

// OrchestratorResult contains the complete result of an orchestration run.
type OrchestratorResult struct {
	// MissionID is the ID of the mission that was orchestrated
	MissionID string

	// Status is the final status of the orchestration run
	Status OrchestratorStatus

	// TotalIterations is the number of observe-think-act cycles performed
	TotalIterations int

	// TotalDecisions is the number of LLM decisions made
	TotalDecisions int

	// TotalTokensUsed is the total tokens consumed by LLM calls
	TotalTokensUsed int

	// Duration is the total time spent in orchestration
	Duration time.Duration

	// CompletedNodes is the number of workflow nodes that completed
	CompletedNodes int

	// FailedNodes is the number of workflow nodes that failed
	FailedNodes int

	// Error contains any fatal error that occurred
	Error error

	// StopReason explains why orchestration stopped (for completed missions)
	StopReason string

	// FinalState is the last observed state before stopping
	FinalState *ObservationState
}

// Run executes the orchestration loop for the specified mission.
//
// The orchestration loop repeats until:
//   - The mission completes (all nodes executed)
//   - A terminal decision is made (complete action)
//   - Max iterations are reached
//   - Token budget is exhausted
//   - Timeout occurs
//   - Context is cancelled
//   - A fatal error occurs
//
// Each iteration follows the pattern:
//  1. OBSERVE - Gather current execution state from graph
//  2. CHECK - Verify termination conditions and constraints
//  3. THINK - Use LLM to make a decision about what to do next
//  4. LOG - Record the decision for observability
//  5. ACT - Execute the decision (run agent, skip node, etc.)
//  6. VERIFY - Check if the action was terminal
//
// Returns an OrchestratorResult summarizing the execution.
func (o *Orchestrator) Run(ctx context.Context, missionID string) (*OrchestratorResult, error) {
	startTime := time.Now()

	// Validate mission ID
	parsedMissionID, err := types.ParseID(missionID)
	if err != nil {
		return nil, fmt.Errorf("invalid mission ID: %w", err)
	}

	// Apply timeout if configured
	if o.timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, o.timeout)
		defer cancel()
	}

	// Start tracing span
	ctx, span := o.tracer.Start(ctx, "orchestrator.Run")
	defer span.End()

	// Emit mission started event
	if o.eventBus != nil {
		o.eventBus.Publish(events.Event{
			Type:      events.EventMissionStarted,
			Timestamp: time.Now(),
			MissionID: parsedMissionID,
			TraceID:   span.SpanContext().TraceID().String(),
			SpanID:    span.SpanContext().SpanID().String(),
			Payload: events.MissionStartedPayload{
				MissionID: parsedMissionID,
			},
		})
	}

	o.logger.Info(ctx, "orchestrator starting",
		"mission_id", missionID,
		"max_iterations", o.maxIterations,
		"max_concurrent", o.maxConcurrent,
		"budget", o.budget,
	)

	// Record mission started metric
	o.recordMissionStarted(missionID)

	// Initialize result
	result := &OrchestratorResult{
		MissionID: missionID,
		Status:    StatusCompleted, // Optimistic default
	}

	// Track token usage
	totalTokens := 0

	// Main orchestration loop
	for iteration := 0; iteration < o.maxIterations; iteration++ {
		// Check context cancellation
		select {
		case <-ctx.Done():
			o.logger.Warn(ctx, "orchestrator cancelled", "iteration", iteration, "error", ctx.Err())
			result.Status = StatusCancelled
			result.Error = ctx.Err()
			result.Duration = time.Since(startTime)
			result.TotalIterations = iteration
			o.recordMissionCompleted(result)
			return result, nil
		default:
		}

		o.logger.Debug(ctx, "orchestration iteration starting", "iteration", iteration)

		// 1. OBSERVE - Gather current state
		state, err := o.observer.Observe(ctx, missionID)
		if err != nil {
			o.logger.Error(ctx, "observation failed", "iteration", iteration, "error", err)
			result.Status = StatusFailed
			result.Error = fmt.Errorf("observation failed: %w", err)
			result.TotalIterations = iteration
			result.Duration = time.Since(startTime)
			o.recordMissionCompleted(result)
			return result, err
		}

		result.FinalState = state

		o.logger.Debug(ctx, "observation complete",
			"iteration", iteration,
			"ready_nodes", len(state.ReadyNodes),
			"running_nodes", len(state.RunningNodes),
			"completed_nodes", len(state.CompletedNodes),
			"failed_nodes", len(state.FailedNodes),
		)

		// 2. CHECK TERMINATION CONDITIONS

		// Check if workflow is naturally complete (no work left)
		if len(state.ReadyNodes) == 0 && len(state.RunningNodes) == 0 {
			o.logger.Info(ctx, "workflow naturally complete", "iteration", iteration)
			result.Status = StatusCompleted
			result.TotalIterations = iteration + 1
			result.CompletedNodes = len(state.CompletedNodes)
			result.FailedNodes = len(state.FailedNodes)
			result.Duration = time.Since(startTime)
			result.TotalTokensUsed = totalTokens
			result.StopReason = "all workflow nodes completed or no more work available"
			o.recordMissionCompleted(result)
			return result, nil
		}

		// Check concurrency limit
		if len(state.RunningNodes) >= o.maxConcurrent {
			o.logger.Debug(ctx, "concurrency limit reached, skipping iteration",
				"iteration", iteration,
				"running", len(state.RunningNodes),
				"limit", o.maxConcurrent,
			)
			// Sleep briefly and retry in next iteration
			time.Sleep(1 * time.Second)
			continue
		}

		// Check token budget
		if o.budget > 0 && totalTokens >= o.budget {
			o.logger.Warn(ctx, "token budget exceeded",
				"iteration", iteration,
				"used", totalTokens,
				"budget", o.budget,
			)
			result.Status = StatusBudgetExceeded
			result.TotalIterations = iteration + 1
			result.TotalTokensUsed = totalTokens
			result.Duration = time.Since(startTime)
			o.recordMissionCompleted(result)
			return result, nil
		}

		// 3. THINK - LLM decides what to do next
		thinkResult, err := o.thinker.Think(ctx, state)
		if err != nil {
			o.logger.Error(ctx, "thinking failed", "iteration", iteration, "error", err)
			result.Status = StatusFailed
			result.Error = fmt.Errorf("thinking failed: %w", err)
			result.TotalIterations = iteration + 1
			result.TotalTokensUsed = totalTokens
			result.Duration = time.Since(startTime)
			o.recordMissionCompleted(result)
			return result, err
		}

		// Update token usage
		totalTokens += thinkResult.TotalTokens
		result.TotalDecisions++

		o.logger.Info(ctx, "decision made",
			"iteration", iteration,
			"action", thinkResult.Decision.Action,
			"target", thinkResult.Decision.TargetNodeID,
			"confidence", thinkResult.Decision.Confidence,
			"tokens", thinkResult.TotalTokens,
			"latency_ms", thinkResult.Latency.Milliseconds(),
		)

		// 4. LOG DECISION - Write to graph and external systems
		if err := o.logDecision(ctx, thinkResult, iteration, missionID); err != nil {
			o.logger.Warn(ctx, "failed to log decision", "iteration", iteration, "error", err)
			// Non-fatal error, continue
		}

		// 5. ACT - Execute the decision

		// Emit node.started event before execution (for execute_agent and retry actions)
		if thinkResult.Decision.Action == ActionExecuteAgent || thinkResult.Decision.Action == ActionRetry {
			if o.eventBus != nil && thinkResult.Decision.TargetNodeID != "" {
				// Get node type from state if available
				nodeType := ""
				for _, node := range state.ReadyNodes {
					if node.ID == thinkResult.Decision.TargetNodeID {
						nodeType = node.Type
						break
					}
				}

				o.eventBus.Publish(events.Event{
					Type:      events.EventNodeStarted,
					Timestamp: time.Now(),
					MissionID: parsedMissionID,
					Payload: events.NodeStartedPayload{
						MissionID: parsedMissionID,
						NodeID:    thinkResult.Decision.TargetNodeID,
						NodeType:  nodeType,
						Message:   "Starting node execution",
					},
				})
			}
		}

		actionResult, err := o.actor.Act(ctx, thinkResult.Decision, missionID)
		if err != nil {
			o.logger.Error(ctx, "action failed", "iteration", iteration, "error", err)
			result.Status = StatusFailed
			result.Error = fmt.Errorf("action failed: %w", err)
			result.TotalIterations = iteration + 1
			result.TotalTokensUsed = totalTokens
			result.Duration = time.Since(startTime)
			o.recordMissionCompleted(result)
			return result, err
		}

		// Log action result
		if err := o.logAction(ctx, actionResult, iteration, missionID); err != nil {
			o.logger.Warn(ctx, "failed to log action", "iteration", iteration, "error", err)
			// Non-fatal error, continue
		}

		o.logger.Debug(ctx, "action completed",
			"iteration", iteration,
			"action", actionResult.Action,
			"terminal", actionResult.IsTerminal,
			"error", actionResult.Error,
		)

		// Emit progress event
		if o.eventBus != nil {
			o.eventBus.Publish(events.Event{
				Type:      events.EventMissionProgress,
				Timestamp: time.Now(),
				MissionID: parsedMissionID,
				Payload: events.MissionProgressPayload{
					MissionID:      parsedMissionID,
					CompletedNodes: len(state.CompletedNodes),
					TotalNodes:     state.GraphSummary.TotalNodes,
				},
			})
		}

		// 6. CHECK TERMINAL - Did this action end the workflow?
		if actionResult.IsTerminal {
			o.logger.Info(ctx, "terminal action executed", "iteration", iteration+1)
			result.Status = StatusCompleted
			result.TotalIterations = iteration + 1
			result.CompletedNodes = len(state.CompletedNodes)
			result.FailedNodes = len(state.FailedNodes)
			result.TotalTokensUsed = totalTokens
			result.Duration = time.Since(startTime)
			result.StopReason = thinkResult.Decision.StopReason
			o.recordMissionCompleted(result)
			return result, nil
		}

		// Check if action resulted in an error
		if actionResult.Error != nil {
			// Non-terminal error - log and continue
			// The failed node is tracked in the graph
			o.logger.Warn(ctx, "action error (non-terminal)",
				"iteration", iteration,
				"error", actionResult.Error,
			)
		}
	}

	// Max iterations reached
	o.logger.Warn(ctx, "max iterations reached", "iterations", o.maxIterations)
	result.Status = StatusMaxIterations
	result.TotalIterations = o.maxIterations
	result.TotalTokensUsed = totalTokens
	result.Duration = time.Since(startTime)

	if result.FinalState != nil {
		result.CompletedNodes = len(result.FinalState.CompletedNodes)
		result.FailedNodes = len(result.FinalState.FailedNodes)
	}

	o.recordMissionCompleted(result)
	return result, nil
}

// logDecision writes the decision to the graph and external log systems.
func (o *Orchestrator) logDecision(ctx context.Context, result *ThinkResult, iteration int, missionID string) error {
	// Emit structured decision event
	o.logger.Event(ctx, EventTypeDecision, "orchestrator decision", DecisionEventData{
		Action:       result.Decision.Action.String(),
		TargetNodeID: result.Decision.TargetNodeID,
		Confidence:   result.Decision.Confidence,
		Reasoning:    result.Decision.Reasoning, // Will be truncated by logger
	})

	// Log to external system (Langfuse, etc.) if configured
	if o.logWriter != nil {
		if err := o.logWriter.LogDecision(ctx, result.Decision, result, iteration, missionID); err != nil {
			return fmt.Errorf("failed to write decision log: %w", err)
		}
	}

	// Emit decision event
	if o.eventBus != nil {
		parsedMissionID, _ := types.ParseID(missionID)
		o.eventBus.Publish(events.Event{
			Type:      events.EventMissionProgress,
			Timestamp: time.Now(),
			MissionID: parsedMissionID,
			Attrs: map[string]any{
				"iteration":   iteration,
				"action":      result.Decision.Action.String(),
				"target":      result.Decision.TargetNodeID,
				"confidence":  result.Decision.Confidence,
				"tokens":      result.TotalTokens,
				"latency_ms":  result.Latency.Milliseconds(),
				"retry_count": result.RetryCount,
			},
		})
	}

	return nil
}

// logAction writes the action result to external log systems.
func (o *Orchestrator) logAction(ctx context.Context, action *ActionResult, iteration int, missionID string) error {
	// Log to external system (Langfuse, etc.) if configured
	if o.logWriter != nil {
		if err := o.logWriter.LogAction(ctx, action, iteration, missionID); err != nil {
			return fmt.Errorf("failed to write action log: %w", err)
		}
	}

	// Emit action-specific events
	if o.eventBus != nil {
		parsedMissionID, _ := types.ParseID(missionID)

		// If an agent was executed, emit node events
		if action.AgentExecution != nil {
			exec := action.AgentExecution

			switch exec.Status {
			case schema.ExecutionStatusCompleted:
				o.eventBus.Publish(events.Event{
					Type:      events.EventNodeCompleted,
					Timestamp: time.Now(),
					MissionID: parsedMissionID,
					Payload: events.NodeCompletedPayload{
						MissionID: parsedMissionID,
						NodeID:    exec.WorkflowNodeID,
						Duration:  exec.Duration(),
					},
				})

			case schema.ExecutionStatusFailed:
				o.eventBus.Publish(events.Event{
					Type:      events.EventNodeFailed,
					Timestamp: time.Now(),
					MissionID: parsedMissionID,
					Payload: events.NodeFailedPayload{
						MissionID: parsedMissionID,
						NodeID:    exec.WorkflowNodeID,
						Error:     exec.Error,
						Duration:  exec.Duration(),
					},
				})
			}
		}

		// Emit node.skipped event for skip_agent action
		if action.Action == ActionSkipAgent && action.TargetNodeID != "" {
			skipReason := "Node skipped by orchestrator decision"
			if reasoning, ok := action.Metadata["reasoning"].(string); ok && reasoning != "" {
				skipReason = reasoning
			}

			o.eventBus.Publish(events.Event{
				Type:      events.EventNodeSkipped,
				Timestamp: time.Now(),
				MissionID: parsedMissionID,
				Payload: events.NodeSkippedPayload{
					MissionID:  parsedMissionID,
					NodeID:     action.TargetNodeID,
					SkipReason: skipReason,
				},
			})
		}

		// Also emit node.skipped for policy-based skips during execute_agent
		if action.Action == ActionExecuteAgent && action.TargetNodeID != "" {
			if skipped, ok := action.Metadata["skipped"].(bool); ok && skipped {
				skipReason := "Policy check prevented execution"
				if reason, ok := action.Metadata["skip_reason"].(string); ok && reason != "" {
					skipReason = reason
				}

				o.eventBus.Publish(events.Event{
					Type:      events.EventNodeSkipped,
					Timestamp: time.Now(),
					MissionID: parsedMissionID,
					Payload: events.NodeSkippedPayload{
						MissionID:  parsedMissionID,
						NodeID:     action.TargetNodeID,
						SkipReason: skipReason,
					},
				})
			}
		}
	}

	return nil
}

// String returns a human-readable representation of the orchestrator result.
func (r *OrchestratorResult) String() string {
	return fmt.Sprintf(
		"OrchestratorResult{Status: %s, Iterations: %d, Decisions: %d, Tokens: %d, Duration: %s, Completed: %d, Failed: %d}",
		r.Status,
		r.TotalIterations,
		r.TotalDecisions,
		r.TotalTokensUsed,
		r.Duration,
		r.CompletedNodes,
		r.FailedNodes,
	)
}

// RunMode returns the current run mode of the orchestrator.
// This can be used to conditionally adjust behavior based on the mode.
func (o *Orchestrator) RunMode() RunMode {
	return o.runMode
}

// recordMissionStarted records metrics when a mission starts.
func (o *Orchestrator) recordMissionStarted(missionID string) {
	if o.metrics == nil {
		return
	}

	labels := map[string]string{
		"mission_id": missionID,
		"status":     "running",
	}

	// Set mission status to running (1)
	o.metrics.RecordGauge("gibson.mission.status", 1, labels)

	// Increment total missions counter
	o.metrics.RecordCounter("gibson.missions.total", 1, map[string]string{})
}

// recordMissionCompleted records metrics when a mission completes.
func (o *Orchestrator) recordMissionCompleted(result *OrchestratorResult) {
	if o.metrics == nil || result == nil {
		return
	}

	statusStr := result.Status.String()
	labels := map[string]string{
		"mission_id": result.MissionID,
		"status":     statusStr,
	}

	// Determine gauge value based on status
	// 0 = completed, 1 = running, 2 = failed/other
	var statusValue float64
	switch result.Status {
	case StatusCompleted:
		statusValue = 0
	case StatusFailed, StatusTimeout, StatusCancelled, StatusBudgetExceeded, StatusMaxIterations:
		statusValue = 2
	default:
		statusValue = 2
	}

	// Set mission status gauge
	o.metrics.RecordGauge("gibson.mission.status", statusValue, labels)

	// Record duration histogram
	o.metrics.RecordHistogram("gibson.mission.duration", result.Duration.Seconds(), labels)

	// Record node counts
	if result.CompletedNodes > 0 {
		o.metrics.RecordCounter("gibson.mission.nodes", int64(result.CompletedNodes), map[string]string{
			"mission_id": result.MissionID,
			"status":     "completed",
		})
	}
	if result.FailedNodes > 0 {
		o.metrics.RecordCounter("gibson.mission.nodes", int64(result.FailedNodes), map[string]string{
			"mission_id": result.MissionID,
			"status":     "failed",
		})
	}

	// Record iterations
	if result.TotalIterations > 0 {
		o.metrics.RecordCounter("gibson.mission.iterations", int64(result.TotalIterations), map[string]string{
			"mission_id": result.MissionID,
		})
	}

	// Record tokens used
	if result.TotalTokensUsed > 0 {
		o.metrics.RecordCounter("gibson.mission.tokens", int64(result.TotalTokensUsed), map[string]string{
			"mission_id": result.MissionID,
		})
	}
}
