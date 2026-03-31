package attack

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/zero-day-ai/gibson/internal/agent"
	"github.com/zero-day-ai/gibson/internal/component"
	"github.com/zero-day-ai/gibson/internal/finding"
	"github.com/zero-day-ai/gibson/internal/mission"
	"github.com/zero-day-ai/gibson/internal/payload"
	"github.com/zero-day-ai/gibson/internal/types"
	"go.opentelemetry.io/otel/trace"
)

// AttackRunner executes attacks against targets with ephemeral mission creation.
// It orchestrates the complete attack flow: target resolution, agent selection,
// payload filtering, mission execution, and optional persistence based on results.
type AttackRunner interface {
	// Run executes an attack with the provided options and returns results.
	// The attack is executed as an ephemeral mission that is only persisted
	// if findings are discovered (unless explicitly controlled via options).
	Run(ctx context.Context, opts *AttackOptions) (*AttackResult, error)
}

// DefaultAttackRunner implements AttackRunner using the Gibson infrastructure.
// It creates ephemeral missions, delegates execution to the MissionOrchestrator,
// and handles auto-persistence logic based on findings.
type DefaultAttackRunner struct {
	orchestrator    mission.MissionOrchestrator
	discovery       component.ComponentDiscovery
	payloadRegistry payload.PayloadRegistry
	missionStore    mission.MissionStore
	findingStore    finding.FindingStore
	targetResolver  TargetResolver
	agentSelector   AgentSelector
	payloadFilter   PayloadFilter
	logger          *slog.Logger
	tracer          trace.Tracer
}

// RunnerOption is a functional option for configuring the AttackRunner.
type RunnerOption func(*DefaultAttackRunner)

// WithLogger sets the logger for the runner.
func WithLogger(logger *slog.Logger) RunnerOption {
	return func(r *DefaultAttackRunner) {
		r.logger = logger
	}
}

// WithTracer sets the OpenTelemetry tracer for the runner.
func WithTracer(tracer trace.Tracer) RunnerOption {
	return func(r *DefaultAttackRunner) {
		r.tracer = tracer
	}
}

// WithTargetResolver sets a custom target resolver.
func WithTargetResolver(resolver TargetResolver) RunnerOption {
	return func(r *DefaultAttackRunner) {
		r.targetResolver = resolver
	}
}

// WithAgentSelector sets a custom agent selector.
func WithAgentSelector(selector AgentSelector) RunnerOption {
	return func(r *DefaultAttackRunner) {
		r.agentSelector = selector
	}
}

// WithPayloadFilter sets a custom payload filter.
func WithPayloadFilter(filter PayloadFilter) RunnerOption {
	return func(r *DefaultAttackRunner) {
		r.payloadFilter = filter
	}
}

// WithComponentDiscovery sets the component discovery interface for agent discovery.
func WithComponentDiscovery(discovery component.ComponentDiscovery) RunnerOption {
	return func(r *DefaultAttackRunner) {
		r.discovery = discovery
	}
}

// NewAttackRunner creates a new DefaultAttackRunner with the provided dependencies.
// It uses functional options for optional configuration.
func NewAttackRunner(
	orchestrator mission.MissionOrchestrator,
	discovery component.ComponentDiscovery,
	payloadRegistry payload.PayloadRegistry,
	missionStore mission.MissionStore,
	findingStore finding.FindingStore,
	opts ...RunnerOption,
) *DefaultAttackRunner {
	runner := &DefaultAttackRunner{
		orchestrator:    orchestrator,
		discovery:       discovery,
		payloadRegistry: payloadRegistry,
		missionStore:    missionStore,
		findingStore:    findingStore,
		logger:          slog.Default(),
		tracer:          trace.NewNoopTracerProvider().Tracer("attack-runner"),
	}

	// Apply functional options
	for _, opt := range opts {
		opt(runner)
	}

	// Initialize default components if not provided
	if runner.targetResolver == nil {
		runner.targetResolver = NewDefaultTargetResolver(nil)
	}
	if runner.agentSelector == nil {
		// Create agent selector using ComponentDiscovery
		runner.agentSelector = NewAgentSelector(discovery)
	}
	if runner.payloadFilter == nil {
		runner.payloadFilter = NewPayloadFilter(payloadRegistry)
	}

	return runner
}

// Run executes the complete attack flow:
// 1. Resolve and validate target configuration
// 2. Select and validate agent
// 3. Filter payloads based on criteria
// 4. Create ephemeral mission with single-node workflow
// 5. Execute mission through orchestrator
// 6. Collect findings and results
// 7. Auto-persist if findings discovered (unless --no-persist)
// 8. Return complete attack result
func (r *DefaultAttackRunner) Run(ctx context.Context, opts *AttackOptions) (*AttackResult, error) {
	ctx, span := r.tracer.Start(ctx, "AttackRunner.Run")
	defer span.End()

	startTime := time.Now()
	result := NewAttackResult()

	r.logger.Debug("AttackRunner.Run called",
		"target_url", opts.TargetURL,
		"target_name", opts.TargetName,
		"agent", opts.AgentName)

	// Validate attack options
	if err := opts.Validate(); err != nil {
		r.logger.Error("Attack options validation failed", "error", err)
		return result.WithError(fmt.Errorf("invalid attack options: %w", err)), nil
	}

	r.logger.Info("Starting attack execution",
		"agent", opts.AgentName,
		"target", opts.TargetURL,
		"dry_run", opts.DryRun)

	// Step 1: Resolve target configuration
	targetConfig, err := r.targetResolver.Resolve(ctx, opts)
	if err != nil {
		r.logger.Error("Failed to resolve target", "error", err)
		return result.WithError(fmt.Errorf("target resolution failed: %w", err)), nil
	}

	r.logger.Debug("Target resolved",
		"url", targetConfig.URL,
		"type", targetConfig.Type,
		"provider", targetConfig.Provider)

	// Step 2: Select agent
	selectedAgent, err := r.agentSelector.Select(ctx, opts.AgentName)
	if err != nil {
		r.logger.Error("Failed to select agent", "agent", opts.AgentName, "error", err)
		return result.WithError(fmt.Errorf("agent selection failed: %w", err)), nil
	}

	r.logger.Debug("Agent selected", "agent", opts.AgentName)

	// Step 3: Filter payloads
	filteredPayloads, err := r.payloadFilter.Filter(ctx, opts)
	if err != nil {
		r.logger.Error("Failed to filter payloads", "error", err)
		return result.WithError(fmt.Errorf("payload filtering failed: %w", err)), nil
	}

	r.logger.Debug("Payloads filtered", "count", len(filteredPayloads))

	// Return early if dry-run mode
	if opts.DryRun {
		r.logger.Info("Dry-run mode: attack validation successful")
		result.Status = AttackStatusSuccess
		return result, nil
	}

	// Step 4: Create ephemeral mission
	missionObj, err := r.createEphemeralMission(ctx, opts, targetConfig, selectedAgent)
	if err != nil {
		r.logger.Error("Failed to create ephemeral mission", "error", err)
		return result.WithError(fmt.Errorf("mission creation failed: %w", err)), nil
	}

	r.logger.Debug("Ephemeral mission created", "mission_id", missionObj.ID)

	// Save ephemeral mission to database so the orchestrator can update it
	if err := r.missionStore.Save(ctx, missionObj); err != nil {
		r.logger.Error("Failed to save ephemeral mission", "error", err)
		return result.WithError(fmt.Errorf("mission save failed: %w", err)), nil
	}

	// Step 5: Execute mission through orchestrator
	// Create a cancellable context with timeout if specified
	execCtx := ctx
	var cancel context.CancelFunc
	if opts.Timeout > 0 {
		execCtx, cancel = context.WithTimeout(ctx, opts.Timeout)
		defer cancel()
	}

	missionResult, err := r.executeMission(execCtx, missionObj)
	if err != nil {
		// Check if error is due to cancellation
		if ctx.Err() == context.Canceled {
			r.logger.Info("Attack cancelled by user")
			result.Status = AttackStatusCancelled
			result.Duration = time.Since(startTime)
			return result, nil
		}

		// Check if error is due to timeout
		if execCtx.Err() == context.DeadlineExceeded {
			r.logger.Error("Attack timed out", "timeout", opts.Timeout)
			result.Status = AttackStatusTimeout
			result.Duration = time.Since(startTime)
			result.Error = fmt.Errorf("attack timed out after %s", opts.Timeout)
			return result, nil
		}

		r.logger.Error("Mission execution failed", "error", err)
		return result.WithError(fmt.Errorf("mission execution failed: %w", err)), nil
	}

	// Check for node failures before collecting findings
	r.logger.Info("Checking node failures",
		"workflow_result_nil", missionResult.WorkflowResult == nil,
		"workflow_result_len", len(missionResult.WorkflowResult),
	)
	failed, agentOutput, failedNodes := r.checkNodeFailures(missionResult)
	r.logger.Info("Node failure check result",
		"failed", failed,
		"agent_output", agentOutput,
		"failed_nodes", failedNodes,
	)
	if failed {
		r.logger.Error("Agent execution failed",
			"failed_nodes", failedNodes,
			"agent_output", agentOutput,
		)
		result.WithAgentFailure(agentOutput, failedNodes)
		result.Error = fmt.Errorf("agent failed: %s", agentOutput)
		// Continue to collect findings - some may have been submitted before failure
	}

	// Step 6: Collect findings from the mission
	findings, err := r.collectFindings(ctx, missionResult)
	if err != nil {
		r.logger.Error("Failed to collect findings", "error", err)
		return result.WithError(fmt.Errorf("finding collection failed: %w", err)), nil
	}

	// Populate result with findings
	result.AddFindings(findings)

	// Set execution metrics
	result.Duration = time.Since(startTime)
	if missionResult.Metrics != nil {
		result.TurnsUsed = missionResult.Metrics.CompletedNodes
		result.TokensUsed = missionResult.Metrics.TotalTokens
	}

	r.logger.Info("Attack execution completed",
		"duration", result.Duration,
		"findings", len(findings),
		"status", result.Status)

	// Step 7: Auto-persist logic
	shouldPersist := r.shouldPersistMission(opts, result)
	if shouldPersist {
		if err := r.persistMission(ctx, missionObj, findings); err != nil {
			r.logger.Error("Failed to persist mission", "error", err)
			// Don't fail the attack if persistence fails, just log it
		} else {
			result.WithMissionID(missionObj.ID)
			r.logger.Info("Mission persisted", "mission_id", missionObj.ID)
		}
	} else {
		r.logger.Debug("Mission not persisted (ephemeral)")
	}

	return result, nil
}

// createEphemeralMission creates a mission and workflow for the attack.
// The mission is not persisted to the database by default.
func (r *DefaultAttackRunner) createEphemeralMission(
	ctx context.Context,
	opts *AttackOptions,
	targetConfig *TargetConfig,
	selectedAgent agent.Agent,
) (*mission.Mission, error) {
	// Create a single-node workflow for the agent
	workflowObj := r.createSingleNodeWorkflow(opts, selectedAgent)

	// Generate ephemeral IDs for mission and workflow
	missionID := types.NewID()
	workflowObj.ID = types.NewID()

	// Serialize workflow to JSON for storage
	workflowJSON, err := json.Marshal(workflowObj)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize workflow: %w", err)
	}

	// Create mission with constraints from options
	// Include mission ID suffix to ensure uniqueness (name is UNIQUE in DB)
	// Use the real stored target ID (security guardrail - no ephemeral targets)
	missionObj := &mission.Mission{
		ID:           missionID,
		Name:         fmt.Sprintf("Attack: %s on %s [%s]", opts.AgentName, targetConfig.URL, missionID.String()[:8]),
		Description:  fmt.Sprintf("Ephemeral attack mission executing %s agent", opts.AgentName),
		Status:       mission.MissionStatusPending,
		TargetID:     opts.TargetID, // Use stored target ID
		WorkflowID:   workflowObj.ID,
		WorkflowJSON: string(workflowJSON),
		Constraints:  r.buildConstraints(opts),
		CreatedAt:    mission.NewUnixTimeNow(),
		UpdatedAt:    mission.NewUnixTimeNow(),
	}

	return missionObj, nil
}

// createSingleNodeWorkflow creates a mission definition with a single agent node.
func (r *DefaultAttackRunner) createSingleNodeWorkflow(
	opts *AttackOptions,
	selectedAgent agent.Agent,
) *mission.MissionDefinition {
	// Create agent node
	nodeID := "attack-node-1"

	// Create agent task
	taskInput := make(map[string]any)
	if opts.MaxTurns > 0 {
		taskInput["max_turns"] = opts.MaxTurns
	}

	agentTask := agent.NewTask(
		opts.AgentName,
		fmt.Sprintf("Execute %s agent", opts.AgentName), // description
		taskInput,
	)

	if opts.Timeout > 0 {
		agentTask = agentTask.WithTimeout(opts.Timeout)
	}

	node := &mission.MissionNode{
		ID:          nodeID,
		Type:        mission.NodeTypeAgent,
		Name:        opts.AgentName,
		Description: fmt.Sprintf("Execute %s agent", opts.AgentName),
		AgentName:   opts.AgentName,
		AgentTask:   &agentTask,
		Metadata: map[string]any{
			"ephemeral": true,
			"attack":    true,
		},
	}

	// Set timeout if specified
	if opts.Timeout > 0 {
		node.Timeout = opts.Timeout
	}

	// Create mission definition with single node
	missionDef := &mission.MissionDefinition{
		ID:          types.NewID(),
		Name:        fmt.Sprintf("Attack Workflow: %s", opts.AgentName),
		Description: "Ephemeral single-node workflow for attack command",
		Nodes: map[string]*mission.MissionNode{
			nodeID: node,
		},
		Edges:       []mission.MissionEdge{},
		EntryPoints: []string{nodeID},
		ExitPoints:  []string{nodeID},
		Metadata: map[string]any{
			"ephemeral": true,
			"attack":    true,
		},
		CreatedAt: time.Now(),
	}

	return missionDef
}

// buildConstraints creates mission constraints from attack options.
func (r *DefaultAttackRunner) buildConstraints(opts *AttackOptions) *mission.MissionConstraints {
	constraints := &mission.MissionConstraints{}

	if opts.Timeout > 0 {
		constraints.MaxDuration = opts.Timeout
	}

	if opts.MaxFindings > 0 {
		constraints.MaxFindings = opts.MaxFindings
	}

	if opts.SeverityThreshold != "" {
		constraints.SeverityThreshold = agent.FindingSeverity(opts.SeverityThreshold)
		constraints.SeverityAction = mission.ConstraintActionPause
	}

	return constraints
}

// executeMission executes the mission through the orchestrator.
// It handles context cancellation and returns the mission result.
func (r *DefaultAttackRunner) executeMission(
	ctx context.Context,
	missionObj *mission.Mission,
) (*mission.MissionResult, error) {
	// Execute mission through orchestrator
	result, err := r.orchestrator.Execute(ctx, missionObj)
	if err != nil {
		return nil, err
	}

	return result, nil
}

// checkNodeFailures examines the mission result for failed nodes
// and returns failure details if any nodes failed.
// It parses the WorkflowResult map to extract node statuses and output messages.
func (r *DefaultAttackRunner) checkNodeFailures(
	missionResult *mission.MissionResult,
) (failed bool, agentOutput string, failedNodes []string) {
	// WorkflowResult is stored as map[string]any
	if missionResult.WorkflowResult == nil {
		r.logger.Debug("checkNodeFailures: WorkflowResult is nil")
		return false, "", nil
	}

	// Debug: log all keys in WorkflowResult
	var keys []string
	for k := range missionResult.WorkflowResult {
		keys = append(keys, k)
	}
	r.logger.Info("checkNodeFailures: WorkflowResult keys", "keys", keys)

	// Extract node_results from the map
	nodeResultsRaw, ok := missionResult.WorkflowResult["node_results"]
	if !ok {
		r.logger.Info("checkNodeFailures: no node_results key found")
		return false, "", nil
	}

	r.logger.Info("checkNodeFailures: node_results type", "type", fmt.Sprintf("%T", nodeResultsRaw))

	nodeResults, ok := nodeResultsRaw.(map[string]any)
	if !ok {
		r.logger.Info("checkNodeFailures: node_results is not map[string]any", "actual_type", fmt.Sprintf("%T", nodeResultsRaw))
		return false, "", nil
	}

	r.logger.Info("checkNodeFailures: found node_results", "count", len(nodeResults))

	var outputs []string
	for nodeID, resultRaw := range nodeResults {
		result, ok := resultRaw.(map[string]any)
		if !ok {
			continue
		}

		// Check status
		status, _ := result["status"].(string)
		if status == "failed" || status == "error" {
			failedNodes = append(failedNodes, nodeID)

			// Extract output from multiple possible locations
			// 1. Check result["output"]["output"] or result["output"]["message"]
			if output, ok := result["output"].(map[string]any); ok {
				if msg, ok := output["output"].(string); ok && msg != "" {
					outputs = append(outputs, msg)
				} else if msg, ok := output["message"].(string); ok && msg != "" {
					outputs = append(outputs, msg)
				}
			}

			// 2. Check result["error"]["message"]
			if errObj, ok := result["error"].(map[string]any); ok {
				if msg, ok := errObj["message"].(string); ok && msg != "" {
					outputs = append(outputs, msg)
				}
			}
		}
	}

	if len(failedNodes) > 0 {
		return true, strings.Join(outputs, "; "), failedNodes
	}
	return false, "", nil
}

// collectFindings retrieves all findings from the mission result.
// For now, this is a placeholder that returns an empty list.
// In a full implementation, it would query the finding store or
// extract findings from the mission result.
func (r *DefaultAttackRunner) collectFindings(
	ctx context.Context,
	missionResult *mission.MissionResult,
) ([]finding.EnhancedFinding, error) {
	// If mission result contains finding IDs, retrieve them
	if len(missionResult.FindingIDs) == 0 {
		return []finding.EnhancedFinding{}, nil
	}

	// For ephemeral missions, findings might not be in the store yet
	// They would be in the mission result's workflow output
	// This is a simplified implementation
	findings := make([]finding.EnhancedFinding, 0, len(missionResult.FindingIDs))

	for _, findingID := range missionResult.FindingIDs {
		f, err := r.findingStore.Get(ctx, findingID)
		if err != nil {
			r.logger.Warn("Failed to retrieve finding", "finding_id", findingID, "error", err)
			continue
		}
		findings = append(findings, *f)
	}

	return findings, nil
}

// shouldPersistMission determines whether the mission should be persisted
// based on the attack options and results.
//
// Persistence logic:
// - If --no-persist is set, never persist
// - If --persist is set, always persist
// - Otherwise, auto-persist if findings were discovered
func (r *DefaultAttackRunner) shouldPersistMission(opts *AttackOptions, result *AttackResult) bool {
	// Never persist if --no-persist is explicitly set
	if opts.NoPersist {
		return false
	}

	// Always persist if --persist is explicitly set
	if opts.Persist {
		return true
	}

	// Auto-persist if findings were discovered
	return result.HasFindings()
}

// persistMission saves the mission and its findings to the database.
func (r *DefaultAttackRunner) persistMission(
	ctx context.Context,
	missionObj *mission.Mission,
	findings []finding.EnhancedFinding,
) error {
	// Save mission to database
	if err := r.missionStore.Save(ctx, missionObj); err != nil {
		return fmt.Errorf("failed to save mission: %w", err)
	}

	// Save all findings
	for _, f := range findings {
		if err := r.findingStore.Store(ctx, f); err != nil {
			r.logger.Error("Failed to save finding",
				"finding_id", f.ID,
				"mission_id", missionObj.ID,
				"error", err)
			// Continue saving other findings even if one fails
		}
	}

	return nil
}

// Ensure DefaultAttackRunner implements AttackRunner at compile time.
var _ AttackRunner = (*DefaultAttackRunner)(nil)
