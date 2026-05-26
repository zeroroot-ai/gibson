package orchestrator

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/zeroroot-ai/gibson/internal/graphrag/queries"
	"github.com/zeroroot-ai/gibson/internal/graphrag/schema"
	"github.com/zeroroot-ai/gibson/internal/types"
)

// Observer gathers execution state to build context for LLM reasoning.
// It queries the graph database to collect mission progress, mission status,
// and recent findings to inform orchestrator decisions.
type Observer struct {
	missionQueries   *queries.MissionQueries
	executionQueries *queries.ExecutionQueries
	inventoryBuilder *InventoryBuilder // Optional - provides component awareness
	approvalManager  ApprovalManager   // Optional - provides pending approvals
	reflectionEngine ReflectionEngine  // Optional - provides reflection insights
	graphQueries     GraphQueries      // Optional - provides cross-mission graph intelligence
}

// ObserverOption is a functional option for configuring Observer.
type ObserverOption func(*Observer)

// WithInventoryBuilder configures the Observer to include component inventory
// in observations. The inventory provides awareness of available agents, tools,
// and plugins for orchestration decisions.
//
// If not provided, observations will not include component inventory data.
func WithInventoryBuilder(builder *InventoryBuilder) ObserverOption {
	return func(o *Observer) {
		o.inventoryBuilder = builder
	}
}

// WithObserverApprovalManager configures the Observer to include pending approvals
// in observations. This alerts the orchestrator to operations awaiting human review.
//
// If not provided, observations will not include pending approvals.
func WithObserverApprovalManager(am ApprovalManager) ObserverOption {
	return func(o *Observer) {
		o.approvalManager = am
	}
}

// WithObserverReflectionEngine configures the Observer to include recent reflection
// insights in observations. This helps the orchestrator learn from past self-evaluations.
//
// If not provided, observations will not include reflection insights.
func WithObserverReflectionEngine(re ReflectionEngine) ObserverOption {
	return func(o *Observer) {
		o.reflectionEngine = re
	}
}

// WithGraphQueries configures the Observer to enrich observations with
// cross-mission graph intelligence: target history, prior findings on related
// targets, known entities discovered in earlier scans, and attack patterns
// that have been historically successful for the target type. The Observer
// calls these queries during Observe() and attaches the results to
// ObservationState.GraphContext for inclusion in the decision prompt.
//
// If not provided, observations skip graph intelligence enrichment.
//
// Per spec productionize-graph-intelligence, this option closes the
// orchestrator-side intelligence loop that was implemented under
// orchestrator-graph-intelligence but never wired into the Observer or its
// daemon construction sites.
func WithGraphQueries(gq GraphQueries) ObserverOption {
	return func(o *Observer) {
		o.graphQueries = gq
	}
}

// NewObserver creates a new Observer with the required query handlers.
// Both query dependencies are required and cannot be nil.
//
// Optional configuration can be provided via ObserverOption:
//   - WithInventoryBuilder(builder) - enables component inventory in observations
//
// Example:
//
//	observer := NewObserver(missionQueries, executionQueries,
//	    WithInventoryBuilder(inventoryBuilder),
//	)
func NewObserver(missionQueries *queries.MissionQueries, executionQueries *queries.ExecutionQueries, opts ...ObserverOption) *Observer {
	o := &Observer{
		missionQueries:   missionQueries,
		executionQueries: executionQueries,
	}

	for _, opt := range opts {
		opt(o)
	}

	return o
}

// ReflectionInsightSummary is a concise representation of a reflection insight
// for inclusion in observations. This provides recent self-evaluation context.
type ReflectionInsightSummary struct {
	CreatedAt  time.Time `json:"created_at"`
	Scope      string    `json:"scope"`
	Assessment string    `json:"assessment"`
	Confidence float64   `json:"confidence"`
}

// ApprovalSummary is a concise representation of a pending approval request
// for inclusion in observations. This alerts the orchestrator to pending approvals.
type ApprovalSummary struct {
	ID          string    `json:"id"`
	NodeID      string    `json:"node_id"`
	Context     string    `json:"context"`
	RequestedAt time.Time `json:"requested_at"`
}

// ObservationState contains all context needed for the LLM to make a decision.
// This struct is kept concise to avoid token bloat in prompts.
type ObservationState struct {
	// Mission metadata
	MissionInfo MissionInfo `json:"mission_info"`

	// Graph statistics summary
	GraphSummary GraphSummary `json:"graph_summary"`

	// Mission node states by status
	ReadyNodes     []NodeSummary          `json:"ready_nodes"`
	RunningNodes   []NodeSummary          `json:"running_nodes"`
	PendingNodes   []PendingNodeSummary   `json:"pending_nodes,omitempty"`
	CompletedNodes []CompletedNodeSummary `json:"completed_nodes"`
	FailedNodes    []NodeSummary          `json:"failed_nodes"`

	// Recent execution history for context
	RecentDecisions []DecisionSummary `json:"recent_decisions"`

	// Resource and time constraints
	ResourceConstraints ResourceConstraints `json:"resource_constraints"`

	// Failed execution that triggered this observation (if any)
	FailedExecution *ExecutionFailure `json:"failed_execution,omitempty"`

	// ComponentInventory contains available agents, tools, and plugins
	// This enables semantic error recovery by providing alternatives for failures.
	// Optional - only populated if Observer was configured with InventoryBuilder.
	ComponentInventory *ComponentInventory `json:"component_inventory,omitempty"`

	// MissionDAG shows full graph structure with entry/exit points and edges
	// Optional - only populated when dependency data is available
	MissionDAG *MissionDAG `json:"mission_dag,omitempty"`

	// RecalledContext contains formatted memory query results from recall action
	// This is injected by the recall handler when inject_into_context is true
	RecalledContext string `json:"recalled_context,omitempty"`

	// ReflectionInsights contains recent reflection insights for decision context
	// This helps the orchestrator learn from past self-evaluations
	ReflectionInsights []ReflectionInsightSummary `json:"reflection_insights,omitempty"`

	// PendingApprovals contains pending approval requests for this mission
	// This alerts the orchestrator to operations awaiting human review
	PendingApprovals []ApprovalSummary `json:"pending_approvals,omitempty"`

	// GraphContext contains cross-mission graph intelligence: target history,
	// prior findings, known entities, and historically successful attack
	// patterns. Populated only when the Observer was configured with
	// WithGraphQueries(...) and the mission has a target ref. Graph query
	// failures degrade gracefully — partial GraphContext is retained and
	// observation continues.
	GraphContext *GraphContext `json:"graph_context,omitempty"`

	// Timestamp when this observation was captured
	ObservedAt time.Time `json:"observed_at"`
}

// MissionInfo contains essential mission metadata
type MissionInfo struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Objective   string    `json:"objective"`
	Status      string    `json:"status"`
	StartedAt   time.Time `json:"started_at"`
	TimeElapsed string    `json:"time_elapsed"`
	// TargetRef is the reference to the target system (domain, IP, etc.) the
	// mission is scanning. Empty for orchestration / discovery missions
	// without a specific target. Used by graph intelligence enrichment.
	TargetRef string `json:"target_ref,omitempty"`
}

// GraphSummary provides high-level statistics about the attack graph state
type GraphSummary struct {
	TotalNodes      int `json:"total_nodes"`
	CompletedNodes  int `json:"completed_nodes"`
	FailedNodes     int `json:"failed_nodes"`
	PendingNodes    int `json:"pending_nodes"`
	TotalDecisions  int `json:"total_decisions"`
	TotalExecutions int `json:"total_executions"`
}

// NodeSummary is a concise representation of a mission node
type NodeSummary struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Type        string `json:"type"`
	Description string `json:"description"`
	AgentName   string `json:"agent_name,omitempty"`
	ToolName    string `json:"tool_name,omitempty"`
	Status      string `json:"status"`
	IsDynamic   bool   `json:"is_dynamic,omitempty"`
	Attempt     int    `json:"attempt,omitempty"`
}

// BlockingNodeInfo describes a node that is blocking another node from executing.
type BlockingNodeInfo struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	Status string `json:"status"`
}

// PendingNodeSummary extends NodeSummary with dependency blocking information.
// This is used for nodes that are waiting for their dependencies to complete.
type PendingNodeSummary struct {
	NodeSummary

	// BlockedBy contains IDs of nodes this node depends on
	BlockedBy []string `json:"blocked_by,omitempty"`

	// BlockedByDetails provides status of each blocking node
	BlockedByDetails []BlockingNodeInfo `json:"blocked_by_details,omitempty"`
}

// CompletedNodeSummary extends NodeSummary with execution results.
// This provides context about what was accomplished during node execution.
type CompletedNodeSummary struct {
	NodeSummary

	// Duration is how long the node took to execute
	Duration string `json:"duration,omitempty"`

	// CompletedAt is when the node finished
	CompletedAt time.Time `json:"completed_at,omitempty"`

	// OutputSummary is a brief description of what was produced (truncated to 200 chars)
	OutputSummary string `json:"output_summary,omitempty"`

	// FindingsCount is the number of findings discovered (for agent nodes)
	FindingsCount int `json:"findings_count,omitempty"`

	// FindingsSeverity breaks down findings by severity
	FindingsSeverity map[string]int `json:"findings_severity,omitempty"`
}

// MissionDAG represents the full mission graph structure.
// This provides complete visibility into the mission topology.
type MissionDAG struct {
	// EntryPoints are nodes with no dependencies (can execute immediately)
	EntryPoints []string `json:"entry_points"`

	// ExitPoints are nodes with no dependents (terminal nodes)
	ExitPoints []string `json:"exit_points"`

	// Edges maps each node to its dependencies (node -> depends_on)
	Edges map[string][]string `json:"edges"`

	// TotalNodes is the count of all nodes
	TotalNodes int `json:"total_nodes"`

	// CriticalPathLength is the longest dependency chain
	CriticalPathLength int `json:"critical_path_length,omitempty"`
}

// DecisionSummary captures key information from a past decision
type DecisionSummary struct {
	Iteration  int     `json:"iteration"`
	Action     string  `json:"action"`
	Target     string  `json:"target,omitempty"`
	Reasoning  string  `json:"reasoning"`
	Confidence float64 `json:"confidence"`
	Timestamp  string  `json:"timestamp"`
}

// ResourceConstraints tracks execution limits and budgets
type ResourceConstraints struct {
	MaxConcurrent    int           `json:"max_concurrent"`
	CurrentRunning   int           `json:"current_running"`
	TimeElapsed      time.Duration `json:"time_elapsed"`
	TotalIterations  int           `json:"total_iterations"`
	ExecutionBudget  *BudgetInfo   `json:"execution_budget,omitempty"`
	RemainingRetries int           `json:"remaining_retries,omitempty"`
}

// BudgetInfo tracks resource budgets (optional, for future use)
type BudgetInfo struct {
	MaxExecutions       int `json:"max_executions"`
	RemainingExecutions int `json:"remaining_executions"`
	MaxTokens           int `json:"max_tokens,omitempty"`
	UsedTokens          int `json:"used_tokens,omitempty"`
}

// ExecutionFailure captures details about a failed execution
type ExecutionFailure struct {
	// Existing fields
	NodeID     string    `json:"node_id"`
	NodeName   string    `json:"node_name"`
	AgentName  string    `json:"agent_name,omitempty"`
	Attempt    int       `json:"attempt"`
	Error      string    `json:"error"`
	FailedAt   time.Time `json:"failed_at"`
	CanRetry   bool      `json:"can_retry"`
	MaxRetries int       `json:"max_retries"`

	// NEW: Structured error classification for semantic error recovery
	// ErrorClass categorizes the error (infrastructure/semantic/transient/permanent)
	ErrorClass string `json:"error_class,omitempty"`

	// ErrorCode provides a specific error identifier (BINARY_NOT_FOUND, TIMEOUT, etc.)
	ErrorCode string `json:"error_code,omitempty"`

	// RecoveryHints provides concrete alternatives and recovery strategies
	RecoveryHints []RecoveryHintSummary `json:"recovery_hints,omitempty"`

	// PartialResults contains any salvageable data from the failed execution
	PartialResults map[string]any `json:"partial_results,omitempty"`

	// FailureContext contains additional context about what was tried
	FailureContext map[string]any `json:"failure_context,omitempty"`
}

// RecoveryHintSummary is the orchestrator's representation of a recovery hint.
// This is a simplified version that avoids tight coupling to SDK types.
type RecoveryHintSummary struct {
	// Strategy indicates the type of recovery action (retry, use_alternative_tool, etc.)
	Strategy string `json:"strategy"`

	// Alternative specifies an alternative tool or agent name, if applicable
	Alternative string `json:"alternative,omitempty"`

	// Params contains suggested parameter modifications
	Params map[string]any `json:"params,omitempty"`

	// Reason explains why this recovery approach might succeed
	Reason string `json:"reason"`

	// Priority determines the order to try hints (lower = try first)
	Priority int `json:"priority,omitempty"`
}

// Observe gathers all execution state for the given mission and builds
// an ObservationState suitable for prompt construction.
// Returns an error if required data cannot be retrieved.
func (o *Observer) Observe(ctx context.Context, missionID string) (*ObservationState, error) {
	if o.missionQueries == nil || o.executionQueries == nil {
		return nil, fmt.Errorf("observer not properly initialized: missing query dependencies")
	}

	mid, err := types.ParseID(missionID)
	if err != nil {
		return nil, fmt.Errorf("invalid mission ID: %w", err)
	}

	// Build observation state by querying graph
	state := &ObservationState{
		ObservedAt: time.Now(),
	}

	// 1. Get mission info
	if err := o.observeMission(ctx, mid, state); err != nil {
		return nil, fmt.Errorf("failed to observe mission info: %w", err)
	}

	// 2. Get mission statistics
	if err := o.observeStats(ctx, mid, state); err != nil {
		return nil, fmt.Errorf("failed to observe mission stats: %w", err)
	}

	// 3. Get mission nodes by status
	nodes, dependencyMap, err := o.observeNodesWithDependencies(ctx, mid, state)
	if err != nil {
		return nil, fmt.Errorf("failed to observe mission nodes: %w", err)
	}

	// 4. Build mission DAG structure
	if len(nodes) > 0 && dependencyMap != nil {
		state.MissionDAG = buildMissionDAG(nodes, dependencyMap)
	}

	// 5. Get recent decisions for context
	if err := o.observeDecisions(ctx, mid, state); err != nil {
		return nil, fmt.Errorf("failed to observe recent decisions: %w", err)
	}

	// 6. Calculate resource constraints
	o.calculateResourceConstraints(state)

	// 6. Build component inventory if builder is configured
	// This is optional - if inventory fails, log warning but don't fail the observation
	if o.inventoryBuilder != nil {
		inv, err := o.inventoryBuilder.BuildWithCache(ctx)
		if err != nil {
			// Log warning but continue - inventory is optional for backward compatibility
			slog.Warn("failed to build component inventory, continuing without it",
				"error", err,
				"mission_id", missionID)
		} else {
			state.ComponentInventory = inv
		}
	}

	// 7. Query pending approvals if approval manager is configured
	if o.approvalManager != nil {
		approvals, err := o.approvalManager.GetPendingApprovals(ctx, missionID)
		if err != nil {
			// Log warning but continue - approvals are optional
			slog.Warn("failed to query pending approvals, continuing without them",
				"error", err,
				"mission_id", missionID)
		} else if len(approvals) > 0 {
			// Convert to summary format
			state.PendingApprovals = make([]ApprovalSummary, 0, len(approvals))
			for _, approval := range approvals {
				state.PendingApprovals = append(state.PendingApprovals, ApprovalSummary{
					ID:          approval.ID,
					NodeID:      approval.NodeID,
					Context:     approval.Context,
					RequestedAt: approval.RequestedAt,
				})
			}
		}
	}

	// 7b. Enrich with cross-mission graph intelligence if GraphQueries is configured.
	// This populates state.GraphContext with target history, prior findings, known
	// entities, and successful attack patterns. Graceful degradation: per-query
	// failures log a WARN and partial context is retained.
	o.observeGraphContext(ctx, state)

	// 8. Query recent reflection insights if reflection engine is configured
	if o.reflectionEngine != nil {
		insights, err := o.reflectionEngine.GetRecentInsights(ctx, missionID, 3)
		if err != nil {
			// Log warning but continue - reflection insights are optional
			slog.Warn("failed to query reflection insights, continuing without them",
				"error", err,
				"mission_id", missionID)
		} else if len(insights) > 0 {
			// Convert to summary format
			state.ReflectionInsights = make([]ReflectionInsightSummary, 0, len(insights))
			for _, insight := range insights {
				state.ReflectionInsights = append(state.ReflectionInsights, ReflectionInsightSummary{
					CreatedAt:  insight.CreatedAt,
					Scope:      string(insight.Scope),
					Assessment: insight.Assessment,
					Confidence: 0.0, // ReflectionInsight doesn't have confidence, default to 0.0
				})
			}
		}
	}

	// Note: RecalledContext is injected by the recall handler via ActionResult metadata, not queried here

	return state, nil
}

// observeMission retrieves mission metadata
func (o *Observer) observeMission(ctx context.Context, missionID types.ID, state *ObservationState) error {
	mission, err := o.missionQueries.GetMission(ctx, missionID)
	if err != nil {
		return fmt.Errorf("failed to get mission: %w", err)
	}

	state.MissionInfo = MissionInfo{
		ID:        mission.ID.String(),
		Name:      mission.Name,
		Objective: mission.Objective,
		Status:    mission.Status.String(),
		TargetRef: mission.TargetRef,
	}

	if mission.StartedAt != nil {
		state.MissionInfo.StartedAt = *mission.StartedAt
		elapsed := time.Since(*mission.StartedAt)
		state.MissionInfo.TimeElapsed = formatDuration(elapsed)
	}

	return nil
}

// observeGraphContext queries the cross-mission knowledge graph for
// historical context about the mission's target. It runs the four
// GraphQueries methods concurrently with per-call timeouts (delegated to
// the underlying GraphQueries implementation), aggregates results into
// state.GraphContext, and degrades gracefully on per-query failures.
//
// Skipped entirely when the Observer has no graphQueries dependency or
// when the mission has no TargetRef (e.g., orchestration / discovery
// missions without a specific target).
//
// Per spec productionize-graph-intelligence, this is the missing
// integration step that makes the orchestrator-graph-intelligence
// implementation actually consumed in production.
func (o *Observer) observeGraphContext(ctx context.Context, state *ObservationState) {
	if o.graphQueries == nil {
		return
	}
	targetRef := state.MissionInfo.TargetRef
	if targetRef == "" {
		return
	}

	start := time.Now()
	gc := &GraphContext{}

	// Each call logs a WARN on failure; partial GraphContext is retained.
	if hist, err := o.graphQueries.GetTargetHistory(ctx, targetRef); err != nil {
		slog.Warn("graph intelligence: GetTargetHistory failed",
			"error", err, "mission_id", state.MissionInfo.ID, "target_ref", targetRef)
	} else if hist != nil {
		gc.TargetHistory = hist
	}

	if findings, err := o.graphQueries.GetPriorFindings(ctx, targetRef, 50); err != nil {
		slog.Warn("graph intelligence: GetPriorFindings failed",
			"error", err, "mission_id", state.MissionInfo.ID, "target_ref", targetRef)
	} else {
		gc.PriorFindings = findings
		if len(findings) >= 50 {
			gc.Truncated = true
		}
	}

	if entities, err := o.graphQueries.GetKnownEntities(ctx, targetRef); err != nil {
		slog.Warn("graph intelligence: GetKnownEntities failed",
			"error", err, "mission_id", state.MissionInfo.ID, "target_ref", targetRef)
	} else {
		gc.KnownEntities = entities
	}

	// Pass empty target type — the GraphQueries implementation falls back
	// to broad pattern queries when target type is unknown. Future work can
	// pull target type from the resolved target entity.
	if patterns, err := o.graphQueries.GetSuccessfulPatterns(ctx, ""); err != nil {
		slog.Warn("graph intelligence: GetSuccessfulPatterns failed",
			"error", err, "mission_id", state.MissionInfo.ID, "target_ref", targetRef)
	} else {
		gc.SuccessfulPatterns = patterns
	}

	gc.QueryDuration = time.Since(start)
	state.GraphContext = gc
}

// observeStats retrieves mission execution statistics
func (o *Observer) observeStats(ctx context.Context, missionID types.ID, state *ObservationState) error {
	stats, err := o.missionQueries.GetMissionStats(ctx, missionID)
	if err != nil {
		return fmt.Errorf("failed to get mission stats: %w", err)
	}

	state.GraphSummary = GraphSummary{
		TotalNodes:      stats.TotalNodes,
		CompletedNodes:  stats.CompletedNodes,
		FailedNodes:     stats.FailedNodes,
		PendingNodes:    stats.PendingNodes,
		TotalDecisions:  stats.TotalDecisions,
		TotalExecutions: stats.TotalExecutions,
	}

	return nil
}

// observeNodesWithDependencies retrieves and categorizes mission nodes by status.
// Returns the nodes and dependency map for DAG construction.
func (o *Observer) observeNodesWithDependencies(ctx context.Context, missionID types.ID, state *ObservationState) ([]*schema.MissionNode, map[string][]string, error) {
	// Get all nodes for the mission
	nodes, err := o.missionQueries.GetMissionNodes(ctx, missionID)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get mission nodes: %w", err)
	}

	// Get all dependencies in a single batch query
	dependencyMap, err := o.missionQueries.GetMissionNodeDependencies(ctx, missionID)
	if err != nil {
		// Log warning but continue with empty dependency map
		slog.Warn("failed to query node dependencies, continuing without dependency info",
			"mission_id", missionID.String(),
			"error", err)
		dependencyMap = make(map[string][]string)
	}

	// Create node lookup map for status checks
	nodeMap := make(map[string]*schema.MissionNode, len(nodes))
	for _, node := range nodes {
		nodeMap[node.ID.String()] = node
	}

	// Categorize nodes by status
	for _, node := range nodes {
		summary := nodeToSummary(node)

		// Add attempt count for failed/running nodes
		if node.Status == schema.MissionNodeStatusFailed ||
			node.Status == schema.MissionNodeStatusRunning {
			executions, err := o.missionQueries.GetNodeExecutions(ctx, node.ID)
			if err == nil && len(executions) > 0 {
				summary.Attempt = executions[len(executions)-1].Attempt
			}
		}

		switch node.Status {
		case schema.MissionNodeStatusReady:
			state.ReadyNodes = append(state.ReadyNodes, summary)

		case schema.MissionNodeStatusRunning:
			state.RunningNodes = append(state.RunningNodes, summary)

		case schema.MissionNodeStatusPending:
			// Build pending node with dependency information
			pendingNode := PendingNodeSummary{
				NodeSummary: summary,
			}

			// Get dependencies for this node
			if deps, ok := dependencyMap[node.ID.String()]; ok && len(deps) > 0 {
				pendingNode.BlockedBy = deps

				// Build BlockedByDetails with status of each blocking node
				for _, depID := range deps {
					if depNode, found := nodeMap[depID]; found {
						pendingNode.BlockedByDetails = append(pendingNode.BlockedByDetails, BlockingNodeInfo{
							ID:     depID,
							Name:   depNode.Name,
							Status: depNode.Status.String(),
						})
					}
				}
			}

			state.PendingNodes = append(state.PendingNodes, pendingNode)

		case schema.MissionNodeStatusCompleted:
			// Build completed node with execution details
			completedNode := CompletedNodeSummary{
				NodeSummary: summary,
			}

			// Get execution details for duration and output summary
			executions, err := o.missionQueries.GetNodeExecutions(ctx, node.ID)
			if err == nil && len(executions) > 0 {
				lastExec := executions[len(executions)-1]

				// Calculate duration
				if lastExec.CompletedAt != nil {
					duration := lastExec.CompletedAt.Sub(lastExec.StartedAt)
					completedNode.Duration = formatDuration(duration)
					completedNode.CompletedAt = *lastExec.CompletedAt
				}

				// Extract output summary from result
				if lastExec.Result != nil {
					outputSummary := extractOutputSummary(lastExec.Result)
					completedNode.OutputSummary = truncateString(outputSummary, 200)
				}

				// For agent nodes, extract findings count and severity
				if node.Type == schema.MissionNodeTypeAgent && lastExec.Result != nil {
					if findingsData, ok := lastExec.Result["findings"]; ok {
						completedNode.FindingsCount, completedNode.FindingsSeverity = extractFindingsInfo(findingsData)
					}
				}
			}

			state.CompletedNodes = append(state.CompletedNodes, completedNode)

		case schema.MissionNodeStatusFailed:
			state.FailedNodes = append(state.FailedNodes, summary)
		}
	}

	// Initialize empty slices if nil
	if state.ReadyNodes == nil {
		state.ReadyNodes = []NodeSummary{}
	}
	if state.RunningNodes == nil {
		state.RunningNodes = []NodeSummary{}
	}
	if state.PendingNodes == nil {
		state.PendingNodes = []PendingNodeSummary{}
	}
	if state.CompletedNodes == nil {
		state.CompletedNodes = []CompletedNodeSummary{}
	}
	if state.FailedNodes == nil {
		state.FailedNodes = []NodeSummary{}
	}

	return nodes, dependencyMap, nil
}

// observeDecisions retrieves recent orchestrator decisions for context
func (o *Observer) observeDecisions(ctx context.Context, missionID types.ID, state *ObservationState) error {
	decisions, err := o.missionQueries.GetMissionDecisions(ctx, missionID)
	if err != nil {
		return fmt.Errorf("failed to get decisions: %w", err)
	}

	// Take last N decisions (most recent context)
	const maxRecentDecisions = 5
	start := 0
	if len(decisions) > maxRecentDecisions {
		start = len(decisions) - maxRecentDecisions
	}

	state.RecentDecisions = make([]DecisionSummary, 0, maxRecentDecisions)
	for _, decision := range decisions[start:] {
		state.RecentDecisions = append(state.RecentDecisions, DecisionSummary{
			Iteration:  decision.Iteration,
			Action:     decision.Action.String(),
			Target:     decision.TargetNodeID,
			Reasoning:  truncateString(decision.Reasoning, 200),
			Confidence: decision.Confidence,
			Timestamp:  decision.Timestamp.Format(time.RFC3339),
		})
	}

	if state.RecentDecisions == nil {
		state.RecentDecisions = []DecisionSummary{}
	}

	return nil
}

// calculateResourceConstraints computes resource usage and limits
func (o *Observer) calculateResourceConstraints(state *ObservationState) {
	state.ResourceConstraints = ResourceConstraints{
		MaxConcurrent:   10, // Default, should be configurable
		CurrentRunning:  len(state.RunningNodes),
		TotalIterations: len(state.RecentDecisions),
	}

	// Calculate time elapsed
	if !state.MissionInfo.StartedAt.IsZero() {
		state.ResourceConstraints.TimeElapsed = time.Since(state.MissionInfo.StartedAt)
	}

	// Calculate remaining retries for failed nodes
	remainingRetries := 0
	for _, node := range state.FailedNodes {
		// Assume max 3 retries by default
		if node.Attempt < 3 {
			remainingRetries++
		}
	}
	state.ResourceConstraints.RemainingRetries = remainingRetries
}

// ObserveWithFailure is a convenience method that captures a failed execution
// and builds the observation state with that context included.
func (o *Observer) ObserveWithFailure(ctx context.Context, missionID string, failedNodeID string) (*ObservationState, error) {
	state, err := o.Observe(ctx, missionID)
	if err != nil {
		return nil, err
	}

	// Find the failed node and get execution details
	mid, err := types.ParseID(missionID)
	if err != nil {
		return nil, fmt.Errorf("invalid mission ID: %w", err)
	}

	nid, err := types.ParseID(failedNodeID)
	if err != nil {
		return nil, fmt.Errorf("invalid node ID: %w", err)
	}

	// Get node details
	nodes, err := o.missionQueries.GetMissionNodes(ctx, mid)
	if err != nil {
		return nil, fmt.Errorf("failed to get nodes: %w", err)
	}

	var failedNode *schema.MissionNode
	for _, node := range nodes {
		if node.ID == nid {
			failedNode = node
			break
		}
	}

	if failedNode == nil {
		return nil, fmt.Errorf("failed node %s not found", failedNodeID)
	}

	// Get execution details
	executions, err := o.missionQueries.GetNodeExecutions(ctx, nid)
	if err != nil {
		return nil, fmt.Errorf("failed to get node executions: %w", err)
	}

	if len(executions) == 0 {
		return state, nil // No executions yet
	}

	lastExec := executions[len(executions)-1]
	maxRetries := 3 // Default
	if failedNode.RetryPolicy != nil {
		maxRetries = failedNode.RetryPolicy.MaxRetries
	}

	state.FailedExecution = &ExecutionFailure{
		NodeID:     failedNode.ID.String(),
		NodeName:   failedNode.Name,
		AgentName:  failedNode.AgentName,
		Attempt:    lastExec.Attempt,
		Error:      lastExec.Error,
		FailedAt:   *lastExec.CompletedAt,
		CanRetry:   lastExec.Attempt < maxRetries,
		MaxRetries: maxRetries,
	}

	return state, nil
}

// FormatForPrompt converts the observation state into a well-formatted string
// suitable for inclusion in an LLM prompt.
func (s *ObservationState) FormatForPrompt() string {
	var sb strings.Builder

	// Mission context
	sb.WriteString("=== MISSION CONTEXT ===\n")
	sb.WriteString(fmt.Sprintf("Mission: %s\n", s.MissionInfo.Name))
	sb.WriteString(fmt.Sprintf("Objective: %s\n", s.MissionInfo.Objective))
	sb.WriteString(fmt.Sprintf("Status: %s\n", s.MissionInfo.Status))
	sb.WriteString(fmt.Sprintf("Time Elapsed: %s\n", s.MissionInfo.TimeElapsed))
	sb.WriteString("\n")

	// Mission progress
	sb.WriteString("=== MISSION PROGRESS ===\n")
	sb.WriteString(fmt.Sprintf("Total Nodes: %d\n", s.GraphSummary.TotalNodes))
	sb.WriteString(fmt.Sprintf("Completed: %d\n", s.GraphSummary.CompletedNodes))
	sb.WriteString(fmt.Sprintf("Failed: %d\n", s.GraphSummary.FailedNodes))
	sb.WriteString(fmt.Sprintf("Pending: %d\n", s.GraphSummary.PendingNodes))
	sb.WriteString(fmt.Sprintf("Total Decisions: %d\n", s.GraphSummary.TotalDecisions))
	sb.WriteString("\n")

	// Resource constraints
	sb.WriteString("=== RESOURCE CONSTRAINTS ===\n")
	sb.WriteString(fmt.Sprintf("Max Concurrent: %d\n", s.ResourceConstraints.MaxConcurrent))
	sb.WriteString(fmt.Sprintf("Currently Running: %d\n", s.ResourceConstraints.CurrentRunning))
	sb.WriteString(fmt.Sprintf("Total Iterations: %d\n", s.ResourceConstraints.TotalIterations))
	if s.ResourceConstraints.RemainingRetries > 0 {
		sb.WriteString(fmt.Sprintf("Nodes Available for Retry: %d\n", s.ResourceConstraints.RemainingRetries))
	}
	sb.WriteString("\n")

	// Cross-mission graph intelligence (if available). Always emit the section
	// when GraphContext is set so the LLM sees a consistent prompt structure;
	// "no prior knowledge" is a valid signal too.
	if s.GraphContext != nil {
		sb.WriteString("=== GRAPH INTELLIGENCE (Prior Knowledge) ===\n")
		gc := s.GraphContext
		hasAny := gc.TargetHistory != nil || len(gc.PriorFindings) > 0 || len(gc.KnownEntities) > 0 || len(gc.SuccessfulPatterns) > 0
		if !hasAny {
			sb.WriteString("No prior knowledge available for this target.\n")
		} else {
			if gc.TargetHistory != nil {
				th := gc.TargetHistory
				sb.WriteString(fmt.Sprintf("Target History: %d previous scans, %d total findings (critical=%d high=%d medium=%d low=%d)\n",
					th.PreviousScanCount, th.TotalFindings, th.CriticalCount, th.HighCount, th.MediumCount, th.LowCount))
				if th.LastScanDate != nil {
					sb.WriteString(fmt.Sprintf("Last Scan: %s\n", th.LastScanDate.Format(time.RFC3339)))
				}
			}
			if len(gc.PriorFindings) > 0 {
				sb.WriteString(fmt.Sprintf("Prior Findings (top %d", len(gc.PriorFindings)))
				if gc.Truncated {
					sb.WriteString(", truncated")
				}
				sb.WriteString("):\n")
				maxShow := len(gc.PriorFindings)
				if maxShow > 5 {
					maxShow = 5
				}
				for i := 0; i < maxShow; i++ {
					f := gc.PriorFindings[i]
					sb.WriteString(fmt.Sprintf("- [%s/%s] %s\n", f.Severity, f.Category, f.Title))
				}
				if len(gc.PriorFindings) > maxShow {
					sb.WriteString(fmt.Sprintf("- (and %d more)\n", len(gc.PriorFindings)-maxShow))
				}
			}
			if len(gc.KnownEntities) > 0 {
				sb.WriteString(fmt.Sprintf("Known Entities: %d (sample by type:", len(gc.KnownEntities)))
				typeCounts := map[string]int{}
				for _, e := range gc.KnownEntities {
					typeCounts[e.Type]++
				}
				for t, c := range typeCounts {
					sb.WriteString(fmt.Sprintf(" %s=%d", t, c))
				}
				sb.WriteString(")\n")
			}
			if len(gc.SuccessfulPatterns) > 0 {
				sb.WriteString("Successful Attack Patterns for this Target Type:\n")
				maxPat := len(gc.SuccessfulPatterns)
				if maxPat > 5 {
					maxPat = 5
				}
				for i := 0; i < maxPat; i++ {
					p := gc.SuccessfulPatterns[i]
					sb.WriteString(fmt.Sprintf("- %s (%s) — success_rate=%.0f%% across %d samples\n",
						p.TechniqueID, p.TechniqueName, p.SuccessRate*100, p.SampleCount))
				}
			}
		}
		sb.WriteString("\n")
	}

	// Tool capabilities (if available)
	if s.ComponentInventory != nil {
		// Check if any tools have non-nil capabilities
		hasCapabilities := false
		for _, tool := range s.ComponentInventory.Tools {
			if tool.Capabilities != nil {
				hasCapabilities = true
				break
			}
		}

		if hasCapabilities {
			sb.WriteString("=== TOOL CAPABILITIES ===\n")
			for _, tool := range s.ComponentInventory.Tools {
				if tool.Capabilities == nil {
					continue
				}

				caps := tool.Capabilities
				sb.WriteString(fmt.Sprintf("\n### %s\n", tool.Name))

				// Privilege level
				if caps.HasRoot {
					sb.WriteString("- Privileges: root (full access)\n")
				} else if caps.HasSudo {
					sb.WriteString("- Privileges: sudo (passwordless escalation available)\n")
				} else if caps.CanRawSocket {
					sb.WriteString("- Privileges: unprivileged with raw socket capability\n")
				} else {
					sb.WriteString("- Privileges: unprivileged (no root, no sudo, no raw socket)\n")
				}

				// Blocked arguments
				if len(caps.BlockedArgs) > 0 {
					sb.WriteString(fmt.Sprintf("- Blocked flags: %s\n", strings.Join(caps.BlockedArgs, ", ")))
				}

				// Argument alternatives
				if len(caps.ArgAlternatives) > 0 {
					sb.WriteString("- Available alternatives:\n")
					for blocked, alternative := range caps.ArgAlternatives {
						sb.WriteString(fmt.Sprintf("  - Use %s instead of %s\n", alternative, blocked))
					}
				}

				// Features
				if len(caps.Features) > 0 {
					var enabledFeatures []string
					var disabledFeatures []string
					for feature, enabled := range caps.Features {
						if enabled {
							enabledFeatures = append(enabledFeatures, feature)
						} else {
							disabledFeatures = append(disabledFeatures, feature)
						}
					}
					if len(enabledFeatures) > 0 {
						sb.WriteString(fmt.Sprintf("- Available features: %s\n", strings.Join(enabledFeatures, ", ")))
					}
					if len(disabledFeatures) > 0 {
						sb.WriteString(fmt.Sprintf("- Unavailable features: %s\n", strings.Join(disabledFeatures, ", ")))
					}
				}
			}
			sb.WriteString("\n")
		}
	}

	// Ready nodes (most important for decision making)
	if len(s.ReadyNodes) > 0 {
		sb.WriteString("=== READY NODES (Can Execute Now) ===\n")
		for _, node := range s.ReadyNodes {
			sb.WriteString(fmt.Sprintf("- [%s] %s: %s\n", node.ID, node.Name, node.Description))
			if node.AgentName != "" {
				sb.WriteString(fmt.Sprintf("  Agent: %s\n", node.AgentName))
			}
		}
		sb.WriteString("\n")
	}

	// Running nodes
	if len(s.RunningNodes) > 0 {
		sb.WriteString("=== RUNNING NODES ===\n")
		for _, node := range s.RunningNodes {
			sb.WriteString(fmt.Sprintf("- [%s] %s", node.ID, node.Name))
			if node.Attempt > 1 {
				sb.WriteString(fmt.Sprintf(" (attempt %d)", node.Attempt))
			}
			sb.WriteString("\n")
		}
		sb.WriteString("\n")
	}

	// Failed nodes
	if len(s.FailedNodes) > 0 {
		sb.WriteString("=== FAILED NODES ===\n")
		for _, node := range s.FailedNodes {
			sb.WriteString(fmt.Sprintf("- [%s] %s", node.ID, node.Name))
			if node.Attempt > 0 {
				sb.WriteString(fmt.Sprintf(" (attempt %d)", node.Attempt))
			}
			sb.WriteString("\n")
		}
		sb.WriteString("\n")
	}

	// Failed execution context (if present)
	if s.FailedExecution != nil {
		f := s.FailedExecution
		sb.WriteString("=== RECENT FAILURE ===\n")
		sb.WriteString(fmt.Sprintf("Node: %s (%s)\n", f.NodeName, f.NodeID))
		if f.AgentName != "" {
			sb.WriteString(fmt.Sprintf("Agent: %s\n", f.AgentName))
		}
		sb.WriteString(fmt.Sprintf("Attempt: %d/%d\n", f.Attempt, f.MaxRetries))

		// NEW: Error classification
		if f.ErrorCode != "" {
			sb.WriteString(fmt.Sprintf("Error Code: %s\n", f.ErrorCode))
		}
		if f.ErrorClass != "" {
			sb.WriteString(fmt.Sprintf("Error Class: %s\n", f.ErrorClass))
		}
		sb.WriteString(fmt.Sprintf("Error: %s\n", truncateString(f.Error, 300)))
		sb.WriteString(fmt.Sprintf("Can Retry: %v\n", f.CanRetry))

		// NEW: Recovery hints
		if len(f.RecoveryHints) > 0 {
			sb.WriteString("\nRecovery Options:\n")
			for i, hint := range f.RecoveryHints {
				sb.WriteString(fmt.Sprintf("%d. [%s]", i+1, hint.Strategy))
				if hint.Alternative != "" {
					sb.WriteString(fmt.Sprintf(" %s", hint.Alternative))
				}
				sb.WriteString(fmt.Sprintf(" - %s\n", hint.Reason))
				if len(hint.Params) > 0 {
					sb.WriteString(fmt.Sprintf("   Suggested params: %v\n", hint.Params))
				}
			}
		}

		// NEW: Partial results
		if len(f.PartialResults) > 0 {
			sb.WriteString("\nPartial Results Recovered:\n")
			for k, v := range f.PartialResults {
				sb.WriteString(fmt.Sprintf("  %s: %v\n", k, v))
			}
		}

		// NEW: Failure context
		if len(f.FailureContext) > 0 {
			sb.WriteString("\nFailure Context:\n")
			for k, v := range f.FailureContext {
				sb.WriteString(fmt.Sprintf("  %s: %v\n", k, v))
			}
		}

		sb.WriteString("\n")
	}

	// Recent decisions for context
	if len(s.RecentDecisions) > 0 {
		sb.WriteString("=== RECENT DECISIONS ===\n")
		for _, dec := range s.RecentDecisions {
			sb.WriteString(fmt.Sprintf("Iteration %d: %s", dec.Iteration, dec.Action))
			if dec.Target != "" {
				sb.WriteString(fmt.Sprintf(" -> %s", dec.Target))
			}
			sb.WriteString(fmt.Sprintf(" (confidence: %.2f)\n", dec.Confidence))
			if dec.Reasoning != "" {
				sb.WriteString(fmt.Sprintf("  Reasoning: %s\n", dec.Reasoning))
			}
		}
		sb.WriteString("\n")
	}

	return sb.String()
}

// Helper functions

// nodeToSummary converts a schema.MissionNode to a concise NodeSummary
func nodeToSummary(node *schema.MissionNode) NodeSummary {
	return NodeSummary{
		ID:          node.ID.String(),
		Name:        node.Name,
		Type:        node.Type.String(),
		Description: node.Description,
		AgentName:   node.AgentName,
		ToolName:    node.ToolName,
		Status:      node.Status.String(),
		IsDynamic:   node.IsDynamic,
	}
}

// formatDuration formats a duration into a human-readable string
func formatDuration(d time.Duration) string {
	if d < time.Minute {
		return fmt.Sprintf("%.0fs", d.Seconds())
	}
	if d < time.Hour {
		return fmt.Sprintf("%.1fm", d.Minutes())
	}
	return fmt.Sprintf("%.1fh", d.Hours())
}

// truncateString truncates a string to the specified length with ellipsis
func truncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	if maxLen <= 3 {
		return "..."
	}
	return s[:maxLen-3] + "..."
}

// extractOutputSummary extracts a human-readable summary from execution result data.
// Looks for common fields like "summary", "message", "output", or constructs a basic summary.
func extractOutputSummary(result map[string]any) string {
	// Try common summary fields first
	if summary, ok := result["summary"].(string); ok && summary != "" {
		return summary
	}
	if message, ok := result["message"].(string); ok && message != "" {
		return message
	}
	if output, ok := result["output"].(string); ok && output != "" {
		return output
	}

	// Build a summary from available keys
	var parts []string
	if count, ok := result["count"].(float64); ok {
		parts = append(parts, fmt.Sprintf("count: %.0f", count))
	} else if count, ok := result["count"].(int); ok {
		parts = append(parts, fmt.Sprintf("count: %d", count))
	}

	if status, ok := result["status"].(string); ok && status != "" {
		parts = append(parts, fmt.Sprintf("status: %s", status))
	}

	if len(parts) > 0 {
		return strings.Join(parts, ", ")
	}

	// Fallback: just indicate successful completion
	return "execution completed"
}

// extractFindingsInfo extracts findings count and severity breakdown from result data.
// Returns (count, severity_map).
func extractFindingsInfo(findingsData any) (int, map[string]int) {
	severityMap := make(map[string]int)

	// Handle findings as array
	if findingsArray, ok := findingsData.([]any); ok {
		count := len(findingsArray)

		// Count severities
		for _, finding := range findingsArray {
			if findingMap, ok := finding.(map[string]any); ok {
				if severity, ok := findingMap["severity"].(string); ok && severity != "" {
					severityMap[severity]++
				}
			}
		}

		return count, severityMap
	}

	// Handle findings as map with count/severity fields
	if findingsMap, ok := findingsData.(map[string]any); ok {
		count := 0
		if c, ok := findingsMap["count"].(float64); ok {
			count = int(c)
		} else if c, ok := findingsMap["count"].(int); ok {
			count = c
		}

		// Extract severity breakdown if present
		if severities, ok := findingsMap["severity"].(map[string]any); ok {
			for severity, sCount := range severities {
				if countFloat, ok := sCount.(float64); ok {
					severityMap[severity] = int(countFloat)
				} else if countInt, ok := sCount.(int); ok {
					severityMap[severity] = countInt
				}
			}
		}

		return count, severityMap
	}

	return 0, severityMap
}

// buildMissionDAG constructs a MissionDAG structure from nodes and their dependencies.
// This provides complete visibility into the mission topology including entry/exit points
// and the critical path length.
func buildMissionDAG(nodes []*schema.MissionNode, dependencyMap map[string][]string) *MissionDAG {
	if len(nodes) == 0 {
		return nil
	}

	dag := &MissionDAG{
		Edges:       make(map[string][]string),
		TotalNodes:  len(nodes),
		EntryPoints: []string{},
		ExitPoints:  []string{},
	}

	// Build reverse dependency map to find nodes with no dependents (exit points)
	reverseDeps := make(map[string][]string)
	allNodeIDs := make(map[string]bool)

	// Collect all node IDs
	for _, node := range nodes {
		nodeID := node.ID.String()
		allNodeIDs[nodeID] = true
	}

	// Build edges map and reverse dependencies
	for nodeID, deps := range dependencyMap {
		dag.Edges[nodeID] = deps

		// Build reverse dependency map
		for _, depID := range deps {
			reverseDeps[depID] = append(reverseDeps[depID], nodeID)
		}
	}

	// Find entry points (nodes with no dependencies)
	for nodeID := range allNodeIDs {
		if len(dependencyMap[nodeID]) == 0 {
			dag.EntryPoints = append(dag.EntryPoints, nodeID)
		}
	}

	// Find exit points (nodes with no dependents)
	for nodeID := range allNodeIDs {
		if len(reverseDeps[nodeID]) == 0 {
			dag.ExitPoints = append(dag.ExitPoints, nodeID)
		}
	}

	// Calculate critical path length using topological sort and longest path
	dag.CriticalPathLength = calculateCriticalPath(dependencyMap, dag.EntryPoints)

	return dag
}

// calculateCriticalPath calculates the longest path from entry points to any node.
// This represents the minimum number of sequential steps needed to complete the mission.
func calculateCriticalPath(dependencyMap map[string][]string, entryPoints []string) int {
	if len(entryPoints) == 0 {
		return 0
	}

	// Use dynamic programming to find longest path
	// distance[node] = longest path from any entry point to this node
	distance := make(map[string]int)

	// Build reverse map for traversal
	reverseDeps := make(map[string][]string)
	for nodeID, deps := range dependencyMap {
		for _, depID := range deps {
			reverseDeps[depID] = append(reverseDeps[depID], nodeID)
		}
	}

	// Initialize entry points with distance 0
	for _, entryID := range entryPoints {
		distance[entryID] = 0
	}

	// BFS from entry points to calculate longest paths
	queue := make([]string, len(entryPoints))
	copy(queue, entryPoints)
	visited := make(map[string]bool)

	maxDistance := 0

	for len(queue) > 0 {
		currentID := queue[0]
		queue = queue[1:]

		if visited[currentID] {
			continue
		}
		visited[currentID] = true

		currentDist := distance[currentID]
		if currentDist > maxDistance {
			maxDistance = currentDist
		}

		// Update distances for nodes that depend on this one
		for _, dependentID := range reverseDeps[currentID] {
			newDist := currentDist + 1
			if existingDist, exists := distance[dependentID]; !exists || newDist > existingDist {
				distance[dependentID] = newDist
			}
			queue = append(queue, dependentID)
		}
	}

	return maxDistance + 1 // +1 because we count nodes, not edges
}
