package report

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"golang.org/x/sync/errgroup"

	"github.com/zero-day-ai/gibson/internal/agent"
	"github.com/zero-day-ai/gibson/internal/database"
	"github.com/zero-day-ai/gibson/internal/finding"
	"github.com/zero-day-ai/gibson/internal/graphrag"
	"github.com/zero-day-ai/gibson/internal/mission"
	"github.com/zero-day-ai/gibson/internal/payload"
	"github.com/zero-day-ai/gibson/internal/types"
)

// DefaultAggregator is the default implementation of DataAggregator.
// It coordinates multiple sub-aggregators to collect data from all Gibson subsystems.
type DefaultAggregator struct {
	findingStore  finding.FindingStore
	missionStore  mission.MissionStore
	targetDAO     database.TargetDAO
	graphStore    graphrag.GraphRAGStore
	payloadStore  payload.ExecutionStore
	payloadDefs   payload.PayloadStore
	logger        *slog.Logger
}

// AggregatorConfig contains dependencies for the DefaultAggregator.
type AggregatorConfig struct {
	FindingStore finding.FindingStore
	MissionStore mission.MissionStore
	TargetDAO    database.TargetDAO
	GraphStore   graphrag.GraphRAGStore // Optional, can be nil
	PayloadStore payload.ExecutionStore // Optional, can be nil
	PayloadDefs  payload.PayloadStore   // Optional, can be nil
	Logger       *slog.Logger
}

// NewDefaultAggregator creates a new default aggregator with the given dependencies.
func NewDefaultAggregator(cfg AggregatorConfig) *DefaultAggregator {
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}

	return &DefaultAggregator{
		findingStore:  cfg.FindingStore,
		missionStore:  cfg.MissionStore,
		targetDAO:     cfg.TargetDAO,
		graphStore:    cfg.GraphStore,
		payloadStore:  cfg.PayloadStore,
		payloadDefs:   cfg.PayloadDefs,
		logger:        cfg.Logger,
	}
}

// Aggregate collects all data for a single mission.
func (a *DefaultAggregator) Aggregate(ctx context.Context, missionID types.ID, opts AggregateOptions) (*ReportData, error) {
	a.logger.Info("starting data aggregation", "mission_id", missionID)
	startTime := time.Now()

	// Apply timeout if specified
	if opts.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, opts.Timeout)
		defer cancel()
	}

	// Initialize report data
	reportData := &ReportData{
		FindingsByAgent: make(map[string][]types.ID),
		ComplianceState: make(map[string]ComplianceMapping),
	}

	// Run aggregation based on parallel mode
	var err error
	if opts.ParallelMode {
		err = a.aggregateParallel(ctx, missionID, opts, reportData)
	} else {
		err = a.aggregateSequential(ctx, missionID, opts, reportData)
	}

	if err != nil {
		return nil, fmt.Errorf("aggregation failed: %w", err)
	}

	// Calculate derived metrics
	a.calculateDerivedMetrics(reportData)

	duration := time.Since(startTime)
	a.logger.Info("data aggregation completed",
		"mission_id", missionID,
		"duration", duration,
		"findings_count", len(reportData.Findings),
		"assets_count", len(reportData.Assets),
		"events_count", len(reportData.Timeline),
	)

	return reportData, nil
}

// aggregateParallel runs sub-aggregators concurrently using errgroup.
func (a *DefaultAggregator) aggregateParallel(ctx context.Context, missionID types.ID, opts AggregateOptions, reportData *ReportData) error {
	g, ctx := errgroup.WithContext(ctx)

	// Critical aggregations (failures will abort report generation)
	g.Go(func() error {
		return a.aggregateMission(ctx, missionID, reportData)
	})

	g.Go(func() error {
		return a.aggregateFindings(ctx, missionID, opts, reportData)
	})

	g.Go(func() error {
		return a.aggregateMetrics(ctx, missionID, reportData)
	})

	// Optional aggregations (failures are logged but don't abort)
	if opts.IncludeGraphRAG && a.graphStore != nil {
		g.Go(func() error {
			if err := a.aggregateGraph(ctx, missionID, reportData); err != nil {
				a.logger.Warn("graph aggregation failed, continuing without graph data",
					"mission_id", missionID,
					"error", err,
				)
				// Don't return error - graceful degradation
			}
			return nil
		})
	}

	if opts.IncludeTimeline {
		g.Go(func() error {
			if err := a.aggregateTimeline(ctx, missionID, opts, reportData); err != nil {
				a.logger.Warn("timeline aggregation failed, continuing without timeline data",
					"mission_id", missionID,
					"error", err,
				)
				// Don't return error - graceful degradation
			}
			return nil
		})
	}

	if a.payloadStore != nil && a.payloadDefs != nil {
		g.Go(func() error {
			if err := a.aggregatePayloads(ctx, missionID, reportData); err != nil {
				a.logger.Warn("payload aggregation failed, continuing without payload data",
					"mission_id", missionID,
					"error", err,
				)
				// Don't return error - graceful degradation
			}
			return nil
		})
	}

	return g.Wait()
}

// aggregateSequential runs sub-aggregators one at a time.
func (a *DefaultAggregator) aggregateSequential(ctx context.Context, missionID types.ID, opts AggregateOptions, reportData *ReportData) error {
	// Critical aggregations
	if err := a.aggregateMission(ctx, missionID, reportData); err != nil {
		return err
	}

	if err := a.aggregateFindings(ctx, missionID, opts, reportData); err != nil {
		return err
	}

	if err := a.aggregateMetrics(ctx, missionID, reportData); err != nil {
		return err
	}

	// Optional aggregations
	if opts.IncludeGraphRAG && a.graphStore != nil {
		if err := a.aggregateGraph(ctx, missionID, reportData); err != nil {
			a.logger.Warn("graph aggregation failed", "error", err)
		}
	}

	if opts.IncludeTimeline {
		if err := a.aggregateTimeline(ctx, missionID, opts, reportData); err != nil {
			a.logger.Warn("timeline aggregation failed", "error", err)
		}
	}

	if a.payloadStore != nil && a.payloadDefs != nil {
		if err := a.aggregatePayloads(ctx, missionID, reportData); err != nil {
			a.logger.Warn("payload aggregation failed", "error", err)
		}
	}

	return nil
}

// aggregateMission collects mission metadata, target info, and workflow structure.
func (a *DefaultAggregator) aggregateMission(ctx context.Context, missionID types.ID, reportData *ReportData) error {
	a.logger.Debug("aggregating mission metadata", "mission_id", missionID)

	// Get mission
	m, err := a.missionStore.Get(ctx, missionID)
	if err != nil {
		return fmt.Errorf("failed to get mission: %w", err)
	}

	// Build mission summary
	reportData.Mission = MissionSummary{
		ID:              m.ID,
		Name:            m.Name,
		Description:     m.Description,
		StartedAt:       m.CreatedAt,
		CompletedAt:     m.CompletedAt,
		Status:          string(m.Status),
		RunNumber:       m.RunNumber,
		ParentMissionID: m.ParentMissionID,
		Constraints: MissionConstraints{
			TimeLimit:    durationPtr(m.Constraints.MaxDuration),
			CostLimit:    float64Ptr(m.Constraints.MaxCost),
			FindingLimit: intPtr(m.Constraints.MaxFindings),
		},
	}

	// Get target information
	target, err := a.targetDAO.Get(ctx, m.TargetID)
	if err != nil {
		return fmt.Errorf("failed to get target: %w", err)
	}

	reportData.Target = TargetSummary{
		ID:           target.ID,
		Type:         target.Type,
		Provider:     string(target.Provider),
		Model:        target.Model,
		URL:          target.GetURL(),
		Capabilities: target.Capabilities,
		Metadata:     target.Config,
	}

	// Extract workflow summary from mission
	reportData.Workflow = a.extractWorkflowSummary(m)

	return nil
}

// aggregateFindings collects all findings with filtering and enhancement.
func (a *DefaultAggregator) aggregateFindings(ctx context.Context, missionID types.ID, opts AggregateOptions, reportData *ReportData) error {
	a.logger.Debug("aggregating findings", "mission_id", missionID)

	// Build finding filter
	filter := finding.NewFindingFilter()
	if opts.MinSeverity != "" {
		filter = filter.WithSeverity(opts.MinSeverity)
	}

	// Get findings
	findings, err := a.findingStore.List(ctx, missionID, filter)
	if err != nil {
		return fmt.Errorf("failed to list findings: %w", err)
	}

	// Apply additional filters
	filteredFindings := a.applyFindingFilters(findings, opts)

	// Convert to EnhancedFindingData and group by agent
	reportData.Findings = make([]EnhancedFindingData, 0, len(filteredFindings))
	for _, f := range filteredFindings {
		enhanced := EnhancedFindingData{
			EnhancedFinding: f,
		}
		reportData.Findings = append(reportData.Findings, enhanced)

		// Group by agent
		if _, ok := reportData.FindingsByAgent[f.AgentName]; !ok {
			reportData.FindingsByAgent[f.AgentName] = make([]types.ID, 0)
		}
		reportData.FindingsByAgent[f.AgentName] = append(reportData.FindingsByAgent[f.AgentName], f.ID)
	}

	return nil
}

// aggregateMetrics collects execution metrics and cost breakdown.
func (a *DefaultAggregator) aggregateMetrics(ctx context.Context, missionID types.ID, reportData *ReportData) error {
	a.logger.Debug("aggregating metrics", "mission_id", missionID)

	// Get mission for metrics
	m, err := a.missionStore.Get(ctx, missionID)
	if err != nil {
		return fmt.Errorf("failed to get mission for metrics: %w", err)
	}

	// Build aggregated metrics
	reportData.Metrics = AggregatedMetrics{
		NodesExecuted:      m.Metrics.CompletedNodes,
		NodesFailed:        m.Metrics.FailedNodes,
		TotalDuration:      m.Metrics.Duration,
		FindingsBySeverity: m.Metrics.FindingsBySeverity,
		TokensByProvider:   make(map[string]int64),
		TotalLLMCalls:      0,
		TotalToolCalls:     0,
		TotalRetries:       0,
		TotalErrors:        0,
	}

	// Count findings by severity (override with actual finding counts)
	reportData.Metrics.FindingsBySeverity = make(map[string]int)
	for _, f := range reportData.Findings {
		severity := string(f.Severity)
		reportData.Metrics.FindingsBySeverity[severity]++
	}

	// Build cost breakdown
	reportData.CostBreakdown = CostBreakdown{
		TotalCost:      m.Metrics.TotalCost,
		CostByAgent:    make(map[string]float64),
		CostByProvider: make(map[string]float64),
		CostByPhase:    make(map[string]float64),
	}

	return nil
}

// aggregateGraph collects knowledge graph data (assets, relationships, MITRE patterns).
func (a *DefaultAggregator) aggregateGraph(ctx context.Context, missionID types.ID, reportData *ReportData) error {
	a.logger.Debug("aggregating graph data", "mission_id", missionID)

	// Query nodes from graph scoped to mission
	// This is a placeholder - actual implementation would query Neo4j
	// for assets, relationships, and MITRE patterns discovered during the mission

	reportData.Assets = make([]DiscoveredAsset, 0)
	reportData.Relationships = make([]AssetRelationship, 0)
	reportData.AttackPatterns = make([]MitrePattern, 0)

	// TODO: Implement actual graph queries when GraphRAG is fully integrated
	// For now, return empty collections

	return nil
}

// aggregateTimeline constructs the mission event timeline.
func (a *DefaultAggregator) aggregateTimeline(ctx context.Context, missionID types.ID, opts AggregateOptions, reportData *ReportData) error {
	a.logger.Debug("aggregating timeline", "mission_id", missionID)

	// Timeline aggregation would query event store/logs
	// This is a placeholder for future implementation

	reportData.Timeline = make([]TimelineEvent, 0)

	// TODO: Implement timeline aggregation from event store
	// Should include:
	// - Mission start/stop events
	// - Agent execution events
	// - Finding discovery events
	// - Payload execution events
	// Apply date filtering from opts.DateFrom/DateTo
	// Limit to opts.MaxEvents

	return nil
}

// aggregatePayloads collects payload execution data.
func (a *DefaultAggregator) aggregatePayloads(ctx context.Context, missionID types.ID, reportData *ReportData) error {
	a.logger.Debug("aggregating payloads", "mission_id", missionID)

	// Get payload executions for mission
	executions, err := a.payloadStore.GetByMission(ctx, missionID, 0)
	if err != nil {
		return fmt.Errorf("failed to list payload executions: %w", err)
	}

	// Convert to PayloadExecutionData
	reportData.PayloadExecutions = make([]PayloadExecutionData, 0, len(executions))
	for _, exec := range executions {
		// Get the payload to extract category, name, description
		p, err := a.payloadDefs.Get(ctx, exec.PayloadID)
		if err != nil {
			a.logger.Warn("failed to get payload for execution",
				"execution_id", exec.ID,
				"payload_id", exec.PayloadID,
				"error", err,
			)
			continue
		}

		// Get primary category (first one, or empty)
		var category string
		if len(p.Categories) > 0 {
			category = string(p.Categories[0])
		}

		// Convert MITRE technique strings to SimpleMitreMapping
		mitreMappings := make([]finding.SimpleMitreMapping, 0, len(p.MitreTechniques))
		for _, technique := range p.MitreTechniques {
			mitreMappings = append(mitreMappings, finding.SimpleMitreMapping{
				TechniqueID: technique,
			})
		}

		payloadData := PayloadExecutionData{
			ID:               exec.ID,
			Category:         category,
			Name:             p.Name,
			Description:      p.Description,
			Severity:         p.Severity,
			ExecutedAt:       exec.CreatedAt,
			Status:           string(exec.Status),
			ResultingFinding: exec.FindingID,
			MitreMappings:    mitreMappings,
			Metadata:         exec.Metadata,
		}
		reportData.PayloadExecutions = append(reportData.PayloadExecutions, payloadData)
	}

	return nil
}

// AggregateMultiple collects data from multiple missions.
func (a *DefaultAggregator) AggregateMultiple(ctx context.Context, missionIDs []types.ID, opts AggregateOptions) ([]*ReportData, error) {
	a.logger.Info("aggregating multiple missions", "count", len(missionIDs))

	results := make([]*ReportData, 0, len(missionIDs))

	for _, missionID := range missionIDs {
		data, err := a.Aggregate(ctx, missionID, opts)
		if err != nil {
			return nil, fmt.Errorf("failed to aggregate mission %s: %w", missionID, err)
		}
		results = append(results, data)
	}

	return results, nil
}

// Helper methods

// extractWorkflowSummary extracts workflow information from mission.
func (a *DefaultAggregator) extractWorkflowSummary(m *mission.Mission) WorkflowSummary {
	// This is a simplified version - actual implementation would parse WorkflowJSON
	return WorkflowSummary{
		Nodes:      make([]WorkflowNode, 0),
		Edges:      make([]WorkflowEdge, 0),
		EntryPoint: "",
		ExitPoints: make([]string, 0),
		Agents:     m.AgentAssignments,
	}
}

// applyFindingFilters applies additional filters to findings.
func (a *DefaultAggregator) applyFindingFilters(findings []finding.EnhancedFinding, opts AggregateOptions) []finding.EnhancedFinding {
	if len(opts.Categories) == 0 && opts.MaxFindings == 0 {
		return findings
	}

	filtered := make([]finding.EnhancedFinding, 0, len(findings))

	for _, f := range findings {
		// Category filter
		if len(opts.Categories) > 0 {
			matched := false
			for _, cat := range opts.Categories {
				if f.Category == cat {
					matched = true
					break
				}
			}
			if !matched {
				continue
			}
		}

		filtered = append(filtered, f)

		// Max findings limit
		if opts.MaxFindings > 0 && len(filtered) >= opts.MaxFindings {
			break
		}
	}

	return filtered
}

// calculateDerivedMetrics calculates derived values like risk score and executive summary.
func (a *DefaultAggregator) calculateDerivedMetrics(reportData *ReportData) {
	// Calculate overall risk score (0.0 - 10.0)
	// Simple algorithm: weight by severity
	totalRisk := 0.0
	criticalWeight := 10.0
	highWeight := 7.5
	mediumWeight := 5.0
	lowWeight := 2.5
	infoWeight := 1.0

	for _, f := range reportData.Findings {
		switch f.Severity {
		case agent.SeverityCritical:
			totalRisk += criticalWeight
		case agent.SeverityHigh:
			totalRisk += highWeight
		case agent.SeverityMedium:
			totalRisk += mediumWeight
		case agent.SeverityLow:
			totalRisk += lowWeight
		case agent.SeverityInfo:
			totalRisk += infoWeight
		}
	}

	// Normalize to 0-10 scale (cap at 10)
	if len(reportData.Findings) > 0 {
		avgRisk := totalRisk / float64(len(reportData.Findings))
		reportData.RiskScore = min(avgRisk, 10.0)
	}

	// Build executive summary
	reportData.ExecutiveSummary = a.buildExecutiveSummary(reportData)
}

// buildExecutiveSummary creates executive-level summary data.
func (a *DefaultAggregator) buildExecutiveSummary(reportData *ReportData) ExecutiveSummaryData {
	summary := ExecutiveSummaryData{
		KeyFindings:        make([]KeyFinding, 0, 5),
		RecommendedActions: make([]string, 0),
	}

	// Extract top 5 critical findings
	criticalCount := 0
	for _, f := range reportData.Findings {
		if f.Severity == agent.SeverityCritical && criticalCount < 5 {
			summary.KeyFindings = append(summary.KeyFindings, KeyFinding{
				FindingID:      f.ID,
				Title:          f.Title,
				Severity:       f.Severity,
				BusinessImpact: f.BusinessImpact,
				Summary:        a.truncate(f.Description, 200),
			})
			criticalCount++
		}
	}

	// Build risk summary
	summary.RiskSummary = RiskSummary{
		OverallRiskScore: reportData.RiskScore,
		TotalFindings:    len(reportData.Findings),
	}

	// Count by severity
	for _, f := range reportData.Findings {
		switch f.Severity {
		case agent.SeverityCritical:
			summary.RiskSummary.CriticalFindings++
		case agent.SeverityHigh:
			summary.RiskSummary.HighFindings++
		case agent.SeverityMedium:
			summary.RiskSummary.MediumFindings++
		case agent.SeverityLow:
			summary.RiskSummary.LowFindings++
		case agent.SeverityInfo:
			summary.RiskSummary.InfoFindings++
		}
	}

	// Generate recommended actions based on findings
	if summary.RiskSummary.CriticalFindings > 0 {
		summary.RecommendedActions = append(summary.RecommendedActions,
			fmt.Sprintf("Immediately address %d critical security findings", summary.RiskSummary.CriticalFindings))
	}
	if summary.RiskSummary.HighFindings > 0 {
		summary.RecommendedActions = append(summary.RecommendedActions,
			fmt.Sprintf("Prioritize remediation of %d high-severity vulnerabilities", summary.RiskSummary.HighFindings))
	}

	return summary
}

// truncate truncates a string to the specified length with ellipsis.
func (a *DefaultAggregator) truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}

// Helper functions for pointer conversion
func durationPtr(d time.Duration) *time.Duration {
	if d == 0 {
		return nil
	}
	return &d
}

func intPtr(i int) *int {
	if i == 0 {
		return nil
	}
	return &i
}

func float64Ptr(f float64) *float64 {
	if f == 0 {
		return nil
	}
	return &f
}

// Ensure DefaultAggregator implements DataAggregator
var _ DataAggregator = (*DefaultAggregator)(nil)
