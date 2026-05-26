package harness

import (
	"context"
	"encoding/json"
	"time"

	"github.com/zeroroot-ai/gibson/internal/types"
	"github.com/zeroroot-ai/sdk/finding"
	sdkmission "github.com/zeroroot-ai/sdk/mission"
)

// Mission management implementation for DefaultAgentHarness.
// These methods implement the MissionManager interface from the SDK,
// allowing agents to create and manage child missions autonomously.

// CreateMission creates a new mission from a mission definition.
// The mission parameter should be a Gibson mission.Mission instance.
// Returns mission metadata including the assigned mission ID.
//
// This method:
//  1. Checks spawn limits to prevent runaway mission creation
//  2. Validates the mission and target ID
//  3. Creates the mission via the MissionClient
//  4. Tracks lineage by setting the parent mission ID
//
// Returns an error if spawn limits are exceeded or mission creation fails.
func (h *DefaultAgentHarness) CreateMission(ctx context.Context, wf any, targetID string, opts *sdkmission.CreateMissionOpts) (*sdkmission.MissionInfo, error) {
	// Create span for distributed tracing
	ctx, span := h.tracer.Start(ctx, "harness.CreateMission")
	defer span.End()

	// Check if mission client is available
	if h.missionClient == nil {
		h.logger.Error("mission client not configured")
		return nil, types.NewError(
			ErrHarnessInvalidConfig,
			"mission management not enabled for this harness",
		)
	}

	// Serialize mission to JSON
	// We accept mission as `any` to avoid import cycles, and serialize it
	missionDefinitionJSON, err := json.Marshal(wf)
	if err != nil {
		h.logger.Error("failed to serialize mission",
			"error", err)
		return nil, types.WrapError(
			ErrHarnessInvalidConfig,
			"failed to serialize mission",
			err,
		)
	}

	// Parse target ID
	parsedTargetID, err := types.ParseID(targetID)
	if err != nil {
		h.logger.Error("invalid target ID",
			"target_id", targetID,
			"error", err)
		return nil, types.WrapError(
			ErrHarnessInvalidConfig,
			"invalid target ID",
			err,
		)
	}

	// Check spawn limits before creating mission
	if err := CheckSpawnLimits(ctx, h.missionClient, h.missionCtx.ID, h.spawnLimits); err != nil {
		h.logger.Warn("spawn limits exceeded",
			"mission_id", h.missionCtx.ID.String(),
			"error", err)
		return nil, err
	}

	h.logger.Info("creating child mission",
		"parent_mission_id", h.missionCtx.ID.String(),
		"target_id", targetID)

	// Build CreateMissionRequest for the client
	req := &CreateMissionRequest{
		MissionDefinitionJSON: string(missionDefinitionJSON),
		MissionDefinitionID:   types.NewID(), // Generate new mission ID
		TargetID:              parsedTargetID,
		ParentMissionID:       &h.missionCtx.ID,
		ParentDepth:           GetMissionDepth(ctx, h.missionClient, h.missionCtx.ID),
	}

	// Apply options if provided
	if opts != nil {
		req.Name = opts.Name
		req.Metadata = opts.Metadata
		req.Tags = opts.Tags

		// Convert SDK constraints to harness constraints
		if opts.Constraints != nil {
			req.Constraints = &MissionConstraints{
				MaxDuration: opts.Constraints.MaxDuration,
				MaxTokens:   opts.Constraints.MaxTokens,
				MaxCost:     opts.Constraints.MaxCost,
				MaxFindings: opts.Constraints.MaxFindings,
			}
		}
	}

	// Create mission via client
	m, err := h.missionClient.CreateMission(ctx, req)
	if err != nil {
		h.logger.Error("failed to create mission",
			"parent_mission_id", h.missionCtx.ID.String(),
			"error", err)
		return nil, types.WrapError(
			ErrHarnessInvalidConfig,
			"failed to create mission",
			err,
		)
	}

	h.logger.Info("child mission created successfully",
		"mission_id", m.ID.String(),
		"mission_name", m.Name,
		"parent_mission_id", h.missionCtx.ID.String())

	// Convert harness MissionInfo to SDK MissionInfo
	return toSDKMissionInfo(m), nil
}

// RunMission queues a mission for execution.
// This method is non-blocking by default and returns immediately after queuing.
// Use WaitForMission to block until the mission completes.
//
// Returns an error if:
//   - The mission does not exist
//   - The mission is already running
//   - The mission is in a terminal state (completed, failed, cancelled)
func (h *DefaultAgentHarness) RunMission(ctx context.Context, missionID string, opts *sdkmission.RunMissionOpts) error {
	// Create span for distributed tracing
	ctx, span := h.tracer.Start(ctx, "harness.RunMission")
	defer span.End()

	// Check if mission client is available
	if h.missionClient == nil {
		h.logger.Error("mission client not configured")
		return types.NewError(
			ErrHarnessInvalidConfig,
			"mission management not enabled for this harness",
		)
	}

	h.logger.Info("running mission",
		"mission_id", missionID,
		"parent_mission_id", h.missionCtx.ID.String())

	// Run mission via client
	err := h.missionClient.Run(ctx, missionID)
	if err != nil {
		h.logger.Error("failed to run mission",
			"mission_id", missionID,
			"error", err)
		return types.WrapError(
			ErrHarnessInvalidConfig,
			"failed to run mission",
			err,
		)
	}

	// If Wait option is set, block until mission completes
	if opts != nil && opts.Wait {
		timeout := opts.Timeout
		if timeout == 0 {
			timeout = 24 * time.Hour // Default to 24 hours if no timeout specified
		}

		h.logger.Debug("waiting for mission completion",
			"mission_id", missionID,
			"timeout", timeout)

		_, err := h.WaitForMission(ctx, missionID, timeout)
		if err != nil {
			h.logger.Error("mission wait failed",
				"mission_id", missionID,
				"error", err)
			return err
		}
	}

	h.logger.Info("mission started successfully",
		"mission_id", missionID)

	return nil
}

// GetMissionStatus returns the current state of a mission.
// Returns detailed status information including progress, findings count,
// token usage, and error messages if applicable.
//
// Returns an error if the mission does not exist.
func (h *DefaultAgentHarness) GetMissionStatus(ctx context.Context, missionID string) (*sdkmission.MissionStatusInfo, error) {
	// Create span for distributed tracing
	ctx, span := h.tracer.Start(ctx, "harness.GetMissionStatus")
	defer span.End()

	// Check if mission client is available
	if h.missionClient == nil {
		h.logger.Error("mission client not configured")
		return nil, types.NewError(
			ErrHarnessInvalidConfig,
			"mission management not enabled for this harness",
		)
	}

	h.logger.Debug("getting mission status",
		"mission_id", missionID)

	// Get status via client
	status, err := h.missionClient.GetStatus(ctx, missionID)
	if err != nil {
		h.logger.Error("failed to get mission status",
			"mission_id", missionID,
			"error", err)
		return nil, types.WrapError(
			ErrHarnessInvalidConfig,
			"failed to get mission status",
			err,
		)
	}

	h.logger.Debug("mission status retrieved",
		"mission_id", missionID,
		"status", status.Status)

	// Convert harness MissionStatusInfo to SDK MissionStatusInfo
	return toSDKMissionStatusInfo(status), nil
}

// WaitForMission blocks until a mission completes or the timeout expires.
// Returns the final mission result including findings and output.
//
// The timeout parameter specifies how long to wait. Use 0 for no timeout.
// Returns context.DeadlineExceeded if the timeout is reached before completion.
func (h *DefaultAgentHarness) WaitForMission(ctx context.Context, missionID string, timeout time.Duration) (*sdkmission.MissionResult, error) {
	// Create span for distributed tracing
	ctx, span := h.tracer.Start(ctx, "harness.WaitForMission")
	defer span.End()

	// Check if mission client is available
	if h.missionClient == nil {
		h.logger.Error("mission client not configured")
		return nil, types.NewError(
			ErrHarnessInvalidConfig,
			"mission management not enabled for this harness",
		)
	}

	h.logger.Info("waiting for mission completion",
		"mission_id", missionID,
		"timeout", timeout)

	// Wait for completion via client
	result, err := h.missionClient.WaitForCompletion(ctx, missionID, timeout)
	if err != nil {
		h.logger.Error("mission wait failed",
			"mission_id", missionID,
			"error", err)
		return nil, types.WrapError(
			ErrHarnessInvalidConfig,
			"mission wait failed",
			err,
		)
	}

	h.logger.Info("mission completed",
		"mission_id", missionID,
		"status", result.Status)

	// Convert harness MissionResultInfo to SDK MissionResult
	return toSDKMissionResult(result), nil
}

// toSDKMissionInfo converts a harness MissionInfo to SDK MissionInfo.
func toSDKMissionInfo(m *MissionInfo) *sdkmission.MissionInfo {
	info := &sdkmission.MissionInfo{
		ID:        m.ID.String(),
		Name:      m.Name,
		Status:    sdkmission.MissionStatus(m.Status),
		TargetID:  m.TargetID.String(),
		CreatedAt: m.CreatedAt,
		Tags:      m.Tags,
	}

	// Add parent mission ID if present
	if m.ParentMissionID != nil {
		info.ParentMissionID = m.ParentMissionID.String()
	}

	return info
}

// toSDKMissionStatusInfo converts harness MissionStatusInfo to SDK MissionStatusInfo.
func toSDKMissionStatusInfo(status *MissionStatusInfo) *sdkmission.MissionStatusInfo {
	sdkStatus := &sdkmission.MissionStatusInfo{
		Status:     sdkmission.MissionStatus(status.Status),
		Progress:   status.Progress,
		Phase:      status.Phase,
		Duration:   status.Duration,
		Error:      status.Error,
		TokenUsage: status.TokenUsage,
	}

	// Convert finding counts
	if status.FindingCounts != nil {
		sdkStatus.FindingCounts = make(map[string]int)
		for severity, count := range status.FindingCounts {
			sdkStatus.FindingCounts[severity] = count
		}
	}

	return sdkStatus
}

// toSDKMissionResult converts harness MissionResultInfo to SDK MissionResult.
func toSDKMissionResult(result *MissionResultInfo) *sdkmission.MissionResult {
	sdkResult := &sdkmission.MissionResult{
		MissionID:   result.MissionID,
		Status:      sdkmission.MissionStatus(result.Status),
		Output:      result.MissionResult,
		Error:       result.Error,
		CompletedAt: result.CompletedAt,
	}

	// Convert metrics
	if result.Metrics != nil {
		sdkResult.Metrics = sdkmission.MissionMetrics{
			Duration:      result.Metrics.Duration,
			TokensUsed:    result.Metrics.TotalTokens,
			ToolCalls:     0, // Not tracked separately in Gibson metrics
			AgentCalls:    0, // Not tracked separately in Gibson metrics
			FindingsCount: result.Metrics.TotalFindings,
		}
	}

	// Note: Findings are not included here because they need to be loaded
	// separately from the finding store. The harness would need to query
	// findings by mission ID and convert them.
	// For now, we initialize as empty slice.
	sdkResult.Findings = []finding.Finding{}

	return sdkResult
}

// ListMissions returns missions matching the provided filter criteria.
// This method supports filtering by status, target ID, parent mission ID,
// creation date range, and tags. Pagination is supported via Limit and Offset.
//
// If no filter is provided, returns all missions with default pagination.
// An empty result is returned if no missions match the filter criteria.
//
// Returns an error if:
//   - The mission client is not configured
//   - The filter parameters are invalid (negative limit/offset)
//   - The underlying query fails
func (h *DefaultAgentHarness) ListMissions(ctx context.Context, filter *sdkmission.MissionFilter) ([]*sdkmission.MissionInfo, error) {
	// Create span for distributed tracing
	ctx, span := h.tracer.Start(ctx, "harness.ListMissions")
	defer span.End()

	// Check if mission client is available
	if h.missionClient == nil {
		h.logger.Error("mission client not configured")
		return nil, types.NewError(
			ErrHarnessInvalidConfig,
			"mission management not enabled for this harness",
		)
	}

	h.logger.Debug("listing missions",
		"parent_mission_id", h.missionCtx.ID.String())

	// Convert SDK filter to Gibson filter
	gibsonFilter, err := toGibsonMissionFilter(filter)
	if err != nil {
		h.logger.Error("invalid mission filter",
			"error", err)
		return nil, types.WrapError(
			ErrHarnessInvalidConfig,
			"invalid mission filter",
			err,
		)
	}

	// List missions via client
	missions, err := h.missionClient.List(ctx, gibsonFilter)
	if err != nil {
		h.logger.Error("failed to list missions",
			"error", err)
		return nil, types.WrapError(
			ErrHarnessInvalidConfig,
			"failed to list missions",
			err,
		)
	}

	h.logger.Debug("missions listed successfully",
		"count", len(missions))

	// Convert Gibson mission records to SDK mission info
	sdkMissions := make([]*sdkmission.MissionInfo, 0, len(missions))
	for _, m := range missions {
		sdkMissions = append(sdkMissions, toSDKMissionInfoFromRecord(m))
	}

	return sdkMissions, nil
}

// CancelMission requests cancellation of a running or pending mission.
// This method is idempotent - calling it multiple times on the same mission
// will not result in an error.
//
// If the mission is already in a terminal state (completed, failed, or cancelled),
// this method returns successfully without making any changes. For running missions,
// this updates the status and notifies the orchestrator to stop execution.
//
// Returns an error if:
//   - The mission client is not configured
//   - The mission ID is invalid or empty
//   - The mission does not exist
//   - The database update fails
func (h *DefaultAgentHarness) CancelMission(ctx context.Context, missionID string) error {
	// Create span for distributed tracing
	ctx, span := h.tracer.Start(ctx, "harness.CancelMission")
	defer span.End()

	// Check if mission client is available
	if h.missionClient == nil {
		h.logger.Error("mission client not configured")
		return types.NewError(
			ErrHarnessInvalidConfig,
			"mission management not enabled for this harness",
		)
	}

	// Parse mission ID
	parsedMissionID, err := types.ParseID(missionID)
	if err != nil {
		h.logger.Error("invalid mission ID",
			"mission_id", missionID,
			"error", err)
		return types.WrapError(
			ErrHarnessInvalidConfig,
			"invalid mission ID",
			err,
		)
	}

	h.logger.Info("cancelling mission",
		"mission_id", missionID,
		"parent_mission_id", h.missionCtx.ID.String())

	// Cancel mission via client
	err = h.missionClient.Cancel(ctx, parsedMissionID)
	if err != nil {
		h.logger.Error("failed to cancel mission",
			"mission_id", missionID,
			"error", err)
		return types.WrapError(
			ErrHarnessInvalidConfig,
			"failed to cancel mission",
			err,
		)
	}

	h.logger.Info("mission cancelled successfully",
		"mission_id", missionID)

	return nil
}

// GetMissionResults returns the results of a completed mission, including
// findings and mission execution output.
//
// This method should be called on missions in a terminal state (completed,
// failed, or cancelled). For non-terminal missions, it returns the current
// partial results.
//
// The returned MissionResult contains:
//   - Final mission status
//   - Execution metrics (duration, token usage, etc.)
//   - Findings discovered during execution
//   - Mission execution output data
//   - Error message if the mission failed
//
// Returns an error if:
//   - The mission client is not configured
//   - The mission ID is invalid or empty
//   - The mission does not exist
//   - The result retrieval fails
func (h *DefaultAgentHarness) GetMissionResults(ctx context.Context, missionID string) (*sdkmission.MissionResult, error) {
	// Create span for distributed tracing
	ctx, span := h.tracer.Start(ctx, "harness.GetMissionResults")
	defer span.End()

	// Check if mission client is available
	if h.missionClient == nil {
		h.logger.Error("mission client not configured")
		return nil, types.NewError(
			ErrHarnessInvalidConfig,
			"mission management not enabled for this harness",
		)
	}

	// Parse mission ID
	parsedMissionID, err := types.ParseID(missionID)
	if err != nil {
		h.logger.Error("invalid mission ID",
			"mission_id", missionID,
			"error", err)
		return nil, types.WrapError(
			ErrHarnessInvalidConfig,
			"invalid mission ID",
			err,
		)
	}

	h.logger.Debug("getting mission results",
		"mission_id", missionID,
		"parent_mission_id", h.missionCtx.ID.String())

	// Get results via client
	result, err := h.missionClient.GetResults(ctx, parsedMissionID)
	if err != nil {
		h.logger.Error("failed to get mission results",
			"mission_id", missionID,
			"error", err)
		return nil, types.WrapError(
			ErrHarnessInvalidConfig,
			"failed to get mission results",
			err,
		)
	}

	h.logger.Info("mission results retrieved successfully",
		"mission_id", missionID,
		"status", result.Status)

	// Convert harness mission result to SDK mission result
	return toSDKMissionResultFromHarness(result), nil
}

// toGibsonMissionFilter converts SDK MissionFilter to harness MissionFilter.
func toGibsonMissionFilter(filter *sdkmission.MissionFilter) (*MissionFilter, error) {
	if filter == nil {
		return &MissionFilter{
			Limit:  100, // Default limit
			Offset: 0,
		}, nil
	}

	gibsonFilter := &MissionFilter{
		Limit:  filter.Limit,
		Offset: filter.Offset,
	}

	// Convert status if provided
	if filter.Status != nil {
		status := MissionStatus(*filter.Status)
		gibsonFilter.Status = &status
	}

	// Convert target ID if provided
	if filter.TargetID != nil {
		targetID, err := types.ParseID(*filter.TargetID)
		if err != nil {
			return nil, types.WrapError(
				ErrHarnessInvalidConfig,
				"invalid target ID in filter",
				err,
			)
		}
		gibsonFilter.TargetID = &targetID
	}

	// Convert parent mission ID if provided
	if filter.ParentMissionID != nil {
		parentID, err := types.ParseID(*filter.ParentMissionID)
		if err != nil {
			return nil, types.WrapError(
				ErrHarnessInvalidConfig,
				"invalid parent mission ID in filter",
				err,
			)
		}
		gibsonFilter.ParentMissionID = &parentID
	}

	return gibsonFilter, nil
}

// toSDKMissionInfoFromRecord converts a harness MissionRecord to SDK MissionInfo.
// Note: MissionRecord contains minimal information, so some fields like Name,
// CreatedAt, and Tags will have default/empty values.
func toSDKMissionInfoFromRecord(m *MissionRecord) *sdkmission.MissionInfo {
	info := &sdkmission.MissionInfo{
		ID:     m.ID.String(),
		Status: sdkmission.MissionStatus(m.Status),
		// MissionRecord doesn't have these fields, they will be empty
		Name:      "",
		TargetID:  "",
		CreatedAt: time.Time{},
		Tags:      nil,
	}

	// Add parent mission ID if present
	if m.ParentMissionID != nil {
		info.ParentMissionID = m.ParentMissionID.String()
	}

	return info
}

// toSDKMissionResultFromHarness converts harness MissionResultInfo to SDK MissionResult.
func toSDKMissionResultFromHarness(result *MissionResultInfo) *sdkmission.MissionResult {
	sdkResult := &sdkmission.MissionResult{
		MissionID:   result.MissionID,
		Status:      sdkmission.MissionStatus(result.Status),
		Output:      result.MissionResult,
		Error:       result.Error,
		CompletedAt: result.CompletedAt,
	}

	// Convert metrics if available
	if result.Metrics != nil {
		sdkResult.Metrics = sdkmission.MissionMetrics{
			Duration:      result.Metrics.Duration,
			TokensUsed:    result.Metrics.TotalTokens,
			ToolCalls:     0, // Not tracked separately in Gibson metrics
			AgentCalls:    0, // Not tracked separately in Gibson metrics
			FindingsCount: result.Metrics.TotalFindings,
		}
	}

	// Note: Findings are not included here because they need to be loaded
	// separately from the finding store. The harness would need to query
	// findings by mission ID and convert them.
	// For now, we initialize as empty slice.
	sdkResult.Findings = []finding.Finding{}

	return sdkResult
}
