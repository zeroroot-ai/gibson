package daemon

// mission_harness_adapter.go bridges the daemon's mission stores and missionManager
// to the harness.MissionClientIface interface without introducing an import cycle.
//
// The harness package defines MissionClientIface with method names like
// CreateMission (distinct from mission.MissionClient.Create) so harness can
// hold a typed interface without importing the mission package. This adapter
// lives in the daemon package, which can safely import both harness and mission.
//
// missionHarnessAdapter lazily resolves the *missionManager on first lifecycle
// operation (Run, Cancel) by calling d.ensureMissionManager(). Status and list
// queries work directly against the missionStore and do not require the manager.

import (
	"context"
	"encoding/json"
	"os"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/zero-day-ai/gibson/internal/harness"
	"github.com/zero-day-ai/gibson/internal/mission"
	"github.com/zero-day-ai/gibson/internal/types"
)

// missionHarnessAdapter implements harness.MissionClientIface by delegating to
// the daemon's missionStore (for reads) and missionManager (for lifecycle ops).
// The daemon field is accessed lazily so the adapter can be wired before the
// missionManager is initialized.
type missionHarnessAdapter struct {
	daemon *daemonImpl
}

// newMissionHarnessAdapter constructs the adapter. d must not be nil.
func newMissionHarnessAdapter(d *daemonImpl) *missionHarnessAdapter {
	if d == nil {
		panic("daemon: newMissionHarnessAdapter: daemon must not be nil")
	}
	return &missionHarnessAdapter{daemon: d}
}

// mgr returns the initialized missionManager, calling ensureMissionManager if needed.
// Returns a non-nil *missionManager or an error.
func (a *missionHarnessAdapter) mgr(ctx context.Context) (*missionManager, error) {
	if a.daemon.missionManager != nil {
		return a.daemon.missionManager, nil
	}
	if err := a.daemon.ensureMissionManager(); err != nil {
		return nil, status.Errorf(codes.Unavailable, "mission manager not available: %v", err)
	}
	if a.daemon.missionManager == nil {
		return nil, status.Error(codes.Unavailable, "mission manager not initialized")
	}
	return a.daemon.missionManager, nil
}

// store returns the missionStore, or an error if unavailable.
func (a *missionHarnessAdapter) store() (mission.MissionStore, error) {
	if a.daemon.missionStore == nil {
		return nil, status.Error(codes.Unavailable, "mission store not available")
	}
	return a.daemon.missionStore, nil
}

// CreateMission implements harness.MissionClientIface.
// Parses WorkflowJSON into a MissionDefinition, creates the mission record,
// and persists it to the store. Does NOT start execution (call Run for that).
func (a *missionHarnessAdapter) CreateMission(ctx context.Context, req *harness.MissionClientCreateRequest) (*harness.MissionClientInfo, error) {
	if req == nil {
		return nil, status.Error(codes.InvalidArgument, "create mission request is required")
	}

	store, err := a.store()
	if err != nil {
		return nil, err
	}

	// Parse the workflow JSON into a MissionDefinition.
	var def mission.MissionDefinition
	if req.WorkflowJSON != "" {
		if jsonErr := json.Unmarshal([]byte(req.WorkflowJSON), &def); jsonErr != nil {
			return nil, status.Errorf(codes.InvalidArgument, "failed to parse workflow JSON: %v", jsonErr)
		}
	}

	// Overlay explicit name/description from the request.
	if req.Name != "" {
		def.Name = req.Name
	}
	if req.Description != "" {
		def.Description = req.Description
	}

	// Generate a new workflow ID if not already set.
	if def.ID.IsZero() {
		def.ID = types.NewID()
	}

	// Compute depth: root missions are depth 0, sub-missions are ParentDepth+1.
	depth := 0
	if req.ParentMissionID != nil {
		depth = req.ParentDepth + 1
	}

	// Build the mission record directly using the store.
	m := &mission.Mission{
		ID:              types.NewID(),
		Name:            def.Name,
		Description:     def.Description,
		Status:          mission.MissionStatusPending,
		TargetID:        req.TargetID,
		WorkflowID:      def.ID,
		WorkflowJSON:    req.WorkflowJSON,
		ParentMissionID: req.ParentMissionID,
		Depth:           depth,
		Metadata:        req.Metadata,
	}

	if saveErr := store.Save(ctx, m); saveErr != nil {
		return nil, status.Errorf(codes.Internal, "failed to save mission: %v", saveErr)
	}

	return &harness.MissionClientInfo{
		ID:   m.ID,
		Name: m.Name,
	}, nil
}

// Run implements harness.MissionClientIface.
// Loads the mission's WorkflowJSON from the store, writes it to a temp file,
// and delegates to missionManager.Run (which requires a file path).
// The temp file is removed after Run returns. Agents can poll via GetStatus.
func (a *missionHarnessAdapter) Run(ctx context.Context, missionID string) error {
	mgr, mgrErr := a.mgr(ctx)
	if mgrErr != nil {
		return mgrErr
	}

	store, storeErr := a.store()
	if storeErr != nil {
		return storeErr
	}

	id, parseErr := types.ParseID(missionID)
	if parseErr != nil {
		return status.Errorf(codes.InvalidArgument, "invalid mission ID: %v", parseErr)
	}

	m, getErr := store.Get(ctx, id)
	if getErr != nil {
		return status.Errorf(codes.NotFound, "mission %s not found: %v", missionID, getErr)
	}

	// Write the WorkflowJSON to a temp file so missionManager.Run can parse it.
	workflowJSON := m.WorkflowJSON
	if workflowJSON == "" {
		// No workflow JSON — mission cannot be executed.
		return status.Errorf(codes.FailedPrecondition, "mission %s has no workflow definition", missionID)
	}

	tmpFile, tmpErr := os.CreateTemp("", "gibson-sub-mission-*.yaml")
	if tmpErr != nil {
		return status.Errorf(codes.Internal, "failed to create temp workflow file: %v", tmpErr)
	}
	defer os.Remove(tmpFile.Name())

	if _, writeErr := tmpFile.WriteString(workflowJSON); writeErr != nil {
		tmpFile.Close()
		return status.Errorf(codes.Internal, "failed to write workflow to temp file: %v", writeErr)
	}
	tmpFile.Close()

	// Use missionManager.Run with the temp file path and the existing mission ID.
	// The manager will re-parse the definition and create a new activeMission entry.
	_, runErr := mgr.Run(ctx, tmpFile.Name(), missionID, nil, m.MemoryContinuity)
	if runErr != nil {
		return status.Errorf(codes.Internal, "failed to start mission %s: %v", missionID, runErr)
	}

	return nil
}

// GetStatus implements harness.MissionClientIface.
func (a *missionHarnessAdapter) GetStatus(ctx context.Context, missionID string) (*harness.MissionClientStatusInfo, error) {
	store, err := a.store()
	if err != nil {
		return nil, err
	}

	id, parseErr := types.ParseID(missionID)
	if parseErr != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid mission ID: %v", parseErr)
	}

	m, getErr := store.Get(ctx, id)
	if getErr != nil {
		return nil, status.Errorf(codes.NotFound, "mission %s not found: %v", missionID, getErr)
	}

	si := &harness.MissionClientStatusInfo{
		Status:        string(m.Status),
		Progress:      m.Progress,
		FindingCounts: make(map[string]int),
	}

	// Extract phase from checkpoint if available.
	if m.Checkpoint != nil && len(m.Checkpoint.PendingNodes) > 0 {
		si.Phase = m.Checkpoint.PendingNodes[0]
	}

	// Extract metrics if available.
	if m.Metrics != nil {
		si.TokenUsage = m.Metrics.TotalTokens
		si.FindingCounts = m.Metrics.FindingsBySeverity
		if !m.StartedAt.IsNil() {
			if !m.CompletedAt.IsNil() {
				si.Duration = m.CompletedAt.Time.Sub(*m.StartedAt.Time)
			} else {
				si.Duration = time.Since(*m.StartedAt.Time)
			}
		}
	}

	if m.Error != "" {
		si.Error = m.Error
	}

	return si, nil
}

// WaitForCompletion implements harness.MissionClientIface.
func (a *missionHarnessAdapter) WaitForCompletion(ctx context.Context, missionID string, timeout time.Duration) (*harness.MissionClientResult, error) {
	store, err := a.store()
	if err != nil {
		return nil, err
	}

	id, parseErr := types.ParseID(missionID)
	if parseErr != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid mission ID: %v", parseErr)
	}

	var cancel context.CancelFunc
	if timeout > 0 {
		ctx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}

	const pollInterval = 2 * time.Second
	ticker := time.NewTicker(pollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil, status.Errorf(codes.DeadlineExceeded, "timed out waiting for mission %s", missionID)
		case <-ticker.C:
			m, getErr := store.Get(ctx, id)
			if getErr != nil {
				return nil, status.Errorf(codes.Internal, "failed to poll mission %s: %v", missionID, getErr)
			}
			if m.Status.IsTerminal() {
				return missionToHarnessResult(m), nil
			}
		}
	}
}

// Cancel implements harness.MissionClientIface.
func (a *missionHarnessAdapter) Cancel(ctx context.Context, missionID types.ID) error {
	mgr, err := a.mgr(ctx)
	if err != nil {
		// Fallback: update store directly if manager is unavailable.
		store, storeErr := a.store()
		if storeErr != nil {
			return err // return original error
		}
		m, getErr := store.Get(ctx, missionID)
		if getErr != nil {
			return status.Errorf(codes.NotFound, "mission %s not found", missionID)
		}
		if !m.Status.IsTerminal() {
			m.Status = mission.MissionStatusCancelled
			_ = store.Update(ctx, m)
		}
		return nil
	}

	// Delegate to missionManager.Stop (non-force cancel).
	if stopErr := mgr.Stop(ctx, missionID.String(), false); stopErr != nil {
		// If not found in active missions, fall back to store update.
		store, storeErr := a.store()
		if storeErr != nil {
			return status.Errorf(codes.Internal, "failed to cancel mission: %v", stopErr)
		}
		m, getErr := store.Get(ctx, missionID)
		if getErr != nil {
			return status.Errorf(codes.NotFound, "mission %s not found", missionID)
		}
		if !m.Status.IsTerminal() {
			m.Status = mission.MissionStatusCancelled
			_ = store.Update(ctx, m)
		}
	}
	return nil
}

// GetResults implements harness.MissionClientIface.
func (a *missionHarnessAdapter) GetResults(ctx context.Context, missionID types.ID) (*harness.MissionClientResult, error) {
	store, err := a.store()
	if err != nil {
		return nil, err
	}

	m, getErr := store.Get(ctx, missionID)
	if getErr != nil {
		return nil, status.Errorf(codes.NotFound, "mission %s not found: %v", missionID, getErr)
	}

	return missionToHarnessResult(m), nil
}

// List implements harness.MissionClientIface.
func (a *missionHarnessAdapter) List(ctx context.Context, filter *harness.MissionClientFilter) ([]*harness.MissionClientRecord, error) {
	store, err := a.store()
	if err != nil {
		return nil, err
	}

	mFilter := &mission.MissionFilter{
		Limit:  filter.Limit,
		Offset: filter.Offset,
	}
	if filter.Status != nil {
		s := mission.MissionStatus(*filter.Status)
		mFilter.Status = &s
	}

	missions, listErr := store.List(ctx, mFilter)
	if listErr != nil {
		return nil, status.Errorf(codes.Internal, "failed to list missions: %v", listErr)
	}

	records := make([]*harness.MissionClientRecord, 0, len(missions))
	for _, m := range missions {
		rec := &harness.MissionClientRecord{
			ID:     m.ID,
			Status: string(m.Status),
			Depth:  m.Depth,
		}
		if m.ParentMissionID != nil {
			pid := *m.ParentMissionID
			rec.ParentMissionID = &pid
		}
		records = append(records, rec)
	}
	return records, nil
}

// missionToHarnessResult converts a *mission.Mission to *harness.MissionClientResult.
func missionToHarnessResult(m *mission.Mission) *harness.MissionClientResult {
	if m == nil {
		return &harness.MissionClientResult{}
	}

	var completedAt time.Time
	if !m.CompletedAt.IsNil() {
		completedAt = *m.CompletedAt.Time
	}

	var errStr string
	if m.Error != "" {
		errStr = m.Error
	}

	return &harness.MissionClientResult{
		MissionID:   m.ID.String(),
		Status:      string(m.Status),
		Error:       errStr,
		CompletedAt: completedAt,
	}
}
