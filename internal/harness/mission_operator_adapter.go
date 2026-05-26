package harness

// mission_operator_adapter.go implements harness.MissionOperator by wrapping
// the daemon's mission.MissionClient.  This adapter lives in the harness
// package rather than the mission package to prevent an import cycle
// (mission → harness → mission).
//
// The adapter is constructed during daemon startup and passed to
// HarnessCallbackService via WithMissionManager so that the six stub methods
// in callback_service.go can delegate to real mission lifecycle operations.

import (
	"context"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/zeroroot-ai/gibson/internal/types"
)

// MissionClientIface is the minimal interface from the mission package that the
// adapter needs.  It mirrors the actual *mission.MissionClient methods without
// importing the mission package, keeping the harness package import-cycle-free.
//
// The concrete *mission.MissionClient satisfies this interface at daemon startup;
// the daemon wires it via:
//
//	harness.NewMissionOperatorAdapter(missionClient)
type MissionClientIface interface {
	// CreateMission corresponds to mission.MissionClient.Create.
	// Parameters match mission.CreateMissionRequest fields.
	CreateMission(ctx context.Context, req *MissionClientCreateRequest) (*MissionClientInfo, error)

	// Run starts execution of an already-created mission.
	Run(ctx context.Context, missionID string) error

	// GetStatus returns current status for a mission.
	GetStatus(ctx context.Context, missionID string) (*MissionClientStatusInfo, error)

	// WaitForCompletion blocks until the mission reaches a terminal state.
	WaitForCompletion(ctx context.Context, missionID string, timeout time.Duration) (*MissionClientResult, error)

	// Cancel cancels a running or pending mission.
	Cancel(ctx context.Context, missionID types.ID) error

	// GetResults returns the final result for a completed mission.
	GetResults(ctx context.Context, missionID types.ID) (*MissionClientResult, error)

	// List returns missions matching the filter.
	List(ctx context.Context, filter *MissionClientFilter) ([]*MissionClientRecord, error)
}

// MissionClientCreateRequest maps from harness.CreateMissionRequest to the
// mission-package create request without importing the mission package.
type MissionClientCreateRequest struct {
	MissionDefinitionJSON string
	Name                  string
	Description           string
	TargetID              types.ID
	ParentMissionID       *types.ID
	ParentDepth           int
	Tags                  []string
	Metadata              map[string]any
}

// MissionClientInfo is the create-response from the mission package.
type MissionClientInfo struct {
	ID   types.ID
	Name string
}

// MissionClientStatusInfo mirrors mission.MissionStatusInfo.
type MissionClientStatusInfo struct {
	Status        string
	Progress      float64
	Phase         string
	FindingCounts map[string]int
	TokenUsage    int64
	Duration      time.Duration
	Error         string
}

// MissionClientResult mirrors mission.MissionResult fields needed here.
type MissionClientResult struct {
	MissionID     string
	Status        string
	FindingIDs    []string
	MissionResult map[string]any
	Error         string
	CompletedAt   time.Time
}

// MissionClientRecord mirrors mission.Mission fields needed for listing.
type MissionClientRecord struct {
	ID              types.ID
	ParentMissionID *types.ID
	Depth           int
	Status          string
}

// MissionClientFilter mirrors mission.MissionFilter.
type MissionClientFilter struct {
	Status *string
	Limit  int
	Offset int
}

// ---------------------------------------------------------------------------
// MissionOperatorAdapter
// ---------------------------------------------------------------------------

// MissionOperatorAdapter implements harness.MissionOperator by delegating to a
// MissionClientIface.  The adapter translates between harness domain types and
// the mission-client domain types without creating an import cycle.
type MissionOperatorAdapter struct {
	client MissionClientIface
}

// NewMissionOperatorAdapter constructs an adapter wrapping the given client.
// client must not be nil.
func NewMissionOperatorAdapter(client MissionClientIface) *MissionOperatorAdapter {
	if client == nil {
		panic("harness: NewMissionOperatorAdapter: client must not be nil")
	}
	return &MissionOperatorAdapter{client: client}
}

// CreateMission implements MissionCreator (part of MissionOperator).
func (a *MissionOperatorAdapter) CreateMission(ctx context.Context, req *CreateMissionRequest) (*MissionInfo, error) {
	if req == nil {
		return nil, status.Error(codes.InvalidArgument, "create mission request is required")
	}

	clientReq := &MissionClientCreateRequest{
		MissionDefinitionJSON: req.MissionDefinitionJSON,
		Name:                  req.Name,
		Description:           req.Description,
		TargetID:              req.TargetID,
		ParentMissionID:       req.ParentMissionID,
		ParentDepth:           req.ParentDepth,
		Tags:                  req.Tags,
		Metadata:              req.Metadata,
	}

	info, err := a.client.CreateMission(ctx, clientReq)
	if err != nil {
		return nil, err
	}

	return &MissionInfo{
		ID:   info.ID,
		Name: info.Name,
	}, nil
}

// Run implements MissionOperator.
func (a *MissionOperatorAdapter) Run(ctx context.Context, missionID string) error {
	return a.client.Run(ctx, missionID)
}

// GetStatus implements MissionOperator.
func (a *MissionOperatorAdapter) GetStatus(ctx context.Context, missionID string) (*MissionStatusInfo, error) {
	si, err := a.client.GetStatus(ctx, missionID)
	if err != nil {
		return nil, err
	}
	return &MissionStatusInfo{
		Status:        MissionStatus(si.Status),
		Progress:      si.Progress,
		Phase:         si.Phase,
		FindingCounts: si.FindingCounts,
		TokenUsage:    si.TokenUsage,
		Duration:      si.Duration,
		Error:         si.Error,
	}, nil
}

// WaitForCompletion implements MissionOperator.
func (a *MissionOperatorAdapter) WaitForCompletion(ctx context.Context, missionID string, timeout time.Duration) (*MissionResultInfo, error) {
	result, err := a.client.WaitForCompletion(ctx, missionID, timeout)
	if err != nil {
		return nil, err
	}
	return a.toResultInfo(result), nil
}

// Cancel implements MissionOperator.
func (a *MissionOperatorAdapter) Cancel(ctx context.Context, missionID types.ID) error {
	return a.client.Cancel(ctx, missionID)
}

// GetResults implements MissionOperator.
func (a *MissionOperatorAdapter) GetResults(ctx context.Context, missionID types.ID) (*MissionResultInfo, error) {
	result, err := a.client.GetResults(ctx, missionID)
	if err != nil {
		return nil, err
	}
	return a.toResultInfo(result), nil
}

// List implements MissionLister (part of MissionOperator).
func (a *MissionOperatorAdapter) List(ctx context.Context, filter *MissionFilter) ([]*MissionRecord, error) {
	clientFilter := &MissionClientFilter{
		Limit:  filter.Limit,
		Offset: filter.Offset,
	}
	if filter.Status != nil {
		s := string(*filter.Status)
		clientFilter.Status = &s
	}

	records, err := a.client.List(ctx, clientFilter)
	if err != nil {
		return nil, err
	}

	result := make([]*MissionRecord, 0, len(records))
	for _, r := range records {
		rec := &MissionRecord{
			ID:     r.ID,
			Status: MissionStatus(r.Status),
			Depth:  r.Depth,
		}
		if r.ParentMissionID != nil {
			pid := *r.ParentMissionID
			rec.ParentMissionID = &pid
		}
		result = append(result, rec)
	}
	return result, nil
}

// toResultInfo converts a MissionClientResult to MissionResultInfo.
func (a *MissionOperatorAdapter) toResultInfo(r *MissionClientResult) *MissionResultInfo {
	if r == nil {
		return &MissionResultInfo{}
	}
	return &MissionResultInfo{
		MissionID:     r.MissionID,
		Status:        MissionStatus(r.Status),
		FindingIDs:    r.FindingIDs,
		MissionResult: r.MissionResult,
		Error:         r.Error,
		CompletedAt:   r.CompletedAt,
	}
}
