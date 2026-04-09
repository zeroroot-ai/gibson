package daemon

import (
	"context"
	"errors"

	"github.com/zero-day-ai/gibson/internal/harness"
	"github.com/zero-day-ai/gibson/internal/mission"
)

// missionAuthzStoreAdapter adapts mission.MissionAuthzStore to harness.RunAuthzLookup.
//
// This adapter exists because the harness package cannot import the mission package
// without creating a circular dependency (harness→mission→eval→harness).
// The daemon package can import both, so it bridges the two interfaces here.
type missionAuthzStoreAdapter struct {
	inner mission.MissionAuthzStore
}

// newMissionAuthzStoreAdapter wraps a mission.MissionAuthzStore as a harness.RunAuthzLookup.
func newMissionAuthzStoreAdapter(store mission.MissionAuthzStore) harness.RunAuthzLookup {
	return &missionAuthzStoreAdapter{inner: store}
}

// Get retrieves the authz state for a run ID, translating mission package types to
// the harness package's RunAuthzState and sentinel error.
func (a *missionAuthzStoreAdapter) Get(ctx context.Context, runID string) (*harness.RunAuthzState, error) {
	state, err := a.inner.Get(ctx, runID)
	if err != nil {
		if errors.Is(err, mission.ErrMissionAuthzNotFound) {
			return nil, harness.ErrRunNotFound
		}
		return nil, err
	}
	return &harness.RunAuthzState{
		RunID:     state.RunID,
		UserID:    state.UserID,
		TenantID:  state.TenantID,
		Status:    state.Status,
		StartedAt: state.StartedAt,
	}, nil
}
