package daemon

import (
	"context"

	"github.com/zero-day-ai/gibson/internal/mission"
)

// queryMissionCounts queries the mission store for total and active mission counts.
// This is a helper function to keep the status() method clean.
func (d *daemonImpl) queryMissionCounts(ctx context.Context) (total int, active int) {
	// Query total missions
	totalMissions, err := d.missionStore.Count(ctx, mission.NewMissionFilter())
	if err != nil {
		d.logger.Warn(ctx, "failed to get total mission count", "error", err)
		totalMissions = 0
	}

	// Query active missions
	activeMissions, err := d.missionStore.GetActive(ctx)
	if err != nil {
		d.logger.Warn(ctx, "failed to get active mission count", "error", err)
		activeMissions = nil
	}

	return totalMissions, len(activeMissions)
}
