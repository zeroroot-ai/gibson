package daemon

import (
	"context"
)

// queryMissionCounts returns mission counts from the in-memory mission manager.
// After the per-tenant cutover, cross-tenant mission counting requires enumerating
// all tenants; for the daemon status helper we use the mission manager's in-process
// counters which reflect only active (in-memory) missions. Completed missions in
// per-tenant Postgres databases are not counted here — this is advisory for the
// daemon status RPC and the /healthz endpoint, not an authoritative count.
func (d *daemonImpl) queryMissionCounts(ctx context.Context) (total int, active int) {
	if d.missionManager == nil {
		return 0, 0
	}
	active = d.missionManager.GetActiveMissionCount()
	total = d.missionManager.GetTotalMissionCount()
	return total, active
}
