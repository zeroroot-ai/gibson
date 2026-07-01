package daemon

import (
	"context"
	"strings"

	"github.com/zeroroot-ai/gibson/internal/engine/brain"
	"github.com/zeroroot-ai/gibson/internal/server/daemon/api"
)

// ListMissions returns mission list with optional filtering and pagination.
//
// Status and progress are World-derived (ADR-0011/gibson#1118): the brain's
// folded World is the single source of truth — no Redis store reads for status.
// The caller may filter by status string, name pattern, and active-only.
//
// Parameters:
//   - ctx: Context for the request (tenant resolved from here)
//   - activeOnly: If true, return only running/paused missions
//   - statusFilter: Filter by specific status (running, completed, failed) — empty means all
//   - namePattern: Substring filter on mission name — empty means all
//   - limit: Maximum results (0 = default 100)
//   - offset: Number of results to skip for pagination
func (d *daemonImpl) ListMissions(ctx context.Context, activeOnly bool, statusFilter, namePattern string, limit, offset int) ([]api.MissionData, int, error) {
	d.logger.Debug(ctx, "ListMissions called",
		"active_only", activeOnly,
		"status_filter", statusFilter,
		"name_pattern", namePattern,
		"limit", limit,
		"offset", offset,
	)

	if limit == 0 {
		limit = 100
	}

	tenant := tenantFromCtxOrSystem(ctx)

	// brainRegistry is nil when the daemon boots without a security key provider
	// (dev / no-pool mode). Return empty rather than panic.
	if d.brainRegistry == nil {
		d.logger.Warn(ctx, "brainRegistry not configured; returning empty mission list")
		return []api.MissionData{}, 0, nil
	}

	eng := d.brainRegistry.For(tenant.String())
	snapshots := eng.Missions()

	var result []api.MissionData
	for _, ms := range snapshots {
		// C9 closure: only return missions belonging to the calling tenant.
		// Missions with an empty TenantID (e.g. legacy or no-pool runs) are
		// included for backward compatibility.
		if ms.TenantID != "" && ms.TenantID != tenant.String() {
			continue
		}
		if activeOnly && ms.Status != brain.MissionRunning && ms.Status != brain.MissionPaused {
			continue
		}
		if statusFilter != "" && string(ms.Status) != statusFilter {
			continue
		}
		if namePattern != "" && !containsCI(ms.Name, namePattern) {
			continue
		}
		result = append(result, missionSnapshotToData(ms))
	}

	total := len(result)

	// Apply pagination.
	if offset > 0 {
		if offset >= len(result) {
			result = []api.MissionData{}
		} else {
			result = result[offset:]
		}
	}
	if limit > 0 && len(result) > limit {
		result = result[:limit]
	}

	d.logger.Debug(ctx, "listed missions", "count", len(result), "total", total)
	return result, total, nil
}

// containsCI is a case-insensitive substring match.
func containsCI(s, substr string) bool {
	return strings.Contains(strings.ToLower(s), strings.ToLower(substr))
}
