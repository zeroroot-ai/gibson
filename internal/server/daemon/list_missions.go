package daemon

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/zeroroot-ai/gibson/internal/engine/mission"
	"github.com/zeroroot-ai/gibson/internal/infra/datapool"
	"github.com/zeroroot-ai/gibson/internal/infra/types"
	"github.com/zeroroot-ai/gibson/internal/server/daemon/api"
)

// ListMissions returns mission list with optional filtering and pagination.
//
// This method queries the mission store to retrieve missions based on the provided
// filters. When activeOnly is true, it returns only missions with status "running"
// or "paused". Additional filters include status and name pattern matching.
// Pagination is supported via limit and offset parameters.
//
// Parameters:
//   - ctx: Context for the database query
//   - activeOnly: If true, return only running/paused missions
//   - statusFilter: Filter by specific status (running, completed, failed, cancelled) - empty means all
//   - namePattern: Filter by mission name using glob pattern - empty means all
//   - limit: Maximum number of missions to return (0 = use default)
//   - offset: Number of missions to skip for pagination
//
// Returns:
//   - []api.MissionData: List of missions matching the filter
//   - int: Total count of missions (for pagination, not affected by limit/offset)
//   - error: Non-nil if query fails
func (d *daemonImpl) ListMissions(ctx context.Context, activeOnly bool, statusFilter, namePattern string, limit, offset int) ([]api.MissionData, int, error) {
	d.logger.Debug(ctx, "ListMissions called",
		"active_only", activeOnly,
		"status_filter", statusFilter,
		"name_pattern", namePattern,
		"limit", limit,
		"offset", offset,
	)

	// Set default limit if not specified
	if limit == 0 {
		limit = 100
	}

	// Build mission filter
	var missions []*mission.Mission
	var total int
	var err error

	// Acquire per-tenant store via pool.
	tenant := tenantFromCtxOrSystem(ctx)
	if d.pool == nil {
		d.logger.Warn(ctx, "pool not configured; returning empty mission list")
		return []api.MissionData{}, 0, nil
	}
	conn, connErr := d.pool.For(ctx, tenant)
	if connErr != nil {
		return nil, 0, datapool.MapPoolError(connErr)
	}
	defer conn.Release()
	mStore := mission.NewConnBoundMissionStore(conn.Redis)

	if activeOnly {
		// Query only running or paused missions
		missions, err = mStore.GetActive(ctx)
		if err != nil {
			d.logger.Error(ctx, "failed to get active missions", "error", err)
			return nil, 0, fmt.Errorf("failed to get active missions: %w", err)
		}

		// Apply additional filters in-memory for active missions
		missions = d.filterMissions(missions, statusFilter, namePattern)

		// Total is the number of filtered active missions
		total = len(missions)

		// Apply pagination manually for active missions
		start := offset
		if start > total {
			start = total
		}
		end := start + limit
		if end > total {
			end = total
		}

		// Slice the results for pagination
		missions = missions[start:end]
	} else {
		// Query all missions with pagination and filters
		filter := mission.NewMissionFilter()
		filter.WithPagination(limit, offset)

		// Apply status filter if provided
		if statusFilter != "" {
			status := mission.MissionStatus(statusFilter)
			filter.WithStatus(status)
		}

		// Apply name pattern filter if provided
		if namePattern != "" {
			filter.SearchText = &namePattern
		}

		missions, err = mStore.List(ctx, filter)
		if err != nil {
			d.logger.Error(ctx, "failed to list missions", "error", err)
			return nil, 0, fmt.Errorf("failed to list missions: %w", err)
		}

		// Get total count for pagination (count all missions matching filters, not just the page)
		totalFilter := mission.NewMissionFilter()
		if statusFilter != "" {
			status := mission.MissionStatus(statusFilter)
			totalFilter.WithStatus(status)
		}
		if namePattern != "" {
			totalFilter.SearchText = &namePattern
		}

		total, err = mStore.Count(ctx, totalFilter)
		if err != nil {
			d.logger.Error(ctx, "failed to count missions", "error", err)
			return nil, 0, fmt.Errorf("failed to count missions: %w", err)
		}
	}

	// Convert to API format
	result := make([]api.MissionData, len(missions))
	for i, m := range missions {
		result[i] = convertMissionToData(m)
	}

	d.logger.Debug(ctx, "listed missions", "count", len(result), "total", total, "active_only", activeOnly)
	return result, total, nil
}

// convertMissionToData converts a mission.Mission to api.MissionData.
//
// This helper function transforms the internal mission representation to the
// API data structure used in gRPC responses. It handles time pointer conversions
// and extracts relevant fields for the API response.
func convertMissionToData(m *mission.Mission) api.MissionData {
	var startTime, endTime time.Time

	// Convert time pointers to values
	if !m.StartedAt.IsNil() {
		startTime = *m.StartedAt.Time
	}
	if !m.CompletedAt.IsNil() {
		endTime = *m.CompletedAt.Time
	}

	return api.MissionData{
		ID:                  m.ID.String(),
		TenantID:            m.TenantID,
		Name:                m.Name,
		Description:         m.Description,
		MissionDefinitionID: m.MissionDefinitionID.String(),
		TargetID:            m.TargetID.String(),
		Status:              string(m.Status),
		StartTime:           startTime,
		EndTime:             endTime,
		FindingCount:        int32(m.FindingsCount),
		Progress:            m.Progress,
	}
}

// filterMissions applies in-memory filtering to a mission list.
//
// This helper is used when filtering active missions that are retrieved from GetActive()
// which doesn't support the full filter API. It applies status and name pattern filters
// in memory to reduce the result set before pagination.
//
// Parameters:
//   - missions: The missions to filter
//   - statusFilter: Status to match (empty = no filter)
//   - namePattern: Name pattern to match (empty = no filter)
//
// Returns:
//   - []*mission.Mission: Filtered mission list
func (d *daemonImpl) filterMissions(missions []*mission.Mission, statusFilter, namePattern string) []*mission.Mission {
	if statusFilter == "" && namePattern == "" {
		return missions
	}

	filtered := make([]*mission.Mission, 0, len(missions))
	for _, m := range missions {
		// Apply status filter
		if statusFilter != "" && string(m.Status) != statusFilter {
			continue
		}

		// Apply name pattern filter (simple contains match for now)
		if namePattern != "" {
			if !contains(m.Name, namePattern) {
				continue
			}
		}

		filtered = append(filtered, m)
	}

	return filtered
}

// contains is a simple case-insensitive substring match helper.
func contains(s, substr string) bool {
	return len(substr) == 0 || len(s) >= len(substr) &&
		(s == substr || len(s) > len(substr) && containsSubstring(s, substr))
}

// containsSubstring performs case-insensitive substring search.
func containsSubstring(s, substr string) bool {
	s = strings.ToLower(s)
	substr = strings.ToLower(substr)
	return strings.Contains(s, substr)
}

// parseMissionID is a helper to parse and validate mission IDs.
func parseMissionID(missionIDStr string) (types.ID, error) {
	if missionIDStr == "" {
		return types.ID(""), fmt.Errorf("mission ID cannot be empty")
	}

	missionID, err := types.ParseID(missionIDStr)
	if err != nil {
		return types.ID(""), fmt.Errorf("invalid mission ID format: %w", err)
	}

	return missionID, nil
}
