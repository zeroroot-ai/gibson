package mission

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	goredis "github.com/redis/go-redis/v9"
	"github.com/zero-day-ai/gibson/internal/auth"
	"github.com/zero-day-ai/gibson/internal/state"
	"github.com/zero-day-ai/gibson/internal/types"
)

// RedisMissionStore implements MissionStore using Redis.
// It provides high-performance, scalable mission storage.
// Mission definitions are stored in Redis alongside mission instances.
type RedisMissionStore struct {
	client *state.StateClient
}

// NewRedisMissionStore creates a new Redis-backed mission store.
func NewRedisMissionStore(client *state.StateClient) *RedisMissionStore {
	return &RedisMissionStore{
		client: client,
	}
}

// Key naming functions for Redis keys
// All key functions accept a tenantID parameter for multi-tenant isolation.
// When tenantID is non-empty, it is embedded in the key for defense-in-depth
// isolation. When empty, the legacy (unscoped) key format is returned for
// backward compatibility.

// missionKey returns the Redis key for a mission document.
// Format: gibson:mission:{tenant}:{id} or gibson:mission:{id} (legacy)
func missionKey(tenantID string, id types.ID) string {
	if tenantID != "" {
		return fmt.Sprintf("gibson:mission:%s:%s", tenantID, id)
	}
	return fmt.Sprintf("gibson:mission:%s", id)
}

// missionRunsKey returns the Redis key for mission runs sorted set.
// Format: gibson:mission:{tenant}:{id}:runs or gibson:mission:{id}:runs (legacy)
func missionRunsKey(tenantID string, id types.ID) string {
	if tenantID != "" {
		return fmt.Sprintf("gibson:mission:%s:%s:runs", tenantID, id)
	}
	return fmt.Sprintf("gibson:mission:%s:runs", id)
}

// missionRunKey returns the Redis key for a mission run document.
// Format: gibson:mission_run:{tenant}:{id} or gibson:mission_run:{id} (legacy)
func missionRunKey(tenantID string, id types.ID) string {
	if tenantID != "" {
		return fmt.Sprintf("gibson:mission_run:%s:%s", tenantID, id)
	}
	return fmt.Sprintf("gibson:mission_run:%s", id)
}

// missionEventsStream returns the Redis key for mission events stream.
// Format: gibson:stream:mission:{tenant}:{id}:events or gibson:stream:mission:{id}:events (legacy)
func missionEventsStream(tenantID string, id types.ID) string {
	if tenantID != "" {
		return fmt.Sprintf("gibson:stream:mission:%s:%s:events", tenantID, id)
	}
	return fmt.Sprintf("gibson:stream:mission:%s:events", id)
}

// missionCounterKey returns the Redis key for mission run counter.
// Format: gibson:counter:mission:{tenant}:{name}:run or gibson:counter:mission:{name}:run (legacy)
func missionCounterKey(tenantID string, name string) string {
	if tenantID != "" {
		return fmt.Sprintf("gibson:counter:mission:%s:%s:run", tenantID, name)
	}
	return fmt.Sprintf("gibson:counter:mission:%s:run", name)
}

// missionByStatusKey returns the Redis key for missions grouped by status.
// Format: gibson:mission:by_status:{tenant}:{status} or gibson:mission:by_status:{status} (legacy)
func missionByStatusKey(tenantID string, status MissionStatus) string {
	if tenantID != "" {
		return fmt.Sprintf("gibson:mission:by_status:%s:%s", tenantID, status)
	}
	return fmt.Sprintf("gibson:mission:by_status:%s", status)
}

// missionByTargetKey returns the Redis key for missions grouped by target ID.
// Format: gibson:mission:by_target:{tenant}:{target_id} or gibson:mission:by_target:{target_id} (legacy)
func missionByTargetKey(tenantID string, targetID types.ID) string {
	if tenantID != "" {
		return fmt.Sprintf("gibson:mission:by_target:%s:%s", tenantID, targetID)
	}
	return fmt.Sprintf("gibson:mission:by_target:%s", targetID)
}

// Save persists a new mission to Redis with secondary index maintenance.
func (s *RedisMissionStore) Save(ctx context.Context, mission *Mission) error {
	if mission == nil {
		return fmt.Errorf("mission cannot be nil")
	}

	if err := mission.Validate(); err != nil {
		return fmt.Errorf("validation failed: %w", err)
	}

	// Generate ID if not set
	if mission.ID.IsZero() {
		mission.ID = types.NewID()
	}

	// Set timestamps if not already set
	now := NewUnixTimeNow()
	if mission.CreatedAt.IsZero() {
		mission.CreatedAt = now
	}
	mission.UpdatedAt = now

	// Extract tenant for key scoping — writes always use tenant-scoped key
	tenantID := auth.TenantFromContext(ctx)

	// Store mission document using JSON.SET
	key := missionKey(tenantID, mission.ID)
	if err := s.client.JSONSet(ctx, key, "$", mission); err != nil {
		return fmt.Errorf("failed to save mission: %w", err)
	}

	// Maintain secondary indexes atomically using pipeline
	pipe := s.client.Pipeline(ctx)

	// Add to by_status set
	statusSetKey := missionByStatusKey(tenantID, mission.Status)
	pipe.SAdd(ctx, statusSetKey, mission.ID.String())

	// Add to by_target set
	targetSetKey := missionByTargetKey(tenantID, mission.TargetID)
	pipe.SAdd(ctx, targetSetKey, mission.ID.String())

	// Execute pipeline
	if _, err := pipe.Exec(ctx); err != nil {
		return fmt.Errorf("failed to update secondary indexes: %w", err)
	}

	return nil
}

// Get retrieves a mission by ID.
// Uses backward-compatible reads: tries tenant-scoped key first, falls back to legacy.
func (s *RedisMissionStore) Get(ctx context.Context, id types.ID) (*Mission, error) {
	tenantID := auth.TenantFromContext(ctx)
	key := missionKey(tenantID, id)

	var mission Mission
	if err := s.client.JSONGet(ctx, key, "$", &mission); err != nil {
		if state.IsNotFound(err) && tenantID != "" {
			// Fallback to legacy (unscoped) key for backward compatibility
			legacyKey := missionKey("", id)
			if legacyErr := s.client.JSONGet(ctx, legacyKey, "$", &mission); legacyErr != nil {
				if state.IsNotFound(legacyErr) {
					return nil, NewNotFoundError(id.String())
				}
				return nil, fmt.Errorf("failed to get mission: %w", legacyErr)
			}
			return &mission, nil
		}
		if state.IsNotFound(err) {
			return nil, NewNotFoundError(id.String())
		}
		return nil, fmt.Errorf("failed to get mission: %w", err)
	}

	return &mission, nil
}

// GetByName retrieves a mission by name using RediSearch.
func (s *RedisMissionStore) GetByName(ctx context.Context, name string) (*Mission, error) {
	// Build TAG search query for exact name match
	escapedName := state.EscapeTag(name)
	query := fmt.Sprintf("@name:{%s}", escapedName)

	// Search with limit 1
	opts := &state.SearchOptions{
		Limit:  1,
		Offset: 0,
	}

	result, err := s.client.Search(ctx, "gibson:idx:missions", query, opts)
	if err != nil {
		return nil, fmt.Errorf("failed to search missions by name: %w", err)
	}

	if result.Total == 0 {
		return nil, NewNotFoundError(name)
	}

	// Unmarshal the first result
	var mission Mission
	if err := json.Unmarshal(result.Documents[0].JSON, &mission); err != nil {
		return nil, fmt.Errorf("failed to unmarshal mission: %w", err)
	}

	return &mission, nil
}

// List retrieves missions with optional filtering using RediSearch.
func (s *RedisMissionStore) List(ctx context.Context, filter *MissionFilter) ([]*Mission, error) {
	if filter == nil {
		filter = NewMissionFilter()
	}

	// Set default limit if not specified
	if filter.Limit == 0 {
		filter.Limit = 100
	}

	// Build search query
	query := s.buildSearchQuery(filter)

	// Build search options
	opts := &state.SearchOptions{
		Limit:   filter.Limit,
		Offset:  filter.Offset,
		SortBy:  "created_at",
		SortAsc: false, // DESC by default
	}

	result, err := s.client.Search(ctx, "gibson:idx:missions", query, opts)
	if err != nil {
		return nil, fmt.Errorf("failed to search missions: %w", err)
	}

	// Unmarshal results
	missions := make([]*Mission, 0, len(result.Documents))
	for _, doc := range result.Documents {
		var mission Mission
		if err := json.Unmarshal(doc.JSON, &mission); err != nil {
			return nil, fmt.Errorf("failed to unmarshal mission: %w", err)
		}
		missions = append(missions, &mission)
	}

	return missions, nil
}

// buildSearchQuery constructs a RediSearch query from MissionFilter.
func (s *RedisMissionStore) buildSearchQuery(filter *MissionFilter) string {
	if filter == nil {
		return "*" // Match all
	}

	var conditions []string

	// Status filter (TAG field)
	if filter.Status != nil {
		escapedStatus := state.EscapeTag(string(*filter.Status))
		conditions = append(conditions, fmt.Sprintf("@status:{%s}", escapedStatus))
	}

	// TargetID filter (TAG field)
	if filter.TargetID != nil {
		escapedTargetID := state.EscapeTag(filter.TargetID.String())
		conditions = append(conditions, fmt.Sprintf("@target_id:{%s}", escapedTargetID))
	}

	// WorkflowID filter (TAG field)
	if filter.WorkflowID != nil {
		escapedWorkflowID := state.EscapeTag(filter.WorkflowID.String())
		conditions = append(conditions, fmt.Sprintf("@workflow_id:{%s}", escapedWorkflowID))
	}

	// CreatedAfter filter (NUMERIC range)
	if filter.CreatedAfter != nil {
		timestamp := filter.CreatedAfter.Unix()
		conditions = append(conditions, fmt.Sprintf("@created_at:[%d +inf]", timestamp))
	}

	// CreatedBefore filter (NUMERIC range)
	if filter.CreatedBefore != nil {
		timestamp := filter.CreatedBefore.Unix()
		conditions = append(conditions, fmt.Sprintf("@created_at:[-inf %d]", timestamp))
	}

	// SearchText filter (full-text search on name and description)
	if filter.SearchText != nil && *filter.SearchText != "" {
		escapedText := state.EscapeQuery(*filter.SearchText)
		conditions = append(conditions, fmt.Sprintf("(@name:%s | @description:%s)", escapedText, escapedText))
	}

	// Combine conditions with AND
	if len(conditions) == 0 {
		return "*" // No filters - match all
	}

	query := ""
	for i, cond := range conditions {
		if i > 0 {
			query += " "
		}
		query += cond
	}

	return query
}

// Update modifies an existing mission with secondary index maintenance.
func (s *RedisMissionStore) Update(ctx context.Context, mission *Mission) error {
	if mission == nil {
		return fmt.Errorf("mission cannot be nil")
	}

	if err := mission.Validate(); err != nil {
		return fmt.Errorf("validation failed: %w", err)
	}

	// Update timestamp
	mission.UpdatedAt = NewUnixTimeNow()

	// Extract tenant for key scoping — writes always use tenant-scoped key
	tenantID := auth.TenantFromContext(ctx)

	// Check if mission exists and get old values for index comparison
	key := missionKey(tenantID, mission.ID)
	var existing Mission
	if err := s.client.JSONGet(ctx, key, "$", &existing); err != nil {
		if state.IsNotFound(err) {
			return NewNotFoundError(mission.ID.String())
		}
		return fmt.Errorf("failed to check mission existence: %w", err)
	}

	// Update entire document
	if err := s.client.JSONSet(ctx, key, "$", mission); err != nil {
		return fmt.Errorf("failed to update mission: %w", err)
	}

	// Maintain secondary indexes if status or target changed
	pipe := s.client.Pipeline(ctx)
	indexUpdates := false

	// Handle status change
	if existing.Status != mission.Status {
		// Remove from old status set
		oldStatusKey := missionByStatusKey(tenantID, existing.Status)
		pipe.SRem(ctx, oldStatusKey, mission.ID.String())

		// Add to new status set
		newStatusKey := missionByStatusKey(tenantID, mission.Status)
		pipe.SAdd(ctx, newStatusKey, mission.ID.String())

		indexUpdates = true
	}

	// Handle target change
	if existing.TargetID != mission.TargetID {
		// Remove from old target set
		oldTargetKey := missionByTargetKey(tenantID, existing.TargetID)
		pipe.SRem(ctx, oldTargetKey, mission.ID.String())

		// Add to new target set
		newTargetKey := missionByTargetKey(tenantID, mission.TargetID)
		pipe.SAdd(ctx, newTargetKey, mission.ID.String())

		indexUpdates = true
	}

	// Execute pipeline if we have index updates
	if indexUpdates {
		if _, err := pipe.Exec(ctx); err != nil {
			return fmt.Errorf("failed to update secondary indexes: %w", err)
		}
	}

	return nil
}

// UpdateStatus updates only the status field of a mission with secondary index maintenance.
func (s *RedisMissionStore) UpdateStatus(ctx context.Context, id types.ID, status MissionStatus) error {
	tenantID := auth.TenantFromContext(ctx)
	key := missionKey(tenantID, id)

	// Check if mission exists and get old status for index update
	var existing Mission
	if err := s.client.JSONGet(ctx, key, "$", &existing); err != nil {
		if state.IsNotFound(err) {
			return NewNotFoundError(id.String())
		}
		return fmt.Errorf("failed to get mission: %w", err)
	}

	// Update status field using JSON.SET with path
	if err := s.client.JSONSet(ctx, key, "$.status", string(status)); err != nil {
		return fmt.Errorf("failed to update mission status: %w", err)
	}

	// Update updated_at field
	if err := s.client.JSONSet(ctx, key, "$.updated_at", NewUnixTimeNow()); err != nil {
		return fmt.Errorf("failed to update timestamp: %w", err)
	}

	// Maintain by_status secondary index if status changed
	if existing.Status != status {
		pipe := s.client.Pipeline(ctx)

		// Remove from old status set
		oldStatusKey := missionByStatusKey(tenantID, existing.Status)
		pipe.SRem(ctx, oldStatusKey, id.String())

		// Add to new status set
		newStatusKey := missionByStatusKey(tenantID, status)
		pipe.SAdd(ctx, newStatusKey, id.String())

		// Execute pipeline
		if _, err := pipe.Exec(ctx); err != nil {
			return fmt.Errorf("failed to update by_status index: %w", err)
		}
	}

	return nil
}

// UpdateProgress updates only the progress field of a mission.
func (s *RedisMissionStore) UpdateProgress(ctx context.Context, id types.ID, progress float64) error {
	// Validate progress is in valid range (0.0 to 1.0)
	if progress < 0.0 || progress > 1.0 {
		return fmt.Errorf("progress must be between 0.0 and 1.0, got %f", progress)
	}

	tenantID := auth.TenantFromContext(ctx)
	key := missionKey(tenantID, id)

	// Check if mission exists
	var existing Mission
	if err := s.client.JSONGet(ctx, key, "$", &existing); err != nil {
		if state.IsNotFound(err) {
			return NewNotFoundError(id.String())
		}
		return fmt.Errorf("failed to get mission: %w", err)
	}

	// Update progress field using JSON.SET with path
	if err := s.client.JSONSet(ctx, key, "$.progress", progress); err != nil {
		return fmt.Errorf("failed to update mission progress: %w", err)
	}

	// Update updated_at field
	if err := s.client.JSONSet(ctx, key, "$.updated_at", NewUnixTimeNow()); err != nil {
		return fmt.Errorf("failed to update timestamp: %w", err)
	}

	return nil
}

// Delete soft-deletes a mission using cascade delete script with secondary index cleanup.
// Only missions in terminal states can be deleted.
func (s *RedisMissionStore) Delete(ctx context.Context, id types.ID) error {
	tenantID := auth.TenantFromContext(ctx)

	// First, check if mission exists and is in a terminal state
	mission, err := s.Get(ctx, id)
	if err != nil {
		return err
	}

	if !mission.Status.IsTerminal() {
		return NewInvalidStateError(mission.Status, MissionStatusCancelled)
	}

	// Use cascade delete script to remove mission and all related data
	if err := s.client.CascadeDeleteMission(ctx, id.String()); err != nil {
		return fmt.Errorf("failed to delete mission: %w", err)
	}

	// Remove from secondary indexes
	pipe := s.client.Pipeline(ctx)

	// Remove from by_status set
	statusKey := missionByStatusKey(tenantID, mission.Status)
	pipe.SRem(ctx, statusKey, id.String())

	// Remove from by_target set
	targetKey := missionByTargetKey(tenantID, mission.TargetID)
	pipe.SRem(ctx, targetKey, id.String())

	// Execute pipeline
	if _, err := pipe.Exec(ctx); err != nil {
		return fmt.Errorf("failed to clean up secondary indexes: %w", err)
	}

	return nil
}

// GetByTarget retrieves all missions for a specific target using RediSearch.
func (s *RedisMissionStore) GetByTarget(ctx context.Context, targetID types.ID) ([]*Mission, error) {
	filter := NewMissionFilter().WithTarget(targetID)
	return s.List(ctx, filter)
}

// GetActive retrieves all active missions (running or paused) using RediSearch.
func (s *RedisMissionStore) GetActive(ctx context.Context) ([]*Mission, error) {
	// Build query for status IN (running, paused)
	escapedRunning := state.EscapeTag(string(MissionStatusRunning))
	escapedPaused := state.EscapeTag(string(MissionStatusPaused))
	query := fmt.Sprintf("@status:{%s | %s}", escapedRunning, escapedPaused)

	opts := &state.SearchOptions{
		Limit:   1000, // Large limit for active missions
		Offset:  0,
		SortBy:  "created_at",
		SortAsc: false,
	}

	result, err := s.client.Search(ctx, "gibson:idx:missions", query, opts)
	if err != nil {
		return nil, fmt.Errorf("failed to search active missions: %w", err)
	}

	// Unmarshal results
	missions := make([]*Mission, 0, len(result.Documents))
	for _, doc := range result.Documents {
		var mission Mission
		if err := json.Unmarshal(doc.JSON, &mission); err != nil {
			return nil, fmt.Errorf("failed to unmarshal mission: %w", err)
		}
		missions = append(missions, &mission)
	}

	return missions, nil
}

// SaveCheckpoint persists a mission checkpoint and adds event to stream.
func (s *RedisMissionStore) SaveCheckpoint(ctx context.Context, missionID types.ID, checkpoint *MissionCheckpoint) error {
	if checkpoint == nil {
		return fmt.Errorf("checkpoint cannot be nil")
	}

	tenantID := auth.TenantFromContext(ctx)
	key := missionKey(tenantID, missionID)

	// Check if mission exists
	var existing Mission
	if err := s.client.JSONGet(ctx, key, "$", &existing); err != nil {
		if state.IsNotFound(err) {
			return NewNotFoundError(missionID.String())
		}
		return fmt.Errorf("failed to get mission: %w", err)
	}

	// Update checkpoint field using JSON.SET with path
	if err := s.client.JSONSet(ctx, key, "$.checkpoint", checkpoint); err != nil {
		return fmt.Errorf("failed to save checkpoint: %w", err)
	}

	// Update checkpoint_at timestamp
	now := NewUnixTimeNow()
	if err := s.client.JSONSet(ctx, key, "$.checkpoint_at", now); err != nil {
		return fmt.Errorf("failed to update checkpoint_at: %w", err)
	}

	// Update updated_at field
	if err := s.client.JSONSet(ctx, key, "$.updated_at", now); err != nil {
		return fmt.Errorf("failed to update timestamp: %w", err)
	}

	// Add checkpoint event to stream
	streamKey := missionEventsStream(tenantID, missionID)
	eventData := map[string]any{
		"type":            "checkpoint",
		"checkpoint_id":   checkpoint.ID.String(),
		"checkpointed_at": checkpoint.CheckpointedAt.Format(time.RFC3339),
		"timestamp":       now.Format(time.RFC3339),
	}

	if _, err := s.client.StreamAdd(ctx, streamKey, eventData); err != nil {
		// Don't fail if stream add fails - checkpoint is already saved
		// Just log the error (in production, use proper logging)
	}

	return nil
}

// Count returns the total number of missions matching the filter using RediSearch.
func (s *RedisMissionStore) Count(ctx context.Context, filter *MissionFilter) (int, error) {
	if filter == nil {
		filter = NewMissionFilter()
	}

	// Build search query
	query := s.buildSearchQuery(filter)

	// Search with LIMIT 0 0 to only get total count
	opts := &state.SearchOptions{
		Limit:  0,
		Offset: 0,
	}

	result, err := s.client.Search(ctx, "gibson:idx:missions", query, opts)
	if err != nil {
		return 0, fmt.Errorf("failed to count missions: %w", err)
	}

	return int(result.Total), nil
}

// GetByNameAndStatus retrieves a mission by name and status using RediSearch.
func (s *RedisMissionStore) GetByNameAndStatus(ctx context.Context, name string, status MissionStatus) (*Mission, error) {
	// Build query with both name and status filters
	escapedName := state.EscapeTag(name)
	escapedStatus := state.EscapeTag(string(status))
	query := fmt.Sprintf("@name:{%s} @status:{%s}", escapedName, escapedStatus)

	opts := &state.SearchOptions{
		Limit:   1,
		Offset:  0,
		SortBy:  "created_at",
		SortAsc: false,
	}

	result, err := s.client.Search(ctx, "gibson:idx:missions", query, opts)
	if err != nil {
		return nil, fmt.Errorf("failed to search missions: %w", err)
	}

	if result.Total == 0 {
		return nil, NewNotFoundError(fmt.Sprintf("%s (status=%s)", name, status))
	}

	// Unmarshal the first result
	var mission Mission
	if err := json.Unmarshal(result.Documents[0].JSON, &mission); err != nil {
		return nil, fmt.Errorf("failed to unmarshal mission: %w", err)
	}

	return &mission, nil
}

// ListByName retrieves all missions with the given name, ordered by run number descending.
func (s *RedisMissionStore) ListByName(ctx context.Context, name string, limit int) ([]*Mission, error) {
	if limit <= 0 {
		limit = 100
	}

	// Build query for name
	escapedName := state.EscapeTag(name)
	query := fmt.Sprintf("@name:{%s}", escapedName)

	opts := &state.SearchOptions{
		Limit:   limit,
		Offset:  0,
		SortBy:  "run_number",
		SortAsc: false, // DESC
	}

	result, err := s.client.Search(ctx, "gibson:idx:missions", query, opts)
	if err != nil {
		return nil, fmt.Errorf("failed to search missions by name: %w", err)
	}

	// Unmarshal results
	missions := make([]*Mission, 0, len(result.Documents))
	for _, doc := range result.Documents {
		var mission Mission
		if err := json.Unmarshal(doc.JSON, &mission); err != nil {
			return nil, fmt.Errorf("failed to unmarshal mission: %w", err)
		}
		missions = append(missions, &mission)
	}

	return missions, nil
}

// GetLatestByName retrieves the most recent mission with the given name.
func (s *RedisMissionStore) GetLatestByName(ctx context.Context, name string) (*Mission, error) {
	// Build query for name
	escapedName := state.EscapeTag(name)
	query := fmt.Sprintf("@name:{%s}", escapedName)

	opts := &state.SearchOptions{
		Limit:   1,
		Offset:  0,
		SortBy:  "run_number",
		SortAsc: false, // DESC to get latest
	}

	result, err := s.client.Search(ctx, "gibson:idx:missions", query, opts)
	if err != nil {
		return nil, fmt.Errorf("failed to search latest mission: %w", err)
	}

	if result.Total == 0 {
		return nil, NewNotFoundError(name)
	}

	// Unmarshal the first result
	var mission Mission
	if err := json.Unmarshal(result.Documents[0].JSON, &mission); err != nil {
		return nil, fmt.Errorf("failed to unmarshal mission: %w", err)
	}

	return &mission, nil
}

// IncrementRunNumber atomically increments and returns the next run number for a mission name.
func (s *RedisMissionStore) IncrementRunNumber(ctx context.Context, name string) (int, error) {
	tenantID := auth.TenantFromContext(ctx)
	counterKey := missionCounterKey(tenantID, name)

	// Use the IncrementAndGetRunNumber script
	runNumber, err := s.client.RunScript(ctx, state.IncrementAndGetRunNumberScript, []string{counterKey})
	if err != nil {
		return 0, fmt.Errorf("failed to increment run number: %w", err)
	}

	// Convert to int
	runNumberInt64, ok := runNumber.(int64)
	if !ok {
		return 0, fmt.Errorf("unexpected script return type: %T", runNumber)
	}

	return int(runNumberInt64), nil
}

// FindOrCreateByName looks up a mission by name, or creates it if it doesn't exist.
// This ensures missions have stable IDs across multiple runs.
// Uses app-level distributed locking to prevent race conditions.
// Returns the mission and a boolean indicating if it was created (true) or found (false).
func (s *RedisMissionStore) FindOrCreateByName(ctx context.Context, mission *Mission) (*Mission, bool, error) {
	if mission == nil {
		return nil, false, fmt.Errorf("mission cannot be nil")
	}

	if mission.Name == "" {
		return nil, false, fmt.Errorf("mission name is required")
	}

	// Generate ID if not set
	if mission.ID.IsZero() {
		mission.ID = types.NewID()
	}

	// Set timestamps
	now := NewUnixTimeNow()
	if mission.CreatedAt.IsZero() {
		mission.CreatedAt = now
	}
	mission.UpdatedAt = now

	// Marshal mission to JSON
	missionJSON, err := json.Marshal(mission)
	if err != nil {
		return nil, false, fmt.Errorf("failed to marshal mission: %w", err)
	}

	// Use FindOrCreateMission with app-level locking (not Lua script)
	// This prevents race conditions that can occur with FT.SEARCH
	result, err := s.client.FindOrCreateMission(ctx, mission.Name, string(missionJSON), mission.ID.String())
	if err != nil {
		return nil, false, fmt.Errorf("failed to find or create mission: %w", err)
	}

	// Parse the returned JSON
	var foundMission Mission
	if err := json.Unmarshal([]byte(result.JSON), &foundMission); err != nil {
		return nil, false, fmt.Errorf("failed to unmarshal mission: %w", err)
	}

	// If mission was created, add to secondary indexes
	if result.Created {
		tenantID := auth.TenantFromContext(ctx)
		pipe := s.client.Pipeline(ctx)

		// Add to by_status set
		statusSetKey := missionByStatusKey(tenantID, foundMission.Status)
		pipe.SAdd(ctx, statusSetKey, foundMission.ID.String())

		// Add to by_target set
		targetSetKey := missionByTargetKey(tenantID, foundMission.TargetID)
		pipe.SAdd(ctx, targetSetKey, foundMission.ID.String())

		// Execute pipeline
		if _, err := pipe.Exec(ctx); err != nil {
			return nil, false, fmt.Errorf("failed to update secondary indexes: %w", err)
		}
	}

	return &foundMission, result.Created, nil
}

// Mission definition methods (Redis-backed)

// missionDefinitionKey returns the Redis key for a mission definition.
// Format: gibson:mission-definitions:{tenant}:{name} or gibson:mission-definitions:{name} (legacy)
func missionDefinitionKey(tenantID, name string) string {
	if tenantID != "" {
		return fmt.Sprintf("gibson:mission-definitions:%s:%s", tenantID, name)
	}
	return fmt.Sprintf("gibson:mission-definitions:%s", name)
}

// missionDefinitionIndexKey returns the Redis set key that indexes all definition names.
// Format: gibson:mission-definitions:{tenant} or gibson:mission-definitions (legacy)
func missionDefinitionIndexKey(tenantID string) string {
	if tenantID != "" {
		return fmt.Sprintf("gibson:mission-definitions:%s", tenantID)
	}
	return "gibson:mission-definitions"
}

// CreateDefinition stores a new mission definition in Redis.
// Returns ErrDefinitionExists if a definition with the same name already exists.
func (s *RedisMissionStore) CreateDefinition(ctx context.Context, def *MissionDefinition) error {
	if s.client == nil {
		return fmt.Errorf("Redis client not configured")
	}

	if def == nil {
		return fmt.Errorf("mission definition cannot be nil")
	}

	if def.Name == "" {
		return fmt.Errorf("mission definition name is required")
	}

	// Set timestamps
	now := time.Now()
	def.InstalledAt = now
	if def.CreatedAt.IsZero() {
		def.CreatedAt = now
	}

	data, err := json.Marshal(def)
	if err != nil {
		return fmt.Errorf("failed to marshal mission definition: %w", err)
	}

	tenantID := auth.TenantFromContext(ctx)
	key := missionDefinitionKey(tenantID, def.Name)

	// SET NX — only set if key does not exist
	ok, err := s.client.Client().SetNX(ctx, key, string(data), 0).Result()
	if err != nil {
		return fmt.Errorf("failed to create mission definition: %w", err)
	}
	if !ok {
		return ErrDefinitionExists
	}

	// Track definition name in the index set
	_ = s.client.Client().SAdd(ctx, missionDefinitionIndexKey(tenantID), def.Name).Err()

	return nil
}

// GetDefinition retrieves a mission definition by name from Redis.
// Returns nil, nil if not found.
// Uses backward-compatible reads: tries tenant-scoped key first, falls back to legacy.
func (s *RedisMissionStore) GetDefinition(ctx context.Context, name string) (*MissionDefinition, error) {
	if s.client == nil {
		return nil, fmt.Errorf("Redis client not configured")
	}

	tenantID := auth.TenantFromContext(ctx)
	key := missionDefinitionKey(tenantID, name)

	data, err := s.client.Client().Get(ctx, key).Result()
	if err == goredis.Nil && tenantID != "" {
		// Fallback to legacy (unscoped) key for backward compatibility
		legacyKey := missionDefinitionKey("", name)
		data, err = s.client.Client().Get(ctx, legacyKey).Result()
	}
	if err == goredis.Nil {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get mission definition: %w", err)
	}

	var def MissionDefinition
	if err := json.Unmarshal([]byte(data), &def); err != nil {
		return nil, fmt.Errorf("failed to unmarshal mission definition: %w", err)
	}

	return &def, nil
}

// ListDefinitions returns all installed mission definitions from Redis.
// Returns an empty slice if no definitions are found.
func (s *RedisMissionStore) ListDefinitions(ctx context.Context) ([]*MissionDefinition, error) {
	if s.client == nil {
		return nil, fmt.Errorf("Redis client not configured")
	}

	tenantID := auth.TenantFromContext(ctx)
	indexKey := missionDefinitionIndexKey(tenantID)

	names, err := s.client.Client().SMembers(ctx, indexKey).Result()
	if err != nil {
		return nil, fmt.Errorf("failed to list mission definitions: %w", err)
	}

	definitions := make([]*MissionDefinition, 0, len(names))
	for _, name := range names {
		def, err := s.GetDefinition(ctx, name)
		if err != nil || def == nil {
			// Stale index entry — remove it
			_ = s.client.Client().SRem(ctx, indexKey, name).Err()
			continue
		}
		definitions = append(definitions, def)
	}

	return definitions, nil
}

// UpdateDefinition updates an existing mission definition in Redis.
// Returns ErrDefinitionNotFound if the definition does not exist.
func (s *RedisMissionStore) UpdateDefinition(ctx context.Context, def *MissionDefinition) error {
	if s.client == nil {
		return fmt.Errorf("Redis client not configured")
	}

	if def == nil {
		return fmt.Errorf("mission definition cannot be nil")
	}

	if def.Name == "" {
		return fmt.Errorf("mission definition name is required")
	}

	// Fetch existing to preserve timestamps (GetDefinition handles fallback)
	existing, err := s.GetDefinition(ctx, def.Name)
	if err != nil {
		return fmt.Errorf("failed to get existing definition: %w", err)
	}
	if existing == nil {
		return ErrDefinitionNotFound
	}

	def.InstalledAt = existing.InstalledAt
	def.CreatedAt = existing.CreatedAt

	data, err := json.Marshal(def)
	if err != nil {
		return fmt.Errorf("failed to marshal mission definition: %w", err)
	}

	// Writes always use tenant-scoped key
	tenantID := auth.TenantFromContext(ctx)
	key := missionDefinitionKey(tenantID, def.Name)

	if err := s.client.Client().Set(ctx, key, string(data), 0).Err(); err != nil {
		return fmt.Errorf("failed to update mission definition: %w", err)
	}

	return nil
}

// DeleteDefinition removes a mission definition from Redis.
// Returns ErrDefinitionNotFound if the definition does not exist.
func (s *RedisMissionStore) DeleteDefinition(ctx context.Context, name string) error {
	if s.client == nil {
		return fmt.Errorf("Redis client not configured")
	}

	tenantID := auth.TenantFromContext(ctx)
	key := missionDefinitionKey(tenantID, name)

	n, err := s.client.Client().Del(ctx, key).Result()
	if err != nil {
		return fmt.Errorf("failed to delete mission definition: %w", err)
	}
	if n == 0 {
		return ErrDefinitionNotFound
	}

	_ = s.client.Client().SRem(ctx, missionDefinitionIndexKey(tenantID), name).Err()

	return nil
}

// Ensure RedisMissionStore implements MissionStore at compile time.
var _ MissionStore = (*RedisMissionStore)(nil)
