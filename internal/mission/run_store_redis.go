package mission

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/zero-day-ai/gibson/internal/state"
	"github.com/zero-day-ai/gibson/internal/types"
)

// RedisMissionRunStore implements MissionRunStore using Redis with RedisJSON.
// It provides high-performance, scalable mission run storage with sorted set indexing.
//
// Data Structure:
//   - Run documents: gibson:mission_run:{id} (RedisJSON)
//   - Runs by mission: gibson:mission:{mission_id}:runs (sorted set, score = run_number)
//
// The sorted set enables efficient queries:
//   - Get latest run: ZREVRANGE with LIMIT 0 1
//   - Get run by number: ZSCORE to find ID, then JSON.GET
//   - List all runs: ZRANGE to get IDs, then JSON.MGET
type RedisMissionRunStore struct {
	client *state.StateClient
}

// NewRedisMissionRunStore creates a new Redis-backed mission run store.
func NewRedisMissionRunStore(client *state.StateClient) *RedisMissionRunStore {
	return &RedisMissionRunStore{
		client: client,
	}
}

// runKey returns the Redis key for a mission run document.
// Format: gibson:mission_run:{id}
func runKey(id types.ID) string {
	return fmt.Sprintf("gibson:mission_run:%s", id)
}

// runsByMissionKey returns the Redis key for mission runs sorted set.
// Format: gibson:mission:{mission_id}:runs
func runsByMissionKey(missionID types.ID) string {
	return fmt.Sprintf("gibson:mission:%s:runs", missionID)
}

// Save persists a new mission run to Redis.
// It stores the run document using JSON.SET and adds it to the sorted set with run_number as score.
func (s *RedisMissionRunStore) Save(ctx context.Context, run *MissionRun) error {
	if run == nil {
		return fmt.Errorf("mission run cannot be nil")
	}

	if err := run.Validate(); err != nil {
		return fmt.Errorf("validation failed: %w", err)
	}

	// Set timestamps
	now := time.Now()
	if run.CreatedAt.IsZero() {
		run.CreatedAt = now
	}
	run.UpdatedAt = now

	rdb := s.client.Client()
	pipe := rdb.Pipeline()

	// Store run document using JSON.SET
	key := runKey(run.ID)
	data, err := json.Marshal(run)
	if err != nil {
		return fmt.Errorf("failed to marshal run: %w", err)
	}

	pipe.Do(ctx, "JSON.SET", key, "$", string(data))

	// Add to sorted set (score = run_number, member = run_id)
	// Use NX flag to ensure we don't overwrite existing scores
	sortedSetKey := runsByMissionKey(run.MissionID)
	pipe.ZAddNX(ctx, sortedSetKey, redis.Z{
		Score:  float64(run.RunNumber),
		Member: run.ID.String(),
	})

	// Execute pipeline
	if _, err := pipe.Exec(ctx); err != nil {
		return fmt.Errorf("failed to save mission run: %w", err)
	}

	return nil
}

// Get retrieves a mission run by ID.
func (s *RedisMissionRunStore) Get(ctx context.Context, id types.ID) (*MissionRun, error) {
	key := runKey(id)

	var run MissionRun
	if err := s.client.JSONGet(ctx, key, "$", &run); err != nil {
		if state.IsNotFound(err) {
			return nil, NewNotFoundError(id.String())
		}
		return nil, fmt.Errorf("failed to get mission run: %w", err)
	}

	return &run, nil
}

// GetByMissionAndNumber retrieves a run by mission ID and run number.
// It uses ZSCORE to find the run ID in the sorted set, then fetches the document.
func (s *RedisMissionRunStore) GetByMissionAndNumber(ctx context.Context, missionID types.ID, runNumber int) (*MissionRun, error) {
	rdb := s.client.Client()
	sortedSetKey := runsByMissionKey(missionID)

	// Use ZRANGEBYSCORE to find the run with exact score
	// Score is the run_number, so we search for [runNumber, runNumber]
	members, err := rdb.ZRangeByScore(ctx, sortedSetKey, &redis.ZRangeBy{
		Min:    fmt.Sprintf("%d", runNumber),
		Max:    fmt.Sprintf("%d", runNumber),
		Offset: 0,
		Count:  1,
	}).Result()

	if err != nil {
		return nil, fmt.Errorf("failed to find run by number: %w", err)
	}

	if len(members) == 0 {
		return nil, NewNotFoundError(fmt.Sprintf("mission %s run %d", missionID, runNumber))
	}

	// Parse the run ID and fetch the document
	runID, err := types.ParseID(members[0])
	if err != nil {
		return nil, fmt.Errorf("failed to parse run ID: %w", err)
	}

	return s.Get(ctx, runID)
}

// ListByMission retrieves all runs for a mission, ordered by run number descending.
// It uses ZREVRANGE to get run IDs in reverse score order, then batch fetches with JSON.MGET.
func (s *RedisMissionRunStore) ListByMission(ctx context.Context, missionID types.ID) ([]*MissionRun, error) {
	rdb := s.client.Client()
	sortedSetKey := runsByMissionKey(missionID)

	// Get all run IDs ordered by run_number descending (ZREVRANGE)
	runIDs, err := rdb.ZRevRange(ctx, sortedSetKey, 0, -1).Result()
	if err != nil {
		return nil, fmt.Errorf("failed to list run IDs: %w", err)
	}

	if len(runIDs) == 0 {
		return []*MissionRun{}, nil
	}

	// Build keys for JSON.MGET
	keys := make([]string, len(runIDs))
	for i, idStr := range runIDs {
		id, err := types.ParseID(idStr)
		if err != nil {
			return nil, fmt.Errorf("failed to parse run ID %q: %w", idStr, err)
		}
		keys[i] = runKey(id)
	}

	// Batch fetch all runs using JSON.MGET
	results, err := s.client.JSONMGet(ctx, keys, "$")
	if err != nil {
		return nil, fmt.Errorf("failed to batch get runs: %w", err)
	}

	// Unmarshal results
	runs := make([]*MissionRun, 0, len(results))
	for i, raw := range results {
		if raw == nil {
			// Run was deleted, skip it
			continue
		}

		var run MissionRun
		if err := json.Unmarshal(raw, &run); err != nil {
			return nil, fmt.Errorf("failed to unmarshal run at index %d: %w", i, err)
		}
		runs = append(runs, &run)
	}

	return runs, nil
}

// GetLatestByMission retrieves the most recent run for a mission.
// It uses ZREVRANGE with LIMIT 0 1 to get the highest run_number.
func (s *RedisMissionRunStore) GetLatestByMission(ctx context.Context, missionID types.ID) (*MissionRun, error) {
	rdb := s.client.Client()
	sortedSetKey := runsByMissionKey(missionID)

	// Get the highest scored member (latest run_number)
	runIDs, err := rdb.ZRevRange(ctx, sortedSetKey, 0, 0).Result()
	if err != nil {
		return nil, fmt.Errorf("failed to get latest run: %w", err)
	}

	if len(runIDs) == 0 {
		return nil, nil // No runs yet is not an error
	}

	// Parse and fetch the run
	runID, err := types.ParseID(runIDs[0])
	if err != nil {
		return nil, fmt.Errorf("failed to parse run ID: %w", err)
	}

	return s.Get(ctx, runID)
}

// GetNextRunNumber returns the next run number for a mission.
// It queries the sorted set for the maximum score (run_number) and adds 1.
func (s *RedisMissionRunStore) GetNextRunNumber(ctx context.Context, missionID types.ID) (int, error) {
	rdb := s.client.Client()
	sortedSetKey := runsByMissionKey(missionID)

	// Get the highest scored member with ZREVRANGE WITHSCORES
	results, err := rdb.ZRevRangeWithScores(ctx, sortedSetKey, 0, 0).Result()
	if err != nil {
		return 0, fmt.Errorf("failed to get max run number: %w", err)
	}

	if len(results) == 0 {
		return 1, nil // First run
	}

	// The score is the run_number
	maxRunNumber := int(results[0].Score)
	return maxRunNumber + 1, nil
}

// Update modifies an existing mission run.
// It updates the entire document using JSON.SET.
func (s *RedisMissionRunStore) Update(ctx context.Context, run *MissionRun) error {
	if run == nil {
		return fmt.Errorf("mission run cannot be nil")
	}

	if err := run.Validate(); err != nil {
		return fmt.Errorf("validation failed: %w", err)
	}

	// Update timestamp
	run.UpdatedAt = time.Now()

	// Check if run exists
	key := runKey(run.ID)
	rdb := s.client.Client()
	exists, err := rdb.Exists(ctx, key).Result()
	if err != nil {
		return fmt.Errorf("failed to check run existence: %w", err)
	}

	if exists == 0 {
		return NewNotFoundError(run.ID.String())
	}

	// Update document using JSON.SET
	if err := s.client.JSONSet(ctx, key, "$", run); err != nil {
		return fmt.Errorf("failed to update mission run: %w", err)
	}

	return nil
}

// UpdateStatus updates only the status field.
// It uses JSON.SET with a path to update just the status field atomically.
func (s *RedisMissionRunStore) UpdateStatus(ctx context.Context, id types.ID, status MissionRunStatus) error {
	// Check if run exists first
	run, err := s.Get(ctx, id)
	if err != nil {
		return err
	}

	// Update status and timestamp
	now := time.Now()
	key := runKey(id)
	rdb := s.client.Client()

	pipe := rdb.Pipeline()

	// Update status field
	statusJSON, err := json.Marshal(string(status))
	if err != nil {
		return fmt.Errorf("failed to marshal status: %w", err)
	}
	pipe.Do(ctx, "JSON.SET", key, "$.status", string(statusJSON))

	// Update updated_at field
	updatedAtJSON, err := json.Marshal(now)
	if err != nil {
		return fmt.Errorf("failed to marshal updated_at: %w", err)
	}
	pipe.Do(ctx, "JSON.SET", key, "$.updated_at", string(updatedAtJSON))

	// Also update started_at/completed_at if status transitions to terminal states
	switch status {
	case MissionRunStatusRunning:
		if run.StartedAt == nil {
			startedAtJSON, err := json.Marshal(now)
			if err != nil {
				return fmt.Errorf("failed to marshal started_at: %w", err)
			}
			pipe.Do(ctx, "JSON.SET", key, "$.started_at", string(startedAtJSON))
		}
	case MissionRunStatusCompleted, MissionRunStatusFailed, MissionRunStatusCancelled:
		if run.CompletedAt == nil {
			completedAtJSON, err := json.Marshal(now)
			if err != nil {
				return fmt.Errorf("failed to marshal completed_at: %w", err)
			}
			pipe.Do(ctx, "JSON.SET", key, "$.completed_at", string(completedAtJSON))
		}
	}

	if _, err := pipe.Exec(ctx); err != nil {
		return fmt.Errorf("failed to update status: %w", err)
	}

	return nil
}

// UpdateProgress updates only the progress field.
func (s *RedisMissionRunStore) UpdateProgress(ctx context.Context, id types.ID, progress float64) error {
	if progress < 0 || progress > 1 {
		return fmt.Errorf("progress must be between 0.0 and 1.0, got %f", progress)
	}

	// Check if run exists
	key := runKey(id)
	rdb := s.client.Client()
	exists, err := rdb.Exists(ctx, key).Result()
	if err != nil {
		return fmt.Errorf("failed to check run existence: %w", err)
	}

	if exists == 0 {
		return NewNotFoundError(id.String())
	}

	now := time.Now()
	pipe := rdb.Pipeline()

	// Update progress field
	progressJSON, err := json.Marshal(progress)
	if err != nil {
		return fmt.Errorf("failed to marshal progress: %w", err)
	}
	pipe.Do(ctx, "JSON.SET", key, "$.progress", string(progressJSON))

	// Update updated_at field
	updatedAtJSON, err := json.Marshal(now)
	if err != nil {
		return fmt.Errorf("failed to marshal updated_at: %w", err)
	}
	pipe.Do(ctx, "JSON.SET", key, "$.updated_at", string(updatedAtJSON))

	if _, err := pipe.Exec(ctx); err != nil {
		return fmt.Errorf("failed to update progress: %w", err)
	}

	return nil
}

// GetActive retrieves all active runs (running or paused).
// This requires scanning all run documents since we don't have a status index yet.
// For production use, consider adding a RediSearch index on status field.
func (s *RedisMissionRunStore) GetActive(ctx context.Context) ([]*MissionRun, error) {
	rdb := s.client.Client()

	// Use SCAN to find all mission run keys
	// Pattern: gibson:mission_run:*
	var cursor uint64
	var allRuns []*MissionRun

	for {
		var keys []string
		var err error

		keys, cursor, err = rdb.Scan(ctx, cursor, "gibson:mission_run:*", 100).Result()
		if err != nil {
			return nil, fmt.Errorf("failed to scan run keys: %w", err)
		}

		if len(keys) > 0 {
			// Batch fetch runs
			results, err := s.client.JSONMGet(ctx, keys, "$")
			if err != nil {
				return nil, fmt.Errorf("failed to batch get runs: %w", err)
			}

			// Filter for active runs
			for _, raw := range results {
				if raw == nil {
					continue
				}

				var run MissionRun
				if err := json.Unmarshal(raw, &run); err != nil {
					continue // Skip invalid runs
				}

				if run.Status == MissionRunStatusRunning || run.Status == MissionRunStatusPaused {
					allRuns = append(allRuns, &run)
				}
			}
		}

		if cursor == 0 {
			break
		}
	}

	return allRuns, nil
}

// Delete removes a mission run (only terminal states).
// It deletes the document and removes the entry from the sorted set.
func (s *RedisMissionRunStore) Delete(ctx context.Context, id types.ID) error {
	// First check if run exists and is in terminal state
	run, err := s.Get(ctx, id)
	if err != nil {
		return err
	}

	if !run.Status.IsTerminal() {
		return fmt.Errorf("cannot delete run in non-terminal status: %s", run.Status)
	}

	rdb := s.client.Client()
	pipe := rdb.Pipeline()

	// Delete the document
	key := runKey(id)
	pipe.Do(ctx, "JSON.DEL", key, "$")

	// Remove from sorted set
	sortedSetKey := runsByMissionKey(run.MissionID)
	pipe.ZRem(ctx, sortedSetKey, id.String())

	// Execute pipeline
	if _, err := pipe.Exec(ctx); err != nil {
		return fmt.Errorf("failed to delete mission run: %w", err)
	}

	return nil
}

// CountByMission returns the number of runs for a mission.
func (s *RedisMissionRunStore) CountByMission(ctx context.Context, missionID types.ID) (int, error) {
	rdb := s.client.Client()
	sortedSetKey := runsByMissionKey(missionID)

	count, err := rdb.ZCard(ctx, sortedSetKey).Result()
	if err != nil {
		return 0, fmt.Errorf("failed to count runs: %w", err)
	}

	return int(count), nil
}

// Ensure RedisMissionRunStore implements MissionRunStore at compile time.
var _ MissionRunStore = (*RedisMissionRunStore)(nil)
