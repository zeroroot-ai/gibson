// Package mission — run_store_conn.go
//
// ConnBoundRunStore implements MissionRunStore using a tenant-bound *redis.Client.
// No key prefixes are used; tenant isolation is structural (audit C7 closure).
package mission

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	goredis "github.com/redis/go-redis/v9"
	"github.com/zeroroot-ai/gibson/internal/infra/types"
)

// ConnBoundRunStore implements MissionRunStore against a tenant-bound Redis client.
// Keys carry no tenant prefix; isolation is provided by the per-tenant logical DB.
type ConnBoundRunStore struct {
	rdb *goredis.Client
}

// NewConnBoundRunStore creates a MissionRunStore backed by the given tenant-bound client.
func NewConnBoundRunStore(rdb *goredis.Client) *ConnBoundRunStore {
	return &ConnBoundRunStore{rdb: rdb}
}

// connRunKey returns the Redis key for a run document.
func connRunKey(id types.ID) string {
	return fmt.Sprintf("gibson:mission_run:%s", id)
}

// connRunsByMissionKey returns the sorted-set key for a mission's runs.
func connRunsByMissionKey(missionID types.ID) string {
	return fmt.Sprintf("gibson:mission:%s:runs", missionID)
}

// Save persists a new mission run.
func (s *ConnBoundRunStore) Save(ctx context.Context, run *MissionRun) error {
	if run == nil {
		return fmt.Errorf("mission run cannot be nil")
	}
	if err := run.Validate(); err != nil {
		return fmt.Errorf("validation failed: %w", err)
	}
	now := time.Now()
	if run.CreatedAt.IsZero() {
		run.CreatedAt = now
	}
	run.UpdatedAt = now

	data, err := json.Marshal(run)
	if err != nil {
		return fmt.Errorf("failed to marshal run: %w", err)
	}

	pipe := s.rdb.Pipeline()
	pipe.Do(ctx, "JSON.SET", connRunKey(run.ID), "$", string(data))
	pipe.ZAddNX(ctx, connRunsByMissionKey(run.MissionID), goredis.Z{
		Score:  float64(run.RunNumber),
		Member: run.ID.String(),
	})
	if _, err := pipe.Exec(ctx); err != nil {
		return fmt.Errorf("failed to save mission run: %w", err)
	}
	return nil
}

// Get retrieves a mission run by ID.
func (s *ConnBoundRunStore) Get(ctx context.Context, id types.ID) (*MissionRun, error) {
	result, err := s.rdb.Do(ctx, "JSON.GET", connRunKey(id), "$").Result()
	if err == goredis.Nil || result == nil {
		return nil, NewNotFoundError(id.String())
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get mission run: %w", err)
	}
	return unmarshalRunJSON(result)
}

// GetByMissionAndNumber retrieves a run by mission ID and run number.
func (s *ConnBoundRunStore) GetByMissionAndNumber(ctx context.Context, missionID types.ID, runNumber int) (*MissionRun, error) {
	members, err := s.rdb.ZRangeByScore(ctx, connRunsByMissionKey(missionID), &goredis.ZRangeBy{
		Min:   fmt.Sprintf("%d", runNumber),
		Max:   fmt.Sprintf("%d", runNumber),
		Count: 1,
	}).Result()
	if err != nil {
		return nil, fmt.Errorf("failed to find run by number: %w", err)
	}
	if len(members) == 0 {
		return nil, NewNotFoundError(fmt.Sprintf("mission %s run %d", missionID, runNumber))
	}
	runID, err := types.ParseID(members[0])
	if err != nil {
		return nil, fmt.Errorf("failed to parse run ID: %w", err)
	}
	return s.Get(ctx, runID)
}

// ListByMission retrieves all runs for a mission ordered by run number descending.
func (s *ConnBoundRunStore) ListByMission(ctx context.Context, missionID types.ID) ([]*MissionRun, error) {
	runIDs, err := s.rdb.ZRevRange(ctx, connRunsByMissionKey(missionID), 0, -1).Result()
	if err != nil {
		return nil, fmt.Errorf("failed to list run IDs: %w", err)
	}
	if len(runIDs) == 0 {
		return []*MissionRun{}, nil
	}
	runs := make([]*MissionRun, 0, len(runIDs))
	for _, idStr := range runIDs {
		id, err := types.ParseID(idStr)
		if err != nil {
			continue
		}
		run, err := s.Get(ctx, id)
		if err != nil {
			continue
		}
		runs = append(runs, run)
	}
	return runs, nil
}

// GetLatestByMission retrieves the most recent run for a mission.
func (s *ConnBoundRunStore) GetLatestByMission(ctx context.Context, missionID types.ID) (*MissionRun, error) {
	runIDs, err := s.rdb.ZRevRange(ctx, connRunsByMissionKey(missionID), 0, 0).Result()
	if err != nil {
		return nil, fmt.Errorf("failed to get latest run: %w", err)
	}
	if len(runIDs) == 0 {
		return nil, nil
	}
	runID, err := types.ParseID(runIDs[0])
	if err != nil {
		return nil, fmt.Errorf("failed to parse run ID: %w", err)
	}
	return s.Get(ctx, runID)
}

// GetNextRunNumber returns the next run number for a mission.
func (s *ConnBoundRunStore) GetNextRunNumber(ctx context.Context, missionID types.ID) (int, error) {
	results, err := s.rdb.ZRevRangeWithScores(ctx, connRunsByMissionKey(missionID), 0, 0).Result()
	if err != nil {
		return 0, fmt.Errorf("failed to get max run number: %w", err)
	}
	if len(results) == 0 {
		return 1, nil
	}
	return int(results[0].Score) + 1, nil
}

// Update modifies an existing mission run.
func (s *ConnBoundRunStore) Update(ctx context.Context, run *MissionRun) error {
	if run == nil {
		return fmt.Errorf("mission run cannot be nil")
	}
	if err := run.Validate(); err != nil {
		return fmt.Errorf("validation failed: %w", err)
	}
	run.UpdatedAt = time.Now()

	exists, err := s.rdb.Exists(ctx, connRunKey(run.ID)).Result()
	if err != nil {
		return fmt.Errorf("failed to check run existence: %w", err)
	}
	if exists == 0 {
		return NewNotFoundError(run.ID.String())
	}

	data, err := json.Marshal(run)
	if err != nil {
		return fmt.Errorf("failed to marshal run: %w", err)
	}
	if err := s.rdb.Do(ctx, "JSON.SET", connRunKey(run.ID), "$", string(data)).Err(); err != nil {
		return fmt.Errorf("failed to update mission run: %w", err)
	}
	return nil
}

// UpdateStatus updates only the status field.
func (s *ConnBoundRunStore) UpdateStatus(ctx context.Context, id types.ID, status MissionRunStatus) error {
	run, err := s.Get(ctx, id)
	if err != nil {
		return err
	}

	now := time.Now()
	pipe := s.rdb.Pipeline()
	statusJSON, _ := json.Marshal(string(status))
	nowJSON, _ := json.Marshal(now)
	pipe.Do(ctx, "JSON.SET", connRunKey(id), "$.status", string(statusJSON))
	pipe.Do(ctx, "JSON.SET", connRunKey(id), "$.updated_at", string(nowJSON))

	switch status {
	case MissionRunStatusRunning:
		if run.StartedAt == nil {
			pipe.Do(ctx, "JSON.SET", connRunKey(id), "$.started_at", string(nowJSON))
		}
	case MissionRunStatusCompleted, MissionRunStatusFailed, MissionRunStatusCancelled:
		if run.CompletedAt == nil {
			pipe.Do(ctx, "JSON.SET", connRunKey(id), "$.completed_at", string(nowJSON))
		}
	}

	if _, err := pipe.Exec(ctx); err != nil {
		return fmt.Errorf("failed to update status: %w", err)
	}
	return nil
}

// UpdateProgress updates only the progress field.
func (s *ConnBoundRunStore) UpdateProgress(ctx context.Context, id types.ID, progress float64) error {
	if progress < 0 || progress > 1 {
		return fmt.Errorf("progress must be between 0.0 and 1.0, got %f", progress)
	}
	exists, err := s.rdb.Exists(ctx, connRunKey(id)).Result()
	if err != nil {
		return fmt.Errorf("failed to check run existence: %w", err)
	}
	if exists == 0 {
		return NewNotFoundError(id.String())
	}
	now := time.Now()
	pipe := s.rdb.Pipeline()
	progressJSON, _ := json.Marshal(progress)
	nowJSON, _ := json.Marshal(now)
	pipe.Do(ctx, "JSON.SET", connRunKey(id), "$.progress", string(progressJSON))
	pipe.Do(ctx, "JSON.SET", connRunKey(id), "$.updated_at", string(nowJSON))
	if _, err := pipe.Exec(ctx); err != nil {
		return fmt.Errorf("failed to update progress: %w", err)
	}
	return nil
}

// GetActive retrieves all active runs (running or paused).
func (s *ConnBoundRunStore) GetActive(ctx context.Context) ([]*MissionRun, error) {
	var cursor uint64
	var allRuns []*MissionRun
	for {
		var keys []string
		var err error
		keys, cursor, err = s.rdb.Scan(ctx, cursor, "gibson:mission_run:*", 100).Result()
		if err != nil {
			return nil, fmt.Errorf("failed to scan run keys: %w", err)
		}
		for _, key := range keys {
			result, err := s.rdb.Do(ctx, "JSON.GET", key, "$").Result()
			if err != nil || result == nil {
				continue
			}
			run, err := unmarshalRunJSON(result)
			if err != nil {
				continue
			}
			if run.Status == MissionRunStatusRunning || run.Status == MissionRunStatusPaused {
				allRuns = append(allRuns, run)
			}
		}
		if cursor == 0 {
			break
		}
	}
	return allRuns, nil
}

// Delete removes a mission run (only terminal states).
func (s *ConnBoundRunStore) Delete(ctx context.Context, id types.ID) error {
	run, err := s.Get(ctx, id)
	if err != nil {
		return err
	}
	if !run.Status.IsTerminal() {
		return fmt.Errorf("cannot delete run in non-terminal status: %s", run.Status)
	}
	pipe := s.rdb.Pipeline()
	pipe.Do(ctx, "JSON.DEL", connRunKey(id), "$")
	pipe.ZRem(ctx, connRunsByMissionKey(run.MissionID), id.String())
	if _, err := pipe.Exec(ctx); err != nil {
		return fmt.Errorf("failed to delete mission run: %w", err)
	}
	return nil
}

// CountByMission returns the number of runs for a mission.
func (s *ConnBoundRunStore) CountByMission(ctx context.Context, missionID types.ID) (int, error) {
	n, err := s.rdb.ZCard(ctx, connRunsByMissionKey(missionID)).Result()
	if err != nil {
		return 0, fmt.Errorf("failed to count runs: %w", err)
	}
	return int(n), nil
}

// unmarshalRunJSON unwraps the JSON.GET "$" array envelope and unmarshals a MissionRun.
func unmarshalRunJSON(result any) (*MissionRun, error) {
	raw, ok := result.(string)
	if !ok {
		return nil, fmt.Errorf("unexpected JSON result type %T", result)
	}
	var docs []json.RawMessage
	if err := json.Unmarshal([]byte(raw), &docs); err == nil && len(docs) > 0 {
		var run MissionRun
		if err := json.Unmarshal(docs[0], &run); err != nil {
			return nil, fmt.Errorf("failed to unmarshal run: %w", err)
		}
		return &run, nil
	}
	var run MissionRun
	if err := json.Unmarshal([]byte(raw), &run); err != nil {
		return nil, fmt.Errorf("failed to unmarshal run: %w", err)
	}
	return &run, nil
}

// Ensure ConnBoundRunStore implements MissionRunStore at compile time.
var _ MissionRunStore = (*ConnBoundRunStore)(nil)
