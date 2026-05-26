package datapool

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	goredis "github.com/redis/go-redis/v9"
	"github.com/zeroroot-ai/gibson/internal/types"
)

// Missions returns a MissionOps bundle bound to this Conn's tenant-bound Redis client.
// The returned ops struct is valid only while the Conn is held (before Release is called).
// All Redis keys produced by MissionOps carry no tenant prefix; isolation is provided
// structurally by the tenant-bound client routing to the tenant's dedicated logical DB.
func (c *Conn) Missions() *MissionOps {
	return &MissionOps{rdb: c.Redis}
}

// MissionOps provides mission and mission-run/event store operations bound to a
// single tenant's Redis logical DB. Keys carry no tenant prefix — the per-tenant
// client is the isolation boundary (audit C6 closure).
type MissionOps struct {
	rdb *goredis.Client
}

// ---------------------------------------------------------------------------
// Mission definition key helpers (no tenant prefix — C6 closure)
// ---------------------------------------------------------------------------

func missionDefKey(name string) string {
	return fmt.Sprintf("gibson:mission-definitions:%s", name)
}

func missionDefIndexKey() string {
	return "gibson:mission-definitions"
}

// ---------------------------------------------------------------------------
// Mission run key helpers
// ---------------------------------------------------------------------------

func missionRunKey(id types.ID) string {
	return fmt.Sprintf("gibson:mission_run:%s", id)
}

func runsByMissionKey(missionID types.ID) string {
	return fmt.Sprintf("gibson:mission:%s:runs", missionID)
}

// ---------------------------------------------------------------------------
// Mission event stream key helpers
// ---------------------------------------------------------------------------

func missionEventsStreamKey(missionID types.ID) string {
	return fmt.Sprintf("gibson:stream:mission:%s:events", missionID)
}

// ---------------------------------------------------------------------------
// MissionDefinition operations
// ---------------------------------------------------------------------------

// MissionDefinition is a lightweight copy of the mission.MissionDefinition shape
// used by MissionOps to avoid a circular import. Callers in the mission package
// marshal/unmarshal their own type through JSON.
type MissionDefinition struct {
	Name        string    `json:"name"`
	InstalledAt time.Time `json:"installed_at"`
	CreatedAt   time.Time `json:"created_at"`
}

// CreateDefinition stores a mission definition. Returns an error if the name already exists.
func (m *MissionOps) CreateDefinition(ctx context.Context, name string, data []byte) error {
	key := missionDefKey(name)
	ok, err := m.rdb.SetNX(ctx, key, string(data), 0).Result()
	if err != nil {
		return fmt.Errorf("mission ops: create definition: %w", err)
	}
	if !ok {
		return fmt.Errorf("mission ops: definition %q already exists", name)
	}
	_ = m.rdb.SAdd(ctx, missionDefIndexKey(), name).Err()
	return nil
}

// GetDefinition retrieves a mission definition by name. Returns nil bytes when not found.
func (m *MissionOps) GetDefinition(ctx context.Context, name string) ([]byte, error) {
	data, err := m.rdb.Get(ctx, missionDefKey(name)).Result()
	if err == goredis.Nil {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("mission ops: get definition: %w", err)
	}
	return []byte(data), nil
}

// ListDefinitionNames returns all definition names in the index set.
func (m *MissionOps) ListDefinitionNames(ctx context.Context) ([]string, error) {
	names, err := m.rdb.SMembers(ctx, missionDefIndexKey()).Result()
	if err != nil {
		return nil, fmt.Errorf("mission ops: list definitions: %w", err)
	}
	return names, nil
}

// UpdateDefinition overwrites an existing definition; returns an error if missing.
func (m *MissionOps) UpdateDefinition(ctx context.Context, name string, data []byte) error {
	key := missionDefKey(name)
	exists, err := m.rdb.Exists(ctx, key).Result()
	if err != nil {
		return fmt.Errorf("mission ops: check definition: %w", err)
	}
	if exists == 0 {
		return fmt.Errorf("mission ops: definition %q not found", name)
	}
	if err := m.rdb.Set(ctx, key, string(data), 0).Err(); err != nil {
		return fmt.Errorf("mission ops: update definition: %w", err)
	}
	return nil
}

// DeleteDefinition removes a definition; returns an error if missing.
func (m *MissionOps) DeleteDefinition(ctx context.Context, name string) error {
	n, err := m.rdb.Del(ctx, missionDefKey(name)).Result()
	if err != nil {
		return fmt.Errorf("mission ops: delete definition: %w", err)
	}
	if n == 0 {
		return fmt.Errorf("mission ops: definition %q not found", name)
	}
	_ = m.rdb.SRem(ctx, missionDefIndexKey(), name).Err()
	return nil
}

// ---------------------------------------------------------------------------
// Mission run operations
// ---------------------------------------------------------------------------

// SaveRun persists a mission run JSON document and registers it in the sorted set.
func (m *MissionOps) SaveRun(ctx context.Context, runID, missionID types.ID, runNumber int, data []byte) error {
	pipe := m.rdb.Pipeline()
	key := missionRunKey(runID)
	pipe.Do(ctx, "JSON.SET", key, "$", string(data))
	pipe.ZAddNX(ctx, runsByMissionKey(missionID), goredis.Z{
		Score:  float64(runNumber),
		Member: runID.String(),
	})
	if _, err := pipe.Exec(ctx); err != nil {
		return fmt.Errorf("mission ops: save run: %w", err)
	}
	return nil
}

// GetRun retrieves a mission run JSON document by ID.
func (m *MissionOps) GetRun(ctx context.Context, id types.ID) ([]byte, error) {
	result, err := m.rdb.Do(ctx, "JSON.GET", missionRunKey(id), "$").Result()
	if err == goredis.Nil || result == nil {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("mission ops: get run: %w", err)
	}
	// JSON.GET returns a string in array form: `[{...}]`; unwrap the outer array.
	raw, ok := result.(string)
	if !ok {
		return nil, fmt.Errorf("mission ops: unexpected JSON.GET result type %T", result)
	}
	var docs []json.RawMessage
	if err := json.Unmarshal([]byte(raw), &docs); err != nil || len(docs) == 0 {
		return []byte(raw), nil
	}
	return docs[0], nil
}

// UpdateRun overwrites the run JSON document atomically.
func (m *MissionOps) UpdateRun(ctx context.Context, id types.ID, data []byte) error {
	if err := m.rdb.Do(ctx, "JSON.SET", missionRunKey(id), "$", string(data)).Err(); err != nil {
		return fmt.Errorf("mission ops: update run: %w", err)
	}
	return nil
}

// ListRunIDsByMission returns all run IDs for a mission ordered by run number descending.
func (m *MissionOps) ListRunIDsByMission(ctx context.Context, missionID types.ID) ([]string, error) {
	ids, err := m.rdb.ZRevRange(ctx, runsByMissionKey(missionID), 0, -1).Result()
	if err != nil {
		return nil, fmt.Errorf("mission ops: list runs by mission: %w", err)
	}
	return ids, nil
}

// GetLatestRunIDByMission returns the ID of the most recent run for a mission.
func (m *MissionOps) GetLatestRunIDByMission(ctx context.Context, missionID types.ID) (string, error) {
	ids, err := m.rdb.ZRevRange(ctx, runsByMissionKey(missionID), 0, 0).Result()
	if err != nil {
		return "", fmt.Errorf("mission ops: get latest run: %w", err)
	}
	if len(ids) == 0 {
		return "", nil
	}
	return ids[0], nil
}

// GetRunIDByMissionAndNumber looks up the run ID for a specific run number.
func (m *MissionOps) GetRunIDByMissionAndNumber(ctx context.Context, missionID types.ID, runNumber int) (string, error) {
	members, err := m.rdb.ZRangeByScore(ctx, runsByMissionKey(missionID), &goredis.ZRangeBy{
		Min:   fmt.Sprintf("%d", runNumber),
		Max:   fmt.Sprintf("%d", runNumber),
		Count: 1,
	}).Result()
	if err != nil {
		return "", fmt.Errorf("mission ops: get run by number: %w", err)
	}
	if len(members) == 0 {
		return "", nil
	}
	return members[0], nil
}

// GetMaxRunNumber returns the highest run number for a mission (or 0 if none).
func (m *MissionOps) GetMaxRunNumber(ctx context.Context, missionID types.ID) (int, error) {
	results, err := m.rdb.ZRevRangeWithScores(ctx, runsByMissionKey(missionID), 0, 0).Result()
	if err != nil {
		return 0, fmt.Errorf("mission ops: get max run number: %w", err)
	}
	if len(results) == 0 {
		return 0, nil
	}
	return int(results[0].Score), nil
}

// DeleteRun removes a run document and its sorted-set entry.
func (m *MissionOps) DeleteRun(ctx context.Context, id, missionID types.ID) error {
	pipe := m.rdb.Pipeline()
	pipe.Do(ctx, "JSON.DEL", missionRunKey(id), "$")
	pipe.ZRem(ctx, runsByMissionKey(missionID), id.String())
	if _, err := pipe.Exec(ctx); err != nil {
		return fmt.Errorf("mission ops: delete run: %w", err)
	}
	return nil
}

// CountRunsByMission returns the number of runs for a mission.
func (m *MissionOps) CountRunsByMission(ctx context.Context, missionID types.ID) (int, error) {
	n, err := m.rdb.ZCard(ctx, runsByMissionKey(missionID)).Result()
	if err != nil {
		return 0, fmt.Errorf("mission ops: count runs: %w", err)
	}
	return int(n), nil
}

// ---------------------------------------------------------------------------
// Event stream operations
// ---------------------------------------------------------------------------

// AppendEvent adds an event to the mission's Redis Stream.
func (m *MissionOps) AppendEvent(ctx context.Context, missionID types.ID, values map[string]any) error {
	if _, err := m.rdb.XAdd(ctx, &goredis.XAddArgs{
		Stream: missionEventsStreamKey(missionID),
		Values: values,
	}).Result(); err != nil {
		return fmt.Errorf("mission ops: append event: %w", err)
	}
	return nil
}

// ReadEventsRange reads events from start to end IDs (use "-" and "+" for all).
func (m *MissionOps) ReadEventsRange(ctx context.Context, missionID types.ID, start, end string, count int64) ([]goredis.XMessage, error) {
	msgs, err := m.rdb.XRange(ctx, missionEventsStreamKey(missionID), start, end).Result()
	if err != nil {
		return nil, fmt.Errorf("mission ops: read events range: %w", err)
	}
	return msgs, nil
}

// SubscribeEvents returns a channel delivering new event messages added after fromID.
// The channel closes when ctx is cancelled.
func (m *MissionOps) SubscribeEvents(ctx context.Context, missionID types.ID, fromID string) <-chan goredis.XMessage {
	ch := make(chan goredis.XMessage, 64)
	if fromID == "" {
		fromID = "$"
	}
	go func() {
		defer close(ch)
		lastID := fromID
		for {
			select {
			case <-ctx.Done():
				return
			default:
			}
			msgs, err := m.rdb.XRead(ctx, &goredis.XReadArgs{
				Streams: []string{missionEventsStreamKey(missionID), lastID},
				Count:   100,
				Block:   500 * time.Millisecond,
			}).Result()
			if err != nil {
				if ctx.Err() != nil {
					return
				}
				continue
			}
			for _, stream := range msgs {
				for _, msg := range stream.Messages {
					select {
					case ch <- msg:
					case <-ctx.Done():
						return
					}
					lastID = msg.ID
				}
			}
		}
	}()
	return ch
}

// TrimEvents limits the stream to maxLen messages (approximate).
func (m *MissionOps) TrimEvents(ctx context.Context, missionID types.ID, maxLen int64) (int64, error) {
	n, err := m.rdb.XTrimMaxLen(ctx, missionEventsStreamKey(missionID), maxLen).Result()
	if err != nil {
		return 0, fmt.Errorf("mission ops: trim events: %w", err)
	}
	return n, nil
}

// DeleteEventStream removes the entire event stream for a mission.
func (m *MissionOps) DeleteEventStream(ctx context.Context, missionID types.ID) error {
	if err := m.rdb.Del(ctx, missionEventsStreamKey(missionID)).Err(); err != nil {
		return fmt.Errorf("mission ops: delete event stream: %w", err)
	}
	return nil
}

// IncrRunCounter atomically increments and returns the run counter for a mission name.
func (m *MissionOps) IncrRunCounter(ctx context.Context, name string) (int64, error) {
	n, err := m.rdb.Incr(ctx, fmt.Sprintf("gibson:counter:mission:%s:run", name)).Result()
	if err != nil {
		return 0, fmt.Errorf("mission ops: incr run counter: %w", err)
	}
	return n, nil
}

// ---------------------------------------------------------------------------
// RunningMission is a lightweight summary returned by ListRunning.
// ---------------------------------------------------------------------------

// RunningMission is a condensed view of a mission run that was active when the
// daemon last stopped. Only the fields required for crash-recovery are included.
type RunningMission struct {
	MissionID   string `json:"mission_id"`
	MissionName string `json:"mission_name"`
	RunID       string `json:"run_id"`
}

// runningMissionDoc is the JSON shape stored per mission run key.
// We only decode the fields we need for recovery.
type runningMissionDoc struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	Status string `json:"status"`
	RunID  string `json:"run_id,omitempty"`
}

// ListRunning returns all missions currently in the "running" or "paused"
// state in this tenant's Redis logical DB. Used by the per-tenant lazy
// recovery hook (internal/datapool/recovery_hook.go) on first Pool.For
// dial after a daemon restart — see ADR-0023.
//
// The scan covers all gibson:mission:* keys that are not secondary-index
// keys. Keys carrying no-tenant prefixes are exactly the pattern produced by
// MissionOps.SaveRun; isolation is structural (per-tenant logical DB).
func (m *MissionOps) ListRunning(ctx context.Context) ([]RunningMission, error) {
	if m.rdb == nil {
		return nil, nil
	}

	var results []RunningMission
	var cursor uint64

	for {
		keys, next, err := m.rdb.Scan(ctx, cursor, "gibson:mission_run:*", 100).Result()
		if err != nil {
			return nil, fmt.Errorf("mission ops: list running scan: %w", err)
		}

		for _, key := range keys {
			raw, err := m.rdb.Do(ctx, "JSON.GET", key, "$").Result()
			if err == goredis.Nil || raw == nil {
				continue
			}
			if err != nil {
				continue
			}
			rawStr, ok := raw.(string)
			if !ok {
				continue
			}
			var docs []runningMissionDoc
			if err := json.Unmarshal([]byte(rawStr), &docs); err != nil || len(docs) == 0 {
				continue
			}
			doc := docs[0]
			if doc.Status != "running" && doc.Status != "paused" {
				continue
			}
			results = append(results, RunningMission{
				MissionID:   doc.ID,
				MissionName: doc.Name,
				RunID:       doc.RunID,
			})
		}

		cursor = next
		if cursor == 0 {
			break
		}
	}

	return results, nil
}
