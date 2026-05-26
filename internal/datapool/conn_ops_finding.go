package datapool

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	goredis "github.com/redis/go-redis/v9"
	"github.com/zeroroot-ai/gibson/internal/types"
)

// Findings returns a FindingOps bundle bound to this Conn's tenant-bound Postgres pool
// and Redis client. The returned ops struct is valid only while the Conn is held.
// Findings are stored in per-tenant Postgres; Redis is used for secondary indexes.
func (c *Conn) Findings() *FindingOps {
	return &FindingOps{rdb: c.Redis}
}

// FindingOps provides finding store operations bound to a single tenant's Redis DB.
// Keys carry no tenant prefix — the per-tenant client is the isolation boundary
// (audit C14/C15 closure).
type FindingOps struct {
	rdb *goredis.Client
}

// ---------------------------------------------------------------------------
// Key helpers — no tenant prefix (C14/C15 closure)
// ---------------------------------------------------------------------------

func findingDocKey(id types.ID) string {
	return fmt.Sprintf("gibson:finding:%s", id)
}

func findingMissionSetKey(missionID types.ID) string {
	return fmt.Sprintf("gibson:finding:by_mission:%s", missionID)
}

func findingSeveritySetKey(severity string) string {
	return fmt.Sprintf("gibson:finding:by_severity:%s", severity)
}

// ---------------------------------------------------------------------------
// Operations
// ---------------------------------------------------------------------------

// Store persists a finding JSON document and updates secondary indexes.
func (f *FindingOps) Store(ctx context.Context, id, missionID types.ID, severity string, data []byte) error {
	pipe := f.rdb.Pipeline()
	pipe.Do(ctx, "JSON.SET", findingDocKey(id), "$", string(data))
	pipe.SAdd(ctx, findingMissionSetKey(missionID), id.String())
	pipe.SAdd(ctx, findingSeveritySetKey(severity), id.String())
	if _, err := pipe.Exec(ctx); err != nil {
		return fmt.Errorf("finding ops: store: %w", err)
	}
	return nil
}

// Get retrieves a finding JSON document by ID. Returns nil when not found.
func (f *FindingOps) Get(ctx context.Context, id types.ID) ([]byte, error) {
	result, err := f.rdb.Do(ctx, "JSON.GET", findingDocKey(id), "$").Result()
	if err == goredis.Nil || result == nil {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("finding ops: get: %w", err)
	}
	raw, ok := result.(string)
	if !ok {
		return nil, fmt.Errorf("finding ops: unexpected result type %T", result)
	}
	// Unwrap JSONPath array envelope.
	var docs []json.RawMessage
	if err := json.Unmarshal([]byte(raw), &docs); err == nil && len(docs) > 0 {
		return docs[0], nil
	}
	return []byte(raw), nil
}

// ListIDsByMission returns all finding IDs for a mission.
func (f *FindingOps) ListIDsByMission(ctx context.Context, missionID types.ID) ([]string, error) {
	ids, err := f.rdb.SMembers(ctx, findingMissionSetKey(missionID)).Result()
	if err != nil {
		return nil, fmt.Errorf("finding ops: list by mission: %w", err)
	}
	return ids, nil
}

// ListIDsBySeverity returns all finding IDs for a severity level.
func (f *FindingOps) ListIDsBySeverity(ctx context.Context, severity string) ([]string, error) {
	ids, err := f.rdb.SMembers(ctx, findingSeveritySetKey(severity)).Result()
	if err != nil {
		return nil, fmt.Errorf("finding ops: list by severity: %w", err)
	}
	return ids, nil
}

// Update overwrites an existing finding and adjusts secondary indexes if needed.
func (f *FindingOps) Update(ctx context.Context, id, oldMissionID, newMissionID types.ID, oldSeverity, newSeverity string, data []byte) error {
	pipe := f.rdb.Pipeline()
	pipe.Do(ctx, "JSON.SET", findingDocKey(id), "$", string(data))
	if oldMissionID != newMissionID {
		pipe.SRem(ctx, findingMissionSetKey(oldMissionID), id.String())
		pipe.SAdd(ctx, findingMissionSetKey(newMissionID), id.String())
	}
	if oldSeverity != newSeverity {
		pipe.SRem(ctx, findingSeveritySetKey(oldSeverity), id.String())
		pipe.SAdd(ctx, findingSeveritySetKey(newSeverity), id.String())
	}
	if _, err := pipe.Exec(ctx); err != nil {
		return fmt.Errorf("finding ops: update: %w", err)
	}
	return nil
}

// Delete removes a finding and cleans up secondary indexes.
func (f *FindingOps) Delete(ctx context.Context, id, missionID types.ID, severity string) error {
	pipe := f.rdb.Pipeline()
	pipe.Do(ctx, "JSON.DEL", findingDocKey(id), "$")
	pipe.SRem(ctx, findingMissionSetKey(missionID), id.String())
	pipe.SRem(ctx, findingSeveritySetKey(severity), id.String())
	if _, err := pipe.Exec(ctx); err != nil {
		return fmt.Errorf("finding ops: delete: %w", err)
	}
	return nil
}

// CountByMission returns the number of findings for a mission.
func (f *FindingOps) CountByMission(ctx context.Context, missionID types.ID) (int, error) {
	n, err := f.rdb.SCard(ctx, findingMissionSetKey(missionID)).Result()
	if err != nil {
		return 0, fmt.Errorf("finding ops: count: %w", err)
	}
	return int(n), nil
}

// ScanAll returns JSON documents for all findings (full scan).
func (f *FindingOps) ScanAll(ctx context.Context) ([][]byte, error) {
	var results [][]byte
	var cursor uint64
	for {
		keys, nextCursor, err := f.rdb.Scan(ctx, cursor, "gibson:finding:*", 100).Result()
		if err != nil {
			return nil, fmt.Errorf("finding ops: scan: %w", err)
		}
		for _, key := range keys {
			if strings.Contains(key, ":by_mission:") || strings.Contains(key, ":by_severity:") {
				continue
			}
			data, err := f.Get(ctx, types.ID(strings.TrimPrefix(key, "gibson:finding:")))
			if err != nil || data == nil {
				continue
			}
			results = append(results, data)
		}
		cursor = nextCursor
		if cursor == 0 {
			break
		}
	}
	return results, nil
}
