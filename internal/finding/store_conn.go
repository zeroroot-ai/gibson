// Package finding — store_conn.go
//
// ConnBoundFindingStore implements FindingStore using a tenant-bound *redis.Client.
// No tenant prefix is used; isolation is structural (audit C14/C15 closure).
// Get returns NotFound for IDs that don't exist in the connected tenant's DB —
// IDOR is impossible by construction (C15 closure).
package finding

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	goredis "github.com/redis/go-redis/v9"
	"github.com/zero-day-ai/gibson/internal/agent"
	"github.com/zero-day-ai/gibson/internal/types"
)

// ConnBoundFindingStore implements FindingStore against a tenant-bound Redis client.
// All results are scoped to the calling tenant by the client itself (C14 closure).
type ConnBoundFindingStore struct {
	rdb *goredis.Client
}

// NewConnBoundFindingStore creates a FindingStore backed by the given tenant-bound client.
func NewConnBoundFindingStore(rdb *goredis.Client) *ConnBoundFindingStore {
	return &ConnBoundFindingStore{rdb: rdb}
}

// Key helpers — no tenant prefix (C14/C15 closure).

func cbFindingKey(id types.ID) string {
	return fmt.Sprintf("gibson:finding:%s", id)
}

func cbFindingMissionSetKey(missionID types.ID) string {
	return fmt.Sprintf("gibson:finding:by_mission:%s", missionID)
}

func cbFindingSeveritySetKey(severity agent.FindingSeverity) string {
	return fmt.Sprintf("gibson:finding:by_severity:%s", string(severity))
}

// Store persists a finding and updates secondary indexes.
func (s *ConnBoundFindingStore) Store(ctx context.Context, finding EnhancedFinding) error {
	data, err := json.Marshal(finding)
	if err != nil {
		return fmt.Errorf("failed to marshal finding: %w", err)
	}
	pipe := s.rdb.Pipeline()
	pipe.Do(ctx, "JSON.SET", cbFindingKey(finding.ID), "$", string(data))
	pipe.SAdd(ctx, cbFindingMissionSetKey(finding.MissionID), finding.ID.String())
	pipe.SAdd(ctx, cbFindingSeveritySetKey(finding.Severity), finding.ID.String())
	if _, err := pipe.Exec(ctx); err != nil {
		return fmt.Errorf("failed to store finding: %w", err)
	}
	return nil
}

// Get retrieves a finding by ID. Returns an error (not found) for IDs that do not exist
// in the connected tenant's DB — IDOR is impossible by construction (C15 closure).
func (s *ConnBoundFindingStore) Get(ctx context.Context, id types.ID) (*EnhancedFinding, error) {
	result, err := s.rdb.Do(ctx, "JSON.GET", cbFindingKey(id), "$").Result()
	if err == goredis.Nil || result == nil {
		return nil, fmt.Errorf("finding not found: %s", id)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get finding: %w", err)
	}
	finding, err := unmarshalFindingJSON(result)
	if err != nil {
		return nil, err
	}
	return finding, nil
}

// List retrieves findings for a mission with optional filtering.
// All results belong to the connected tenant — no cross-tenant access (C14 closure).
func (s *ConnBoundFindingStore) List(ctx context.Context, missionID types.ID, filter *FindingFilter) ([]EnhancedFinding, error) {
	if filter == nil || s.isEmptyFilter(filter) {
		return s.listByMission(ctx, missionID)
	}
	// Fetch candidate IDs from the mission set, then apply filters.
	ids, err := s.rdb.SMembers(ctx, cbFindingMissionSetKey(missionID)).Result()
	if err != nil {
		return nil, fmt.Errorf("failed to list findings: %w", err)
	}
	var results []EnhancedFinding
	for _, idStr := range ids {
		parsedID, err := types.ParseID(idStr)
		if err != nil {
			continue
		}
		f, err := s.Get(ctx, parsedID)
		if err != nil || f == nil {
			continue
		}
		if !findingMatchesFilter(*f, filter) {
			continue
		}
		results = append(results, *f)
	}
	return results, nil
}

// Update modifies an existing finding and adjusts secondary indexes.
func (s *ConnBoundFindingStore) Update(ctx context.Context, finding EnhancedFinding) error {
	old, err := s.Get(ctx, finding.ID)
	if err != nil {
		return fmt.Errorf("finding not found: %w", err)
	}
	data, err := json.Marshal(finding)
	if err != nil {
		return fmt.Errorf("failed to marshal finding: %w", err)
	}
	pipe := s.rdb.Pipeline()
	pipe.Do(ctx, "JSON.SET", cbFindingKey(finding.ID), "$", string(data))
	if old.MissionID != finding.MissionID {
		pipe.SRem(ctx, cbFindingMissionSetKey(old.MissionID), finding.ID.String())
		pipe.SAdd(ctx, cbFindingMissionSetKey(finding.MissionID), finding.ID.String())
	}
	if old.Severity != finding.Severity {
		pipe.SRem(ctx, cbFindingSeveritySetKey(old.Severity), finding.ID.String())
		pipe.SAdd(ctx, cbFindingSeveritySetKey(finding.Severity), finding.ID.String())
	}
	if _, err := pipe.Exec(ctx); err != nil {
		return fmt.Errorf("failed to update finding: %w", err)
	}
	return nil
}

// Delete removes a finding and cleans up secondary indexes.
func (s *ConnBoundFindingStore) Delete(ctx context.Context, id types.ID) error {
	finding, err := s.Get(ctx, id)
	if err != nil {
		return fmt.Errorf("finding not found: %w", err)
	}
	pipe := s.rdb.Pipeline()
	pipe.Do(ctx, "JSON.DEL", cbFindingKey(id), "$")
	pipe.SRem(ctx, cbFindingMissionSetKey(finding.MissionID), id.String())
	pipe.SRem(ctx, cbFindingSeveritySetKey(finding.Severity), id.String())
	if _, err := pipe.Exec(ctx); err != nil {
		return fmt.Errorf("failed to delete finding: %w", err)
	}
	return nil
}

// Count returns the total number of findings for a mission.
func (s *ConnBoundFindingStore) Count(ctx context.Context, missionID types.ID) (int, error) {
	n, err := s.rdb.SCard(ctx, cbFindingMissionSetKey(missionID)).Result()
	if err != nil {
		return 0, fmt.Errorf("failed to count findings: %w", err)
	}
	return int(n), nil
}

// ListBySeverity retrieves all findings with a specific severity level (C14 closure).
// Results are restricted to the connected tenant's data by the per-tenant client.
func (s *ConnBoundFindingStore) ListBySeverity(ctx context.Context, severity agent.FindingSeverity) ([]EnhancedFinding, error) {
	ids, err := s.rdb.SMembers(ctx, cbFindingSeveritySetKey(severity)).Result()
	if err != nil {
		return nil, fmt.Errorf("failed to list by severity: %w", err)
	}
	findings := make([]EnhancedFinding, 0, len(ids))
	for _, idStr := range ids {
		parsedID, err := types.ParseID(idStr)
		if err != nil {
			continue
		}
		f, err := s.Get(ctx, parsedID)
		if err != nil || f == nil {
			continue
		}
		findings = append(findings, *f)
	}
	return findings, nil
}

// ScanAll retrieves all findings in this tenant's DB.
func (s *ConnBoundFindingStore) ScanAll(ctx context.Context) ([]EnhancedFinding, error) {
	var results []EnhancedFinding
	var cursor uint64
	for {
		keys, nextCursor, err := s.rdb.Scan(ctx, cursor, "gibson:finding:*", 100).Result()
		if err != nil {
			return nil, fmt.Errorf("scan failed: %w", err)
		}
		for _, key := range keys {
			if strings.Contains(key, ":by_mission:") || strings.Contains(key, ":by_severity:") {
				continue
			}
			result, err := s.rdb.Do(ctx, "JSON.GET", key, "$").Result()
			if err != nil || result == nil {
				continue
			}
			f, err := unmarshalFindingJSON(result)
			if err != nil || f == nil {
				continue
			}
			results = append(results, *f)
		}
		cursor = nextCursor
		if cursor == 0 {
			break
		}
	}
	return results, nil
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func (s *ConnBoundFindingStore) listByMission(ctx context.Context, missionID types.ID) ([]EnhancedFinding, error) {
	ids, err := s.rdb.SMembers(ctx, cbFindingMissionSetKey(missionID)).Result()
	if err != nil {
		return nil, fmt.Errorf("failed to get mission set: %w", err)
	}
	findings := make([]EnhancedFinding, 0, len(ids))
	for _, idStr := range ids {
		parsedID, err := types.ParseID(idStr)
		if err != nil {
			continue
		}
		f, err := s.Get(ctx, parsedID)
		if err != nil || f == nil {
			continue
		}
		findings = append(findings, *f)
	}
	return findings, nil
}

func (s *ConnBoundFindingStore) isEmptyFilter(filter *FindingFilter) bool {
	return filter.Severity == nil &&
		filter.Category == nil &&
		filter.Status == nil &&
		filter.MinRisk == nil &&
		filter.MaxRisk == nil &&
		filter.AgentName == nil &&
		filter.SearchText == nil
}

func findingMatchesFilter(f EnhancedFinding, filter *FindingFilter) bool {
	if filter == nil {
		return true
	}
	if filter.Severity != nil && f.Severity != *filter.Severity {
		return false
	}
	if filter.Category != nil && f.Category != string(*filter.Category) {
		return false
	}
	if filter.Status != nil && f.Status != *filter.Status {
		return false
	}
	if filter.MinRisk != nil && f.RiskScore < *filter.MinRisk {
		return false
	}
	if filter.MaxRisk != nil && f.RiskScore > *filter.MaxRisk {
		return false
	}
	if filter.AgentName != nil && f.AgentName != *filter.AgentName {
		return false
	}
	if filter.SearchText != nil {
		text := strings.ToLower(*filter.SearchText)
		if !strings.Contains(strings.ToLower(f.Title), text) &&
			!strings.Contains(strings.ToLower(f.Description), text) {
			return false
		}
	}
	return true
}

func unmarshalFindingJSON(result any) (*EnhancedFinding, error) {
	raw, ok := result.(string)
	if !ok {
		return nil, fmt.Errorf("unexpected result type %T", result)
	}
	var docs []json.RawMessage
	if err := json.Unmarshal([]byte(raw), &docs); err == nil && len(docs) > 0 {
		var f EnhancedFinding
		if err := json.Unmarshal(docs[0], &f); err != nil {
			return nil, fmt.Errorf("failed to unmarshal finding: %w", err)
		}
		return &f, nil
	}
	var f EnhancedFinding
	if err := json.Unmarshal([]byte(raw), &f); err != nil {
		return nil, fmt.Errorf("failed to unmarshal finding: %w", err)
	}
	return &f, nil
}

// Ensure ConnBoundFindingStore implements FindingStore at compile time.
var _ FindingStore = (*ConnBoundFindingStore)(nil)
