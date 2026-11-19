// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

// Package mission — store_conn.go
//
// ConnBoundMissionStore implements MissionStore using a tenant-bound *datapool.MissionOps.
// No key prefixes are used; tenant isolation is structural (per-tenant Redis logical DB).
// This replaces the prefix-based RedisMissionStore for all handler code paths (audit C6 closure).
package mission

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	goredis "github.com/redis/go-redis/v9"
	"github.com/zeroroot-ai/gibson/internal/infra/types"
	missionv1 "github.com/zeroroot-ai/sdk/api/gen/gibson/mission/v1"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// ConnBoundMissionStore implements MissionStore against a tenant-bound Redis client.
// It uses plain key/value operations with set-based secondary indexes.
// No tenant prefix is embedded in any key — the per-tenant client is the isolation boundary.
type ConnBoundMissionStore struct {
	rdb *goredis.Client
	// recorder and tenant tie each mission this store creates to its tenant in
	// the authorization store. A store that only reads needs neither. A store
	// that creates a mission with no recorder fails (ErrNoTenantRecorder).
	recorder TenantRecorder
	tenant   string
}

// TenantRecorder ties a mission to its tenant in the authorization store. The
// tuple (tenant:<tenant>, belongs_to, mission:<id>) is what a grant of an Agent
// Skill or an outside agent to a mission checks, and what the viewer and admin
// relations of a mission derive from.
//
// Record must be idempotent. Forget must treat an absent tuple as success.
type TenantRecorder interface {
	Record(ctx context.Context, tenant string, missionID types.ID) error
	Forget(ctx context.Context, tenant string, missionID types.ID) error
}

// ErrNoTenantRecorder is the error of a store that was asked to create or delete
// a mission and has no TenantRecorder. A new call site that builds its store with
// NewConnBoundMissionStore alone and then creates a mission meets it on its first
// test, not as a mission with no tuple on a cluster.
var ErrNoTenantRecorder = errors.New("mission store: no tenant recorder: a store that creates missions must be built with WithTenantRecorder")

// ErrTenantRecordFailed marks the error of a failed write of the tenant tuple of
// a mission. The authorization store was not reachable or refused the write, and
// the caller can retry, so the API maps it to Unavailable.
var ErrTenantRecordFailed = errors.New("the tenant of the mission could not be recorded")

// WithTenantRecorder returns the store set to record the tenant of each mission
// it creates. The record is written BEFORE the mission, and a failed write
// creates no mission. A mission that exists without its tuple is the defect
// this prevents, so each store that creates missions must be built with it.
func (s *ConnBoundMissionStore) WithTenantRecorder(rec TenantRecorder, tenant string) *ConnBoundMissionStore {
	s.recorder, s.tenant = rec, tenant
	return s
}

// recordTenant writes the tenant tuple of a mission about to be created.
func (s *ConnBoundMissionStore) recordTenant(ctx context.Context, id types.ID) error {
	if s.recorder == nil {
		return ErrNoTenantRecorder
	}
	if err := s.recorder.Record(ctx, s.tenant, id); err != nil {
		return fmt.Errorf("%w: mission %s: %w", ErrTenantRecordFailed, id, err)
	}
	return nil
}

// forgetNewTenant removes the tuple of a mission whose record could not be
// written, so the tuple does not stay for a mission that does not exist. It is a
// best effort: a tuple with no mission opens nothing, and a failure here is not
// worth a second error. The context is detached because the failed write may be
// the cancellation of the caller.
func (s *ConnBoundMissionStore) forgetNewTenant(ctx context.Context, id types.ID) {
	if s.recorder == nil {
		return
	}
	fctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	_ = s.recorder.Forget(fctx, s.tenant, id)
}

// NewConnBoundMissionStore creates a MissionStore backed by the given tenant-bound client.
// The client must already be scoped to a single tenant's logical Redis DB.
func NewConnBoundMissionStore(rdb *goredis.Client) *ConnBoundMissionStore {
	return &ConnBoundMissionStore{rdb: rdb}
}

// Key naming functions — no tenant prefix (C6 closure).

func cbMissionKey(id types.ID) string {
	return fmt.Sprintf("gibson:mission:%s", id)
}

func cbMissionByTargetKey(targetID types.ID) string {
	return fmt.Sprintf("gibson:mission:by_target:%s", targetID)
}

func cbMissionCounterKey(name string) string {
	return fmt.Sprintf("gibson:counter:mission:%s:run", name)
}

func cbMissionByNameKey(name string) string {
	return fmt.Sprintf("gibson:mission:by_name:%s", name)
}

func cbMissionDefinitionKey(name string) string {
	return fmt.Sprintf("gibson:mission-definitions:%s", name)
}

func cbMissionDefinitionIndexKey() string {
	return "gibson:mission-definitions"
}

// cbMissionDefinitionCueKey is the sibling key holding the raw CUE source the
// author submitted for a definition. Stored separately from the compiled proto
// so GetMissionDefinition can return the exact source rather than a
// reconstruction. gibson#504.
func cbMissionDefinitionCueKey(name string) string {
	return fmt.Sprintf("gibson:mission-definition-cue:%s", name)
}

// Save persists a new mission.
func (s *ConnBoundMissionStore) Save(ctx context.Context, mission *Mission) error {
	if mission == nil {
		return fmt.Errorf("mission cannot be nil")
	}
	if err := mission.Validate(); err != nil {
		return fmt.Errorf("validation failed: %w", err)
	}
	if mission.ID.IsZero() {
		mission.ID = types.NewID()
	}
	now := NewUnixTimeNow()
	if mission.CreatedAt.IsZero() {
		mission.CreatedAt = now
	}
	mission.UpdatedAt = now

	data, err := json.Marshal(mission)
	if err != nil {
		return fmt.Errorf("failed to marshal mission: %w", err)
	}

	// The tuple first: with no tuple there is no mission. A Save of a mission
	// that exists writes the same tuple again, which repairs a mission made
	// before the store wrote tuples.
	existed := s.rdb.Exists(ctx, cbMissionKey(mission.ID)).Val() > 0
	if err := s.recordTenant(ctx, mission.ID); err != nil {
		return err
	}

	pipe := s.rdb.Pipeline()
	pipe.Do(ctx, "JSON.SET", cbMissionKey(mission.ID), "$", string(data))
	pipe.SAdd(ctx, cbMissionByTargetKey(mission.TargetID), mission.ID.String())
	pipe.SAdd(ctx, cbMissionByNameKey(mission.Name), mission.ID.String())
	if _, err := pipe.Exec(ctx); err != nil {
		if !existed {
			s.forgetNewTenant(ctx, mission.ID)
		}
		return fmt.Errorf("failed to save mission: %w", err)
	}
	return nil
}

// Get retrieves a mission by ID. Returns NotFoundError if missing.
func (s *ConnBoundMissionStore) Get(ctx context.Context, id types.ID) (*Mission, error) {
	result, err := s.rdb.Do(ctx, "JSON.GET", cbMissionKey(id), "$").Result()
	if err == goredis.Nil || result == nil {
		return nil, NewNotFoundError(id.String())
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get mission: %w", err)
	}
	return unmarshalMissionJSON(result)
}

// GetByName retrieves the most recent mission with the given name.
func (s *ConnBoundMissionStore) GetByName(ctx context.Context, name string) (*Mission, error) {
	ids, err := s.rdb.SMembers(ctx, cbMissionByNameKey(name)).Result()
	if err != nil {
		return nil, fmt.Errorf("failed to get mission by name: %w", err)
	}
	if len(ids) == 0 {
		return nil, NewNotFoundError(name)
	}
	// Return most recently updated (scan all; small set in practice)
	var latest *Mission
	for _, idStr := range ids {
		id, err := types.ParseID(idStr)
		if err != nil {
			continue
		}
		m, err := s.Get(ctx, id)
		if err != nil {
			continue
		}
		if latest == nil || m.UpdatedAt.Time.After(latest.UpdatedAt.Time) {
			latest = m
		}
	}
	if latest == nil {
		return nil, NewNotFoundError(name)
	}
	return latest, nil
}

// List retrieves missions with optional filtering.
func (s *ConnBoundMissionStore) List(ctx context.Context, filter *MissionFilter) ([]*Mission, error) {
	if filter == nil {
		filter = NewMissionFilter()
	}

	// Collect candidate IDs from secondary indexes.
	var candidateIDs []string

	// Status has no secondary index (gibson#1112: the folded World is the
	// status source of truth; the store keeps only definition/layout/record
	// data). A status-filtered List takes the SCAN path below and
	// missionMatchesFilter applies the status predicate per candidate.
	if filter.TargetID != nil {
		ids, err := s.rdb.SMembers(ctx, cbMissionByTargetKey(*filter.TargetID)).Result()
		if err != nil {
			return nil, fmt.Errorf("failed to list by target: %w", err)
		}
		candidateIDs = ids
	} else {
		// Full scan via JSON.GET on known pattern is not available; use SCAN.
		var cursor uint64
		var err error
		for {
			var keys []string
			keys, cursor, err = s.rdb.Scan(ctx, cursor, "gibson:mission:[0-9a-f]*", 100).Result()
			if err != nil {
				return nil, fmt.Errorf("failed to scan missions: %w", err)
			}
			for _, k := range keys {
				// Extract ID from key
				if len(k) > len("gibson:mission:") {
					candidateIDs = append(candidateIDs, k[len("gibson:mission:"):])
				}
			}
			if cursor == 0 {
				break
			}
		}
	}

	limit := filter.Limit
	if limit <= 0 {
		limit = 100
	}
	offset := filter.Offset

	missions := make([]*Mission, 0, len(candidateIDs))
	for _, idStr := range candidateIDs {
		id, err := types.ParseID(idStr)
		if err != nil {
			continue
		}
		m, err := s.Get(ctx, id)
		if err != nil {
			continue
		}
		// Apply remaining filters
		if !missionMatchesFilter(m, filter) {
			continue
		}
		missions = append(missions, m)
	}

	// Sort by created_at descending
	sortMissionsByCreatedAt(missions)

	// Apply pagination
	if offset > len(missions) {
		return []*Mission{}, nil
	}
	end := offset + limit
	if end > len(missions) {
		end = len(missions)
	}
	return missions[offset:end], nil
}

// Update modifies an existing mission.
func (s *ConnBoundMissionStore) Update(ctx context.Context, mission *Mission) error {
	if mission == nil {
		return fmt.Errorf("mission cannot be nil")
	}
	if err := mission.Validate(); err != nil {
		return fmt.Errorf("validation failed: %w", err)
	}
	mission.UpdatedAt = NewUnixTimeNow()

	existing, err := s.Get(ctx, mission.ID)
	if err != nil {
		return err
	}

	data, err := json.Marshal(mission)
	if err != nil {
		return fmt.Errorf("failed to marshal mission: %w", err)
	}

	pipe := s.rdb.Pipeline()
	pipe.Do(ctx, "JSON.SET", cbMissionKey(mission.ID), "$", string(data))

	if existing.TargetID != mission.TargetID {
		pipe.SRem(ctx, cbMissionByTargetKey(existing.TargetID), mission.ID.String())
		pipe.SAdd(ctx, cbMissionByTargetKey(mission.TargetID), mission.ID.String())
	}

	if _, err := pipe.Exec(ctx); err != nil {
		return fmt.Errorf("failed to update mission: %w", err)
	}
	return nil
}

// Delete soft-deletes a mission (only terminal states allowed).
func (s *ConnBoundMissionStore) Delete(ctx context.Context, id types.ID) error {
	if s.recorder == nil {
		return ErrNoTenantRecorder
	}
	mission, err := s.Get(ctx, id)
	if err != nil {
		return err
	}
	if !mission.Status.IsTerminal() {
		return NewInvalidStateError(mission.Status, MissionStatusCanceled)
	}

	pipe := s.rdb.Pipeline()
	pipe.Do(ctx, "JSON.DEL", cbMissionKey(id), "$")
	pipe.SRem(ctx, cbMissionByTargetKey(mission.TargetID), id.String())
	pipe.SRem(ctx, cbMissionByNameKey(mission.Name), id.String())
	if _, err := pipe.Exec(ctx); err != nil {
		return fmt.Errorf("failed to delete mission: %w", err)
	}
	// The record is gone, so the tuple goes. An absent tuple is not an error.
	if err := s.recorder.Forget(ctx, s.tenant, id); err != nil {
		return fmt.Errorf("forget the tenant of mission %s: %w", id, err)
	}
	return nil
}

// GetByTarget retrieves all missions for a specific target.
func (s *ConnBoundMissionStore) GetByTarget(ctx context.Context, targetID types.ID) ([]*Mission, error) {
	filter := NewMissionFilter().WithTarget(targetID)
	return s.List(ctx, filter)
}

// GetActive retrieves all active missions (running or paused).
//
// Status has no secondary index (gibson#1112) — this filters a List scan.
// Its only remaining consumers are non-hot paths; the folded World is the
// authoritative "what is running" answer for anything latency-sensitive.
func (s *ConnBoundMissionStore) GetActive(ctx context.Context) ([]*Mission, error) {
	running := MissionStatusWorking
	paused := MissionStatusPaused
	missions, err := s.List(ctx, &MissionFilter{Status: &running})
	if err != nil {
		return nil, fmt.Errorf("failed to get running missions: %w", err)
	}
	pausedMissions, err := s.List(ctx, &MissionFilter{Status: &paused})
	if err != nil {
		return nil, fmt.Errorf("failed to get paused missions: %w", err)
	}
	return append(missions, pausedMissions...), nil
}

// SaveCheckpoint persists a mission checkpoint.
func (s *ConnBoundMissionStore) SaveCheckpoint(ctx context.Context, missionID types.ID, checkpoint *MissionCheckpoint) error {
	if checkpoint == nil {
		return fmt.Errorf("checkpoint cannot be nil")
	}
	if _, err := s.Get(ctx, missionID); err != nil {
		return err
	}

	now := NewUnixTimeNow()
	checkpointJSON, err := json.Marshal(checkpoint)
	if err != nil {
		return fmt.Errorf("failed to marshal checkpoint: %w", err)
	}
	nowJSON, _ := json.Marshal(now)

	pipe := s.rdb.Pipeline()
	pipe.Do(ctx, "JSON.SET", cbMissionKey(missionID), "$.checkpoint", string(checkpointJSON))
	pipe.Do(ctx, "JSON.SET", cbMissionKey(missionID), "$.checkpoint_at", string(nowJSON))
	pipe.Do(ctx, "JSON.SET", cbMissionKey(missionID), "$.updated_at", string(nowJSON))
	if _, err := pipe.Exec(ctx); err != nil {
		return fmt.Errorf("failed to save checkpoint: %w", err)
	}
	return nil
}

// Count returns the total number of missions matching the filter.
func (s *ConnBoundMissionStore) Count(ctx context.Context, filter *MissionFilter) (int, error) {
	missions, err := s.List(ctx, filter)
	if err != nil {
		return 0, err
	}
	return len(missions), nil
}

// GetByNameAndStatus retrieves a mission by name and status.
//
// The name index survives (it is a record-identity index, not folded state);
// the status half of the old index intersection is now a per-candidate field
// check (gibson#1112). The name set is small — the runs of one mission name.
func (s *ConnBoundMissionStore) GetByNameAndStatus(ctx context.Context, name string, status MissionStatus) (*Mission, error) {
	nameIDs, err := s.rdb.SMembers(ctx, cbMissionByNameKey(name)).Result()
	if err != nil {
		return nil, fmt.Errorf("failed to get by name: %w", err)
	}
	for _, idStr := range nameIDs {
		id, err := types.ParseID(idStr)
		if err != nil {
			continue
		}
		m, err := s.Get(ctx, id)
		if err != nil {
			continue
		}
		if m.Name == name && m.Status == status {
			return m, nil
		}
	}
	return nil, NewNotFoundError(fmt.Sprintf("%s (status=%s)", name, status))
}

// ListByName retrieves all missions with the given name, ordered by run number descending.
func (s *ConnBoundMissionStore) ListByName(ctx context.Context, name string, limit int) ([]*Mission, error) {
	if limit <= 0 {
		limit = 100
	}
	ids, err := s.rdb.SMembers(ctx, cbMissionByNameKey(name)).Result()
	if err != nil {
		return nil, fmt.Errorf("failed to list by name: %w", err)
	}
	missions := make([]*Mission, 0, len(ids))
	for _, idStr := range ids {
		id, err := types.ParseID(idStr)
		if err != nil {
			continue
		}
		m, err := s.Get(ctx, id)
		if err != nil {
			continue
		}
		missions = append(missions, m)
	}
	sortMissionsByRunNumber(missions)
	if limit < len(missions) {
		missions = missions[:limit]
	}
	return missions, nil
}

// GetLatestByName retrieves the most recent mission with the given name.
func (s *ConnBoundMissionStore) GetLatestByName(ctx context.Context, name string) (*Mission, error) {
	missions, err := s.ListByName(ctx, name, 1)
	if err != nil {
		return nil, err
	}
	if len(missions) == 0 {
		return nil, NewNotFoundError(name)
	}
	return missions[0], nil
}

// IncrementRunNumber atomically increments and returns the next run number for a mission name.
func (s *ConnBoundMissionStore) IncrementRunNumber(ctx context.Context, name string) (int, error) {
	n, err := s.rdb.Incr(ctx, cbMissionCounterKey(name)).Result()
	if err != nil {
		return 0, fmt.Errorf("failed to increment run number: %w", err)
	}
	return int(n), nil
}

// FindOrCreateByName looks up a mission by name or creates it if missing.
func (s *ConnBoundMissionStore) FindOrCreateByName(ctx context.Context, mission *Mission) (*Mission, bool, error) {
	if mission == nil {
		return nil, false, fmt.Errorf("mission cannot be nil")
	}
	if mission.Name == "" {
		return nil, false, fmt.Errorf("mission name is required")
	}
	if mission.ID.IsZero() {
		mission.ID = types.NewID()
	}

	now := NewUnixTimeNow()
	if mission.CreatedAt.IsZero() {
		mission.CreatedAt = now
	}
	mission.UpdatedAt = now

	data, err := json.Marshal(mission)
	if err != nil {
		return nil, false, fmt.Errorf("failed to marshal mission: %w", err)
	}

	// Try SET NX on name-index set first as a distributed lock primitive.
	lockKey := fmt.Sprintf("gibson:mission:lock:%s", mission.Name)
	ok, err := s.rdb.SetNX(ctx, lockKey, mission.ID.String(), 10*time.Second).Result()
	if err != nil {
		return nil, false, fmt.Errorf("failed to acquire lock: %w", err)
	}

	if !ok {
		// Another caller is creating — fetch existing
		existingIDs, err := s.rdb.SMembers(ctx, cbMissionByNameKey(mission.Name)).Result()
		if err != nil || len(existingIDs) == 0 {
			// Retry once
			existing, err := s.GetByName(ctx, mission.Name)
			if err != nil {
				return nil, false, err
			}
			return s.existingRecorded(ctx, existing)
		}
		id, _ := types.ParseID(existingIDs[0])
		existing, err := s.Get(ctx, id)
		if err != nil {
			return nil, false, err
		}
		return s.existingRecorded(ctx, existing)
	}

	// We won the lock — check if the name already exists in the set.
	defer s.rdb.Del(ctx, lockKey)

	existingIDs, _ := s.rdb.SMembers(ctx, cbMissionByNameKey(mission.Name)).Result()
	if len(existingIDs) > 0 {
		id, err := types.ParseID(existingIDs[0])
		if err == nil {
			if existing, err := s.Get(ctx, id); err == nil {
				return s.existingRecorded(ctx, existing)
			}
		}
	}

	// Create new mission. The tuple first: with no tuple there is no mission.
	if err := s.recordTenant(ctx, mission.ID); err != nil {
		return nil, false, err
	}
	pipe := s.rdb.Pipeline()
	pipe.Do(ctx, "JSON.SET", cbMissionKey(mission.ID), "$", string(data))
	pipe.SAdd(ctx, cbMissionByTargetKey(mission.TargetID), mission.ID.String())
	pipe.SAdd(ctx, cbMissionByNameKey(mission.Name), mission.ID.String())
	if _, err := pipe.Exec(ctx); err != nil {
		s.forgetNewTenant(ctx, mission.ID)
		return nil, false, fmt.Errorf("failed to create mission: %w", err)
	}
	return mission, true, nil
}

// existingRecorded returns a mission that FindOrCreateByName found, after it
// writes the tenant tuple of that mission again. The write is idempotent. A
// mission made before the store wrote tuples gets its tuple on its next run by
// name, as a run by ID gets it through Save.
func (s *ConnBoundMissionStore) existingRecorded(ctx context.Context, existing *Mission) (*Mission, bool, error) {
	if err := s.recordTenant(ctx, existing.ID); err != nil {
		return nil, false, err
	}
	return existing, false, nil
}

// ---------------------------------------------------------------------------
// Mission definition methods
// ---------------------------------------------------------------------------

// CreateDefinition stores a new mission definition.
func (s *ConnBoundMissionStore) CreateDefinition(ctx context.Context, def *missionv1.MissionDefinition) error {
	if def == nil {
		return fmt.Errorf("mission definition cannot be nil")
	}
	if def.GetName() == "" {
		return fmt.Errorf("mission definition name is required")
	}
	now := timestamppb.New(time.Now())
	def.InstalledAt = now
	if def.GetCreatedAt() == nil {
		def.CreatedAt = now
	}
	data, err := MarshalDefinitionJSON(def)
	if err != nil {
		return fmt.Errorf("failed to marshal definition: %w", err)
	}
	ok, err := s.rdb.SetNX(ctx, cbMissionDefinitionKey(def.GetName()), string(data), 0).Result()
	if err != nil {
		return fmt.Errorf("failed to create definition: %w", err)
	}
	if !ok {
		return ErrDefinitionExists
	}
	_ = s.rdb.SAdd(ctx, cbMissionDefinitionIndexKey(), def.GetName()).Err()
	return nil
}

// GetDefinition retrieves a mission definition by name. Returns nil, nil when not found.
func (s *ConnBoundMissionStore) GetDefinition(ctx context.Context, name string) (*missionv1.MissionDefinition, error) {
	data, err := s.rdb.Get(ctx, cbMissionDefinitionKey(name)).Result()
	if err == goredis.Nil {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get definition: %w", err)
	}
	def, err := UnmarshalDefinitionJSON([]byte(data))
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal definition: %w", err)
	}
	return def, nil
}

// ListDefinitions returns all installed mission definitions.
func (s *ConnBoundMissionStore) ListDefinitions(ctx context.Context) ([]*missionv1.MissionDefinition, error) {
	names, err := s.rdb.SMembers(ctx, cbMissionDefinitionIndexKey()).Result()
	if err != nil {
		return nil, fmt.Errorf("failed to list definition names: %w", err)
	}
	defs := make([]*missionv1.MissionDefinition, 0, len(names))
	for _, name := range names {
		def, err := s.GetDefinition(ctx, name)
		if err != nil || def == nil {
			_ = s.rdb.SRem(ctx, cbMissionDefinitionIndexKey(), name).Err()
			continue
		}
		defs = append(defs, def)
	}
	return defs, nil
}

// UpdateDefinition updates an existing mission definition.
func (s *ConnBoundMissionStore) UpdateDefinition(ctx context.Context, def *missionv1.MissionDefinition) error {
	if def == nil {
		return fmt.Errorf("definition cannot be nil")
	}
	if def.GetName() == "" {
		return fmt.Errorf("definition name is required")
	}
	existing, err := s.GetDefinition(ctx, def.GetName())
	if err != nil {
		return err
	}
	if existing == nil {
		return ErrDefinitionNotFound
	}
	def.InstalledAt = existing.GetInstalledAt()
	def.CreatedAt = existing.GetCreatedAt()
	data, err := MarshalDefinitionJSON(def)
	if err != nil {
		return fmt.Errorf("failed to marshal definition: %w", err)
	}
	return s.rdb.Set(ctx, cbMissionDefinitionKey(def.GetName()), string(data), 0).Err()
}

// DeleteDefinition removes a mission definition and its stored CUE source.
func (s *ConnBoundMissionStore) DeleteDefinition(ctx context.Context, name string) error {
	n, err := s.rdb.Del(ctx, cbMissionDefinitionKey(name)).Result()
	if err != nil {
		return fmt.Errorf("failed to delete definition: %w", err)
	}
	if n == 0 {
		return ErrDefinitionNotFound
	}
	_ = s.rdb.SRem(ctx, cbMissionDefinitionIndexKey(), name).Err()
	_ = s.rdb.Del(ctx, cbMissionDefinitionCueKey(name)).Err()
	return nil
}

// maxDefinitionCueBytes bounds the raw CUE source persisted per definition,
// matching the authoring store's cap (internal/missiondraft).
const maxDefinitionCueBytes = 512 * 1024

// SetDefinitionSource persists the raw CUE source for a definition under its
// sibling key, overwriting any previous source in place. A nil/empty source is
// a no-op so callers that lack the source (e.g. legacy CLI registrations) leave
// any existing source untouched. gibson#504.
func (s *ConnBoundMissionStore) SetDefinitionSource(ctx context.Context, name, cueSource string) error {
	if name == "" {
		return fmt.Errorf("definition name is required")
	}
	if cueSource == "" {
		return nil
	}
	if len(cueSource) > maxDefinitionCueBytes {
		return fmt.Errorf("cue_source exceeds maximum size of 512 KB")
	}
	if err := s.rdb.Set(ctx, cbMissionDefinitionCueKey(name), cueSource, 0).Err(); err != nil {
		return fmt.Errorf("failed to store definition cue source: %w", err)
	}
	return nil
}

// GetDefinitionSource returns the raw CUE source stored for a definition, or
// the empty string when none was recorded (legacy definitions or those
// registered without a source). gibson#504.
func (s *ConnBoundMissionStore) GetDefinitionSource(ctx context.Context, name string) (string, error) {
	src, err := s.rdb.Get(ctx, cbMissionDefinitionCueKey(name)).Result()
	if err == goredis.Nil {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("failed to get definition cue source: %w", err)
	}
	return src, nil
}

// ---------------------------------------------------------------------------
// Helper functions
// ---------------------------------------------------------------------------

func unmarshalMissionJSON(result any) (*Mission, error) {
	raw, ok := result.(string)
	if !ok {
		return nil, fmt.Errorf("unexpected JSON result type %T", result)
	}
	// JSON.GET with "$" path wraps in an array: [{...}]
	var docs []json.RawMessage
	if err := json.Unmarshal([]byte(raw), &docs); err == nil && len(docs) > 0 {
		var m Mission
		if err := json.Unmarshal(docs[0], &m); err != nil {
			return nil, fmt.Errorf("failed to unmarshal mission: %w", err)
		}
		return &m, nil
	}
	var m Mission
	if err := json.Unmarshal([]byte(raw), &m); err != nil {
		return nil, fmt.Errorf("failed to unmarshal mission: %w", err)
	}
	return &m, nil
}

func missionMatchesFilter(m *Mission, filter *MissionFilter) bool {
	if filter.Status != nil && m.Status != *filter.Status {
		return false
	}
	if filter.TargetID != nil && m.TargetID != *filter.TargetID {
		return false
	}
	if filter.MissionDefinitionID != nil && m.MissionDefinitionID != *filter.MissionDefinitionID {
		return false
	}
	if filter.CreatedAfter != nil && m.CreatedAt.Before(*filter.CreatedAfter) {
		return false
	}
	if filter.CreatedBefore != nil && m.CreatedAt.After(*filter.CreatedBefore) {
		return false
	}
	return true
}

func sortMissionsByCreatedAt(missions []*Mission) {
	for i := 1; i < len(missions); i++ {
		for j := i; j > 0 && missions[j].CreatedAt.Time.After(missions[j-1].CreatedAt.Time); j-- {
			missions[j], missions[j-1] = missions[j-1], missions[j]
		}
	}
}

func sortMissionsByRunNumber(missions []*Mission) {
	for i := 1; i < len(missions); i++ {
		for j := i; j > 0 && missions[j].RunNumber > missions[j-1].RunNumber; j-- {
			missions[j], missions[j-1] = missions[j-1], missions[j]
		}
	}
}

// Ensure ConnBoundMissionStore implements MissionStore at compile time.
var _ MissionStore = (*ConnBoundMissionStore)(nil)
