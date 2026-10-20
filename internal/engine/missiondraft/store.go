// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package missiondraft

// store.go implements a Redis-backed mission draft store.
//
// Key patterns:
//   missiondraft:{tenantID}:{draftID}   — hash per draft (durable, no TTL)
//   missiondrafts:{tenantID}            — sorted set (score = updated_at Unix)
//
// Fields per hash:
//   id                     string  UUID
//   name                   string
//   cue_source             string  raw CUE source (max 512 KB)
//   mission_definition_id  string  the definition this record last compiled to
//   created_at             string  RFC 3339
//   updated_at             string  RFC 3339
//
// Authored records are durable: they carry no TTL so a mission can be reopened
// at any time (gibson#505). Earlier records were written with a 30-day TTL;
// rewriting one via Save clears the TTL (PERSIST) so reopened missions stop
// expiring.

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"
	goredis "github.com/redis/go-redis/v9"
)

// ErrDraftNotFound is returned by Get when no draft exists for the given
// (tenantID, draftID). Callers route this to codes.NotFound at the gRPC
// boundary via errors.Is.
var ErrDraftNotFound = errors.New("draft not found")

const (
	draftKeyPrefix = "missiondraft:"
	indexKeyPrefix = "missiondrafts:"
	maxCUEBytes    = 512 * 1024 // 512 KB
)

// MissionDraft is the in-memory representation of a saved draft.
type MissionDraft struct {
	ID        string
	Name      string
	CueSource string
	// MissionDefinitionID links this authored record to the mission definition
	// it last compiled to. Empty for records that have never been run.
	MissionDefinitionID string
	CreatedAt           string
	UpdatedAt           string
}

// RedisMissionDraftStore persists mission YAML drafts in Redis.
// Safe for concurrent use.
type RedisMissionDraftStore struct {
	client *goredis.Client
	logger *slog.Logger
}

// New constructs a RedisMissionDraftStore. client must not be nil.
func New(client *goredis.Client, logger *slog.Logger) *RedisMissionDraftStore {
	if client == nil {
		panic("missiondraft: New: redis client must not be nil")
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &RedisMissionDraftStore{client: client, logger: logger}
}

// draftKey returns the Redis hash key for a single draft.
func draftKey(tenantID, draftID string) string {
	return draftKeyPrefix + tenantID + ":" + draftID
}

// indexKey returns the Redis sorted-set key for the tenant's draft index.
func indexKey(tenantID string) string {
	return indexKeyPrefix + tenantID
}

// Save persists a mission draft for a tenant.
// If draftID is empty a new UUID is generated (create); otherwise the existing
// draft is overwritten (update). missionDefinitionID links the record to the
// definition it last compiled to (empty when never run). Returns the draftID.
// Returns an error if the CUE source exceeds 512 KB.
//
// Saved records are durable (no TTL). Rewriting a record clears any TTL a
// previous version carried so reopened missions stop expiring (gibson#505).
func (s *RedisMissionDraftStore) Save(ctx context.Context, tenantID, name, cueSource, draftID, missionDefinitionID string) (string, error) {
	if tenantID == "" {
		return "", fmt.Errorf("tenant_id is required")
	}
	if len(cueSource) > maxCUEBytes {
		return "", fmt.Errorf("cue_source exceeds maximum size of 512 KB")
	}

	now := time.Now().UTC().Format(time.RFC3339)
	score := float64(time.Now().Unix())

	isNew := draftID == ""
	if isNew {
		draftID = uuid.NewString()
	}

	key := draftKey(tenantID, draftID)
	idx := indexKey(tenantID)

	// Preserve created_at on update.
	createdAt := now
	if !isNew {
		if existing, err := s.client.HGet(ctx, key, "created_at").Result(); err == nil && existing != "" {
			createdAt = existing
		}
	}

	fields := map[string]any{
		"id":                    draftID,
		"name":                  name,
		"cue_source":            cueSource,
		"mission_definition_id": missionDefinitionID,
		"created_at":            createdAt,
		"updated_at":            now,
	}

	pipe := s.client.Pipeline()
	pipe.HMSet(ctx, key, fields)
	pipe.Persist(ctx, key) // clear any TTL a pre-#505 record carried — authored records are durable
	pipe.ZAdd(ctx, idx, goredis.Z{Score: score, Member: draftID})
	if _, pipeErr := pipe.Exec(ctx); pipeErr != nil {
		return "", fmt.Errorf("failed to save mission draft: %w", pipeErr)
	}

	s.logger.InfoContext(ctx, "missiondraft: saved draft",
		slog.String("tenant_id", tenantID),
		slog.String("draft_id", draftID),
		slog.Bool("is_new", isNew),
	)

	return draftID, nil
}

// ErrBadPosition reports a ListPage position that this store did not write.
var ErrBadPosition = errors.New("missiondraft: the list position is not valid")

// position names the place of a draft in the list: its creation time and its
// id. Neither changes when a draft is saved again, so a draft keeps its place
// during a walk. The list order is creation time descending, then id
// descending. Save writes created_at as UTC RFC 3339, which sorts as text.
func position(createdAt, id string) string {
	return createdAt + "|" + id
}

func parsePosition(pos string) (createdAt, id string, err error) {
	createdAt, id, ok := strings.Cut(pos, "|")
	if !ok || createdAt == "" || id == "" {
		return "", "", ErrBadPosition
	}
	return createdAt, id, nil
}

// ListPage returns up to limit saved drafts for a tenant, newest creation
// first. The YAML content is NOT included (only metadata). after is the
// position that the previous call returned as next, or empty for the first
// page. next is empty on the last page. The call reads the index of ids and
// the creation time of each, then the hashes of the drafts on the page only.
// It never uses an offset, and a save of a draft does not change its place,
// so a draft that is saved between two pages does not move the window.
func (s *RedisMissionDraftStore) ListPage(
	ctx context.Context, tenantID, after string, limit int,
) (drafts []*MissionDraft, next string, err error) {
	if tenantID == "" {
		return nil, "", errors.New("tenant_id is required")
	}
	if limit <= 0 {
		return nil, "", errors.New("limit must be positive")
	}
	var afterCreated, afterID string
	if after != "" {
		afterCreated, afterID, err = parsePosition(after)
		if err != nil {
			return nil, "", err
		}
	}
	entries, err := s.sortedIndex(ctx, tenantID)
	if err != nil {
		return nil, "", err
	}

	drafts = make([]*MissionDraft, 0, limit)
	for _, e := range entries {
		if after != "" && !(e.createdAt < afterCreated || (e.createdAt == afterCreated && e.id < afterID)) {
			continue
		}
		if len(drafts) == limit {
			// A draft follows this page.
			last := drafts[len(drafts)-1]
			return drafts, position(last.CreatedAt, last.ID), nil
		}
		if d := s.loadDraft(ctx, tenantID, e.id); d != nil {
			drafts = append(drafts, d)
		}
	}
	return drafts, "", nil
}

// draftRef names one draft of the index: its creation time and its id.
type draftRef struct{ createdAt, id string }

// sortedIndex reads the ids of the tenant index and the creation time of each
// in one pipeline. It returns them newest first, with the id as the tie
// breaker. An index entry with no hash is removed.
func (s *RedisMissionDraftStore) sortedIndex(ctx context.Context, tenantID string) ([]draftRef, error) {
	idx := indexKey(tenantID)
	ids, err := s.client.ZRange(ctx, idx, 0, -1).Result()
	if err != nil && !errors.Is(err, goredis.Nil) {
		return nil, fmt.Errorf("failed to list draft index: %w", err)
	}
	pipe := s.client.Pipeline()
	created := make([]*goredis.StringCmd, len(ids))
	for i, id := range ids {
		created[i] = pipe.HGet(ctx, draftKey(tenantID, id), "created_at")
	}
	// A missing hash makes Exec report goredis.Nil. The cmds carry the verdict.
	if _, execErr := pipe.Exec(ctx); execErr != nil && !errors.Is(execErr, goredis.Nil) {
		return nil, fmt.Errorf("failed to read draft times: %w", execErr)
	}
	entries := make([]draftRef, 0, len(ids))
	for i, id := range ids {
		c, cErr := created[i].Result()
		if errors.Is(cErr, goredis.Nil) {
			// Draft removed; clean stale index entry.
			_ = s.client.ZRem(ctx, idx, id)
			continue
		}
		if cErr != nil {
			return nil, fmt.Errorf("failed to read draft time: %w", cErr)
		}
		entries = append(entries, draftRef{createdAt: c, id: id})
	}
	slices.SortFunc(entries, func(a, b draftRef) int {
		if c := strings.Compare(b.createdAt, a.createdAt); c != 0 {
			return c
		}
		return strings.Compare(b.id, a.id)
	})
	return entries, nil
}

// loadDraft reads the metadata of one draft. It returns nil when the draft is
// gone or the read failed. The CUE source is omitted.
func (s *RedisMissionDraftStore) loadDraft(ctx context.Context, tenantID, id string) *MissionDraft {
	fields, err := s.client.HGetAll(ctx, draftKey(tenantID, id)).Result()
	if err != nil {
		s.logger.WarnContext(ctx, "missiondraft: failed to fetch draft",
			slog.String("tenant_id", tenantID),
			slog.String("draft_id", id),
			slog.String("error", err.Error()),
		)
		return nil
	}
	if len(fields) == 0 {
		return nil
	}
	return &MissionDraft{
		ID:                  fields["id"],
		Name:                fields["name"],
		MissionDefinitionID: fields["mission_definition_id"],
		CreatedAt:           fields["created_at"],
		UpdatedAt:           fields["updated_at"],
	}
}

// Get retrieves a single draft including its YAML content.
func (s *RedisMissionDraftStore) Get(ctx context.Context, tenantID, draftID string) (*MissionDraft, error) {
	if tenantID == "" || draftID == "" {
		return nil, fmt.Errorf("tenant_id and draft_id are required")
	}

	key := draftKey(tenantID, draftID)
	fields, err := s.client.HGetAll(ctx, key).Result()
	if err == goredis.Nil || len(fields) == 0 {
		return nil, fmt.Errorf("%w: %s", ErrDraftNotFound, draftID)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get draft: %w", err)
	}

	cueSource := fields["cue_source"]
	return &MissionDraft{
		ID:                  fields["id"],
		Name:                fields["name"],
		CueSource:           cueSource,
		MissionDefinitionID: fields["mission_definition_id"],
		CreatedAt:           fields["created_at"],
		UpdatedAt:           fields["updated_at"],
	}, nil
}

// Delete removes a draft and its index entry.
func (s *RedisMissionDraftStore) Delete(ctx context.Context, tenantID, draftID string) error {
	if tenantID == "" || draftID == "" {
		return fmt.Errorf("tenant_id and draft_id are required")
	}

	key := draftKey(tenantID, draftID)
	idx := indexKey(tenantID)

	pipe := s.client.Pipeline()
	pipe.Del(ctx, key)
	pipe.ZRem(ctx, idx, draftID)
	if _, err := pipe.Exec(ctx); err != nil {
		return fmt.Errorf("failed to delete draft: %w", err)
	}

	s.logger.InfoContext(ctx, "missiondraft: deleted draft",
		slog.String("tenant_id", tenantID),
		slog.String("draft_id", draftID),
	)

	return nil
}
