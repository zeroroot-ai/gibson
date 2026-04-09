package missiondraft

// store.go implements a Redis-backed mission draft store.
//
// Key patterns:
//   missiondraft:{tenantID}:{draftID}   — hash per draft (TTL 30 days)
//   missiondrafts:{tenantID}            — sorted set (score = updated_at Unix)
//
// Fields per hash:
//   id          string  UUID
//   name        string
//   yaml        string  raw YAML content (max 512 KB)
//   created_at  string  RFC 3339
//   updated_at  string  RFC 3339

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/google/uuid"
	goredis "github.com/redis/go-redis/v9"
)

const (
	draftKeyPrefix = "missiondraft:"
	indexKeyPrefix = "missiondrafts:"
	draftTTL       = 30 * 24 * time.Hour // 30 days
	maxYAMLBytes   = 512 * 1024          // 512 KB
)

// MissionDraft is the in-memory representation of a saved draft.
type MissionDraft struct {
	ID        string
	Name      string
	YAML      string
	CreatedAt string
	UpdatedAt string
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
// draft is overwritten (update). Returns the draftID.
// Returns codes.InvalidArgument if the YAML exceeds 512 KB.
func (s *RedisMissionDraftStore) Save(ctx context.Context, tenantID, name, yaml, draftID string) (string, error) {
	if tenantID == "" {
		return "", fmt.Errorf("tenant_id is required")
	}
	if len(yaml) > maxYAMLBytes {
		return "", fmt.Errorf("yaml exceeds maximum size of 512 KB")
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
		"id":         draftID,
		"name":       name,
		"yaml":       yaml,
		"created_at": createdAt,
		"updated_at": now,
	}

	pipe := s.client.Pipeline()
	pipe.HMSet(ctx, key, fields)
	pipe.Expire(ctx, key, draftTTL)
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

// List returns all saved drafts for a tenant ordered by update time descending.
// The YAML content is NOT included in list responses (only metadata).
func (s *RedisMissionDraftStore) List(ctx context.Context, tenantID string) ([]*MissionDraft, error) {
	if tenantID == "" {
		return nil, fmt.Errorf("tenant_id is required")
	}

	idx := indexKey(tenantID)

	// Fetch draft IDs from the sorted set, newest first.
	ids, err := s.client.ZRevRange(ctx, idx, 0, -1).Result()
	if err == goredis.Nil || len(ids) == 0 {
		return []*MissionDraft{}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to list draft index: %w", err)
	}

	drafts := make([]*MissionDraft, 0, len(ids))
	for _, id := range ids {
		key := draftKey(tenantID, id)
		fields, hErr := s.client.HGetAll(ctx, key).Result()
		if hErr == goredis.Nil || len(fields) == 0 {
			// Draft expired or removed; clean stale index entry.
			_ = s.client.ZRem(ctx, idx, id)
			continue
		}
		if hErr != nil {
			s.logger.WarnContext(ctx, "missiondraft: failed to fetch draft",
				slog.String("tenant_id", tenantID),
				slog.String("draft_id", id),
				slog.String("error", hErr.Error()),
			)
			continue
		}
		drafts = append(drafts, &MissionDraft{
			ID:        fields["id"],
			Name:      fields["name"],
			CreatedAt: fields["created_at"],
			UpdatedAt: fields["updated_at"],
			// YAML omitted from list responses.
		})
	}

	return drafts, nil
}

// Get retrieves a single draft including its YAML content.
func (s *RedisMissionDraftStore) Get(ctx context.Context, tenantID, draftID string) (*MissionDraft, error) {
	if tenantID == "" || draftID == "" {
		return nil, fmt.Errorf("tenant_id and draft_id are required")
	}

	key := draftKey(tenantID, draftID)
	fields, err := s.client.HGetAll(ctx, key).Result()
	if err == goredis.Nil || len(fields) == 0 {
		return nil, fmt.Errorf("draft %s not found", draftID)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get draft: %w", err)
	}

	return &MissionDraft{
		ID:        fields["id"],
		Name:      fields["name"],
		YAML:      fields["yaml"],
		CreatedAt: fields["created_at"],
		UpdatedAt: fields["updated_at"],
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
