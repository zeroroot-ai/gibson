package mission

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

// authzStatusActive, authzStatusCompleted, authzStatusCancelled are the
// canonical status values stored in Redis.
const (
	authzStatusActive    = "active"
	authzStatusCompleted = "completed"
	authzStatusCancelled = "cancelled"

	// authzStateTTLAfterDone is the TTL applied to the Redis key after a
	// mission's status changes from active to completed or cancelled.
	// 30 minutes lets late-arriving component callbacks get a clean error
	// instead of NotFound.
	authzStateTTLAfterDone = 30 * time.Minute
)

// ErrMissionAuthzNotFound is returned by MissionAuthzStore.Get when the
// mission run ID is not found in Redis.
var ErrMissionAuthzNotFound = errors.New("mission authz state not found")

// MissionAuthzState holds the per-run authorization context persisted by the daemon
// so that HarnessCallbackService.Authorize can resolve run_id → (user_id, tenant_id).
type MissionAuthzState struct {
	// RunID is the unique identifier for this mission execution.
	RunID string `json:"run_id"`

	// UserID is the FGA user ID (without the "user:" prefix) that initiated the run.
	UserID string `json:"user_id"`

	// TenantID is the tenant that owns this run.
	TenantID string `json:"tenant_id"`

	// Status is one of: "active", "completed", "cancelled".
	Status string `json:"status"`

	// StartedAt is when this run began.
	StartedAt time.Time `json:"started_at"`
}

// MissionAuthzStore persists and retrieves MissionAuthzState records in Redis
// under the key pattern `mission:authz:{run_id}`.
//
// A 30-minute TTL is applied after the run transitions out of the active state
// to allow late-arriving component callbacks to receive a proper error response.
type MissionAuthzStore interface {
	// Put creates or replaces the authz state for a new mission run.
	// Must be called when the mission starts so the daemon can resolve callbacks.
	Put(ctx context.Context, runID, userID, tenantID string) error

	// Get retrieves the authz state for a run_id.
	// Returns ErrMissionAuthzNotFound if the key does not exist.
	Get(ctx context.Context, runID string) (*MissionAuthzState, error)

	// MarkCompleted transitions status to "completed" and sets the 30-min TTL.
	// Errors are non-fatal — log and continue so mission lifecycle is not blocked.
	MarkCompleted(ctx context.Context, runID string) error

	// MarkCancelled transitions status to "cancelled" and sets the 30-min TTL.
	// Errors are non-fatal — log and continue so mission lifecycle is not blocked.
	MarkCancelled(ctx context.Context, runID string) error
}

// redisMissionAuthzStore implements MissionAuthzStore backed by Redis.
type redisMissionAuthzStore struct {
	rdb redis.UniversalClient
}

// NewRedisMissionAuthzStore creates a new Redis-backed MissionAuthzStore.
func NewRedisMissionAuthzStore(rdb redis.UniversalClient) MissionAuthzStore {
	return &redisMissionAuthzStore{rdb: rdb}
}

// authzKey returns the Redis key for a mission run's authz state.
// Format: mission:authz:{run_id}
func authzKey(runID string) string {
	return fmt.Sprintf("mission:authz:%s", runID)
}

// Put persists the authz state for a new mission run.
// The key is set without a TTL while the mission is active;
// the TTL is applied later when the mission completes or is cancelled.
func (s *redisMissionAuthzStore) Put(ctx context.Context, runID, userID, tenantID string) error {
	if runID == "" {
		return fmt.Errorf("authz state Put: run_id is required")
	}

	state := &MissionAuthzState{
		RunID:     runID,
		UserID:    userID,
		TenantID:  tenantID,
		Status:    authzStatusActive,
		StartedAt: time.Now().UTC(),
	}

	b, err := json.Marshal(state)
	if err != nil {
		return fmt.Errorf("authz state Put: marshal: %w", err)
	}

	// SET with no expiry while active.
	if err := s.rdb.Set(ctx, authzKey(runID), b, 0).Err(); err != nil {
		return fmt.Errorf("authz state Put: redis SET: %w", err)
	}
	return nil
}

// Get retrieves the authz state for a mission run.
func (s *redisMissionAuthzStore) Get(ctx context.Context, runID string) (*MissionAuthzState, error) {
	if runID == "" {
		return nil, fmt.Errorf("authz state Get: run_id is required")
	}

	b, err := s.rdb.Get(ctx, authzKey(runID)).Bytes()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return nil, ErrMissionAuthzNotFound
		}
		return nil, fmt.Errorf("authz state Get: redis GET: %w", err)
	}

	var state MissionAuthzState
	if err := json.Unmarshal(b, &state); err != nil {
		return nil, fmt.Errorf("authz state Get: unmarshal: %w", err)
	}
	return &state, nil
}

// MarkCompleted transitions the run's status to "completed" and applies the
// 30-minute TTL so the key is garbage-collected after the grace period.
func (s *redisMissionAuthzStore) MarkCompleted(ctx context.Context, runID string) error {
	return s.transition(ctx, runID, authzStatusCompleted)
}

// MarkCancelled transitions the run's status to "cancelled" and applies the
// 30-minute TTL so the key is garbage-collected after the grace period.
func (s *redisMissionAuthzStore) MarkCancelled(ctx context.Context, runID string) error {
	return s.transition(ctx, runID, authzStatusCancelled)
}

// transition updates the status and sets the expiry TTL atomically.
func (s *redisMissionAuthzStore) transition(ctx context.Context, runID, newStatus string) error {
	if runID == "" {
		return fmt.Errorf("authz state transition: run_id is required")
	}

	existing, err := s.Get(ctx, runID)
	if err != nil {
		if errors.Is(err, ErrMissionAuthzNotFound) {
			// Nothing to transition — possibly a test or dev-mode run without authz state.
			return nil
		}
		return fmt.Errorf("authz state transition: get: %w", err)
	}

	existing.Status = newStatus

	b, err := json.Marshal(existing)
	if err != nil {
		return fmt.Errorf("authz state transition: marshal: %w", err)
	}

	// SETEX applies the value and TTL atomically.
	if err := s.rdb.Set(ctx, authzKey(runID), b, authzStateTTLAfterDone).Err(); err != nil {
		return fmt.Errorf("authz state transition: redis SETEX: %w", err)
	}
	return nil
}
