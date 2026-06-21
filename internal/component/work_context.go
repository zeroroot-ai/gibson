package component

// work_context.go provides the work-item → mission/tenant context registry.
//
// When the harness enqueues a work item it embeds mission_id + tenant in the
// WorkItem context; PollWork writes a short-lived Redis mapping so later
// harness-proxy calls (and the finding/mission-context paths) can recover the
// mission scope from the work_id alone. (Formerly MemoryResolver — the memory
// tiers were retired in gibson#756; only the work-context mapping remains.)

import (
	"context"
	"fmt"
	"time"

	"github.com/zeroroot-ai/gibson/internal/state"
	"github.com/zeroroot-ai/gibson/internal/types"
)

const (
	// workContextKeyPrefix is the Redis key prefix for work-item→mission mappings.
	//   gibson:work:ctx:{work_id}
	workContextKeyPrefix = "gibson:work:ctx:"

	// workContextTTL is how long the mapping is retained (must exceed max agent
	// execution time; 4h is generous).
	workContextTTL = 4 * time.Hour

	// workContextMissionField / workContextTenantField are the hash fields.
	workContextMissionField = "mission_id"
	workContextTenantField  = "tenant_id"
)

// workContextKey returns the Redis key for a work item's context hash.
func workContextKey(workID string) string { return workContextKeyPrefix + workID }

// ErrCodeWorkContextNotFound is returned when a work-item context mapping has
// expired or was never written.
const ErrCodeWorkContextNotFound types.ErrorCode = "WORK_CONTEXT_NOT_FOUND"

// NewWorkContextNotFoundError creates a typed error for missing work context.
func NewWorkContextNotFoundError(workID string) *types.GibsonError {
	return types.NewError(ErrCodeWorkContextNotFound,
		fmt.Sprintf("no mission context found for work item %q; mapping may have expired", workID))
}

// WorkContextRegistry records the work-item → mission/tenant mapping. PollWork
// registers it after claiming a work item; finding/mission-context paths read it.
type WorkContextRegistry interface {
	// RegisterWorkContext writes the work-item→mission mapping (best-effort).
	RegisterWorkContext(ctx context.Context, workID, missionID, tenantID string) error
}

// RedisWorkContextRegistry implements WorkContextRegistry over Redis.
type RedisWorkContextRegistry struct {
	stateClient *state.StateClient
}

var _ WorkContextRegistry = (*RedisWorkContextRegistry)(nil)

// NewRedisWorkContextRegistry creates a registry backed by the StateClient.
func NewRedisWorkContextRegistry(stateClient *state.StateClient) *RedisWorkContextRegistry {
	return &RedisWorkContextRegistry{stateClient: stateClient}
}

// RegisterWorkContext writes a Redis hash at gibson:work:ctx:{work_id} with
// mission_id + tenant_id and a workContextTTL expiry.
func (r *RedisWorkContextRegistry) RegisterWorkContext(ctx context.Context, workID, missionID, tenantID string) error {
	if workID == "" {
		return fmt.Errorf("work-context registry: RegisterWorkContext: workID must not be empty")
	}
	key := workContextKey(workID)
	pipe := r.stateClient.Client().Pipeline()
	pipe.HSet(ctx, key, workContextMissionField, missionID, workContextTenantField, tenantID)
	pipe.Expire(ctx, key, workContextTTL)
	if _, err := pipe.Exec(ctx); err != nil {
		return fmt.Errorf("work-context registry: register work %q: %w", workID, err)
	}
	return nil
}
