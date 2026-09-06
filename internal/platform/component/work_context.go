// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package component

// work_context.go provides the work-item → mission/tenant context registry.
//
// When the harness enqueues a work item it embeds mission_id + tenant in the
// WorkItem context; PollWork writes a short-lived Redis mapping so later
// harness-proxy calls (and the finding/mission-context paths) can recover the
// mission scope from the work_id alone. (Formerly MemoryResolver — the memory
// tiers were retired in gibson#756; only the work-context mapping remains.)
//
// It also owns the work-item → owning-tenant binding. A work id travels to a
// remote component and comes back on RPCs the component controls (SubmitResult,
// SubmitFinding), so the work id alone carries no authority: every path that
// accepts a component-supplied work id resolves the owner recorded here and
// checks it against the caller's authenticated tenant before acting on it.

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/zeroroot-ai/gibson/internal/engine/state"
	"github.com/zeroroot-ai/gibson/internal/infra/types"
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

	// workOwnerKeyPrefix is the Redis key prefix for the work-item → owning
	// tenant binding.
	//   gibson:work:owner:{work_id}
	//
	// The binding is written by WorkQueue.Enqueue — the one place a work id is
	// minted, and the one place the owning tenant is known from server state
	// rather than from a component's request.
	workOwnerKeyPrefix = "gibson:work:owner:"

	// workOwnerTTL bounds how long a work id stays bound to its tenant. It
	// matches workContextTTL so that both records for a work item age out
	// together and a work id cannot outlive its own execution window.
	workOwnerTTL = workContextTTL
)

// workContextKey returns the Redis key for a work item's context hash.
func workContextKey(workID string) string { return workContextKeyPrefix + workID }

// workOwnerKey returns the Redis key holding a work item's owning tenant.
func workOwnerKey(workID string) string { return workOwnerKeyPrefix + workID }

// ErrCodeWorkContextNotFound is returned when a work-item context mapping has
// expired or was never written.
const ErrCodeWorkContextNotFound types.ErrorCode = "WORK_CONTEXT_NOT_FOUND"

// ErrWorkOwnerUnknown reports that no owning tenant is on record for a work id:
// the id was never enqueued, or its binding has aged out. Callers must treat it
// as "not authorised" rather than "unrestricted" — an unbound work id is
// exactly the shape a forged one takes.
var ErrWorkOwnerUnknown = errors.New("work-context registry: no owning tenant recorded for work id")

// WorkContextRegistry records the work-item → mission/tenant mapping. PollWork
// registers it after claiming a work item; finding/mission-context paths read it.
type WorkContextRegistry interface {
	// RegisterWorkContext writes the work-item→mission mapping (best-effort).
	RegisterWorkContext(ctx context.Context, workID, missionID, tenantID string) error

	// WorkOwner returns the tenant that enqueued workID, as recorded by
	// WorkQueue.Enqueue. It returns ErrWorkOwnerUnknown when no binding
	// exists.
	WorkOwner(ctx context.Context, workID string) (string, error)
}

// bindWorkOwner records tenant as the owner of workID.
//
// Called by WorkQueue.Enqueue before the item becomes visible on the stream, so
// the binding is always in place before any component can claim the work and
// learn the id.
func bindWorkOwner(ctx context.Context, client redis.UniversalClient, workID, tenant string) error {
	if workID == "" {
		return errors.New("work-context registry: bind work owner: workID must not be empty")
	}
	if tenant == "" {
		return errors.New("work-context registry: bind work owner: tenant must not be empty")
	}
	if err := client.Set(ctx, workOwnerKey(workID), tenant, workOwnerTTL).Err(); err != nil {
		return fmt.Errorf("work-context registry: bind owner of work %q: %w", workID, err)
	}
	return nil
}

// lookupWorkOwner returns the tenant bound to workID by bindWorkOwner, or
// ErrWorkOwnerUnknown when there is no binding.
func lookupWorkOwner(ctx context.Context, client redis.UniversalClient, workID string) (string, error) {
	if workID == "" {
		return "", ErrWorkOwnerUnknown
	}
	tenant, err := client.Get(ctx, workOwnerKey(workID)).Result()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return "", ErrWorkOwnerUnknown
		}
		return "", fmt.Errorf("work-context registry: look up owner of work %q: %w", workID, err)
	}
	if tenant == "" {
		return "", ErrWorkOwnerUnknown
	}
	return tenant, nil
}

// tenantMayActOnWork reports whether caller is entitled to act on work owned by
// owner.
//
// The owning tenant always qualifies. The platform's shared-component identity
// (systemTenant) also qualifies: a shared deployment claims work from every
// tenant's stream by design (see claimCrossTenant), so it necessarily returns
// results and findings for work it does not own. That identity is issued to
// platform-deployed components only and already carries cross-tenant claim
// authority, so accepting it here grants nothing new.
func tenantMayActOnWork(caller, owner string) bool {
	if caller == "" || owner == "" {
		return false
	}
	return caller == owner || caller == systemTenant
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

// WorkOwner reads the work-item → owning-tenant binding written by
// WorkQueue.Enqueue. The queue and this registry are constructed over the same
// Redis (see the daemon wiring), so the binding the queue writes is the binding
// read here.
func (r *RedisWorkContextRegistry) WorkOwner(ctx context.Context, workID string) (string, error) {
	return lookupWorkOwner(ctx, r.stateClient.Client(), workID)
}
