// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package component

// mission_context.go provides MissionContextResolver, which maps a work item
// ID to its parent mission. The work-item→mission mapping is written by
// PollWork through RegisterWorkContext at gibson:work:ctx:{work_id} (hash,
// fields: mission_id, tenant_id). The LLM slot pin of a mission node is bound
// to the work item itself (slot_pin.go), not to the mission.

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	"github.com/redis/go-redis/v9"
	"github.com/zeroroot-ai/gibson/internal/engine/state"
)

// ---------------------------------------------------------------------------
// Service-layer helpers
// ---------------------------------------------------------------------------

// resolveMissionContext is a convenience shim for the mission RPCs. It handles
// a nil resolver gracefully (returns "", nil) so callers do not need to guard
// against an unset missionCtx field.
func resolveMissionContext(
	ctx context.Context,
	resolver *MissionContextResolver,
	workID, tenant string,
) (missionID string, err error) {
	if resolver == nil || workID == "" {
		return "", nil
	}
	return resolver.ResolveMissionForWork(ctx, workID, tenant)
}

// ---------------------------------------------------------------------------
// MissionContextResolver
// ---------------------------------------------------------------------------

// MissionContextResolver maps a work item ID to its parent mission.
//
// It reuses the work-item→mission mapping written by RegisterWorkContext so
// that PollWork remains the single writer of that mapping.
//
// Thread safety: all methods are safe for concurrent use; no local state is
// mutated after construction.
type MissionContextResolver struct {
	// stateClient provides raw Redis access for the work-context hash lookup.
	// The hash is not tenant-scoped at the Redis level (it uses the global
	// gibson:work:ctx: prefix), so we read it directly.
	stateClient *state.StateClient

	logger *slog.Logger
}

// NewMissionContextResolver returns a resolver over the state client that
// PollWork writes the work-context hash with. A nil logger uses slog.Default.
// stateClient must not be nil: every lookup reads it.
func NewMissionContextResolver(stateClient *state.StateClient, logger *slog.Logger) *MissionContextResolver {
	if logger == nil {
		logger = slog.Default()
	}
	return &MissionContextResolver{stateClient: stateClient, logger: logger}
}

// ResolveMissionForWork looks up the work item's mission ID. caller is the
// authenticated tenant of the requesting component; the work id itself arrives
// from the component and is NOT trusted — a work context recorded for another
// tenant resolves to nothing (gibson#1250, same rule as
// SubmitResult/SubmitFinding after gibson#1248).
//
// It returns "" with no error when no work context exists, when the context has
// no mission, or when it does not belong to the caller. A non-nil error
// indicates a Redis failure that prevented the lookup.
func (r *MissionContextResolver) ResolveMissionForWork(
	ctx context.Context,
	workID string,
	caller string,
) (missionID string, err error) {
	if workID == "" {
		return "", nil
	}

	fields, redisErr := r.stateClient.Client().HGetAll(ctx, workContextKey(workID)).Result()
	if redisErr != nil {
		if errors.Is(redisErr, redis.Nil) {
			return "", nil
		}
		return "", fmt.Errorf("mission context resolver: failed to fetch work context for work %q: %w", workID, redisErr)
	}
	// HGetAll returns an empty map (not redis.Nil) when the key does not exist.
	if len(fields) == 0 {
		return "", nil
	}

	missionID = fields[workContextMissionField]
	if missionID == "" {
		return "", nil
	}

	// The tenant recorded at RegisterWorkContext time is the owner of record,
	// and the caller must match it (or be the shared-component _system
	// tenant). A mismatch resolves to no mission rather than leaking another
	// tenant's mission id.
	if !tenantMayActOnWork(caller, fields[workContextTenantField]) {
		r.logger.WarnContext(ctx, "mission context resolver: work context does not belong to the calling tenant; ignoring component-supplied work id",
			slog.String("caller_tenant", caller),
			slog.String("work_id", workID),
		)
		return "", nil
	}
	return missionID, nil
}
