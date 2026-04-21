package component

// mission_context.go provides MissionContextResolver, which maps a work item
// ID to its parent mission and any per-mission LLM slot overrides stored in
// Redis.
//
// Design overview:
//
//  1. The work-item→mission mapping is written by PollWork via
//     MemoryResolver.RegisterWorkContext (see memory_resolver.go). The mapping
//     is stored at:
//
//       gibson:work:ctx:{work_id}   (hash, fields: mission_id, tenant_id)
//
//  2. Per-mission slot overrides are stored by the mission orchestrator at the
//     tenant-scoped key:
//
//       tenant:{tenant_id}:mission:{mission_id}:slot-overrides   (JSON string)
//
//  3. ResolveMissionForWork reads both keys and returns the mission ID and any
//     overrides so that Complete() and CompleteStream() can apply them before
//     delegating to the LLMCompleter. Missing keys are not errors — the caller
//     falls back to tenant-level defaults.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"

	"github.com/redis/go-redis/v9"
	"github.com/zero-day-ai/gibson/internal/identity"
	"github.com/zero-day-ai/gibson/internal/state"
)

// ---------------------------------------------------------------------------
// Service-layer helpers
// ---------------------------------------------------------------------------

// resolveMissionContext is a convenience shim for Complete and CompleteStream.
// It handles a nil resolver gracefully (returns "", nil, nil) so callers do not
// need to guard against an unset missionCtx field.
func resolveMissionContext(
	ctx context.Context,
	resolver *MissionContextResolver,
	workID, tenant, slot string,
	logger *slog.Logger,
) (missionID string, overrides *SlotOverrides, err error) {
	if resolver == nil || workID == "" {
		return "", nil, nil
	}
	return resolver.ResolveMissionForWork(ctx, workID)
}

// applySlotOverrides extracts the maxTokens and temperature to pass to the
// LLMCompleter for a given slot name, using overrides where present and falling
// back to zero values (which tell the completer to use tenant defaults) when no
// override is configured.
//
// Returns (0, 0) when overrides is nil or the named slot has no entry — callers
// treat zero values as "use provider defaults".
func applySlotOverrides(slot string, overrides *SlotOverrides) (maxTokens int32, temperature float32) {
	if overrides == nil || len(overrides.Overrides) == 0 {
		return 0, 0
	}

	ov, ok := overrides.Overrides[slot]
	if !ok {
		return 0, 0
	}

	if ov.MaxTokens > 0 {
		maxTokens = int32(ov.MaxTokens)
	}
	if ov.Temperature != nil {
		temperature = float32(*ov.Temperature)
	}
	return maxTokens, temperature
}

// ---------------------------------------------------------------------------
// Slot override types
// ---------------------------------------------------------------------------

// SlotOverrides holds per-mission LLM slot configuration that supersedes the
// tenant-level provider defaults. Only populated fields are applied; a zero
// value for a field means "use the tenant default".
type SlotOverrides struct {
	// MissionID is the mission these overrides belong to. Populated by
	// ResolveMissionForWork for logging and debugging purposes.
	MissionID string `json:"mission_id"`

	// Overrides maps slot name (e.g. "reasoning", "fast") to its per-mission
	// configuration. A slot not present in this map inherits the tenant default.
	Overrides map[string]SlotOverride `json:"overrides"`
}

// SlotOverride specifies per-mission configuration for a single LLM slot.
// All fields are optional; unset fields leave the tenant default in effect.
type SlotOverride struct {
	// PreferredProvider pins the slot to a specific provider (e.g. "anthropic",
	// "openai", "ollama"). Empty string means use tenant default.
	PreferredProvider string `json:"preferred_provider,omitempty"`

	// PreferredModel pins the slot to a specific model name (e.g.
	// "claude-opus-4-5", "gpt-4o"). Empty string means use tenant default.
	PreferredModel string `json:"preferred_model,omitempty"`

	// MaxTokens overrides the maximum number of tokens for responses on this
	// slot. Zero means use the tenant default.
	MaxTokens int `json:"max_tokens,omitempty"`

	// Temperature overrides the sampling temperature for this slot. Nil means
	// use the tenant default. Pointer so that 0.0 is distinguishable from unset.
	Temperature *float64 `json:"temperature,omitempty"`
}

// ---------------------------------------------------------------------------
// MissionContextResolver
// ---------------------------------------------------------------------------

// MissionContextResolver maps a work item ID to its parent mission and any
// per-mission LLM slot overrides stored in Redis.
//
// It reuses the work-item→mission mapping written by RedisMemoryResolver so
// that PollWork remains the single writer of that mapping. Slot overrides are
// read from a separate tenant-scoped key that the mission orchestrator writes
// when launching a mission with custom provider requirements.
//
// Thread safety: all methods are safe for concurrent use; no local state is
// mutated after construction.
type MissionContextResolver struct {
	// stateClient provides raw Redis access for the work-context hash lookup.
	// The hash is not tenant-scoped at the Redis level (it uses the global
	// gibson:work:ctx: prefix), so we read it directly rather than through
	// TenantScopedStore.
	stateClient *state.StateClient

	// tenantStore provides tenant-scoped access for the slot-overrides key.
	tenantStore *state.TenantScopedStore

	logger *slog.Logger
}

// NewMissionContextResolver creates a resolver that uses the provided
// StateClient for work-context lookups and TenantScopedStore for slot-override
// lookups.
//
// Both arguments must be non-nil. The logger may be nil; slog.Default() is
// used in that case.
func NewMissionContextResolver(
	stateClient *state.StateClient,
	tenantStore *state.TenantScopedStore,
	logger *slog.Logger,
) *MissionContextResolver {
	if stateClient == nil {
		panic("component.NewMissionContextResolver: stateClient must not be nil")
	}
	if tenantStore == nil {
		panic("component.NewMissionContextResolver: tenantStore must not be nil")
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &MissionContextResolver{
		stateClient: stateClient,
		tenantStore: tenantStore,
		logger:      logger,
	}
}

// missionSlotOverridesKey returns the tenant-scoped Redis key where per-mission
// slot overrides are stored.
//
//	mission:{missionID}:slot-overrides
//
// The key is passed through TenantScopedStore which prefixes it with
// "tenant:{tenantID}:" automatically.
func missionSlotOverridesKey(missionID string) string {
	return fmt.Sprintf("mission:%s:slot-overrides", missionID)
}

// ResolveMissionForWork looks up the work item's mission ID and any per-mission
// LLM slot overrides.
//
// Return semantics (all three outcomes are non-error):
//   - ("", nil, nil)   — no work context exists; caller uses tenant defaults.
//   - (id, nil, nil)   — mission found but no slot overrides stored; caller
//     uses tenant defaults with the mission ID for logging.
//   - (id, overrides, nil) — mission found with overrides; caller should apply
//     them before resolving the LLM slot.
//
// A non-nil error indicates a Redis failure that prevented lookup. The caller
// should log the error and fall back to tenant defaults rather than failing the
// RPC.
func (r *MissionContextResolver) ResolveMissionForWork(
	ctx context.Context,
	workID string,
) (missionID string, overrides *SlotOverrides, err error) {
	if workID == "" {
		// No work ID supplied — not possible to look anything up.
		return "", nil, nil
	}

	// ------------------------------------------------------------------
	// Step 1: look up the work-item→mission mapping.
	// The hash is at the global (non-tenant-scoped) key gibson:work:ctx:{workID}.
	// ------------------------------------------------------------------
	key := workContextKey(workID)

	fields, redisErr := r.stateClient.Client().HGetAll(ctx, key).Result()
	if redisErr != nil {
		if errors.Is(redisErr, redis.Nil) {
			// Key truly doesn't exist; treat as no-context (not an error).
			return "", nil, nil
		}
		return "", nil, fmt.Errorf("mission context resolver: failed to fetch work context for work %q: %w", workID, redisErr)
	}

	// HGetAll returns an empty map (not redis.Nil) when the key does not exist.
	if len(fields) == 0 {
		return "", nil, nil
	}

	missionID = fields[workContextMissionField]
	if missionID == "" {
		// Work context exists but was registered without a mission — no overrides
		// are possible.
		return "", nil, nil
	}

	// ------------------------------------------------------------------
	// Step 2: look up per-mission slot overrides at the tenant-scoped key.
	// We need the tenant to scope the key correctly. Use the tenant stored
	// alongside the work context (written by RegisterWorkContext), falling
	// back to the tenant in the request context.
	// ------------------------------------------------------------------
	tenant := fields[workContextTenantField]
	if tenant == "" {
		tenant = identity.TenantFromContext(ctx)
	}

	if tenant == "" {
		// Cannot scope the overrides key without a tenant. Return the mission ID
		// alone so the caller at least knows which mission this work belongs to.
		r.logger.DebugContext(ctx, "mission context resolver: no tenant available; cannot look up slot overrides",
			slog.String("work_id", workID),
			slog.String("mission_id", missionID),
		)
		return missionID, nil, nil
	}

	// Inject the resolved tenant into a child context so TenantScopedStore
	// scopes the key correctly, regardless of what the auth middleware put in
	// the original context.
	tenantCtx := identity.ContextWithTenant(ctx, tenant)

	overridesKey := missionSlotOverridesKey(missionID)
	raw, getErr := r.tenantStore.Get(tenantCtx, overridesKey)
	if getErr != nil {
		if errors.Is(getErr, state.ErrNotFound) {
			// No overrides configured for this mission — normal case.
			return missionID, nil, nil
		}
		// Redis error: log and return mission ID without overrides so the caller
		// can still identify the mission for logging purposes.
		r.logger.WarnContext(ctx, "mission context resolver: failed to fetch slot overrides; falling back to tenant defaults",
			slog.String("work_id", workID),
			slog.String("mission_id", missionID),
			slog.String("tenant", tenant),
			slog.String("error", getErr.Error()),
		)
		return missionID, nil, fmt.Errorf("mission context resolver: failed to fetch slot overrides for mission %q: %w", missionID, getErr)
	}

	// ------------------------------------------------------------------
	// Step 3: decode the JSON overrides blob.
	// ------------------------------------------------------------------
	var so SlotOverrides
	if jsonErr := json.Unmarshal([]byte(raw), &so); jsonErr != nil {
		r.logger.WarnContext(ctx, "mission context resolver: invalid slot overrides JSON; falling back to tenant defaults",
			slog.String("work_id", workID),
			slog.String("mission_id", missionID),
			slog.String("tenant", tenant),
			slog.String("error", jsonErr.Error()),
		)
		// Treat malformed JSON as no-overrides rather than a hard error.
		return missionID, nil, nil
	}

	so.MissionID = missionID
	return missionID, &so, nil
}
