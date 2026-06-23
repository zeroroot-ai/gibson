package api

// server_reembed_trigger.go — wires the per-tenant re-embed job
// (internal/engine/memory/reembed, gibson#809/#934) into a reachable daemon code
// path (gibson#940).
//
// The re-embed job brings a tenant's RediSearch vector index to consistency
// after the tenant's embedding model (or provider) changes: it drops+recreates
// the index at the new model's dimension and re-embeds every stored document
// from its own VectorRecord.Content. A dimension mismatch silently fails
// indexing of the WHOLE document ([[project_redisearch_json_indexing_type_mismatch]]),
// so this reconcile is mandatory whenever a tenant changes its embedding config.
//
// Before this wiring the reembed package had zero importers — the feature was
// built (#934) but never connected, so a model change left the index stale and
// search-invisible. The natural reachable trigger is the provider-config write
// path (Create / Update / SetDefault), which is exactly where a tenant's
// embedding provider/model changes.
//
// Trigger semantics:
//   - ASYNC: re-embedding is heavy (recompute every vector), so it must never
//     block the provider-config RPC handler. The trigger fires in a detached
//     goroutine and the RPC returns immediately.
//   - IDEMPOTENT: reembed.RunForTenant is a cheap no-op when the per-tenant index
//     marker already matches the configured embedder (no drift). Firing it
//     speculatively on every embedding-capable provider write is safe.
//   - PER-TENANT SERIALISED: a per-tenant singleflight guard ensures at most one
//     re-embed runs per tenant at a time, so two concurrent provider writes never
//     clobber the same tenant's index mid-recreate. A write that arrives while a
//     re-embed is in flight is dropped (deduped) — the in-flight (or the next)
//     run converges on the latest config via the marker.
//   - FAIL-SOFT: a re-embed failure is logged but never surfaces to the RPC
//     caller; the marker stays stale so the next provider write (or sweep)
//     re-runs to completion.

import (
	"context"
	"log/slog"
	"sync"
	"time"

	tenantv1 "github.com/zeroroot-ai/gibson/internal/server/daemon/api/gibson/tenant/v1"
)

// reembedTrigger reconciles one tenant's vector index against its CURRENT
// embedding configuration. Implementations run the per-tenant re-embed job; the
// production implementation (ReembedJobTrigger) is wired in grpc.go with the
// datapool + embedder resolver. Tests inject a stub to assert the trigger fires
// for the right tenant without doing real Redis work.
//
// Trigger MUST be non-blocking from the caller's perspective: implementations
// own their own goroutine/serialisation. tenantID is the tenant whose embedding
// config just changed.
type reembedTrigger interface {
	Trigger(tenantID string)
}

// noopReembedTrigger is the always-non-nil default reembedTrigger. It does
// nothing, so provider-config writes are safe before the production trigger is
// wired (in tests, or when the re-embed feature is not configured). It exists so
// s.reembedTrigger is NEVER nil at request time — the handlers call
// s.reembedTrigger.Trigger unconditionally instead of guarding against a missing
// dependency in the request path ([[0003]]: validate-at-construction, no
// graceful-nil in request paths).
type noopReembedTrigger struct{}

func (noopReembedTrigger) Trigger(string) {}

// WithReembedTrigger wires the per-tenant re-embed trigger (gibson#940). Passing
// nil restores the no-op default, so provider-config writes do not reconcile the
// vector index — the feature degrades to "configure your embedder, then a vector
// op rebuilds lazily" rather than panicking. The field is never left nil.
// Returns the server for chaining.
func (s *DaemonServer) WithReembedTrigger(t reembedTrigger) *DaemonServer {
	if t == nil {
		t = noopReembedTrigger{}
	}
	s.reembedTrigger = t
	return s
}

// maybeTriggerReembed fires the per-tenant re-embed reconcile when the just-written
// provider input declares the embedding capability. It is called from
// CreateProvider / UpdateProvider after the write commits and the embedder cache
// is invalidated; SetDefaultProvider calls triggerReembed directly (the default
// flip can change which embedder is resolved even without an embedding-input on
// this RPC). The call is non-blocking: the trigger owns the goroutine.
//
// s.reembedTrigger is never nil (defaulted to the no-op at construction), so the
// only branch here is on the input shape, not on a missing dependency.
func (s *DaemonServer) maybeTriggerReembed(tenantID string, input *tenantv1.ProviderConfigInput) {
	if tenantID == "" || !inputServesEmbedding(input) {
		return
	}
	s.reembedTrigger.Trigger(tenantID)
}

// triggerReembed fires the reconcile unconditionally (used by SetDefaultProvider,
// where the default provider may have flipped to/from an embedding provider).
// s.reembedTrigger is never nil (defaulted to the no-op at construction).
func (s *DaemonServer) triggerReembed(tenantID string) {
	if tenantID == "" {
		return
	}
	s.reembedTrigger.Trigger(tenantID)
}

// inputServesEmbedding reports whether the provider input declares the embedding
// capability. Mirrors validateEmbeddingCapability's capability scan.
func inputServesEmbedding(input *tenantv1.ProviderConfigInput) bool {
	if input == nil {
		return false
	}
	for _, c := range input.Capabilities {
		if c == tenantv1.Capability_CAPABILITY_EMBEDDING {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// Production trigger: ReembedJobTrigger
// ---------------------------------------------------------------------------

// reembedRunner is the seam the production trigger calls to run one tenant's
// re-embed pass. It is satisfied by a closure in grpc.go that resolves the
// tenant's per-tenant StateClient (from the datapool) and embedder (from the
// resolver) and calls reembed.RunForTenant. Declared here so this package does
// not import datapool / reembed directly (the api package stays handler-focused;
// the heavy wiring lives in the daemon package).
type ReembedRunner func(ctx context.Context, tenantID string) error

// ReembedJobTrigger is the production reembedTrigger. It serialises re-embeds
// per tenant (one in-flight at a time, later requests deduped) and runs each in
// a detached goroutine so the provider-config RPC never blocks.
type ReembedJobTrigger struct {
	run     ReembedRunner
	logger  *slog.Logger
	timeout time.Duration

	mu       sync.Mutex
	inflight map[string]bool
}

// NewReembedJobTrigger builds the production trigger. run executes one tenant's
// re-embed pass (resolve StateClient + embedder, call reembed.RunForTenant) and
// MUST be non-nil — a nil runner is a wiring bug, so it panics at construction
// rather than silently no-op'ing in the request path ([[0003]]). logger may be
// nil (falls back to slog.Default()). timeout bounds a single re-embed pass;
// <= 0 uses a default. The returned value satisfies the reembedTrigger seam
// consumed by WithReembedTrigger.
func NewReembedJobTrigger(run ReembedRunner, logger *slog.Logger, timeout time.Duration) *ReembedJobTrigger {
	if run == nil {
		panic("api.NewReembedJobTrigger: run must be non-nil")
	}
	if logger == nil {
		logger = slog.Default()
	}
	if timeout <= 0 {
		timeout = 30 * time.Minute
	}
	return &ReembedJobTrigger{
		run:      run,
		logger:   logger.With(slog.String("component", "reembed-trigger")),
		timeout:  timeout,
		inflight: make(map[string]bool),
	}
}

// Trigger schedules a re-embed reconcile for tenantID. If a reconcile for the
// same tenant is already running, the call is deduped (a no-op): the in-flight
// run, or the next Trigger, converges on the latest config via the idempotent
// index marker. Non-blocking — the work runs in a detached goroutine.
func (t *ReembedJobTrigger) Trigger(tenantID string) {
	// t.run is guaranteed non-nil by NewReembedJobTrigger (validate-at-construction,
	// [[0003]]); the only request-path skip is an empty tenant id. The bare nil-receiver
	// check is a defensive shim for a zero-value trigger.
	if t == nil || tenantID == "" {
		return
	}

	t.mu.Lock()
	if t.inflight[tenantID] {
		t.mu.Unlock()
		t.logger.Debug("re-embed already in flight for tenant; skipping (idempotent marker converges)",
			slog.String("tenant", tenantID))
		return
	}
	t.inflight[tenantID] = true
	t.mu.Unlock()

	go func() {
		defer func() {
			t.mu.Lock()
			delete(t.inflight, tenantID)
			t.mu.Unlock()
		}()

		// Detached context: the work outlives the RPC that scheduled it. Bound it
		// so a wedged re-embed cannot leak a goroutine forever.
		ctx, cancel := context.WithTimeout(context.Background(), t.timeout)
		defer cancel()

		t.logger.Info("re-embed reconcile started", slog.String("tenant", tenantID))
		if err := t.run(ctx, tenantID); err != nil {
			// Fail-soft: log and move on. The marker stays stale; the next
			// provider write re-runs the reconcile to completion.
			t.logger.Error("re-embed reconcile failed (will retry on next embedding-config change)",
				slog.String("tenant", tenantID), slog.Any("error", err))
			return
		}
		t.logger.Info("re-embed reconcile completed", slog.String("tenant", tenantID))
	}()
}
