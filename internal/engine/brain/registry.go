package brain

import (
	"context"
	"sort"
	"sync"
)

// StoreFactory creates a TimelineStore bound to the given tenant. It is called
// once per new Engine, just before the tick loop starts. A nil return means
// "no durable store for this tenant" — the engine operates in-memory only.
// The factory must not block indefinitely; it is invoked under the registry mutex.
type StoreFactory func(ctx context.Context, tenant string) TimelineStore

// Registry holds one brain Engine per tenant and runs each engine's tick loop.
// It is the daemon's entry point to the brain: live, per-tenant Worlds (ADR-0001:
// one World per tenant, never shared — no cross-tenant anything). The read path
// (WorldService / TimelineService) and event ingest both go through here.
type Registry struct {
	ctx          context.Context
	mu           sync.Mutex
	engines      map[string]*Engine
	systems      []System        // installed on every per-tenant engine (e.g. belief, orchestrator)
	hooks        []func(*Engine) // run once per engine at creation (e.g. WireExecutor)
	storeFactory StoreFactory    // optional: creates a per-tenant TimelineStore (ADR-0011)
}

// NewRegistry returns a Registry. The systems are installed on each engine as it
// is created; they must be stateless w.r.t. a specific engine (they operate on
// the *World passed at call time), so the same closures serve every tenant.
func NewRegistry(ctx context.Context, systems ...System) *Registry {
	return &Registry{ctx: ctx, engines: make(map[string]*Engine), systems: systems}
}

// OnEngine registers a hook run once for each engine at creation, after its
// systems are installed and before its tick loop starts. The daemon uses this to
// WireExecutor (dispatch + Decider) onto every per-tenant engine. Call before any
// For().
func (r *Registry) OnEngine(fn func(*Engine)) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.hooks = append(r.hooks, fn)
}

// WithStoreFactory installs a StoreFactory that is called once per new Engine to
// produce the per-tenant durable TimelineStore (ADR-0011). The factory is called
// under the registry mutex so it must not block indefinitely or call For(). Set
// this before the first For() call (i.e. before any engine is created).
//
// If the factory returns nil the engine operates in-memory only (backward-compat).
func (r *Registry) WithStoreFactory(f StoreFactory) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.storeFactory = f
}

// For returns the tenant's Engine, creating and starting its tick loop on first
// use. On first creation the store factory (if set) is invoked to wire durable
// persistence and hydrate the World from the persisted Timeline (ADR-0011).
// Tenant isolation is structural: each tenant gets its own Engine + World.
func (r *Registry) For(tenant string) *Engine {
	r.mu.Lock()
	defer r.mu.Unlock()
	if e, ok := r.engines[tenant]; ok {
		return e
	}
	e := NewEngine(tenant)
	for _, s := range r.systems {
		e.AddSystem(s)
	}
	for _, h := range r.hooks {
		h(e)
	}
	// Wire the durable store and hydrate the World before the tick loop starts.
	// Hydrate is a pure fold (no effects); it submits ResumeFailInFlight events
	// to the intake queue so the first tick fails dangling in-flight work.
	if r.storeFactory != nil {
		if store := r.storeFactory(r.ctx, tenant); store != nil {
			e.WithStore(store)
			e.Hydrate(r.ctx)
		}
	}
	r.engines[tenant] = e
	go e.Run(r.ctx)
	return e
}

// Tenants returns the ids of currently-live tenant engines, sorted.
func (r *Registry) Tenants() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]string, 0, len(r.engines))
	for t := range r.engines {
		out = append(out, t)
	}
	sort.Strings(out)
	return out
}
