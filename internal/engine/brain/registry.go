package brain

import (
	"context"
	"sort"
	"sync"
)

// Registry holds one brain Engine per tenant and runs each engine's tick loop.
// It is the daemon's entry point to the brain: live, per-tenant Worlds (ADR-0001:
// one World per tenant, never shared — no cross-tenant anything). The read path
// (WorldService / TimelineService) and event ingest both go through here.
type Registry struct {
	ctx     context.Context
	mu      sync.Mutex
	engines map[string]*Engine
	systems []System        // installed on every per-tenant engine (e.g. belief, orchestrator)
	hooks   []func(*Engine) // run once per engine at creation (e.g. WireExecutor)
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

// For returns the tenant's Engine, creating and starting its tick loop on first
// use. Tenant isolation is structural: each tenant gets its own Engine + World.
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
