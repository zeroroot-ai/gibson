// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package brain

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"sync"
)

// StoreFactory creates the durable TimelineStore of the given tenant (ADR-0163).
// It is called once per new Engine, just before the tick loop starts. A tenant
// has one durable Timeline, so a factory that cannot build the store returns
// an error, and Registry.For builds no serving engine for that tenant. A nil
// store with no error is a programming error, and For treats it the same way.
// The factory must not block indefinitely; it is invoked under the registry mutex.
type StoreFactory func(ctx context.Context, tenant string) (TimelineStore, error)

// errNoTimelineStore is the cause of a stopped engine whose store factory
// returned a nil store and no error.
var errNoTimelineStore = errors.New("brain/registry: the store factory returned no Timeline store")

// Registry holds one brain Engine per tenant and runs each engine's tick loop.
// It is the daemon's entry point to the brain: live, per-tenant Worlds (ADR-0101:
// one World per tenant, never shared — no cross-tenant anything). The read path
// (WorldService / TimelineService) and event ingest both go through here.
type Registry struct {
	ctx          context.Context
	mu           sync.Mutex
	engines      map[string]*Engine
	systems      []System        // installed on every per-tenant engine (e.g. belief, orchestrator)
	hooks        []func(*Engine) // run once per engine at creation (e.g. WireExecutor)
	storeFactory StoreFactory    // optional: creates a per-tenant TimelineStore (ADR-0163)
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
// produce the per-tenant durable TimelineStore (ADR-0163). The factory is called
// under the registry mutex so it must not block indefinitely or call For(). Set
// this before the first For() call (i.e. before any engine is created).
func (r *Registry) WithStoreFactory(f StoreFactory) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.storeFactory = f
}

// For returns the tenant's Engine, creating and starting its tick loop on first
// use. On first creation the store factory (if set) is invoked to wire durable
// persistence and hydrate the World from the persisted Timeline (ADR-0163).
// Tenant isolation is structural: each tenant gets its own Engine + World.
//
// When the store factory or the hydrate fails, For returns a stopped engine
// whose Err is the cause. For does not keep that engine, so the next call tries
// again. An
// engine that stops later (a durable append failed) also leaves the Registry,
// and the next call builds a new engine from the durable store. A caller that
// serves data to a user must check Err first.
func (r *Registry) For(tenant string) *Engine {
	r.mu.Lock()
	defer r.mu.Unlock()
	if e, ok := r.engines[tenant]; ok {
		return e
	}
	e := NewEngine(tenant)
	// Wire the durable store and hydrate the World first. Hydrate is a pure fold
	// (no effects); it submits ResumeFailInFlight events to the intake queue so
	// the first tick fails dangling in-flight work. A failed hydrate installs no
	// system and no hook, so nothing runs for an engine that does not serve.
	if r.storeFactory != nil {
		store, err := r.storeFactory(r.ctx, tenant)
		switch {
		case err != nil:
			e.stop(fmt.Errorf("brain/registry: the Timeline store of tenant %q: %w", tenant, err))
			return e
		case store == nil:
			e.stop(errNoTimelineStore)
			return e
		}
		e.WithStore(store)
		if err := e.Hydrate(r.ctx); err != nil {
			e.stop(err)
			return e
		}
	}
	for _, s := range r.systems {
		e.AddSystem(s)
	}
	for _, h := range r.hooks {
		h(e)
	}
	e.onStop = r.drop
	r.engines[tenant] = e
	go e.Run(r.ctx)
	return e
}

// drop removes a stopped engine, so the next For builds a new one. The tick
// goroutine of the engine calls it. It removes only that engine, never a newer
// engine of the same tenant.
func (r *Registry) drop(e *Engine) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.engines[e.World.Tenant] == e {
		delete(r.engines, e.World.Tenant)
	}
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
