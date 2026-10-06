// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package daemon

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"

	"github.com/zeroroot-ai/gibson/internal/engine/brain"
	"github.com/zeroroot-ai/gibson/internal/engine/ontology"
	"github.com/zeroroot-ai/gibson/internal/infra/config"
	"github.com/zeroroot-ai/gibson/internal/platform/beliefartifact"
)

// beliefPinner pins the belief version of a tenant for one mission. The
// mission manager holds one (tenantBeliefs).
type beliefPinner interface {
	Pin(ctx context.Context, tenant string) (version string, release func(), err error)
}

// initTenantBeliefs builds d.tenantBeliefs over the platform Postgres and
// starts its reload loop on belief.reload_interval. Start opens the platform
// database before it calls this, so the store is a required dependency.
func (d *daemonImpl) initTenantBeliefs(ctx context.Context, schema *ontology.BeliefSchemaRegistry) error {
	if d.platformDB == nil {
		return errNoBeliefArtifacts
	}
	beliefs, err := newTenantBeliefs(beliefartifact.NewStore(d.platformDB), schema, d.logger.Slog())
	if err != nil {
		return fmt.Errorf("failed to build the tenant belief source: %w", err)
	}
	interval := config.DefaultBeliefReloadInterval
	if d.config != nil && d.config.Belief.ReloadInterval > 0 {
		interval = d.config.Belief.ReloadInterval
	}
	d.tenantBeliefs = beliefs
	go beliefs.Run(ctx, interval)
	return nil
}

// beliefArtifacts is the read side of the belief artifact store
// (beliefartifact.Store) that the daemon uses. The trainer writes versions
// through the daemon, and the quality gate makes one current (gibson#788,
// gibson#789). This file only reads.
type beliefArtifacts interface {
	// CurrentVersions returns the current version of each tenant that has one.
	CurrentVersions(ctx context.Context) (map[string]int64, error)
	// Version returns both artifacts of one version of the tenant.
	Version(ctx context.Context, tenantID string, version int64) (beliefModel, edgePosteriors []byte, found bool, err error)
}

// errNoBeliefArtifacts reports that the tenant belief source has no store.
var errNoBeliefArtifacts = errors.New("belief artifacts: the platform database is not open")

// beliefVersionSwapsTotal counts the belief version swaps of each tenant.
var beliefVersionSwapsTotal = promauto.NewCounterVec(prometheus.CounterOpts{
	Name: "gibson_belief_version_swaps_total",
	Help: "Belief version swaps of a tenant engine (gibson#615).",
}, []string{"tenant"})

// beliefVersionLoadErrorsTotal counts failed loads of a belief version.
var beliefVersionLoadErrorsTotal = promauto.NewCounter(prometheus.CounterOpts{
	Name: "gibson_belief_version_load_errors_total",
	Help: "Failed reads or parses of a belief artifact version (gibson#615).",
})

// tenantBeliefs gives each tenant engine the belief version of its own tenant
// (ADR-0106, gibson#615).
//
// A tenant with no current version uses the embedded default model and the
// cold-start prior. That is the only fallback, and the daemon logs it once
// for each tenant.
//
// The version pin: a mission pins the active version of its tenant when it
// starts and records it (MissionStarted.BeliefModel). A new current version
// becomes active only when the tenant has no running mission, so every score
// of a running mission comes from the version it pinned. A replay reads the
// recorded version and the recorded scores. It never reads the current one.
type tenantBeliefs struct {
	// artifacts is the belief artifact store. It is required.
	artifacts beliefArtifacts
	schema    *ontology.BeliefSchemaRegistry
	defaults  *beliefSet
	logger    *slog.Logger

	mu      sync.Mutex
	tenants map[string]*tenantBelief
}

// tenantBelief is the belief state of one tenant.
type tenantBelief struct {
	tenant string
	// active is the set that the providers of the engine score with. It is
	// read on the hot path, so it is an atomic pointer.
	active atomic.Pointer[beliefSet]

	mu sync.Mutex
	// pending is a newer version that waits for the running missions of the
	// tenant to end.
	pending *beliefSet
	// running is the number of running missions that pinned a version.
	running int
	// loaded reports that the current version was read at least once.
	loaded bool
	// loggedDefault reports that the default fallback was logged.
	loggedDefault bool
}

// newTenantBeliefs builds the per-tenant belief source. The store is
// required: a nil store is an error.
func newTenantBeliefs(
	artifacts beliefArtifacts, schema *ontology.BeliefSchemaRegistry, logger *slog.Logger,
) (*tenantBeliefs, error) {
	if artifacts == nil {
		return nil, errNoBeliefArtifacts
	}
	defaults, err := defaultBeliefSet(schema)
	if err != nil {
		return nil, err
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &tenantBeliefs{
		artifacts: artifacts,
		schema:    schema,
		defaults:  defaults,
		logger:    logger.With("component", "tenant-beliefs"),
		tenants:   make(map[string]*tenantBelief),
	}, nil
}

// defaultLabel is the version that a tenant with no current version pins.
func (b *tenantBeliefs) defaultLabel() string { return b.defaults.label() }

// forTenant returns the belief state of the tenant. A new tenant starts on the
// default set and is not loaded: its first Pin reads the current version.
func (b *tenantBeliefs) forTenant(tenant string) *tenantBelief {
	b.mu.Lock()
	defer b.mu.Unlock()
	tb, ok := b.tenants[tenant]
	if !ok {
		tb = &tenantBelief{tenant: tenant}
		tb.active.Store(b.defaults)
		b.tenants[tenant] = tb
	}
	return tb
}

// known returns the belief state of each tenant that the daemon has seen,
// sorted by tenant.
func (b *tenantBeliefs) known() []*tenantBelief {
	b.mu.Lock()
	defer b.mu.Unlock()
	out := make([]*tenantBelief, 0, len(b.tenants))
	for _, tb := range b.tenants {
		out = append(out, tb)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].tenant < out[j].tenant })
	return out
}

// Pin pins the active belief version of the tenant for one mission. It returns
// the version that the mission records, and a release function that the
// mission calls once when it ends. When the tenant was not loaded yet, Pin
// reads its current version first, and an error of that read fails the pin:
// a mission never starts on a version that the daemon could not read.
func (b *tenantBeliefs) Pin(ctx context.Context, tenant string) (version string, release func(), err error) {
	tb := b.forTenant(tenant)
	tb.mu.Lock()
	loaded := tb.loaded
	tb.mu.Unlock()
	if !loaded {
		if err = b.refreshTenants(ctx, []*tenantBelief{tb}); err != nil {
			return "", nil, fmt.Errorf("pin the belief version of tenant %q: %w", tenant, err)
		}
	}

	tb.mu.Lock()
	if tb.running == 0 {
		b.promoteLocked(tb)
	}
	tb.running++
	version = tb.active.Load().label()
	tb.mu.Unlock()

	var once sync.Once
	release = func() {
		once.Do(func() {
			tb.mu.Lock()
			defer tb.mu.Unlock()
			tb.running--
			if tb.running == 0 {
				b.promoteLocked(tb)
			}
		})
	}
	return version, release, nil
}

// Refresh reads the current version of each known tenant and loads each one
// that changed. A changed version becomes active at once when the tenant has
// no running mission, and when the last running mission ends otherwise.
func (b *tenantBeliefs) Refresh(ctx context.Context) error {
	return b.refreshTenants(ctx, b.known())
}

// refreshTenants is Refresh for the given tenants.
func (b *tenantBeliefs) refreshTenants(ctx context.Context, tenants []*tenantBelief) error {
	if len(tenants) == 0 {
		return nil
	}
	store := b.artifacts
	current, err := store.CurrentVersions(ctx)
	if err != nil {
		beliefVersionLoadErrorsTotal.Inc()
		return fmt.Errorf("read the current belief versions: %w", err)
	}
	var errs []error
	for _, tb := range tenants {
		if err := b.refreshOne(ctx, store, tb, current[tb.tenant]); err != nil {
			beliefVersionLoadErrorsTotal.Inc()
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// refreshOne makes want the next version of tb. Zero means the default set.
func (b *tenantBeliefs) refreshOne(ctx context.Context, store beliefArtifacts, tb *tenantBelief, want int64) error {
	tb.mu.Lock()
	target := tb.active.Load()
	if tb.pending != nil {
		target = tb.pending
	}
	if tb.loaded && target.number == want {
		tb.mu.Unlock()
		return nil
	}
	tb.mu.Unlock()

	next := b.defaults
	if want != 0 {
		model, edges, found, err := store.Version(ctx, tb.tenant, want)
		if err != nil {
			return fmt.Errorf("tenant %q: read belief version %d: %w", tb.tenant, want, err)
		}
		if !found {
			return fmt.Errorf("tenant %q: belief version %d is current but has no row", tb.tenant, want)
		}
		set, err := storedBeliefSet(b.schema, want, model, edges)
		if err != nil {
			return fmt.Errorf("tenant %q: %w", tb.tenant, err)
		}
		next = set
	}

	tb.mu.Lock()
	defer tb.mu.Unlock()
	if want == 0 && !tb.loggedDefault {
		tb.loggedDefault = true
		b.logger.Info("tenant has no current belief version; it uses the embedded default model and the cold-start prior",
			"tenant", tb.tenant, "belief_version", next.label())
	}
	tb.loaded = true
	if tb.active.Load().number == want {
		tb.pending = nil
		return nil
	}
	tb.pending = next
	if tb.running == 0 {
		b.promoteLocked(tb)
	} else {
		b.logger.Info("a new belief version waits for the running missions of the tenant",
			"tenant", tb.tenant, "belief_version", next.label(), "running_missions", tb.running)
	}
	return nil
}

// promoteLocked makes the pending set active when the tenant has one. A
// tenant with no pending set keeps its active set. The caller holds tb.mu.
func (b *tenantBeliefs) promoteLocked(tb *tenantBelief) {
	next := tb.pending
	if next != nil {
		prev := tb.active.Swap(next)
		b.logger.Info("belief version swapped", "tenant", tb.tenant,
			"from", prev.label(), "to", next.label())
		tb.pending = nil
		beliefVersionSwapsTotal.WithLabelValues(tb.tenant).Inc()
	}
}

// Run calls Refresh every interval until ctx ends. A failed refresh is logged,
// and the tenants keep their active versions.
func (b *tenantBeliefs) Run(ctx context.Context, interval time.Duration) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if err := b.Refresh(ctx); err != nil {
				b.logger.Warn("belief version refresh failed; tenants keep their active versions", "error", err)
			}
		}
	}
}

// tenantBeliefProvider is the per-host belief provider of one tenant engine.
// It scores with the active set of the tenant.
type tenantBeliefProvider struct{ tb *tenantBelief }

func (p tenantBeliefProvider) Score(ev brain.BeliefEvidence) brain.Belief {
	return p.tb.active.Load().belief.Score(ev)
}

func (p tenantBeliefProvider) Version() string { return p.tb.active.Load().belief.Version() }

// tenantSliceBeliefProvider is the graph-coupled belief provider of one tenant
// engine. It scores with the active set of the tenant.
type tenantSliceBeliefProvider struct{ tb *tenantBelief }

func (p tenantSliceBeliefProvider) ScoreSlice(slice brain.AttackGraph) map[string]brain.NodeBelief {
	return p.tb.active.Load().slice.ScoreSlice(slice)
}

func (p tenantSliceBeliefProvider) Version() string { return p.tb.active.Load().slice.Version() }

// tenantEdgePosteriors is the strength posterior of one tenant engine, which
// the BAMCP planner samples. It reads the active set of the tenant.
type tenantEdgePosteriors struct{ tb *tenantBelief }

func (p tenantEdgePosteriors) Posterior(edgeType string) brain.EdgeStrengthPosterior {
	return p.tb.active.Load().edges.Posterior(edgeType)
}

func (p tenantEdgePosteriors) InNodeStrength(kind, child, parent string) brain.EdgeStrengthPosterior {
	return p.tb.active.Load().edges.InNodeStrength(kind, child, parent)
}

func (p tenantEdgePosteriors) Leak(kind, variable string) brain.EdgeStrengthPosterior {
	return p.tb.active.Load().edges.Leak(kind, variable)
}
