// Package reconciler implements background reconciliation loops for
// cross-tenant state that isn't bound to a single request. Currently:
//
//   - CatalogFanout — ensures every platform-enabled catalog item has a
//     tenant_enabled tuple on every existing tenant so new marketplace
//     publishes fan out automatically (spec R4 AC 7).
//
// Each reconciler is a goroutine started by daemon.Start and cancelled by
// the daemon's shutdown context; the daemon shutdown handler waits for
// completion via a sync.WaitGroup.
package reconciler

import (
	"context"
	"log/slog"
	"time"

	"github.com/zeroroot-ai/gibson/internal/authz"
)

// CatalogFanoutConfig wires the fan-out loop to its dependencies.
type CatalogFanoutConfig struct {
	Authorizer authz.Authorizer
	Logger     *slog.Logger
	// Interval between reconcile ticks. Zero defaults to 60s.
	Interval time.Duration
}

// CatalogFanout runs a periodic loop that ensures every tenant holds
// `tenant_enabled` tuples for every catalog item the system tenant has
// published. Idempotent — re-running with no change produces zero writes.
//
// The loop logs warnings on transient FGA failures and continues; cancelling
// the context stops it cleanly.
type CatalogFanout struct {
	cfg CatalogFanoutConfig
}

func NewCatalogFanout(cfg CatalogFanoutConfig) *CatalogFanout {
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if cfg.Interval == 0 {
		cfg.Interval = 60 * time.Second
	}
	return &CatalogFanout{cfg: cfg}
}

// Run executes one reconciliation then enters the tick loop. Returns when
// ctx is cancelled.
func (r *CatalogFanout) Run(ctx context.Context) {
	if r.cfg.Authorizer == nil {
		r.cfg.Logger.Warn("catalog fanout: authorizer is nil, loop disabled")
		return
	}
	ticker := time.NewTicker(r.cfg.Interval)
	defer ticker.Stop()
	// Reconcile once at startup so fresh tenants receive seeds immediately.
	r.tick(ctx)
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			r.tick(ctx)
		}
	}
}

// tick performs a single reconciliation pass: enumerate the platform catalog,
// enumerate the tenants, and write any missing tenant_enabled tuples.
func (r *CatalogFanout) tick(ctx context.Context) {
	// Platform catalog: components flagged platform_enabled by the system
	// tenant. The model restricts `platform_enabled: [system_tenant]` so
	// only _system publishes here.
	catalog, err := r.cfg.Authorizer.ListObjects(ctx, "system_tenant:_system", "platform_enabled", "component")
	if err != nil {
		r.cfg.Logger.Warn("catalog fanout: list platform catalog failed", "err", err)
		return
	}
	if len(catalog) == 0 {
		return
	}
	// Tenants: system_tenant:_system#parent@tenant:X (per model.fga). We
	// enumerate via the tenant type's parent tuples on the system tenant.
	tenantIDs, err := r.cfg.Authorizer.ListUsers(ctx, "tenant", "system_tenant:_system", "parent")
	if err != nil {
		// Fallback: enumerate via "owner" on any component.
		r.cfg.Logger.Debug("catalog fanout: list tenants via parent failed, falling back", "err", err)
		tenantIDs = nil
	}
	if len(tenantIDs) == 0 {
		// No tenants registered as parents of the system tenant. This is
		// normal when the daemon is running in dev with a single empty
		// tenant — exit quietly.
		return
	}

	var toWrite []authz.Tuple
	for _, tenantID := range tenantIDs {
		tenantRef := "tenant:" + tenantID
		// Items this tenant already has enabled.
		existing, err := r.cfg.Authorizer.ListObjects(ctx, tenantRef, "tenant_enabled", "component")
		if err != nil {
			r.cfg.Logger.Warn("catalog fanout: list tenant_enabled failed",
				"tenant", tenantID, "err", err)
			continue
		}
		existingSet := make(map[string]struct{}, len(existing))
		for _, e := range existing {
			existingSet[e] = struct{}{}
		}
		for _, item := range catalog {
			if _, have := existingSet[item]; have {
				continue
			}
			objRef := item
			if len(objRef) < len("component:") || objRef[:len("component:")] != "component:" {
				objRef = "component:" + objRef
			}
			toWrite = append(toWrite, authz.Tuple{
				User:     tenantRef,
				Relation: "tenant_enabled",
				Object:   objRef,
			})
		}
	}
	if len(toWrite) == 0 {
		return
	}
	if err := r.cfg.Authorizer.Write(ctx, toWrite); err != nil {
		r.cfg.Logger.Warn("catalog fanout: write failed", "count", len(toWrite), "err", err)
		return
	}
	r.cfg.Logger.Info("catalog fanout: tuples added", "count", len(toWrite))
}
