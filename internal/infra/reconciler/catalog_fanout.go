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

	"github.com/zeroroot-ai/gibson/internal/platform/authz"
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

// systemComponentObject is the synthetic component object the `system_tenant`
// deriver targets for the COMPONENT-identity client RPCs (ext-authz resolves
// `object_type: component, object_deriver: system_tenant` to this). It is the
// platform's client/mission backplane, not a catalog item, so it is never
// `platform_enabled` and never enters the catalog fan-out below. ADR-0046
// (option B) makes it executable by seeding a universal `tenant_enabled`
// baseline for it on every tenant — written DIRECTLY here, never via
// `platform_enabled`, so the synthetic object cannot leak into discovery /
// catalog enumerations (which enumerate platform_enabled components).
const systemComponentObject = "component:_system"

// tick performs a single reconciliation pass: enumerate the tenants, seed the
// `component:_system` baseline (ADR-0046 option B), and fan the platform
// catalog (`platform_enabled` items) out as `tenant_enabled` per tenant.
func (r *CatalogFanout) tick(ctx context.Context) {
	// Tenants: enumerate tenant:X from system_tenant:_system#parent (per
	// model.fga). The `parent` userset is typed [tenant], so the default
	// ListUsers (hardcoded user-filter "user") would have OpenFGA reject the
	// request — we need the typed ListUsersOfType. It is concrete-only on the
	// FGA authorizer (not on the authz.Authorizer interface, to avoid the
	// mock cascade), so type-assert; a non-FGA authorizer simply seeds nothing.
	tenantLister, ok := r.cfg.Authorizer.(interface {
		ListUsersOfType(ctx context.Context, objectType, object, relation, userType string) ([]string, error)
	})
	if !ok {
		r.cfg.Logger.Debug("catalog fanout: authorizer does not support typed tenant enumeration, loop idle")
		return
	}
	tenantRefs, err := tenantLister.ListUsersOfType(ctx, "system_tenant", "system_tenant:_system", "parent", "tenant")
	if err != nil {
		r.cfg.Logger.Debug("catalog fanout: list tenants via parent failed", "err", err)
		tenantRefs = nil
	}
	// ListUsersOfType returns fully-qualified "tenant:<id>" refs; the loop
	// below re-derives tenantRef from the bare id, so strip the prefix here.
	tenantIDs := make([]string, 0, len(tenantRefs))
	for _, ref := range tenantRefs {
		tenantIDs = append(tenantIDs, extractTenantID(ref))
	}
	if len(tenantIDs) == 0 {
		// No tenants registered as parents of the system tenant. Normal in dev
		// with a single empty tenant — exit quietly.
		return
	}

	// Platform catalog: components flagged platform_enabled by the system
	// tenant (`platform_enabled: [system_tenant]`, so only _system publishes).
	// May be empty — the _system baseline below is written regardless.
	catalog, err := r.cfg.Authorizer.ListObjects(ctx, "system_tenant:_system", "platform_enabled", "component")
	if err != nil {
		r.cfg.Logger.Warn("catalog fanout: list platform catalog failed", "err", err)
		catalog = nil
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
			// Tolerate unprefixed ListObjects results.
			existingSet["component:"+e] = struct{}{}
		}
		// Option-B baseline: the system backplane is tenant_enabled for every
		// tenant so `component:_system` satisfies in_tenant_catalog (the
		// per-principal direct_execute grant is the real gate, ADR-0046).
		if _, have := existingSet[systemComponentObject]; !have {
			toWrite = append(toWrite, authz.Tuple{
				User:     tenantRef,
				Relation: "tenant_enabled",
				Object:   systemComponentObject,
			})
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

// extractTenantID strips a leading "tenant:" type prefix from an FGA user
// reference, tolerating an already-bare id. "tenant:acme" → "acme".
func extractTenantID(ref string) string {
	const pfx = "tenant:"
	if len(ref) >= len(pfx) && ref[:len(pfx)] == pfx {
		return ref[len(pfx):]
	}
	return ref
}
