package manifest

import (
	"context"
	"log/slog"
	"strings"
	"sync"
	"time"
)

func nowMicro() int64 { return time.Now().UnixMicro() }

// notifier is the concrete ManifestNotifier — wraps a VersionStore and
// an Invalidator so every write-path call site can invoke a single
// Notify. Safe for concurrent use.
type notifier struct {
	versions VersionStore
	inv      Invalidator
	log      *slog.Logger

	// systemFanout, when non-nil, enumerates every tenant that must be
	// notified for _system mutations. If nil, _system mutations notify
	// only the literal "_system" tenant; production deployments should
	// wire a fanout that returns the real tenant list.
	systemFanout SystemTenantEnumerator

	// dedupWindow keeps repeated notifications for the same (tenant, reason)
	// from flooding Redis during tight write loops. A 100ms window is
	// tight enough to catch burst writes and loose enough to never stall.
	dedupWindow time.Duration
	recent      sync.Map // key: tenant+"|"+reason → lastFiredUnixMicro (int64)
}

// SystemTenantEnumerator returns every tenant ID that should be
// invalidated when a _system component or policy changes. Implementations
// typically list tenants from the tenant-operator state store.
type SystemTenantEnumerator interface {
	AllTenantIDs(ctx context.Context) ([]string, error)
}

// NewNotifier constructs a ManifestNotifier. If log is nil, slog.Default
// is used. If systemFanout is nil, _system mutations notify only the
// literal "_system" tenant (suitable for single-tenant dev deployments).
func NewNotifier(versions VersionStore, inv Invalidator, systemFanout SystemTenantEnumerator, log *slog.Logger) ManifestNotifier {
	if log == nil {
		log = slog.Default()
	}
	return &notifier{
		versions:     versions,
		inv:          inv,
		log:          log,
		systemFanout: systemFanout,
		dedupWindow:  100 * time.Millisecond,
	}
}

// Notify bumps the tenant's manifest version and publishes the
// invalidation event. "_system" as tenantID fans out to every tenant
// returned by systemFanout (or to literal "_system" if no enumerator
// is wired).
//
// Failures NEVER propagate — the write-path caller is not allowed to
// fail or stall because manifest notification is downstream cleanup.
func (n *notifier) Notify(ctx context.Context, tenantID string, reason string) {
	if tenantID == "" {
		return
	}

	if tenantID == "_system" {
		n.fanoutSystem(ctx, reason)
		return
	}
	n.notifyOne(ctx, tenantID, reason)
}

func (n *notifier) notifyOne(ctx context.Context, tenantID, reason string) {
	// Dedup: if an identical notification has just been fired, skip.
	key := tenantID + "|" + reason
	now := nowMicro()
	if prior, ok := n.recent.Load(key); ok {
		if now-prior.(int64) < n.dedupWindow.Microseconds() {
			return
		}
	}
	n.recent.Store(key, now)

	if _, err := n.versions.Bump(ctx, tenantID); err != nil {
		n.log.Warn("manifest: Bump failed (non-fatal)", "tenant", tenantID, "reason", reason, "error", err)
		// Still try to publish — Bump + Publish are independent.
	}
	n.inv.Publish(ctx, tenantID, reason)
}

func (n *notifier) fanoutSystem(ctx context.Context, reason string) {
	if n.systemFanout == nil {
		// Dev fallback: fire a single event on literal "_system" so the
		// watch-subscriber receives it. Production wires a real enumerator.
		n.notifyOne(ctx, "_system", "system:"+reason)
		return
	}
	tenants, err := n.systemFanout.AllTenantIDs(ctx)
	if err != nil {
		n.log.Warn("manifest: system fanout enumeration failed (non-fatal — TTL refresh will catch up)",
			"reason", reason, "error", err)
		return
	}
	systemReason := "system:" + reason
	for _, t := range tenants {
		if t == "" || t == "_system" {
			continue
		}
		n.notifyOne(ctx, t, systemReason)
	}
}

// StaticTenantEnumerator is a simple SystemTenantEnumerator backed by a
// fixed list. Tests and dev-mode setups can use this; production wires a
// live enumerator against the tenant-operator state.
type StaticTenantEnumerator struct {
	Tenants []string
}

func (s *StaticTenantEnumerator) AllTenantIDs(_ context.Context) ([]string, error) {
	if s == nil {
		return nil, nil
	}
	return s.Tenants, nil
}

// extractTenantFromFGATuple is a best-effort helper used by the FGA
// observer wrapper to derive the affected tenant from a written tuple.
// Covers the common tuple shapes used in the Gibson model: tenant
// membership (object "tenant:<id>"), component grants (user
// "tenant:<id>#member"), and agent_principal bindings (user "user:<id>"
// with object "agent_principal:...").
//
// Returns empty string when the tenant is not derivable from the tuple
// alone; caller must substitute a sensible fallback.
func extractTenantFromFGATuple(user, relation, object string) string {
	const tenantPrefix = "tenant:"
	if strings.HasPrefix(object, tenantPrefix) {
		return strings.SplitN(object[len(tenantPrefix):], "#", 2)[0]
	}
	if strings.HasPrefix(user, tenantPrefix) {
		return strings.SplitN(user[len(tenantPrefix):], "#", 2)[0]
	}
	_ = relation
	return ""
}
