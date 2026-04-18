package manifest

import (
	"context"
	"log/slog"

	"github.com/zero-day-ai/gibson/internal/component"
)

// RegistryObserver wraps a component.ComponentRegistry and fires
// ManifestNotifier on Register/Deregister so manifest caches learn
// about liveness changes. Read-only methods pass through.
//
// Wrap the real registry once at daemon init; every existing write call
// site is covered without further changes.
type RegistryObserver struct {
	inner    component.ComponentRegistry
	notifier ManifestNotifier
	log      *slog.Logger
}

// NewRegistryObserver wraps inner with notification emissions.
func NewRegistryObserver(inner component.ComponentRegistry, notifier ManifestNotifier, log *slog.Logger) *RegistryObserver {
	if log == nil {
		log = slog.Default()
	}
	return &RegistryObserver{inner: inner, notifier: notifier, log: log}
}

// Register forwards to inner, then Notify on success. "_system" tenant
// triggers fanout inside the notifier.
func (o *RegistryObserver) Register(ctx context.Context, tenant, kind, name string, info component.ComponentInfo) (string, error) {
	id, err := o.inner.Register(ctx, tenant, kind, name, info)
	if err != nil {
		return "", err
	}
	o.notifier.Notify(ctx, tenant, "component_registered:"+kind+":"+name)
	return id, nil
}

// Deregister forwards to inner, then Notify on success.
func (o *RegistryObserver) Deregister(ctx context.Context, tenant, kind, name, instanceID string) error {
	if err := o.inner.Deregister(ctx, tenant, kind, name, instanceID); err != nil {
		return err
	}
	o.notifier.Notify(ctx, tenant, "component_deregistered:"+kind+":"+name)
	return nil
}

// RefreshTTL is a hot path — intentionally NOT a notification trigger.
// Liveness heartbeats happen every 10s and don't change the manifest's
// capability set.
func (o *RegistryObserver) RefreshTTL(ctx context.Context, tenant, kind, name, instanceID string) error {
	return o.inner.RefreshTTL(ctx, tenant, kind, name, instanceID)
}

// Read-through pass-throughs.
func (o *RegistryObserver) Discover(ctx context.Context, tenant, kind, name string) ([]component.ComponentInfo, error) {
	return o.inner.Discover(ctx, tenant, kind, name)
}
func (o *RegistryObserver) DiscoverAll(ctx context.Context, tenant, kind string) ([]component.ComponentInfo, error) {
	return o.inner.DiscoverAll(ctx, tenant, kind)
}
func (o *RegistryObserver) ListTenantComponents(ctx context.Context, tenant string) ([]component.ComponentInfo, error) {
	return o.inner.ListTenantComponents(ctx, tenant)
}
func (o *RegistryObserver) DiscoverTenantOnly(ctx context.Context, tenant, kind, name string) ([]component.ComponentInfo, error) {
	return o.inner.DiscoverTenantOnly(ctx, tenant, kind, name)
}
func (o *RegistryObserver) DiscoverSystemOnly(ctx context.Context, kind, name string) ([]component.ComponentInfo, error) {
	return o.inner.DiscoverSystemOnly(ctx, kind, name)
}

// Compile-time assertion.
var _ component.ComponentRegistry = (*RegistryObserver)(nil)
