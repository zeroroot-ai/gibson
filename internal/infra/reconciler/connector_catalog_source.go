package reconciler

import (
	"context"
	"fmt"
	"log/slog"
	"strings"

	"github.com/zeroroot-ai/gibson/internal/platform/authz"
	"github.com/zeroroot-ai/sdk/auth"
)

// FGACatalogSource derives the desired per-tenant connector set from FGA: for
// every tenant, every component it has `tenant_enabled` that also has a
// connector manifest on record is a desired connector sandbox. The manifest
// store doubles as the "is this component a connector" oracle (only connectors
// have manifests), and its _system fallback means shared connectors are
// recognised the same way as BYO ones. Same tenant-enumeration pattern as
// CatalogFanout. Satisfies CatalogSource.
type FGACatalogSource struct {
	Authorizer authz.Authorizer
	Manifest   ManifestSource
	Logger     *slog.Logger
}

// DesiredConnectors enumerates tenants, then per tenant the components it has
// tenant_enabled, keeping those that have a connector manifest on record.
func (s *FGACatalogSource) DesiredConnectors(ctx context.Context) ([]ConnectorSandbox, error) {
	logger := s.Logger
	if logger == nil {
		logger = slog.Default()
	}

	// Tenants are users of system_tenant:_system#parent (typed [tenant]); the
	// default user-filter would be rejected, so use the typed enumeration. It
	// is concrete-only on the FGA authorizer (not on the interface, to avoid a
	// mock cascade), so type-assert — mirrors CatalogFanout.
	tenantLister, ok := s.Authorizer.(interface {
		ListUsersOfType(ctx context.Context, objectType, object, relation, userType string) ([]string, error)
	})
	if !ok {
		logger.Debug("connector catalog source: authorizer does not support typed tenant enumeration, no desired connectors")
		return nil, nil
	}
	tenantRefs, err := tenantLister.ListUsersOfType(ctx, "system_tenant", "system_tenant:_system", "parent", "tenant")
	if err != nil {
		return nil, err
	}
	if len(tenantRefs) == 0 {
		return nil, nil
	}

	// Any enumeration failure fails the whole pass: the desired set drives a
	// DESTRUCTIVE terminate-orphaned reconcile (gibson#723), so a silently
	// partial list would look like "these connectors are no longer enabled"
	// and tear down healthy sandboxes. Better to do nothing this tick and
	// retry than to act on incomplete state. (A malformed tenant id is data
	// corruption, not a transient read failure, so it is skipped, not fatal.)
	var desired []ConnectorSandbox
	for _, ref := range tenantRefs {
		tenantID := extractTenantID(ref)
		tid, err := auth.NewTenantID(tenantID)
		if err != nil {
			logger.Warn("connector catalog source: skipping malformed tenant id", "ref", ref, "err", err)
			continue
		}
		enabled, err := s.Authorizer.ListObjects(ctx, "tenant:"+tenantID, "tenant_enabled", "component")
		if err != nil {
			return nil, fmt.Errorf("connector catalog source: list tenant_enabled for %q: %w", tenantID, err)
		}
		for _, comp := range enabled {
			name := strings.TrimPrefix(comp, "component:")
			if name == "_system" {
				continue // the synthetic backplane object is never a connector
			}
			_, found, err := s.Manifest.ConnectorManifest(ctx, tid, name)
			if err != nil {
				return nil, fmt.Errorf("connector catalog source: manifest lookup for (%s, %s): %w", tenantID, name, err)
			}
			if !found {
				continue // not a connector (or definition gone) — not desired
			}
			desired = append(desired, ConnectorSandbox{Tenant: tid, Connector: name})
		}
	}
	return desired, nil
}
