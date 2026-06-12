package reconciler

import (
	"context"
	"log/slog"
	"time"

	"github.com/zeroroot-ai/sdk/auth"
)

// ConnectorSandbox is one (tenant, connector) that should have a running
// per-tenant setec sandbox because the tenant has the connector enabled.
type ConnectorSandbox struct {
	Tenant    auth.TenantID
	Connector string // bare component name, e.g. "connector-gitlab"
}

// InventoryEntry records that a (tenant, connector) currently has a running
// sandbox with the given setec sandbox id.
type InventoryEntry struct {
	Tenant    auth.TenantID
	Connector string
	SandboxID string
}

// CatalogSource enumerates the connectors each tenant has enabled — the
// desired running set. Derived from the FGA `tenant_enabled` relation
// restricted to components whose kind is connector.
type CatalogSource interface {
	DesiredConnectors(ctx context.Context) ([]ConnectorSandbox, error)
}

// ManifestSource returns the raw connector manifest YAML for a (tenant,
// connector). found is false when no manifest is on record (e.g. a stale
// tenant_enabled tuple whose definition is gone) — the reconciler skips it
// rather than launching.
type ManifestSource interface {
	ConnectorManifest(ctx context.Context, tenant auth.TenantID, connector string) (manifestYAML []byte, found bool, err error)
}

// IdentityMinter mints a single-use bootstrap token + a (tenant, connector)
// capability-grant principal for a per-tenant connector launch, and revokes a
// principal when a launch is rolled back. Mirrors the register-path identity
// lifecycle so a failed launch never leaks a principal.
type IdentityMinter interface {
	MintConnectorPrincipal(ctx context.Context, tenant auth.TenantID, connector string) (principalID, bootstrapToken string, err error)
	RevokeConnectorPrincipal(ctx context.Context, principalID string) error
}

// Launcher launches one hosted connector sandbox from a manifest + bootstrap
// token and returns the setec sandbox id. Same primitive the register path
// uses (internal/connector.Launcher).
type Launcher interface {
	Launch(ctx context.Context, tenant auth.TenantID, manifestYAML []byte, bootstrapToken string) (sandboxID string, err error)
}

// Inventory is the durable record of which (tenant, connector) has which
// running sandbox. List drives idempotency; Put records a launch. (Delete
// arrives with the teardown slice.)
type Inventory interface {
	List(ctx context.Context) ([]InventoryEntry, error)
	Put(ctx context.Context, entry InventoryEntry) error
}

// ConnectorSandboxConfig wires the reconciler to its dependencies.
type ConnectorSandboxConfig struct {
	Catalog   CatalogSource
	Manifest  ManifestSource
	Identity  IdentityMinter
	Launcher  Launcher
	Inventory Inventory
	Logger    *slog.Logger
	// Interval between reconcile ticks. Zero defaults to 30s.
	Interval time.Duration
}

// ConnectorSandboxReconciler ensures exactly one running per-tenant setec
// sandbox for every connector a tenant has enabled (eager on-enable launch,
// gibson#722). Idempotent and self-healing: re-running with no change
// produces zero launches; a per-connector launch failure is logged and does
// not stall the others. Same desired-state pattern as CatalogFanout.
type ConnectorSandboxReconciler struct {
	cfg ConnectorSandboxConfig
}

// NewConnectorSandboxReconciler validates defaults and constructs the loop.
func NewConnectorSandboxReconciler(cfg ConnectorSandboxConfig) *ConnectorSandboxReconciler {
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if cfg.Interval == 0 {
		cfg.Interval = 30 * time.Second
	}
	return &ConnectorSandboxReconciler{cfg: cfg}
}

// Run reconciles once at startup then enters the tick loop until ctx is
// cancelled. Started by daemon.Start alongside the other reconcilers.
func (r *ConnectorSandboxReconciler) Run(ctx context.Context) {
	if r.cfg.Catalog == nil || r.cfg.Launcher == nil || r.cfg.Inventory == nil ||
		r.cfg.Manifest == nil || r.cfg.Identity == nil {
		r.cfg.Logger.Warn("connector-sandbox reconciler: dependencies not wired, loop disabled")
		return
	}
	ticker := time.NewTicker(r.cfg.Interval)
	defer ticker.Stop()
	r.reconcile(ctx)
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			r.reconcile(ctx)
		}
	}
}

// key uniquely identifies a (tenant, connector) pair.
func key(tenant auth.TenantID, connector string) string {
	return tenant.String() + "\x00" + connector
}

// reconcile performs a single launch-missing pass: for every desired
// connector not already in the inventory, mint an identity, launch a sandbox,
// and record it. Errors on one connector are logged and skipped so one bad
// connector never blocks the rest.
func (r *ConnectorSandboxReconciler) reconcile(ctx context.Context) {
	desired, err := r.cfg.Catalog.DesiredConnectors(ctx)
	if err != nil {
		r.cfg.Logger.Warn("connector-sandbox: list desired connectors failed", "err", err)
		return
	}
	if len(desired) == 0 {
		return
	}

	running, err := r.cfg.Inventory.List(ctx)
	if err != nil {
		r.cfg.Logger.Warn("connector-sandbox: list inventory failed", "err", err)
		return
	}
	runningSet := make(map[string]struct{}, len(running))
	for _, e := range running {
		runningSet[key(e.Tenant, e.Connector)] = struct{}{}
	}

	for _, d := range desired {
		if _, ok := runningSet[key(d.Tenant, d.Connector)]; ok {
			continue // already running — idempotent no-op
		}

		manifest, found, err := r.cfg.Manifest.ConnectorManifest(ctx, d.Tenant, d.Connector)
		if err != nil {
			r.cfg.Logger.Warn("connector-sandbox: fetch manifest failed, skipping",
				"tenant", d.Tenant.String(), "connector", d.Connector, "err", err)
			continue
		}
		if !found {
			// Stale tenant_enabled whose definition is gone — do not launch.
			r.cfg.Logger.Debug("connector-sandbox: no manifest on record, skipping",
				"tenant", d.Tenant.String(), "connector", d.Connector)
			continue
		}

		principalID, token, err := r.cfg.Identity.MintConnectorPrincipal(ctx, d.Tenant, d.Connector)
		if err != nil {
			r.cfg.Logger.Warn("connector-sandbox: mint principal failed, skipping",
				"tenant", d.Tenant.String(), "connector", d.Connector, "err", err)
			continue
		}

		sandboxID, err := r.cfg.Launcher.Launch(ctx, d.Tenant, manifest, token)
		if err != nil {
			// Roll back the principal so a failed launch never leaks identity.
			if rerr := r.cfg.Identity.RevokeConnectorPrincipal(ctx, principalID); rerr != nil {
				r.cfg.Logger.Warn("connector-sandbox: revoke after failed launch also failed",
					"principal", principalID, "err", rerr)
			}
			r.cfg.Logger.Warn("connector-sandbox: launch failed, skipping",
				"tenant", d.Tenant.String(), "connector", d.Connector, "err", err)
			continue
		}

		if err := r.cfg.Inventory.Put(ctx, InventoryEntry{
			Tenant:    d.Tenant,
			Connector: d.Connector,
			SandboxID: sandboxID,
		}); err != nil {
			r.cfg.Logger.Warn("connector-sandbox: record inventory failed",
				"tenant", d.Tenant.String(), "connector", d.Connector, "sandbox", sandboxID, "err", err)
			continue
		}
		r.cfg.Logger.Info("connector-sandbox: launched",
			"tenant", d.Tenant.String(), "connector", d.Connector, "sandbox", sandboxID)
	}
}
