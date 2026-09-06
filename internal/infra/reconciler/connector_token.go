// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package reconciler

import (
	"context"
	"log/slog"
	"time"

	"github.com/zeroroot-ai/sdk/auth"
)

// TokenFreshener keeps one connector's vendor access token fresh. The daemon
// wiring adapts connectorauth.Refresher to this shape: it scopes the secret
// store to the tenant, treats "no grant stored" as a quiet no-op, and records
// the outcome for the status RPC. The reconciler itself stays ignorant of all
// of that — it only walks the enabled set on a clock.
type TokenFreshener interface {
	EnsureFresh(ctx context.Context, tenant auth.TenantID, connector string) (refreshed bool, err error)
}

// Materializer publishes one connector's fresh access token into the place the
// ToolHive proxy reads it — the tenant-namespace Secret <connector>-connector-cred
// whose "authorization" key is the full "Bearer <token>" header (ADR-0015). The
// daemon wiring adapts a kube client plus the tenant secret store to this shape;
// the reconciler stays ignorant of Kubernetes, exactly as it does for the store
// behind TokenFreshener.
//
// Materialize is idempotent and safe to call every pass: it creates the Secret
// or updates it in place, self-healing a Secret that was deleted or never
// written. It reports "no token stored yet" as a quiet success (nil), so an
// authorized-but-not-yet-minted connector produces no log noise.
type Materializer interface {
	Materialize(ctx context.Context, desired ConnectorSandbox) error
}

// ConnectorTokenConfig wires the token refresher loop to its dependencies.
type ConnectorTokenConfig struct {
	// Catalog enumerates the connectors each tenant has enabled — the same
	// desired set the sandbox reconciler launches. A connector outside it has
	// no running bridge, so a warm token would only generate vendor traffic.
	Catalog   CatalogSource
	Freshener TokenFreshener
	// Materializer writes each connector's access token into its
	// <connector>-connector-cred Secret (ADR-0015). Optional: a detached
	// daemon with no kube client leaves it nil and the loop only refreshes.
	Materializer Materializer
	Logger       *slog.Logger
	// Interval between passes. Zero defaults to 5m. The freshener's expiry
	// skew must exceed this interval, or a token can die between passes.
	Interval time.Duration
}

// ConnectorTokenReconciler mints fresh vendor access tokens ahead of expiry
// for every enabled connector with a grant (ADR-0064). A per-connector
// refresh failure is logged and isolated so one revoked grant never stalls
// the others.
type ConnectorTokenReconciler struct {
	cfg ConnectorTokenConfig
}

// NewConnectorTokenReconciler validates defaults and constructs the loop.
func NewConnectorTokenReconciler(cfg ConnectorTokenConfig) *ConnectorTokenReconciler {
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if cfg.Interval == 0 {
		cfg.Interval = 5 * time.Minute
	}
	return &ConnectorTokenReconciler{cfg: cfg}
}

// Run refreshes once at startup then enters the tick loop until ctx is
// cancelled. Started by daemon.Start alongside the other reconcilers.
func (r *ConnectorTokenReconciler) Run(ctx context.Context) {
	if r.cfg.Catalog == nil || r.cfg.Freshener == nil {
		r.cfg.Logger.Warn("connector-token reconciler: dependencies not wired, loop disabled")
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

// reconcile walks the enabled set once. Enumeration failure skips the whole
// pass (a partial list is indistinguishable from a shrunken one); a
// per-connector failure is logged and isolated.
func (r *ConnectorTokenReconciler) reconcile(ctx context.Context) {
	desired, err := r.cfg.Catalog.DesiredConnectors(ctx)
	if err != nil {
		r.cfg.Logger.Warn("connector-token: list desired connectors failed", "err", err)
		return
	}
	for _, d := range desired {
		refreshed, err := r.cfg.Freshener.EnsureFresh(ctx, d.Tenant, d.Connector)
		if err != nil {
			// The error carries the vendor's error code and never credential
			// material (connectorauth's contract), so logging it is what makes
			// a dying grant visible to whoever reads the logs.
			r.cfg.Logger.Warn("connector-token: refresh failed",
				"tenant", d.Tenant.String(), "connector", d.Connector, "err", err)
			continue
		}
		if refreshed {
			r.cfg.Logger.Info("connector-token: refreshed access token",
				"tenant", d.Tenant.String(), "connector", d.Connector)
		}
		// Publish the token into the connector-cred Secret every pass, not only
		// on a refresh: the token may be fresh in the store while the Secret is
		// missing (a fresh restart, a deleted Secret, a proxy pod that never
		// started). Materialize is idempotent, so a healthy connector is a
		// cheap no-op. A failure here is logged and isolated, exactly like a
		// refresh failure, so one connector never stalls the others.
		if r.cfg.Materializer == nil {
			continue
		}
		if err := r.cfg.Materializer.Materialize(ctx, d); err != nil {
			// The error names the tenant and connector but never the token
			// bytes (the materializer's contract), so logging it is what makes
			// a stuck credential visible.
			r.cfg.Logger.Warn("connector-token: materialize secret failed",
				"tenant", d.Tenant.String(), "connector", d.Connector, "err", err)
			continue
		}
	}
}
