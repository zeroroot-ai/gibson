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

// ConnectorTokenConfig wires the token refresher loop to its dependencies.
type ConnectorTokenConfig struct {
	// Catalog enumerates the connectors each tenant has enabled — the same
	// desired set the sandbox reconciler launches. A connector outside it has
	// no running bridge, so a warm token would only generate vendor traffic.
	Catalog   CatalogSource
	Freshener TokenFreshener
	Logger    *slog.Logger
	// Interval between passes. Zero defaults to 5m. The freshener's expiry
	// skew must exceed this interval, or a token can die between passes.
	Interval time.Duration
}

// ConnectorTokenReconciler mints fresh vendor access tokens ahead of expiry
// for every enabled connector with a grant (ADR-0061). A per-connector
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
		switch {
		case err != nil:
			// The error carries the vendor's error code and never credential
			// material (connectorauth's contract), so logging it is what makes
			// a dying grant visible to whoever reads the logs. The freshener
			// has already recorded the reason for GetConnectorAuthStatus, so
			// the ConnectorInstance reports Degraded within one pass.
			r.cfg.Logger.Warn("connector-token: refresh failed",
				"tenant", d.Tenant.String(), "connector", d.Connector, "err", err)
		case refreshed:
			r.cfg.Logger.Info("connector-token: refreshed access token",
				"tenant", d.Tenant.String(), "connector", d.Connector)
		}
		// The connector operator publishes the token into the connector-cred
		// Secret. It reads the token through GetConnectorCredential, which
		// withholds a token past its expiry (ADR-0061, gibson#663).
	}
}
