// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

// Package daemon — connector_token_adapters.go
//
// Adapters between the connector-token reconciler (internal/infra/reconciler)
// and the platform token refresher (internal/platform/connectorauth), plus
// the ConnectorAuthService wiring. The reconciler walks the enabled set on a
// clock; the adapter scopes the secret store to each tenant, treats "no grant
// stored" as a quiet no-op, and records outcomes for the status RPC
// (ADR-0064).
package daemon

import (
	"context"
	"errors"
	"fmt"
	"os"
	"time"

	"google.golang.org/grpc"

	"github.com/zeroroot-ai/sdk/auth"

	"github.com/zeroroot-ai/gibson/internal/infra/reconciler"
	"github.com/zeroroot-ai/gibson/internal/platform/connectorauth"
	"github.com/zeroroot-ai/gibson/internal/server/admin"
	tenantv1 "github.com/zeroroot-ai/gibson/internal/server/daemon/api/gibson/tenant/v1"
)

// registerConnectorAuth registers gibson.tenant.v1.ConnectorAuthService on
// srv and, when the authorizer and platform DB are present, builds the
// connector-token reconciler that Start launches. Extracted from
// buildGRPCServer so the wiring is unit-testable with a minimal daemon.
func (d *daemonImpl) registerConnectorAuth(ctx context.Context, srv *grpc.Server) {
	if d.secretsService == nil {
		tenantv1.RegisterConnectorAuthServiceServer(srv, admin.NewUnavailableConnectorAuthServer())
		return
	}

	// The skew must exceed the loop interval, or a token could expire
	// between passes while NeedsRefresh still reads "fresh".
	const connectorTokenInterval = 5 * time.Minute
	connectorRefresher, crErr := connectorauth.NewRefresher(d.secretsService, nil, nil,
		connectorauth.WithSkew(connectorTokenInterval+2*time.Minute))
	if crErr != nil {
		d.logger.Warn(ctx, "ConnectorAuthService: refresher construction failed; registering Unavailable stub",
			"error", crErr)
		tenantv1.RegisterConnectorAuthServiceServer(srv, admin.NewUnavailableConnectorAuthServer())
		return
	}

	if d.connectorTokenStatus == nil {
		d.connectorTokenStatus = connectorauth.NewStatusBook()
	}
	// The pending-authorization store is SHARED between this RPC handler
	// (StartConnectorAuthorization writes it, CompleteConnectorAuthorization
	// reads it) and the pre-auth OAuth callback (reads it). One store, keyed by
	// state, TTL-bounded (ADR-0014).
	connectorPending := connectorauth.NewPendingStore(connectorauth.DefaultPendingTTL, time.Now)
	connAuthSrv, caErr := admin.NewConnectorAuthAdminServer(admin.ConnectorAuthAdminConfig{
		Secrets:         d.secretsService,
		Prover:          connectorRefresher,
		Status:          d.connectorTokenStatus,
		Pending:         connectorPending,
		CallbackBaseURL: os.Getenv("GIBSON_PUBLIC_URL"),
	})
	if caErr != nil {
		d.logger.Warn(ctx, "ConnectorAuthService: constructor failed; registering Unavailable stub",
			"error", caErr)
		tenantv1.RegisterConnectorAuthServiceServer(srv, admin.NewUnavailableConnectorAuthServer())
		return
	}
	// Hoisted so the pre-auth native-login listener mounts the OAuth callback
	// against this same server (they share connectorPending above).
	d.connectorAuthSrv = connAuthSrv
	tenantv1.RegisterConnectorAuthServiceServer(srv, connAuthSrv)
	d.logger.Info(ctx, "registered gibson.tenant.v1.ConnectorAuthService gRPC endpoint (ADR-0064)")

	// The loop walks the tenant's ConnectorInstance CRs (ADR-0065): the OAuth
	// freshener's connector set comes from the ToolHive path, not from
	// connector_manifest rows, so the legacy connector runtime could be removed
	// (gibson#1524) without connector OAuth going dark. Started by Start()
	// alongside the other reconcilers. Needs a kube client; without one (a
	// detached daemon) the loop stays off.
	if kube, kubeErr := d.connectorKubeClient(); kubeErr != nil {
		d.logger.Warn(ctx, "connector-token reconciler: no kube client; OAuth refresh loop disabled",
			"error", kubeErr)
	} else {
		d.connectorTokenReconciler = reconciler.NewConnectorTokenReconciler(reconciler.ConnectorTokenConfig{
			Catalog: &reconciler.ConnectorInstanceCatalogSource{
				Lister: kube,
				Logger: d.logger.Slog(),
			},
			Freshener: &connectorTokenFreshener{
				refresher: connectorRefresher,
				book:      d.connectorTokenStatus,
				now:       time.Now,
			},
			// The daemon writes the connector-cred Secret directly from the loop
			// (ADR-0015): no RPC returns the token, no ESO. The proxy mounts
			// this Secret, so without it the connector never leaves Provisioning.
			Materializer: &connectorTokenMaterializer{
				kube:    kube,
				secrets: d.secretsService,
			},
			Logger:   d.logger.Slog(),
			Interval: connectorTokenInterval,
		})
	}
}

// connectorTokenFreshener implements reconciler.TokenFreshener over the
// platform refresher.
type connectorTokenFreshener struct {
	refresher *connectorauth.Refresher
	book      *connectorauth.StatusBook
	now       func() time.Time
}

func (f *connectorTokenFreshener) EnsureFresh(ctx context.Context, tenant auth.TenantID, connector string) (bool, error) {
	refreshed, err := f.refresher.EnsureFresh(auth.WithTenant(ctx, tenant), connector)
	if errors.Is(err, connectorauth.ErrNoGrant) {
		// A registered connector nobody has authorized yet is a normal
		// state — the status RPC reports it as UNAUTHORIZED; the loop stays
		// quiet.
		return false, nil
	}
	if refreshed || err != nil {
		// Record actual refresh attempts only, so LastAttempt means "the
		// refresher last talked to the vendor then", not "the loop ticked".
		f.book.Record(tenant.String(), connector, err, f.now().UTC())
	}
	if err != nil {
		return false, fmt.Errorf("connector token refresh: %w", err)
	}
	return refreshed, nil
}
