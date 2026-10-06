// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

// Package daemon — connector_token_adapters.go
//
// Adapters between the connector-token reconciler (internal/infra/reconciler)
// and the platform token refresher (internal/platform/connectorauth), plus
// the ConnectorAuthService wiring. The reconciler walks the enabled set on a
// clock; the adapter scopes the secret store to each tenant, treats "no grant
// stored" as a quiet no-op, and records outcomes for the status RPC
// (ADR-0061).
package daemon

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"time"

	"google.golang.org/grpc"

	"github.com/zeroroot-ai/sdk/auth"

	"github.com/zeroroot-ai/gibson/internal/infra/reconciler"
	"github.com/zeroroot-ai/gibson/internal/platform/componentcatalog"
	"github.com/zeroroot-ai/gibson/internal/platform/connectorauth"
	"github.com/zeroroot-ai/gibson/internal/platform/tenantconnector"
	"github.com/zeroroot-ai/gibson/internal/server/admin"
	tenantv1 "github.com/zeroroot-ai/gibson/internal/server/daemon/api/gibson/tenant/v1"
	connectorv1alpha1 "github.com/zeroroot-ai/gibson/operators/connector/api/v1alpha1"
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
	// One guarded client for every vendor call: the instance URL is tenant
	// input, and discovery follows what the instance advertises.
	allowPrivate := d.config != nil && d.config.Security.AllowPrivateConnectorEndpoints
	vendorClient := connectorauth.NewHTTPClient(30*time.Second, allowPrivate)
	connectorRefresher, crErr := connectorauth.NewRefresher(d.secretsService, vendorClient, nil,
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
	// state, TTL-bounded (ADR-0114).
	connectorPending := connectorauth.NewPendingStore(connectorauth.DefaultPendingTTL, time.Now)
	connAuthSrv, caErr := admin.NewConnectorAuthAdminServer(admin.ConnectorAuthAdminConfig{
		Secrets:         d.secretsService,
		Prover:          connectorRefresher,
		Status:          d.connectorTokenStatus,
		Pending:         connectorPending,
		CallbackBaseURL: os.Getenv("GIBSON_PUBLIC_URL"),
		HTTPClient:      vendorClient,
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
	d.logger.Info(ctx, "registered gibson.tenant.v1.ConnectorAuthService gRPC endpoint (ADR-0061)")

	// The loop walks the connectors each tenant enabled, from the table that
	// ConnectorService writes (gibson#662). It only refreshes: the connector
	// operator reads the token through GetConnectorCredential and writes the
	// connector-cred Secret (gibson#663). The daemon makes no Kubernetes call.
	d.connectorTokenReconciler = reconciler.NewConnectorTokenReconciler(reconciler.ConnectorTokenConfig{
		Catalog: &tenantConnectorCatalogSource{
			store:  tenantconnector.NewStore(d.platformDB),
			logger: d.logger.Slog(),
		},
		Freshener: &connectorTokenFreshener{
			refresher: connectorRefresher,
			book:      d.connectorTokenStatus,
			now:       time.Now,
		},
		Logger:   d.logger.Slog(),
		Interval: connectorTokenInterval,
	})
}

// tenantConnectorCatalogSource is the desired set of the token freshener: each
// connector a tenant enabled whose catalog entry uses OAuth. A static
// credential needs no refresh, and a connector that left the catalog is not
// refreshed.
type tenantConnectorCatalogSource struct {
	store interface {
		ListAll(ctx context.Context) ([]tenantconnector.Connector, error)
	}
	logger *slog.Logger
}

func (s *tenantConnectorCatalogSource) DesiredConnectors(ctx context.Context) ([]reconciler.ConnectorSandbox, error) {
	rows, err := s.store.ListAll(ctx)
	if err != nil {
		return nil, fmt.Errorf("connector token source: list tenant connectors: %w", err)
	}
	out := make([]reconciler.ConnectorSandbox, 0, len(rows))
	for _, r := range rows {
		entry, lerr := componentcatalog.LookupConnector(r.ConnectorID)
		if lerr != nil || entry.Auth != connectorv1alpha1.ConnectorAuthOAuth {
			continue
		}
		tid, terr := auth.NewTenantID(r.TenantID)
		if terr != nil {
			s.logger.Warn("connector token source: skipping a row with a malformed tenant id",
				"tenant", r.TenantID, "err", terr)
			continue
		}
		out = append(out, reconciler.ConnectorSandbox{Tenant: tid, Connector: r.ConnectorID})
	}
	return out, nil
}

// connectorTokenFreshenerActor is the audit actor of a background token
// refresh.
const connectorTokenFreshenerActor = "system:connector-token-freshener"

// connectorTokenFreshener implements reconciler.TokenFreshener over the
// platform refresher.
type connectorTokenFreshener struct {
	refresher *connectorauth.Refresher
	book      *connectorauth.StatusBook
	now       func() time.Time
}

func (f *connectorTokenFreshener) EnsureFresh(ctx context.Context, tenant auth.TenantID, connector string) (bool, error) {
	// The refresh writes secrets, and each secret write records its actor
	// first (gibson#676). This loop has no caller, so the daemon is the actor.
	ctx = auth.WithIdentity(auth.WithTenant(ctx, tenant), auth.Identity{
		Subject:        connectorTokenFreshenerActor,
		Tenant:         tenant,
		CredentialType: auth.CredentialClientCredentials,
	})
	refreshed, err := f.refresher.EnsureFresh(ctx, connector)
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
