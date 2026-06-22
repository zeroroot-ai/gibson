/*
Copyright 2026 Zero Day AI.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
*/

// entitlements_grpc_client.go — gRPC implementation of
// controller.EntitlementsProvisioner that calls the daemon's
// gibson.daemon.operator.v1.DaemonOperatorService directly.
//
// Phase 5.1 of spec tenant-provisioning-unification-phase2 replaces the
// HTTP-to-dashboard fan-out (EntitlementsHTTPClient) with a direct
// service-to-service gRPC call. The dashboard is no longer the auth
// gateway for these RPCs — the daemon receives the operator's Zitadel
// service-account JWT and dispatches to the same FGA Check the dashboard
// previously did via Envoy.
//
// Auth: same TokenSource interface as the HTTP client (Zitadel
// client_credentials), passed as `Authorization: Bearer <jwt>` metadata.

package provision

import (
	"context"
	"fmt"
	"strings"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	grpcstatus "google.golang.org/grpc/status"

	operatorv1 "github.com/zeroroot-ai/gibson/internal/server/daemon/api/gibson/daemon/operator/v1"
	"github.com/zeroroot-ai/gibson/operators/tenant/internal/clients"
	"github.com/zeroroot-ai/gibson/operators/tenant/internal/controller"
	daemontransport "github.com/zeroroot-ai/gibson/operators/tenant/pkg/transport/daemon"
	"github.com/zeroroot-ai/gibson/operators/tenant/plans"
)

// EntitlementsGRPCClient implements controller.EntitlementsProvisioner by
// calling the daemon's DaemonOperatorService over SPIFFE-mTLS gRPC. The
// underlying transport (workload-API-sourced X509 SVIDs + dial) is owned by
// pkg/transport/daemon.Client; this type focuses on the per-RPC marshalling
// and error mapping. Close releases both the gRPC connection and the
// SPIRE-agent stream.
type EntitlementsGRPCClient struct {
	transport *daemontransport.Client
	client    operatorv1.DaemonOperatorServiceClient
	tokens    TokenSource
	// Audience passed to the TokenSource. Defaults to "gibson-daemon"
	// (matching the daemon's expected JWT aud claim).
	audience string
}

// NewEntitlementsGRPCClient dials `addr` over SPIFFE mTLS, authorising the
// daemon's expected SVID, and returns a ready-to-use client. The operator's
// own SVID is fetched continuously from the SPIRE Workload API socket the
// pod mounts (chart wiring: helm/gibson-operators tenant-operator/deployment.yaml).
//
// `tokens` mints a Zitadel service-account JWT carried in
// `authorization: Bearer <jwt>` per-call metadata. NOTE: the daemon does NOT
// validate this JWT on the direct-dial SPIFFE path (ADR-0002). The daemon's
// spiffePlatformBypass intercepts the request before sdkAuthUnary and injects
// a synthetic Identity sourced from the SVID; the Bearer token is carried but
// not checked. SPIFFE mTLS peer-SVID verification (tlsconfig.AuthorizeOneOf)
// is the sole trust anchor. See gibson#245 and tenant-operator#253.
//
// ADR: zeroroot-ai/docs adr/0002-operator-to-daemon-transport.md.
func NewEntitlementsGRPCClient(ctx context.Context, addr, daemonSVID string, tokens TokenSource) (*EntitlementsGRPCClient, error) {
	transport, err := daemontransport.NewClient(ctx, daemontransport.Options{
		Addr:       addr,
		DaemonSVID: daemonSVID,
	})
	if err != nil {
		return nil, fmt.Errorf("entitlements: %w", err)
	}
	return &EntitlementsGRPCClient{
		transport: transport,
		client:    operatorv1.NewDaemonOperatorServiceClient(transport.Conn()),
		tokens:    tokens,
		audience:  "gibson-daemon",
	}, nil
}

// Close releases the gRPC connection and the underlying X509Source.
func (c *EntitlementsGRPCClient) Close() error {
	if c == nil || c.transport == nil {
		return nil
	}
	return c.transport.Close()
}

// authCtx attaches the Zitadel service-account JWT as `authorization: Bearer …`
// metadata. The token is carried for forward-compatibility; on the current
// SPIFFE direct-dial path the daemon's bypass intercept fires before the JWT
// is inspected (see NewEntitlementsGRPCClient doc, gibson#245).
func (c *EntitlementsGRPCClient) authCtx(ctx context.Context) (context.Context, error) {
	if c.tokens == nil {
		return ctx, nil
	}
	tok, err := c.tokens.FetchToken(ctx, c.audience)
	if err != nil {
		return nil, fmt.Errorf("entitlements: fetch token: %w", err)
	}
	return metadata.AppendToOutgoingContext(ctx, "authorization", "Bearer "+tok), nil
}

// translateGRPCError remaps gRPC status codes onto the operator's saga
// retry taxonomy (clients.ErrUnreachable / ErrUnauthorized / ErrInvalidInput),
// matching the HTTP client's behaviour so the saga runner sees the same
// classification regardless of transport.
func translateGRPCError(op string, err error) error {
	if err == nil {
		return nil
	}
	st, ok := grpcstatus.FromError(err)
	if !ok {
		return fmt.Errorf("entitlements: %s: %w: %w", op, clients.ErrUnreachable, err)
	}
	base := fmt.Errorf("entitlements: %s: %s", op, st.Message())
	switch st.Code() {
	case codes.Unauthenticated, codes.PermissionDenied:
		return fmt.Errorf("%w: %w", clients.ErrUnauthorized, base)
	case codes.InvalidArgument, codes.NotFound, codes.AlreadyExists, codes.FailedPrecondition:
		return fmt.Errorf("%w: %w", clients.ErrInvalidInput, base)
	case codes.Unavailable, codes.DeadlineExceeded, codes.ResourceExhausted, codes.Aborted:
		return fmt.Errorf("%w: %w", clients.ErrUnreachable, base)
	default:
		return base
	}
}

// --- Provisioner interface implementation ---

func (c *EntitlementsGRPCClient) UpsertTenantQuota(ctx context.Context, tenantID string, q plans.Quotas) error {
	authedCtx, err := c.authCtx(ctx)
	if err != nil {
		return err
	}
	_, err = c.client.UpsertTenantQuota(authedCtx, &operatorv1.UpsertTenantQuotaRequest{
		TenantId:             tenantID,
		ConcurrentAgents:     int32(q.ConcurrentAgents),
		ConcurrentMissions:   int32(q.ConcurrentMissions),
		ConcurrentConnectors: int32(q.ConcurrentConnectors),
		PlanId:               q.PlanID,
	})
	return translateGRPCError("upsert-quota", err)
}

// SetTenantZitadelOrg seeds the daemon's tenant -> Zitadel-org mapping via
// DaemonOperatorService.SetTenantZitadelOrg (gibson#621). Idempotent.
func (c *EntitlementsGRPCClient) SetTenantZitadelOrg(ctx context.Context, tenantID, zitadelOrgID string) error {
	authedCtx, err := c.authCtx(ctx)
	if err != nil {
		return err
	}
	_, err = c.client.SetTenantZitadelOrg(authedCtx, &operatorv1.SetTenantZitadelOrgRequest{
		TenantId:     tenantID,
		ZitadelOrgId: zitadelOrgID,
	})
	return translateGRPCError("set-tenant-zitadel-org", err)
}

func (c *EntitlementsGRPCClient) ListFeatureTuples(ctx context.Context, tenantID string) ([]string, error) {
	authedCtx, err := c.authCtx(ctx)
	if err != nil {
		return nil, err
	}
	resp, err := c.client.ListFeatureTuples(authedCtx, &operatorv1.ListFeatureTuplesRequest{
		TenantId: tenantID,
	})
	if err := translateGRPCError("list-feature-tuples", err); err != nil {
		return nil, err
	}
	return resp.GetRelations(), nil
}

func (c *EntitlementsGRPCClient) WriteAccessTuples(ctx context.Context, add, del []string, reason string) error {
	authedCtx, err := c.authCtx(ctx)
	if err != nil {
		return err
	}
	_, err = c.client.WriteAccessTuples(authedCtx, &operatorv1.WriteAccessTuplesRequest{
		Add:    parseAccessTuples(add),
		Delete: parseAccessTuples(del),
		Reason: reason,
	})
	return translateGRPCError("write-tuples", err)
}

func (c *EntitlementsGRPCClient) SeedCatalogTenantEnabled(ctx context.Context, tenantID string) error {
	authedCtx, err := c.authCtx(ctx)
	if err != nil {
		return err
	}
	_, err = c.client.SeedCatalogTenantEnabled(authedCtx, &operatorv1.SeedCatalogTenantEnabledRequest{
		TenantId: tenantID,
	})
	return translateGRPCError("seed-catalog", err)
}

// EmitReconcileSummary maps the controller's strongly-typed summary onto
// the daemon's generic AuditEventMessage. The daemon's audit emitter
// stores the event in the platform Postgres + Redis stream.
func (c *EntitlementsGRPCClient) EmitReconcileSummary(ctx context.Context, s controller.ReconcileSummary) error {
	authedCtx, err := c.authCtx(ctx)
	if err != nil {
		return err
	}
	fields := map[string]string{
		"plan":        s.Plan,
		"quota_delta": itoa(s.QuotaDelta),
		"duration_ms": itoaInt64(s.DurationMs),
		"trigger":     s.Trigger,
	}
	_, err = c.client.EmitAuditEvent(authedCtx, &operatorv1.EmitAuditEventRequest{
		Event: &operatorv1.AuditEventMessage{
			Type:        "entitlements_reconcile",
			ActorSource: "tenant-operator",
			ScopeType:   "tenant",
			Operation:   "reconcile",
			Reason:      s.Trigger,
			Timestamp:   time.Now().UTC().Format(time.RFC3339Nano),
			Fields:      fields,
		},
	})
	return translateGRPCError("emit-summary", err)
}

// parseAccessTuples splits "user#relation@object" into the gRPC
// AccessTuple message. Mirrors EntitlementsHTTPClient's tuplesFromStrings
// so the operator's caller surface is unchanged.
func parseAccessTuples(tuples []string) []*operatorv1.AccessTuple {
	out := make([]*operatorv1.AccessTuple, 0, len(tuples))
	for _, t := range tuples {
		hashIdx := strings.IndexByte(t, '#')
		atIdx := strings.IndexByte(t, '@')
		if hashIdx <= 0 || atIdx <= hashIdx+1 || atIdx >= len(t)-1 {
			continue
		}
		out = append(out, &operatorv1.AccessTuple{
			User:     t[:hashIdx],
			Relation: t[hashIdx+1 : atIdx],
			Object:   t[atIdx+1:],
		})
	}
	return out
}

func itoa(n int) string        { return fmt.Sprintf("%d", n) }
func itoaInt64(n int64) string { return fmt.Sprintf("%d", n) }
