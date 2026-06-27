// Copyright 2026 Hack the Planet LLC
// Use of this source code is governed by the Elastic License 2.0
// that can be found in the LICENSE file in the repo root.

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

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	grpcstatus "google.golang.org/grpc/status"

	operatorv1 "github.com/zeroroot-ai/gibson/internal/server/daemon/api/gibson/daemon/operator/v1"
	"github.com/zeroroot-ai/gibson/operators/tenant/internal/clients"
	daemontransport "github.com/zeroroot-ai/gibson/operators/tenant/pkg/transport/daemon"
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

// PendingTenant mirrors operatorv1.PendingTenant in the operator's own
// vocabulary so the pending-provisioning reconciler does not depend on the
// generated proto type directly. Carries exactly the Tenant-CR spec inputs.
type PendingTenant struct {
	TenantID         string
	OwnerUserID      string
	OwnerEmail       string
	WorkspaceName    string
	Tier             string
	StripeCustomerID string
}

// ListPendingTenantProvisioning returns the daemon's queue of tenants awaiting
// Tenant-CR creation (operator-pull provisioning, gibson#948). Each record
// carries the spec the operator stamps onto the Tenant CR.
func (c *EntitlementsGRPCClient) ListPendingTenantProvisioning(ctx context.Context) ([]PendingTenant, error) {
	authedCtx, err := c.authCtx(ctx)
	if err != nil {
		return nil, err
	}
	resp, err := c.client.ListPendingTenantProvisioning(authedCtx,
		&operatorv1.ListPendingTenantProvisioningRequest{})
	if err := translateGRPCError("list-pending-tenant-provisioning", err); err != nil {
		return nil, err
	}
	out := make([]PendingTenant, 0, len(resp.GetPending()))
	for _, p := range resp.GetPending() {
		out = append(out, PendingTenant{
			TenantID:         p.GetTenantId(),
			OwnerUserID:      p.GetOwnerUserId(),
			OwnerEmail:       p.GetOwnerEmail(),
			WorkspaceName:    p.GetWorkspaceName(),
			Tier:             p.GetTier(),
			StripeCustomerID: p.GetStripeCustomerId(),
		})
	}
	return out, nil
}

// AckTenantProvisioned marks a pending record done after the operator has
// ensured the Tenant CR exists (gibson#948). Idempotent.
func (c *EntitlementsGRPCClient) AckTenantProvisioned(ctx context.Context, tenantID string) error {
	authedCtx, err := c.authCtx(ctx)
	if err != nil {
		return err
	}
	_, err = c.client.AckTenantProvisioned(authedCtx,
		&operatorv1.AckTenantProvisionedRequest{TenantId: tenantID})
	return translateGRPCError("ack-tenant-provisioned", err)
}

// TenantStatusReport is the operator's view of the subset of Tenant CR status
// it reports back to the daemon so the dashboard can read provisioning status
// without Kubernetes access (gibson#948, dashboard#813).
type TenantStatusReport struct {
	TenantID         string
	Phase            string
	DataPlaneReady   bool
	StorePostgres    string
	StoreRedis       string
	StoreNeo4j       string
	ZitadelOrgSlug   string
	StripeCustomerID string
}

// ReportTenantStatus upserts the operator-observed Tenant CR status into the
// daemon's tenant_status table and returns the dashboard-recorded
// billing-active flag so the operator can stamp the billing-active CR
// annotation the saga waits on. Best-effort: callers log failures and never
// fail the reconcile on a daemon blip.
func (c *EntitlementsGRPCClient) ReportTenantStatus(ctx context.Context, r TenantStatusReport) (bool, error) {
	authedCtx, err := c.authCtx(ctx)
	if err != nil {
		return false, err
	}
	resp, err := c.client.ReportTenantStatus(authedCtx, &operatorv1.ReportTenantStatusRequest{
		TenantId:         r.TenantID,
		Phase:            r.Phase,
		DataPlaneReady:   r.DataPlaneReady,
		StorePostgres:    r.StorePostgres,
		StoreRedis:       r.StoreRedis,
		StoreNeo4J:       r.StoreNeo4j,
		ZitadelOrgSlug:   r.ZitadelOrgSlug,
		StripeCustomerId: r.StripeCustomerID,
	})
	if err := translateGRPCError("report-tenant-status", err); err != nil {
		return false, err
	}
	return resp.GetBillingActive(), nil
}

// TenantAdminOp is the operator's view of one admin tenant CRUD op the daemon
// has queued for application to a Tenant CR (gibson#964, dashboard#855). It
// mirrors operatorv1.TenantOp in the operator's own vocabulary so the
// admin-ops reconciler does not depend on the generated proto type directly.
type TenantAdminOp struct {
	OpID           string
	TenantID       string
	OpType         string // "provision" | "update" | "delete"
	DisplayName    string
	DisplayNameSet bool
	OwnerEmail     string
	Tier           string
	TierSet        bool
}

// ListPendingTenantOps returns the daemon's queue of admin tenant CRUD ops
// awaiting application to a Tenant CR (operator-pull admin CRUD, gibson#964).
// Each record carries the op type plus the spec inputs the operator applies.
func (c *EntitlementsGRPCClient) ListPendingTenantOps(ctx context.Context) ([]TenantAdminOp, error) {
	authedCtx, err := c.authCtx(ctx)
	if err != nil {
		return nil, err
	}
	resp, err := c.client.ListPendingTenantOps(authedCtx,
		&operatorv1.ListPendingTenantOpsRequest{})
	if err := translateGRPCError("list-pending-tenant-ops", err); err != nil {
		return nil, err
	}
	out := make([]TenantAdminOp, 0, len(resp.GetOps()))
	for _, op := range resp.GetOps() {
		out = append(out, TenantAdminOp{
			OpID:           op.GetOpId(),
			TenantID:       op.GetTenantId(),
			OpType:         op.GetOpType(),
			DisplayName:    op.GetDisplayName(),
			DisplayNameSet: op.GetDisplayNameSet(),
			OwnerEmail:     op.GetOwnerEmail(),
			Tier:           op.GetTier(),
			TierSet:        op.GetTierSet(),
		})
	}
	return out, nil
}

// AckTenantOp marks an admin-op record done after the operator has applied it to
// the Tenant CR (gibson#964). Idempotent.
func (c *EntitlementsGRPCClient) AckTenantOp(ctx context.Context, opID string) error {
	authedCtx, err := c.authCtx(ctx)
	if err != nil {
		return err
	}
	_, err = c.client.AckTenantOp(authedCtx,
		&operatorv1.AckTenantOpRequest{OpId: opID})
	return translateGRPCError("ack-tenant-op", err)
}

// EmitReconcileSummary maps the controller's strongly-typed summary onto
// the daemon's generic AuditEventMessage. The daemon's audit emitter
// stores the event in the platform Postgres + Redis stream.
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
