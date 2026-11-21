// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

// daemon_client.go holds DaemonClient, the gRPC client that the tenant
// operator uses for every call to the daemon
// gibson.daemon.operator.v1.DaemonOperatorService.
//
// Auth: the TokenSource mints a Zitadel client_credentials token. The client
// sends it as `Authorization: Bearer <jwt>` metadata.

package provision

import (
	"context"
	"fmt"
	"strings"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	grpcstatus "google.golang.org/grpc/status"

	"github.com/zeroroot-ai/gibson/internal/platform/pagetoken"
	operatorv1 "github.com/zeroroot-ai/gibson/internal/server/daemon/api/gibson/daemon/operator/v1"
	"github.com/zeroroot-ai/gibson/operators/internal/audit"
	"github.com/zeroroot-ai/gibson/operators/tenant/internal/clients"
	"github.com/zeroroot-ai/gibson/operators/tenant/internal/metrics"
	daemontransport "github.com/zeroroot-ai/gibson/operators/tenant/pkg/transport/daemon"
)

// DaemonClient calls the daemon's DaemonOperatorService over SPIFFE-mTLS gRPC. The
// underlying transport (workload-API-sourced X509 SVIDs + dial) is owned by
// pkg/transport/daemon.Client; this type focuses on the per-RPC marshalling
// and error mapping. Close releases both the gRPC connection and the
// SPIRE-agent stream.
type DaemonClient struct {
	transport *daemontransport.Client
	client    operatorv1.DaemonOperatorServiceClient
	tokens    TokenSource
	// Audience passed to the TokenSource. Defaults to "gibson-daemon"
	// (matching the daemon's expected JWT aud claim).
	audience string
}

// NewDaemonClient dials `addr` over SPIFFE mTLS, authorising the
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
// Decided by ADR-0002, operator-to-daemon transport.
func NewDaemonClient(ctx context.Context, addr, daemonSVID string, tokens TokenSource) (*DaemonClient, error) {
	transport, err := daemontransport.NewClient(ctx, daemontransport.Options{
		Addr:       addr,
		DaemonSVID: daemonSVID,
	})
	if err != nil {
		return nil, fmt.Errorf("daemon client: %w", err)
	}
	return &DaemonClient{
		transport: transport,
		client:    operatorv1.NewDaemonOperatorServiceClient(transport.Conn()),
		tokens:    tokens,
		audience:  "gibson-daemon",
	}, nil
}

// Close releases the gRPC connection and the underlying X509Source.
func (c *DaemonClient) Close() error {
	if c == nil || c.transport == nil {
		return nil
	}
	return c.transport.Close()
}

// authCtx attaches the Zitadel service-account JWT as `authorization: Bearer …`
// metadata. The token is carried for forward-compatibility; on the current
// SPIFFE direct-dial path the daemon's bypass intercept fires before the JWT
// is inspected (see NewDaemonClient doc, gibson#245).
func (c *DaemonClient) authCtx(ctx context.Context) (context.Context, error) {
	if c.tokens == nil {
		return ctx, nil
	}
	tok, err := c.tokens.FetchToken(ctx, c.audience)
	if err != nil {
		return nil, fmt.Errorf("daemon client: fetch token: %w", err)
	}
	return metadata.AppendToOutgoingContext(ctx, "authorization", "Bearer "+tok), nil
}

// translateGRPCError remaps gRPC status codes onto the operator's saga
// retry taxonomy (clients.ErrUnreachable / ErrUnauthorized / ErrInvalidInput),
// matching the HTTP client's behaviour so the saga runner sees the same
// classification regardless of transport.
//
// Every operator->daemon RPC funnels its error through here, so this is also
// the single chokepoint where we record the failure metric
// (gibson_tenant_operator_daemon_call_errors_total). gibson#1043 (a
// SPIFFE-allowlist omission that silently denied the admin-ops drain) is the
// regression this makes observable: it surfaces as outcome="permission_denied".
func translateGRPCError(op string, err error) error {
	if err == nil {
		return nil
	}
	// Record the raw gRPC error before any sentinel wrapping so the status code
	// is still recoverable for the outcome label.
	metrics.ObserveDaemonCallError(op, err)
	st, ok := grpcstatus.FromError(err)
	if !ok {
		return fmt.Errorf("daemon client: %s: %w: %w", op, clients.ErrUnreachable, err)
	}
	base := fmt.Errorf("daemon client: %s: %s", op, st.Message())
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
func (c *DaemonClient) SetTenantZitadelOrg(ctx context.Context, tenantID, zitadelOrgID string) error {
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

// WriteAccessTuples adds and deletes FGA tuples through the daemon. Each
// tuple has the form "user#relation@object".
func (c *DaemonClient) WriteAccessTuples(ctx context.Context, add, del []string, reason string) error {
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

// SeedCatalogTenantEnabled asks the daemon to enable each platform catalog
// item for the tenant.
func (c *DaemonClient) SeedCatalogTenantEnabled(ctx context.Context, tenantID string) error {
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
	TenantID      string
	OwnerUserID   string
	OwnerEmail    string
	WorkspaceName string
	// AuditRecordID is the daemon audit record of the human request that
	// queued this tenant, or "" when no human request is behind it (gibson#583).
	AuditRecordID string
}

// ListPendingTenantProvisioning returns the daemon's queue of tenants awaiting
// Tenant-CR creation (operator-pull provisioning, gibson#948). Each record
// carries the spec the operator stamps onto the Tenant CR.
func (c *DaemonClient) ListPendingTenantProvisioning(ctx context.Context) ([]PendingTenant, error) {
	authedCtx, err := c.authCtx(ctx)
	if err != nil {
		return nil, err
	}
	// The reconcile sees every pending tenant, so it walks every page.
	all, err := pagetoken.Collect(authedCtx, 0,
		func(ctx context.Context, token string) ([]PendingTenant, string, error) {
			resp, err := c.client.ListPendingTenantProvisioning(ctx,
				&operatorv1.ListPendingTenantProvisioningRequest{PageSize: pagetoken.MaxSize, PageToken: token})
			if err := translateGRPCError("list-pending-tenant-provisioning", err); err != nil {
				return nil, "", err
			}
			out := make([]PendingTenant, 0, len(resp.GetPending()))
			for _, p := range resp.GetPending() {
				out = append(out, PendingTenant{
					TenantID:      p.GetTenantId(),
					OwnerUserID:   p.GetOwnerUserId(),
					OwnerEmail:    p.GetOwnerEmail(),
					WorkspaceName: p.GetWorkspaceName(),
					AuditRecordID: p.GetAuditRecordId(),
				})
			}
			return out, resp.GetNextPageToken(), nil
		})
	if err != nil {
		return nil, fmt.Errorf("list-pending-tenant-provisioning: %w", err)
	}
	return all, nil
}

// AckTenantProvisioned marks a pending record done after the operator has
// ensured the Tenant CR exists (gibson#948). Idempotent.
func (c *DaemonClient) AckTenantProvisioned(ctx context.Context, tenantID string) error {
	authedCtx, err := c.authCtx(ctx)
	if err != nil {
		return err
	}
	_, err = c.client.AckTenantProvisioned(authedCtx,
		&operatorv1.AckTenantProvisionedRequest{TenantId: tenantID})
	return translateGRPCError("ack-tenant-provisioned", err)
}

// EnqueueTenantProvisioning inserts a first-tenant provisioning op onto the
// daemon's pending-provisioning queue over the workload-authenticated operator
// surface (gibson#1496). It is the session-less path used by the first-tenant
// seed: AdminProvisionTenant is gated by a session-revocation check only an
// interactive human login satisfies, so a headless self-hosted install seeds
// the first tenant here instead. Idempotent on tenant_id (daemon ON CONFLICT).
// Returns whether the row already existed, so the seed can log "already seeded"
// rather than treat a re-run as new work.
func (c *DaemonClient) EnqueueTenantProvisioning(ctx context.Context, t PendingTenant) (alreadyExisted bool, err error) {
	authedCtx, err := c.authCtx(ctx)
	if err != nil {
		return false, err
	}
	resp, err := c.client.EnqueueTenantProvisioning(authedCtx,
		&operatorv1.EnqueueTenantProvisioningRequest{
			TenantId:    t.TenantID,
			DisplayName: t.WorkspaceName,
			OwnerEmail:  t.OwnerEmail,
		})
	if err := translateGRPCError("enqueue-tenant-provisioning", err); err != nil {
		return false, err
	}
	return resp.GetAlreadyExisted(), nil
}

// TenantStatusReport is the operator's view of the subset of Tenant CR status
// it reports back to the daemon so the dashboard can read provisioning status
// without Kubernetes access (gibson#948, dashboard#813).
type TenantStatusReport struct {
	TenantID       string
	Phase          string
	DataPlaneReady bool
	StorePostgres  string
	StoreRedis     string
	StoreNeo4j     string
	ZitadelOrgSlug string
}

// ReportTenantStatus upserts the operator-observed Tenant CR status into the
// daemon's tenant_status table. Best-effort: callers log failures and never
// fail the reconcile on a daemon blip.
func (c *DaemonClient) ReportTenantStatus(ctx context.Context, r TenantStatusReport) error {
	authedCtx, err := c.authCtx(ctx)
	if err != nil {
		return err
	}
	_, err = c.client.ReportTenantStatus(authedCtx, &operatorv1.ReportTenantStatusRequest{
		TenantId:       r.TenantID,
		Phase:          r.Phase,
		DataPlaneReady: r.DataPlaneReady,
		StorePostgres:  r.StorePostgres,
		StoreRedis:     r.StoreRedis,
		StoreNeo4J:     r.StoreNeo4j,
		ZitadelOrgSlug: r.ZitadelOrgSlug,
	})
	return translateGRPCError("report-tenant-status", err)
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
	// AuditRecordID is the daemon audit record of the admin request behind
	// this op (gibson#583).
	AuditRecordID string
}

// ListPendingTenantOps returns the daemon's queue of admin tenant CRUD ops
// awaiting application to a Tenant CR (operator-pull admin CRUD, gibson#964).
// Each record carries the op type plus the spec inputs the operator applies.
func (c *DaemonClient) ListPendingTenantOps(ctx context.Context) ([]TenantAdminOp, error) {
	authedCtx, err := c.authCtx(ctx)
	if err != nil {
		return nil, err
	}
	// The reconcile sees every pending op, so it walks every page.
	all, err := pagetoken.Collect(authedCtx, 0,
		func(ctx context.Context, token string) ([]TenantAdminOp, string, error) {
			resp, err := c.client.ListPendingTenantOps(ctx,
				&operatorv1.ListPendingTenantOpsRequest{PageSize: pagetoken.MaxSize, PageToken: token})
			if err := translateGRPCError("list-pending-tenant-ops", err); err != nil {
				return nil, "", err
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
					AuditRecordID:  op.GetAuditRecordId(),
				})
			}
			return out, resp.GetNextPageToken(), nil
		})
	if err != nil {
		return nil, fmt.Errorf("list-pending-tenant-ops: %w", err)
	}
	return all, nil
}

// AckTenantOp marks an admin-op record done after the operator has applied it to
// the Tenant CR (gibson#964). Idempotent.
func (c *DaemonClient) AckTenantOp(ctx context.Context, opID string) error {
	authedCtx, err := c.authCtx(ctx)
	if err != nil {
		return err
	}
	_, err = c.client.AckTenantOp(authedCtx,
		&operatorv1.AckTenantOpRequest{OpId: opID})
	return translateGRPCError("ack-tenant-op", err)
}

// EmitAuditEvent sends one audit record of an operator change to the daemon
// (DaemonOperatorService.EmitAuditEvent, gibson#583). The daemon writes it to
// Postgres before it answers, with the SPIFFE identity of the operator as the
// actor. It implements audit.Sink.
func (c *DaemonClient) EmitAuditEvent(ctx context.Context, ev audit.Event) error {
	authedCtx, err := c.authCtx(ctx)
	if err != nil {
		return err
	}
	_, err = c.client.EmitAuditEvent(authedCtx, audit.MessageOf(ev))
	return translateGRPCError("emit-audit-event", err)
}

// parseAccessTuples splits "user#relation@object" into the gRPC
// AccessTuple message.
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

// SetAgentEnrollmentLimits reports the runtime cap an AgentEnrollment
// declares (spec.maxRuntime, gibson#597) so the daemon can bound that
// agent's sandboxed runs. Zero clears the cap.
func (c *DaemonClient) SetAgentEnrollmentLimits(ctx context.Context, tenantID, agentName string, maxRuntime time.Duration) error {
	authedCtx, err := c.authCtx(ctx)
	if err != nil {
		return err
	}
	_, err = c.client.SetAgentEnrollmentLimits(authedCtx, &operatorv1.SetAgentEnrollmentLimitsRequest{
		TenantId:          tenantID,
		AgentName:         agentName,
		MaxRuntimeSeconds: int64(maxRuntime / time.Second),
	})
	if err != nil {
		return fmt.Errorf("set agent enrollment limits %s/%s: %w", tenantID, agentName, err)
	}
	return nil
}

// DesiredCatalogPlugin is one plugin instance the daemon wants the operator to
// run: the catalog plugin PluginID, for the tenant TenantID (gibson#815).
type DesiredCatalogPlugin struct {
	TenantID string
	PluginID string
	// Image is the image of the plugin, pinned by digest, from the catalog of
	// the daemon.
	Image string
	// EgressAllow is the egress list of the catalog entry, as "host:port".
	EgressAllow []string
}

// ListDesiredCatalogPlugins pulls every (tenant, catalog plugin) pair a tenant
// enabled. The operator runs one instance for each pair.
func (c *DaemonClient) ListDesiredCatalogPlugins(ctx context.Context) ([]DesiredCatalogPlugin, error) {
	authedCtx, err := c.authCtx(ctx)
	if err != nil {
		return nil, err
	}
	// The reconcile sees every desired plugin, so it walks every page.
	all, err := pagetoken.Collect(authedCtx, 0,
		func(ctx context.Context, token string) ([]DesiredCatalogPlugin, string, error) {
			resp, err := c.client.ListDesiredCatalogPlugins(ctx,
				&operatorv1.ListDesiredCatalogPluginsRequest{PageSize: pagetoken.MaxSize, PageToken: token})
			if err != nil {
				return nil, "", fmt.Errorf("fetch page: %w", err)
			}
			out := make([]DesiredCatalogPlugin, 0, len(resp.GetPlugins()))
			for _, p := range resp.GetPlugins() {
				out = append(out, DesiredCatalogPlugin{
					TenantID:    p.GetTenantId(),
					PluginID:    p.GetPluginId(),
					Image:       p.GetImage(),
					EgressAllow: p.GetEgressAllow(),
				})
			}
			return out, resp.GetNextPageToken(), nil
		})
	if err != nil {
		return nil, fmt.Errorf("list desired catalog plugins: %w", err)
	}
	return all, nil
}

// ReportCatalogPluginStatus reports the state of one tenant's plugin instance
// to the daemon.
func (c *DaemonClient) ReportCatalogPluginStatus(ctx context.Context, tenantID, pluginID, phase, lastError string) error {
	authedCtx, err := c.authCtx(ctx)
	if err != nil {
		return err
	}
	_, err = c.client.ReportCatalogPluginStatus(authedCtx, &operatorv1.ReportCatalogPluginStatusRequest{
		TenantId:  tenantID,
		PluginId:  pluginID,
		Phase:     phase,
		LastError: lastError,
	})
	if err != nil {
		return fmt.Errorf("report catalog plugin status %s/%s: %w", tenantID, pluginID, err)
	}
	return nil
}

// ModelProviderCredential reads the content of the credential Secret of a model
// provider via DaemonOperatorService.GetModelProviderCredential (gibson#1387).
// A tenant secret that does not exist gives clients.ErrNotFound. The error text
// never holds a value.
func (c *DaemonClient) ModelProviderCredential(
	ctx context.Context, tenantID, credentialSecret, providerType, caBundleSecret string,
) (map[string][]byte, error) {
	authedCtx, err := c.authCtx(ctx)
	if err != nil {
		return nil, err
	}
	resp, err := c.client.GetModelProviderCredential(authedCtx, &operatorv1.GetModelProviderCredentialRequest{
		TenantId: tenantID, CredentialSecret: credentialSecret, ProviderType: providerType,
		CaBundleSecret: caBundleSecret,
	})
	if grpcstatus.Code(err) == codes.NotFound {
		metrics.ObserveDaemonCallError("get-model-provider-credential", err)
		return nil, fmt.Errorf("daemon client: get-model-provider-credential: %w", clients.ErrNotFound)
	}
	if err := translateGRPCError("get-model-provider-credential", err); err != nil {
		return nil, err
	}
	return resp.GetSecret().GetData(), nil
}

// DesiredModelProvider is one provider record of a tenant, as the daemon returns
// it. The credential secret is a name and never a value.
type DesiredModelProvider struct {
	Name             string
	Type             string
	BaseURL          string
	Region           string
	ProjectID        string
	CredentialSecret string
	CABundleSecret   string
}

// TenantModelProviders reads the provider records of one tenant via
// DaemonOperatorService.GetTenantModelProviders (gibson#1387). It satisfies
// the ModelProviderRecords interface of the controller package. The sync
// removes each ModelProvider that is not in the result, so it walks every page.
// A read of the first page only would delete the providers of the later pages.
func (c *DaemonClient) TenantModelProviders(
	ctx context.Context, tenantID string,
) ([]DesiredModelProvider, []string, error) {
	authedCtx, err := c.authCtx(ctx)
	if err != nil {
		return nil, nil, err
	}
	var skipped []string
	out, err := pagetoken.Collect(authedCtx, 0,
		func(ctx context.Context, token string) ([]DesiredModelProvider, string, error) {
			resp, err := c.client.GetTenantModelProviders(ctx, &operatorv1.GetTenantModelProvidersRequest{
				TenantId: tenantID, PageSize: pagetoken.MaxSize, PageToken: token,
			})
			if err := translateGRPCError("get-tenant-model-providers", err); err != nil {
				return nil, "", err
			}
			skipped = append(skipped, resp.GetSkipped()...)
			page := make([]DesiredModelProvider, 0, len(resp.GetProviders()))
			for _, p := range resp.GetProviders() {
				page = append(page, DesiredModelProvider{
					Name: p.GetName(), Type: p.GetType(), BaseURL: p.GetBaseUrl(), Region: p.GetRegion(),
					ProjectID: p.GetProjectId(), CredentialSecret: p.GetCredentialSecret(),
					CABundleSecret: p.GetCaBundleSecret(),
				})
			}
			return page, resp.GetNextPageToken(), nil
		})
	if err != nil {
		return nil, nil, fmt.Errorf("get-tenant-model-providers: %w", err)
	}
	return out, skipped, nil
}

// DesiredOutsideAgent is one outside agent record of a tenant, as the daemon
// returns it. The credential secret is a name and never a value.
type DesiredOutsideAgent struct {
	Name             string
	A2AURL           string
	CredentialSecret string
	CABundleSecret   string
}

// TenantOutsideAgents reads the outside agent records of one tenant via
// DaemonOperatorService.GetTenantOutsideAgents (gibson#1403). It satisfies the
// OutsideAgentRecords interface of the controller package. The sync removes each
// route that is not in the result, so it walks every page.
func (c *DaemonClient) TenantOutsideAgents(
	ctx context.Context, tenantID string,
) ([]DesiredOutsideAgent, error) {
	authedCtx, err := c.authCtx(ctx)
	if err != nil {
		return nil, err
	}
	out, err := pagetoken.Collect(authedCtx, 0,
		func(ctx context.Context, token string) ([]DesiredOutsideAgent, string, error) {
			resp, err := c.client.GetTenantOutsideAgents(ctx, &operatorv1.GetTenantOutsideAgentsRequest{
				TenantId: tenantID, PageSize: pagetoken.MaxSize, PageToken: token,
			})
			if err := translateGRPCError("get-tenant-outside-agents", err); err != nil {
				return nil, "", err
			}
			page := make([]DesiredOutsideAgent, 0, len(resp.GetAgents()))
			for _, a := range resp.GetAgents() {
				page = append(page, DesiredOutsideAgent{
					Name: a.GetName(), A2AURL: a.GetA2AUrl(), CredentialSecret: a.GetCredentialSecret(),
					CABundleSecret: a.GetCaBundleSecret(),
				})
			}
			return page, resp.GetNextPageToken(), nil
		})
	if err != nil {
		return nil, fmt.Errorf("get-tenant-outside-agents: %w", err)
	}
	return out, nil
}

// OutsideAgentCredential reads the content of the credential Secret of an
// outside agent via DaemonOperatorService.GetOutsideAgentCredential
// (gibson#1403). A record or a tenant secret that does not exist gives
// clients.ErrNotFound. The error text never holds a value.
func (c *DaemonClient) OutsideAgentCredential(
	ctx context.Context, tenantID, name string,
) (map[string][]byte, error) {
	authedCtx, err := c.authCtx(ctx)
	if err != nil {
		return nil, err
	}
	resp, err := c.client.GetOutsideAgentCredential(authedCtx, &operatorv1.GetOutsideAgentCredentialRequest{
		TenantId: tenantID, Name: name,
	})
	if grpcstatus.Code(err) == codes.NotFound {
		metrics.ObserveDaemonCallError("get-outside-agent-credential", err)
		return nil, fmt.Errorf("daemon client: get-outside-agent-credential: %w", clients.ErrNotFound)
	}
	if err := translateGRPCError("get-outside-agent-credential", err); err != nil {
		return nil, err
	}
	return resp.GetSecret().GetData(), nil
}
