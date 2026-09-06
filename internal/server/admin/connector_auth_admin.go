// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

// Package admin — connector_auth_admin.go
//
// ConnectorAuthAdminServer implements gibson.tenant.v1.ConnectorAuthService —
// the dashboard's surface for a connector's OAuth grant lifecycle (ADR-0064).
// Pairs with plugin_admin.go (the connectors themselves) and secrets_admin.go
// (the broker the grant lives in).
//
// The human authorization round trip runs in the operator's browser against
// the customer's own vendor instance; this server receives the finished
// grant, proves it by minting the first access token, and owns revocation.
// For an `auth: secret` connector it receives the static credential instead
// (SetConnectorSecret, ADR-0015) and records a static grant. A credential
// crosses the API exactly once, inbound, and no RPC ever returns credential
// material.
package admin

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	tenantv1 "github.com/zeroroot-ai/gibson/internal/server/daemon/api/gibson/tenant/v1"
	"github.com/zeroroot-ai/sdk/auth"

	"github.com/zeroroot-ai/gibson/internal/platform/connectorauth"
)

// ConnectorSecretStore is the slice of the platform secrets service this
// server needs. The tenant comes from the call context, as everywhere else in
// the secrets stack.
type ConnectorSecretStore interface {
	Resolve(ctx context.Context, name string) ([]byte, error)
	Put(ctx context.Context, name string, value []byte) error
	Delete(ctx context.Context, name string) error
}

// GrantProver mints an access token from a stored grant. The production
// wiring is connectorauth.Refresher over the same secret store.
type GrantProver interface {
	Refresh(ctx context.Context, connector string) (*connectorauth.AccessToken, error)
}

// ConnectorAuthAdminConfig wires the server to its dependencies.
type ConnectorAuthAdminConfig struct {
	Secrets ConnectorSecretStore
	Prover  GrantProver
	// Status is the refresher's outcome book; nil is tolerated (status
	// responses then omit refresh diagnostics).
	Status *connectorauth.StatusBook
	// HTTPClient performs the vendor-side OAuth calls: discovery, dynamic
	// client registration, the code-to-token exchange, and revocation. Nil
	// gets a bounded default.
	HTTPClient *http.Client
	// Pending holds the short-TTL server-side records of in-flight
	// authorizations, keyed by state. It is SHARED with the pre-auth HTTP
	// callback so the browser round trip and the RPC complete the same
	// authorization. Nil disables StartConnectorAuthorization and the
	// code-exchange path of CompleteConnectorAuthorization.
	Pending *connectorauth.PendingStore
	// CallbackBaseURL is the daemon's public base URL (GIBSON_PUBLIC_URL). The
	// OAuth redirect_uri is CallbackBaseURL + connectorauth.CallbackPath. Empty
	// disables StartConnectorAuthorization.
	CallbackBaseURL string
	Now             func() time.Time
}

// ConnectorAuthAdminServer implements tenantv1.ConnectorAuthServiceServer.
type ConnectorAuthAdminServer struct {
	tenantv1.UnimplementedConnectorAuthServiceServer

	secrets     ConnectorSecretStore
	prover      GrantProver
	book        *connectorauth.StatusBook
	client      *http.Client
	pending     *connectorauth.PendingStore
	callbackURL string
	now         func() time.Time
}

// NewConnectorAuthAdminServer constructs the server. Secrets and Prover are
// required. Pending and CallbackBaseURL are needed only for the authorize flow
// (StartConnectorAuthorization + the code exchange); without them the server
// still serves status and revoke.
func NewConnectorAuthAdminServer(cfg ConnectorAuthAdminConfig) (*ConnectorAuthAdminServer, error) {
	if cfg.Secrets == nil {
		return nil, errors.New("connector auth admin: Secrets is required")
	}
	if cfg.Prover == nil {
		return nil, errors.New("connector auth admin: Prover is required")
	}
	client := cfg.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second}
	}
	now := cfg.Now
	if now == nil {
		now = time.Now
	}
	return &ConnectorAuthAdminServer{
		secrets:     cfg.Secrets,
		prover:      cfg.Prover,
		book:        cfg.Status,
		client:      client,
		pending:     cfg.Pending,
		callbackURL: strings.TrimRight(cfg.CallbackBaseURL, "/"),
		now:         now,
	}, nil
}

// GetConnectorAuthStatus reports a connector's grant and token state. It
// never returns credential material.
func (s *ConnectorAuthAdminServer) GetConnectorAuthStatus(ctx context.Context, req *tenantv1.GetConnectorAuthStatusRequest) (*tenantv1.GetConnectorAuthStatusResponse, error) {
	tenant, ok := auth.TenantFromContext(ctx)
	if !ok {
		return nil, status.Error(codes.PermissionDenied, "no tenant in context")
	}
	connector := req.GetConnector()
	if connector == "" {
		return nil, status.Error(codes.InvalidArgument, "connector is required")
	}
	return s.buildStatus(ctx, tenant, connector), nil
}

// buildStatus assembles the status view from the two platform-only secrets
// and the refresher's outcome book.
func (s *ConnectorAuthAdminServer) buildStatus(ctx context.Context, tenant auth.TenantID, connector string) *tenantv1.GetConnectorAuthStatusResponse {
	resp := &tenantv1.GetConnectorAuthStatusResponse{
		State: tenantv1.ConnectorAuthState_CONNECTOR_AUTH_STATE_UNAUTHORIZED,
	}

	raw, err := s.secrets.Resolve(ctx, connectorauth.GrantSecretName(connector))
	if err != nil || len(raw) == 0 {
		return resp
	}
	grant, err := connectorauth.UnmarshalGrant(raw)
	if err != nil {
		// A stored-but-unreadable grant is functionally no grant; the fix is
		// to re-authorize, which is what UNAUTHORIZED tells the operator.
		return resp
	}

	resp.State = tenantv1.ConnectorAuthState_CONNECTOR_AUTH_STATE_AUTHORIZED
	resp.AuthorizedBy = grant.AuthorizedBy
	resp.Scope = grant.Scope
	if !grant.AuthorizedAt.IsZero() {
		resp.AuthorizedAt = timestamppb.New(grant.AuthorizedAt)
	}

	if meta, err := s.secrets.Resolve(ctx, connectorauth.AccessMetaSecretName(connector)); err == nil {
		if tok, err := unmarshalAccessMeta(meta); err == nil && !tok.ExpiresAt.IsZero() {
			resp.AccessTokenExpiresAt = timestamppb.New(tok.ExpiresAt)
		}
	}

	if st, ok := s.book.Get(tenant.String(), connector); ok {
		resp.LastRefreshError = st.LastError
		if !st.LastAttempt.IsZero() {
			resp.LastRefreshAt = timestamppb.New(st.LastAttempt)
		}
		if st.LastError != "" {
			resp.State = tenantv1.ConnectorAuthState_CONNECTOR_AUTH_STATE_REFRESH_FAILING
		}
	}
	return resp
}

// StartConnectorAuthorization runs the front half of the OAuth flow: it
// discovers the vendor authorization server, registers a public PKCE client,
// mints a PKCE pair and a random state, records them in the shared pending
// store keyed by state, and returns the authorize URL the operator opens. The
// human who starts the flow is recorded now and carried on the pending record,
// so the unauthenticated callback can attribute the grant.
func (s *ConnectorAuthAdminServer) StartConnectorAuthorization(ctx context.Context, req *tenantv1.StartConnectorAuthorizationRequest) (*tenantv1.StartConnectorAuthorizationResponse, error) {
	tenant, ok := auth.TenantFromContext(ctx)
	if !ok {
		return nil, status.Error(codes.PermissionDenied, "no tenant in context")
	}
	identity, err := auth.IdentityFromContext(ctx)
	if err != nil || identity.Subject == "" {
		// A grant with no recorded human is a service account nobody is
		// accountable for — the thing ADR-0064 refuses to create.
		return nil, status.Error(codes.PermissionDenied, "no identity in context")
	}
	connector := req.GetConnector()
	if connector == "" {
		return nil, status.Error(codes.InvalidArgument, "connector is required")
	}
	instanceURL := req.GetInstanceUrl()
	if instanceURL == "" {
		return nil, status.Error(codes.InvalidArgument, "instance_url is required")
	}
	if s.pending == nil || s.callbackURL == "" {
		return nil, status.Error(codes.FailedPrecondition,
			"authorization callback is not configured on this daemon")
	}

	redirectURI := s.callbackURL + connectorauth.CallbackPath

	// The instance URL doubles as the protected-resource base, so a vendor that
	// advertises RFC 9728 metadata off it is discovered too.
	meta, err := connectorauth.Discover(ctx, s.client, instanceURL, instanceURL)
	if err != nil {
		return nil, status.Errorf(codes.FailedPrecondition, "vendor discovery failed: %v", err)
	}

	// The catalog-driven scope belongs to a later slice; for now the vendor's
	// default applies, and the granted scope is recorded from the token
	// response at exchange time.
	const scope = ""

	reg, err := connectorauth.RegisterClient(ctx, s.client, meta.RegistrationEndpoint, redirectURI, scope)
	if err != nil {
		return nil, status.Errorf(codes.FailedPrecondition, "dynamic client registration failed: %v", err)
	}

	pkce, err := connectorauth.GeneratePKCE()
	if err != nil {
		return nil, status.Errorf(codes.Internal, "generate pkce: %v", err)
	}
	state, err := connectorauth.GenerateState()
	if err != nil {
		return nil, status.Errorf(codes.Internal, "generate state: %v", err)
	}

	s.pending.Put(&connectorauth.PendingAuthorization{
		State:              state,
		Verifier:           pkce.Verifier,
		Connector:          connector,
		TokenEndpoint:      meta.TokenEndpoint,
		ClientID:           reg.ClientID,
		ClientSecret:       reg.ClientSecret,
		RedirectURI:        redirectURI,
		Scope:              scope,
		RevocationEndpoint: meta.RevocationEndpoint,
		AuthorizedBy:       "user:" + identity.Subject,
		AuthorizedTenant:   tenant.String(),
		CreatedAt:          s.now().UTC(),
	})

	authorizeURL, err := connectorauth.BuildAuthorizeURL(
		meta.AuthorizationEndpoint, reg.ClientID, redirectURI, scope, state, pkce.Challenge)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "build authorize url: %v", err)
	}
	return &tenantv1.StartConnectorAuthorizationResponse{
		AuthorizeUrl: authorizeURL,
		State:        state,
	}, nil
}

// CompleteConnectorAuthorization finishes the authorization the daemon started:
// it exchanges the code for a grant daemon-side, stores the grant, then
// immediately proves it by minting the first access token. A grant that cannot
// refresh is removed again and the RPC fails, so the operator learns at
// authorization time rather than when the first token dies. The refresh token
// never leaves the daemon.
func (s *ConnectorAuthAdminServer) CompleteConnectorAuthorization(ctx context.Context, req *tenantv1.CompleteConnectorAuthorizationRequest) (*tenantv1.CompleteConnectorAuthorizationResponse, error) {
	tenant, ok := auth.TenantFromContext(ctx)
	if !ok {
		return nil, status.Error(codes.PermissionDenied, "no tenant in context")
	}
	if identity, err := auth.IdentityFromContext(ctx); err != nil || identity.Subject == "" {
		// The authoritative human is the one who started the flow (recorded on
		// the pending), but this RPC is still an authenticated admin action.
		return nil, status.Error(codes.PermissionDenied, "no identity in context")
	}

	// The connector name on the request is advisory: the state selected the
	// pending, and the pending names the connector the grant lands on.
	st, err := s.FinishAuthorization(ctx, req.GetState(), req.GetCode(), tenant.String())
	if err != nil {
		return nil, err
	}
	return &tenantv1.CompleteConnectorAuthorizationResponse{Status: st}, nil
}

// FinishAuthorization completes a started authorization. It consumes the
// pending record for state, exchanges the code for a grant at the vendor, then
// stores and proves the grant through the same path as CompleteConnectorAuthorization.
// The refresh token never leaves the daemon. Both the RPC and the pre-auth HTTP
// callback call this: the callback passes an empty expectTenant (it trusts the
// state), the RPC passes its caller's tenant so a state minted for another
// tenant is refused.
func (s *ConnectorAuthAdminServer) FinishAuthorization(ctx context.Context, state, code, expectTenant string) (*tenantv1.GetConnectorAuthStatusResponse, error) {
	if s.pending == nil {
		return nil, status.Error(codes.FailedPrecondition, "authorization store is not configured on this daemon")
	}
	if state == "" || code == "" {
		return nil, status.Error(codes.InvalidArgument, "state and code are required")
	}
	pa, ok := s.pending.Take(state)
	if !ok {
		// Unknown or expired state: the CSRF binding failed, or the 5-minute
		// window passed. Either way the operator starts again.
		return nil, status.Error(codes.PermissionDenied, "unknown or expired authorization state")
	}
	if expectTenant != "" && pa.AuthorizedTenant != expectTenant {
		return nil, status.Error(codes.PermissionDenied, "authorization state belongs to another tenant")
	}
	tenant, err := auth.NewTenantID(pa.AuthorizedTenant)
	if err != nil {
		return nil, status.Error(codes.Internal, "pending authorization has an invalid tenant")
	}
	// The callback carries no auth context; scope by the tenant recorded when
	// the (authenticated) Start ran.
	ctx = auth.WithTenant(ctx, tenant)

	grant, err := connectorauth.ExchangeCode(ctx, s.client, pa, code, s.now)
	if err != nil {
		// The error carries the vendor's error code and never credential
		// material (connectorauth's contract).
		return nil, status.Errorf(codes.FailedPrecondition, "authorization-code exchange failed: %v", err)
	}
	return s.storeAndProve(ctx, tenant, pa.Connector, grant)
}

// storeAndProve stores a grant, then proves it by minting the first access
// token. A grant that cannot refresh is removed again and the call fails, so
// the operator learns at authorization time rather than when the first token
// dies. Replacing an existing grant is a plain overwrite: one name, one blob,
// nothing to orphan; the proving refresh rewrites the access pair.
func (s *ConnectorAuthAdminServer) storeAndProve(ctx context.Context, tenant auth.TenantID, connector string, grant *connectorauth.Grant) (*tenantv1.GetConnectorAuthStatusResponse, error) {
	blob, err := connectorauth.MarshalGrant(grant)
	if err != nil {
		// Validate names missing fields only — never their values.
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	if err := s.secrets.Put(ctx, connectorauth.GrantSecretName(connector), blob); err != nil {
		return nil, status.Errorf(codes.Internal, "store connector grant: %v", err)
	}
	if _, err := s.prover.Refresh(ctx, connector); err != nil {
		// The grant does not work. Remove it again so the connector reads
		// UNAUTHORIZED rather than carrying a grant that can never refresh —
		// re-authorizing is the only fix either way.
		_ = s.secrets.Delete(ctx, connectorauth.GrantSecretName(connector))
		s.book.Clear(tenant.String(), connector)
		return nil, status.Errorf(codes.FailedPrecondition, "grant verification failed: %v", err)
	}
	s.book.Record(tenant.String(), connector, nil, s.now().UTC())
	return s.buildStatus(ctx, tenant, connector), nil
}

// RevokeConnectorGrant revokes at the vendor when the grant recorded a
// revocation endpoint, then deletes the grant and the published access pair.
// Idempotent: revoking an unauthorized connector succeeds with
// had_grant=false.
func (s *ConnectorAuthAdminServer) RevokeConnectorGrant(ctx context.Context, req *tenantv1.RevokeConnectorGrantRequest) (*tenantv1.RevokeConnectorGrantResponse, error) {
	tenant, ok := auth.TenantFromContext(ctx)
	if !ok {
		return nil, status.Error(codes.PermissionDenied, "no tenant in context")
	}
	connector := req.GetConnector()
	if connector == "" {
		return nil, status.Error(codes.InvalidArgument, "connector is required")
	}
	hadGrant, vendorRevoked, err := s.Revoke(ctx, tenant, connector)
	if err != nil {
		return nil, err
	}
	return &tenantv1.RevokeConnectorGrantResponse{HadGrant: hadGrant, VendorRevoked: vendorRevoked}, nil
}

// Revoke is the revocation itself, shared by the tenant-scoped RPC above and
// the operator-scoped DaemonOperatorService.RevokeConnectorGrant the
// ConnectorInstance finalizer calls on delete (ADR-0015 §5). The tenant is
// explicit because the finalizer path carries no tenant in its context; the
// store is scoped to it here. Best-effort vendor revocation when the grant
// recorded a revocation endpoint, then deletion of the grant and the published
// access pair. Idempotent: no grant is (false, false, nil). Errors are gRPC
// statuses so both RPCs return them verbatim.
func (s *ConnectorAuthAdminServer) Revoke(ctx context.Context, tenant auth.TenantID, connector string) (hadGrant, vendorRevoked bool, err error) {
	ctx = auth.WithTenant(ctx, tenant)

	raw, err := s.secrets.Resolve(ctx, connectorauth.GrantSecretName(connector))
	if err != nil {
		// Only an ABSENT grant is the idempotent no-grant case. A broker
		// failure must not read as "nothing to revoke" — the caller would
		// believe access is gone while the grant is still live.
		if status.Code(err) == codes.NotFound {
			return false, false, nil
		}
		return false, false, status.Errorf(codes.Internal, "resolve connector grant: %v", err)
	}
	if len(raw) == 0 {
		return false, false, nil
	}

	// Best-effort vendor revocation. Local deletion happens regardless: the
	// platform mints no further tokens either way, and a failed vendor call
	// must not leave the grant alive locally.
	if grant, err := connectorauth.UnmarshalGrant(raw); err == nil && grant.RevocationEndpoint != "" {
		vendorRevoked = s.revokeAtVendor(ctx, grant)
	}

	for _, name := range []string{
		connectorauth.GrantSecretName(connector),
		connectorauth.AccessSecretName(connector),
		connectorauth.AccessMetaSecretName(connector),
	} {
		if err := s.secrets.Delete(ctx, name); err != nil && status.Code(err) != codes.NotFound {
			return false, false, status.Errorf(codes.Internal, "delete %s: %v", name, err)
		}
	}
	s.book.Clear(tenant.String(), connector)

	return true, vendorRevoked, nil
}

// SetConnectorSecret stores a customer-supplied static credential for an
// `auth: secret` connector (ADR-0015). The credential lands in the tenant's
// configured store as the connector's access secret — the same name an OAuth
// access token lives under, so the token materializer publishes both modes
// through one path — and a static grant records the accountable human. The
// access secret is written first: a grant never exists without its credential,
// so a crash between the two writes reads UNAUTHORIZED, never a broken
// AUTHORIZED. Calling it again replaces the credential in place.
func (s *ConnectorAuthAdminServer) SetConnectorSecret(ctx context.Context, req *tenantv1.SetConnectorSecretRequest) (*tenantv1.SetConnectorSecretResponse, error) {
	tenant, ok := auth.TenantFromContext(ctx)
	if !ok {
		return nil, status.Error(codes.PermissionDenied, "no tenant in context")
	}
	identity, err := auth.IdentityFromContext(ctx)
	if err != nil || identity.Subject == "" {
		// A credential with no recorded human is a service account nobody is
		// accountable for — the thing ADR-0064 refuses to create.
		return nil, status.Error(codes.PermissionDenied, "no identity in context")
	}
	connector := req.GetConnector()
	if connector == "" {
		return nil, status.Error(codes.InvalidArgument, "connector is required")
	}
	secret := req.GetSecret()
	if len(secret) == 0 {
		return nil, status.Error(codes.InvalidArgument, "secret is required")
	}

	grant := &connectorauth.Grant{
		Static:       true,
		AuthorizedBy: "user:" + identity.Subject,
		AuthorizedAt: s.now().UTC(),
	}
	blob, err := connectorauth.MarshalGrant(grant)
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}
	if err := s.secrets.Put(ctx, connectorauth.AccessSecretName(connector), secret); err != nil {
		return nil, status.Errorf(codes.Internal, "store connector secret: %v", err)
	}
	if err := s.secrets.Put(ctx, connectorauth.GrantSecretName(connector), blob); err != nil {
		return nil, status.Errorf(codes.Internal, "store connector grant: %v", err)
	}
	// A previous OAuth grant on this connector may have left refresh
	// bookkeeping behind; a static credential has no expiry, and a stale
	// refresh error must not read as REFRESH_FAILING.
	if err := s.secrets.Delete(ctx, connectorauth.AccessMetaSecretName(connector)); err != nil && status.Code(err) != codes.NotFound {
		return nil, status.Errorf(codes.Internal, "clear connector access metadata: %v", err)
	}
	s.book.Clear(tenant.String(), connector)

	return &tenantv1.SetConnectorSecretResponse{Status: s.buildStatus(ctx, tenant, connector)}, nil
}

// revokeAtVendor POSTs an RFC 7009 revocation for the refresh token.
// Revoking the refresh token invalidates its access tokens at every vendor
// that implements the RFC's cascade, which is what makes dashboard-revoke
// take effect for agents holding a still-unexpired access token.
func (s *ConnectorAuthAdminServer) revokeAtVendor(ctx context.Context, grant *connectorauth.Grant) bool {
	form := url.Values{
		"token":           {grant.RefreshToken},
		"token_type_hint": {"refresh_token"},
		"client_id":       {grant.ClientID},
	}
	if grant.ClientSecret != "" {
		form.Set("client_secret", grant.ClientSecret)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, grant.RevocationEndpoint,
		strings.NewReader(form.Encode()))
	if err != nil {
		return false
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := s.client.Do(req)
	if err != nil {
		return false
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<16))
	return resp.StatusCode >= 200 && resp.StatusCode < 300
}

// unmarshalAccessMeta parses the platform-only access metadata blob.
func unmarshalAccessMeta(b []byte) (*connectorauth.AccessToken, error) {
	var tok connectorauth.AccessToken
	if err := json.Unmarshal(b, &tok); err != nil {
		// Named without content: the blob is platform bookkeeping, but the
		// habit of never echoing broker bytes into errors stays uniform.
		return nil, fmt.Errorf("connector access metadata is not valid JSON: %w", err)
	}
	return &tok, nil
}
