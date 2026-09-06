// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

// connector_auth_admin_test.go — ConnectorAuthService handler tests.
//
// The fakes mirror the two production dependencies: a tenant-oblivious secret
// store (tenant scoping is the context's job) and a prover that stands in for
// connectorauth.Refresher. The authorize flow runs against an httptest vendor
// so the daemon-side discovery, registration and code exchange are exercised
// end to end without a network.
package admin

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	tenantv1 "github.com/zeroroot-ai/gibson/internal/server/daemon/api/gibson/tenant/v1"
	"github.com/zeroroot-ai/sdk/auth"

	"github.com/zeroroot-ai/gibson/internal/platform/connectorauth"
)

var fixedNow = time.Unix(1_700_000_000, 0).UTC()

type fakeConnectorSecrets struct {
	mu   sync.Mutex
	data map[string][]byte
}

func newFakeConnectorSecrets() *fakeConnectorSecrets {
	return &fakeConnectorSecrets{data: map[string][]byte{}}
}

func (f *fakeConnectorSecrets) Resolve(_ context.Context, name string) ([]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	v, ok := f.data[name]
	if !ok {
		return nil, status.Errorf(codes.NotFound, "secret %q not found", name)
	}
	return v, nil
}

func (f *fakeConnectorSecrets) Put(_ context.Context, name string, value []byte) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.data[name] = append([]byte(nil), value...)
	return nil
}

func (f *fakeConnectorSecrets) Delete(_ context.Context, name string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, ok := f.data[name]; !ok {
		return status.Errorf(codes.NotFound, "secret %q not found", name)
	}
	delete(f.data, name)
	return nil
}

func (f *fakeConnectorSecrets) has(name string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	_, ok := f.data[name]
	return ok
}

// fakeProver simulates the proving refresh: on success it publishes the access
// pair the way connectorauth.Refresher would.
type fakeProver struct {
	store *fakeConnectorSecrets
	err   error
	calls int
}

func (p *fakeProver) Refresh(ctx context.Context, connector string) (*connectorauth.AccessToken, error) {
	p.calls++
	if p.err != nil {
		return nil, p.err
	}
	tok := &connectorauth.AccessToken{Token: "at-1", ExpiresAt: time.Unix(1_700_007_200, 0).UTC()}
	meta, _ := json.Marshal(tok)
	_ = p.store.Put(ctx, connectorauth.AccessSecretName(connector), []byte(tok.Token))
	_ = p.store.Put(ctx, connectorauth.AccessMetaSecretName(connector), meta)
	return tok, nil
}

func newConnectorAuthServer(t *testing.T, store *fakeConnectorSecrets, prover *fakeProver) *ConnectorAuthAdminServer {
	t.Helper()
	srv, err := NewConnectorAuthAdminServer(ConnectorAuthAdminConfig{
		Secrets: store,
		Prover:  prover,
		Status:  connectorauth.NewStatusBook(),
		Now:     func() time.Time { return fixedNow },
	})
	if err != nil {
		t.Fatalf("NewConnectorAuthAdminServer: %v", err)
	}
	return srv
}

// seedGrant stores a proven grant the way a finished authorization would, so
// the status and revoke tests start from an AUTHORIZED connector without going
// through the whole OAuth round trip.
func seedGrant(ctx context.Context, t *testing.T, store *fakeConnectorSecrets, prover *fakeProver, connector string, mutate func(*connectorauth.Grant)) {
	t.Helper()
	g := &connectorauth.Grant{
		RefreshToken:  "rt-1",
		TokenEndpoint: "https://gitlab.example.com/oauth/token",
		ClientID:      "client-abc",
		Scope:         "mcp",
		AuthorizedBy:  "user:user-1",
		AuthorizedAt:  fixedNow,
	}
	if mutate != nil {
		mutate(g)
	}
	blob, err := connectorauth.MarshalGrant(g)
	if err != nil {
		t.Fatalf("seed grant: %v", err)
	}
	if err := store.Put(ctx, connectorauth.GrantSecretName(connector), blob); err != nil {
		t.Fatalf("seed grant put: %v", err)
	}
	if _, err := prover.Refresh(ctx, connector); err != nil {
		t.Fatalf("seed grant prove: %v", err)
	}
}

// ---------------------------------------------------------------------------
// GetConnectorAuthStatus
// ---------------------------------------------------------------------------

func TestGetConnectorAuthStatus_UnauthorizedWhenNoGrant(t *testing.T) {
	store := newFakeConnectorSecrets()
	srv := newConnectorAuthServer(t, store, &fakeProver{store: store})

	resp, err := srv.GetConnectorAuthStatus(ctxWithTenant(t, "acme"),
		&tenantv1.GetConnectorAuthStatusRequest{Connector: "connector-gitlab"})
	if err != nil {
		t.Fatal(err)
	}
	if resp.GetState() != tenantv1.ConnectorAuthState_CONNECTOR_AUTH_STATE_UNAUTHORIZED {
		t.Errorf("state = %v, want UNAUTHORIZED", resp.GetState())
	}
}

func TestGetConnectorAuthStatus_ReportsTheAuthorizingHuman(t *testing.T) {
	store := newFakeConnectorSecrets()
	prover := &fakeProver{store: store}
	srv := newConnectorAuthServer(t, store, prover)
	ctx := ctxWithTenant(t, "acme")

	seedGrant(ctx, t, store, prover, "connector-gitlab", nil)
	resp, err := srv.GetConnectorAuthStatus(ctx,
		&tenantv1.GetConnectorAuthStatusRequest{Connector: "connector-gitlab"})
	if err != nil {
		t.Fatal(err)
	}
	if resp.GetState() != tenantv1.ConnectorAuthState_CONNECTOR_AUTH_STATE_AUTHORIZED {
		t.Errorf("state = %v, want AUTHORIZED", resp.GetState())
	}
	if resp.GetAuthorizedBy() != "user:user-1" {
		t.Errorf("authorized_by = %q, want user:user-1", resp.GetAuthorizedBy())
	}
	if resp.GetAuthorizedAt() == nil {
		t.Error("authorized_at must be set")
	}
}

// The status surface must never leak credential material — it is what renders
// in the dashboard.
func TestGetConnectorAuthStatus_CarriesNoCredentialMaterial(t *testing.T) {
	store := newFakeConnectorSecrets()
	prover := &fakeProver{store: store}
	srv := newConnectorAuthServer(t, store, prover)
	ctx := ctxWithTenant(t, "acme")

	seedGrant(ctx, t, store, prover, "connector-gitlab", nil)
	resp, err := srv.GetConnectorAuthStatus(ctx,
		&tenantv1.GetConnectorAuthStatusRequest{Connector: "connector-gitlab"})
	if err != nil {
		t.Fatal(err)
	}
	wire := resp.String()
	for _, forbidden := range []string{"rt-1", "at-1"} {
		if strings.Contains(wire, forbidden) {
			t.Errorf("status response leaked %q: %s", forbidden, wire)
		}
	}
}

func TestGetConnectorAuthStatus_SurfacesARefreshFailure(t *testing.T) {
	store := newFakeConnectorSecrets()
	prover := &fakeProver{store: store}
	srv := newConnectorAuthServer(t, store, prover)
	ctx := ctxWithTenant(t, "acme")

	seedGrant(ctx, t, store, prover, "connector-gitlab", nil)
	// A later background refresh fails; the loop records it.
	srv.book.Record("acme", "connector-gitlab",
		errors.New("token refresh refused (400): invalid_grant"), time.Unix(1_700_003_600, 0).UTC())

	resp, err := srv.GetConnectorAuthStatus(ctx,
		&tenantv1.GetConnectorAuthStatusRequest{Connector: "connector-gitlab"})
	if err != nil {
		t.Fatal(err)
	}
	if resp.GetState() != tenantv1.ConnectorAuthState_CONNECTOR_AUTH_STATE_REFRESH_FAILING {
		t.Errorf("state = %v, want REFRESH_FAILING", resp.GetState())
	}
	if !strings.Contains(resp.GetLastRefreshError(), "invalid_grant") {
		t.Errorf("last_refresh_error = %q, want the vendor's error code", resp.GetLastRefreshError())
	}
}

func TestGetConnectorAuthStatus_RequiresAConnectorName(t *testing.T) {
	store := newFakeConnectorSecrets()
	srv := newConnectorAuthServer(t, store, &fakeProver{store: store})

	_, err := srv.GetConnectorAuthStatus(ctxWithTenant(t, "acme"),
		&tenantv1.GetConnectorAuthStatusRequest{})
	if status.Code(err) != codes.InvalidArgument {
		t.Errorf("err = %v, want InvalidArgument", err)
	}
}

// ---------------------------------------------------------------------------
// StartConnectorAuthorization
// ---------------------------------------------------------------------------

// fakeVendor is an httptest server that serves RFC 8414 metadata and RFC 7591
// dynamic client registration, so StartConnectorAuthorization can run its whole
// front half without a real vendor.
func fakeVendor(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	var srv *httptest.Server
	mux.HandleFunc("/.well-known/oauth-authorization-server", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{
			"issuer":                 srv.URL,
			"authorization_endpoint": srv.URL + "/oauth/authorize",
			"token_endpoint":         srv.URL + "/oauth/token",
			"registration_endpoint":  srv.URL + "/oauth/register",
			"revocation_endpoint":    srv.URL + "/oauth/revoke",
		})
	})
	mux.HandleFunc("/oauth/register", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]string{"client_id": "dyn-client-1"})
	})
	srv = httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func newAuthorizeFlowServer(t *testing.T, store *fakeConnectorSecrets, prover *fakeProver, pending *connectorauth.PendingStore, client *http.Client) *ConnectorAuthAdminServer {
	t.Helper()
	srv, err := NewConnectorAuthAdminServer(ConnectorAuthAdminConfig{
		Secrets:         store,
		Prover:          prover,
		Status:          connectorauth.NewStatusBook(),
		Pending:         pending,
		CallbackBaseURL: "https://api.example.com",
		HTTPClient:      client,
		Now:             func() time.Time { return fixedNow },
	})
	if err != nil {
		t.Fatalf("NewConnectorAuthAdminServer: %v", err)
	}
	return srv
}

func TestStartConnectorAuthorization_ReturnsAuthorizeURLAndStoresPending(t *testing.T) {
	vendor := fakeVendor(t)
	store := newFakeConnectorSecrets()
	pending := connectorauth.NewPendingStore(5*time.Minute, func() time.Time { return fixedNow })
	srv := newAuthorizeFlowServer(t, store, &fakeProver{store: store}, pending, vendor.Client())

	resp, err := srv.StartConnectorAuthorization(ctxWithTenant(t, "acme"),
		&tenantv1.StartConnectorAuthorizationRequest{Connector: "connector-gitlab", InstanceUrl: vendor.URL})
	if err != nil {
		t.Fatal(err)
	}
	if resp.GetState() == "" {
		t.Fatal("state must be returned")
	}
	u, err := url.Parse(resp.GetAuthorizeUrl())
	if err != nil {
		t.Fatalf("authorize_url is not a URL: %v", err)
	}
	q := u.Query()
	if q.Get("response_type") != "code" || q.Get("client_id") != "dyn-client-1" {
		t.Errorf("authorize url query = %v", q)
	}
	if q.Get("code_challenge_method") != "S256" || q.Get("code_challenge") == "" {
		t.Errorf("authorize url must carry an S256 PKCE challenge, got %v", q)
	}
	if q.Get("redirect_uri") != "https://api.example.com"+connectorauth.CallbackPath {
		t.Errorf("redirect_uri = %q", q.Get("redirect_uri"))
	}
	if q.Get("state") != resp.GetState() {
		t.Errorf("authorize url state %q != returned state %q", q.Get("state"), resp.GetState())
	}
	// The pending must be stored under the returned state, carrying the human
	// and tenant captured now.
	pa, ok := pending.Take(resp.GetState())
	if !ok {
		t.Fatal("a pending authorization must be stored under the returned state")
	}
	if pa.AuthorizedBy != "user:user-1" || pa.AuthorizedTenant != "acme" {
		t.Errorf("pending records = %+v, want the caller's human and tenant", pa)
	}
	if pa.TokenEndpoint != vendor.URL+"/oauth/token" || pa.Verifier == "" {
		t.Errorf("pending endpoints = %+v", pa)
	}
}

func TestStartConnectorAuthorization_RequiresAConfiguredCallback(t *testing.T) {
	store := newFakeConnectorSecrets()
	// No Pending / CallbackBaseURL: the authorize flow is not configured.
	srv := newConnectorAuthServer(t, store, &fakeProver{store: store})

	_, err := srv.StartConnectorAuthorization(ctxWithTenant(t, "acme"),
		&tenantv1.StartConnectorAuthorizationRequest{Connector: "connector-gitlab", InstanceUrl: "https://gitlab.com"})
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("err = %v, want FailedPrecondition", err)
	}
}

func TestStartConnectorAuthorization_RequiresConnectorAndInstance(t *testing.T) {
	vendor := fakeVendor(t)
	store := newFakeConnectorSecrets()
	pending := connectorauth.NewPendingStore(5*time.Minute, func() time.Time { return fixedNow })
	srv := newAuthorizeFlowServer(t, store, &fakeProver{store: store}, pending, vendor.Client())

	if _, err := srv.StartConnectorAuthorization(ctxWithTenant(t, "acme"),
		&tenantv1.StartConnectorAuthorizationRequest{InstanceUrl: vendor.URL}); status.Code(err) != codes.InvalidArgument {
		t.Errorf("missing connector: err = %v, want InvalidArgument", err)
	}
	if _, err := srv.StartConnectorAuthorization(ctxWithTenant(t, "acme"),
		&tenantv1.StartConnectorAuthorizationRequest{Connector: "connector-gitlab"}); status.Code(err) != codes.InvalidArgument {
		t.Errorf("missing instance_url: err = %v, want InvalidArgument", err)
	}
}

// ---------------------------------------------------------------------------
// CompleteConnectorAuthorization (code + state)
// ---------------------------------------------------------------------------

// tokenVendor serves the authorization-code token exchange. gotForm captures
// the last exchange body so a test can assert the PKCE verifier was sent.
func tokenVendor(t *testing.T, refreshToken string) (srv *httptest.Server, form func() url.Values) {
	t.Helper()
	var (
		mu      sync.Mutex
		gotForm url.Values
	)
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		mu.Lock()
		gotForm = r.PostForm
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token":  "at-vendor",
			"refresh_token": refreshToken,
			"expires_in":    3600,
			"scope":         "api",
		})
	}))
	t.Cleanup(srv.Close)
	return srv, func() url.Values {
		mu.Lock()
		defer mu.Unlock()
		return gotForm
	}
}

func seedPending(pending *connectorauth.PendingStore, state, connector, tokenEndpoint, tenant string) {
	pending.Put(&connectorauth.PendingAuthorization{
		State:            state,
		Verifier:         "verifier-1",
		Connector:        connector,
		TokenEndpoint:    tokenEndpoint,
		ClientID:         "dyn-client-1",
		RedirectURI:      "https://api.example.com" + connectorauth.CallbackPath,
		AuthorizedBy:     "user:user-1",
		AuthorizedTenant: tenant,
		CreatedAt:        fixedNow,
	})
}

func TestCompleteConnectorAuthorization_ExchangesCodeAndStoresGrant(t *testing.T) {
	vendor, form := tokenVendor(t, "rt-vendor")
	store := newFakeConnectorSecrets()
	prover := &fakeProver{store: store}
	pending := connectorauth.NewPendingStore(5*time.Minute, func() time.Time { return fixedNow })
	srv := newAuthorizeFlowServer(t, store, prover, pending, vendor.Client())

	seedPending(pending, "state-1", "connector-gitlab", vendor.URL, "acme")

	resp, err := srv.CompleteConnectorAuthorization(ctxWithTenant(t, "acme"),
		&tenantv1.CompleteConnectorAuthorizationRequest{Connector: "connector-gitlab", Code: "the-code", State: "state-1"})
	if err != nil {
		t.Fatal(err)
	}
	if prover.calls != 1 {
		t.Errorf("proving refresh ran %d times, want 1", prover.calls)
	}
	if resp.GetStatus().GetState() != tenantv1.ConnectorAuthState_CONNECTOR_AUTH_STATE_AUTHORIZED {
		t.Errorf("state = %v, want AUTHORIZED", resp.GetStatus().GetState())
	}
	// The exchange must carry the authorization_code grant and the PKCE verifier.
	if f := form(); f.Get("grant_type") != "authorization_code" || f.Get("code_verifier") != "verifier-1" {
		t.Errorf("exchange form = %v", f)
	}
	// The stored grant keeps the vendor's refresh token and the human recorded
	// at Start.
	raw, _ := store.Resolve(context.Background(), connectorauth.GrantSecretName("connector-gitlab"))
	grant, err := connectorauth.UnmarshalGrant(raw)
	if err != nil {
		t.Fatalf("stored grant: %v", err)
	}
	if grant.RefreshToken != "rt-vendor" || grant.AuthorizedBy != "user:user-1" {
		t.Errorf("stored grant = %+v", grant)
	}
	// The refresh token never leaves the daemon.
	if strings.Contains(resp.String(), "rt-vendor") {
		t.Errorf("response leaked the refresh token: %s", resp.String())
	}
}

func TestCompleteConnectorAuthorization_RejectsAnUnknownState(t *testing.T) {
	vendor, _ := tokenVendor(t, "rt-vendor")
	store := newFakeConnectorSecrets()
	pending := connectorauth.NewPendingStore(5*time.Minute, func() time.Time { return fixedNow })
	srv := newAuthorizeFlowServer(t, store, &fakeProver{store: store}, pending, vendor.Client())

	_, err := srv.CompleteConnectorAuthorization(ctxWithTenant(t, "acme"),
		&tenantv1.CompleteConnectorAuthorizationRequest{Code: "c", State: "never-issued"})
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("err = %v, want PermissionDenied", err)
	}
}

func TestCompleteConnectorAuthorization_RejectsACrossTenantState(t *testing.T) {
	vendor, _ := tokenVendor(t, "rt-vendor")
	store := newFakeConnectorSecrets()
	pending := connectorauth.NewPendingStore(5*time.Minute, func() time.Time { return fixedNow })
	srv := newAuthorizeFlowServer(t, store, &fakeProver{store: store}, pending, vendor.Client())

	// The pending belongs to another tenant.
	seedPending(pending, "state-1", "connector-gitlab", vendor.URL, "other-tenant")

	_, err := srv.CompleteConnectorAuthorization(ctxWithTenant(t, "acme"),
		&tenantv1.CompleteConnectorAuthorizationRequest{Code: "c", State: "state-1"})
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("err = %v, want PermissionDenied", err)
	}
}

// A grant that cannot refresh is not kept: the operator learns now, and the
// connector reads UNAUTHORIZED rather than carrying a dead grant.
func TestCompleteConnectorAuthorization_RemovesAGrantThatFailsProving(t *testing.T) {
	vendor, _ := tokenVendor(t, "rt-vendor")
	store := newFakeConnectorSecrets()
	prover := &fakeProver{store: store, err: errors.New("token refresh refused (400): invalid_grant")}
	pending := connectorauth.NewPendingStore(5*time.Minute, func() time.Time { return fixedNow })
	srv := newAuthorizeFlowServer(t, store, prover, pending, vendor.Client())

	seedPending(pending, "state-1", "connector-gitlab", vendor.URL, "acme")

	_, err := srv.CompleteConnectorAuthorization(ctxWithTenant(t, "acme"),
		&tenantv1.CompleteConnectorAuthorizationRequest{Code: "c", State: "state-1"})
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("err = %v, want FailedPrecondition", err)
	}
	if !strings.Contains(err.Error(), "invalid_grant") {
		t.Errorf("error must carry the vendor's error code, got %v", err)
	}
	if store.has(connectorauth.GrantSecretName("connector-gitlab")) {
		t.Error("a grant that fails proving must be removed")
	}
}

func TestCompleteConnectorAuthorization_RequiresAnIdentity(t *testing.T) {
	vendor, _ := tokenVendor(t, "rt-vendor")
	store := newFakeConnectorSecrets()
	pending := connectorauth.NewPendingStore(5*time.Minute, func() time.Time { return fixedNow })
	srv := newAuthorizeFlowServer(t, store, &fakeProver{store: store}, pending, vendor.Client())
	seedPending(pending, "state-1", "connector-gitlab", vendor.URL, "acme")

	// A context with no identity: a grant with no recorded human is the thing
	// ADR-0064 refuses to create.
	_, err := srv.CompleteConnectorAuthorization(context.Background(),
		&tenantv1.CompleteConnectorAuthorizationRequest{Code: "c", State: "state-1"})
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("err = %v, want PermissionDenied", err)
	}
}

// FinishAuthorization is the shared path the pre-auth callback drives with an
// empty expectTenant. It must complete the same grant.
func TestFinishAuthorization_CompletesUnderThePendingTenant(t *testing.T) {
	vendor, _ := tokenVendor(t, "rt-vendor")
	store := newFakeConnectorSecrets()
	prover := &fakeProver{store: store}
	pending := connectorauth.NewPendingStore(5*time.Minute, func() time.Time { return fixedNow })
	srv := newAuthorizeFlowServer(t, store, prover, pending, vendor.Client())
	seedPending(pending, "state-1", "connector-gitlab", vendor.URL, "acme")

	// The callback carries no auth context and no tenant expectation.
	st, err := srv.FinishAuthorization(context.Background(), "state-1", "the-code", "")
	if err != nil {
		t.Fatal(err)
	}
	if st.GetState() != tenantv1.ConnectorAuthState_CONNECTOR_AUTH_STATE_AUTHORIZED {
		t.Errorf("state = %v, want AUTHORIZED", st.GetState())
	}
	if !store.has(connectorauth.GrantSecretName("connector-gitlab")) {
		t.Error("the grant must be stored under the pending's connector")
	}
}

// ---------------------------------------------------------------------------
// RevokeConnectorGrant
// ---------------------------------------------------------------------------

func TestRevokeConnectorGrant_DeletesTheGrantAndAccessPair(t *testing.T) {
	store := newFakeConnectorSecrets()
	prover := &fakeProver{store: store}
	srv := newConnectorAuthServer(t, store, prover)
	ctx := ctxWithTenant(t, "acme")

	seedGrant(ctx, t, store, prover, "connector-gitlab", nil)
	resp, err := srv.RevokeConnectorGrant(ctx,
		&tenantv1.RevokeConnectorGrantRequest{Connector: "connector-gitlab"})
	if err != nil {
		t.Fatal(err)
	}
	if !resp.GetHadGrant() {
		t.Error("had_grant must be true")
	}
	for _, name := range []string{
		connectorauth.GrantSecretName("connector-gitlab"),
		connectorauth.AccessSecretName("connector-gitlab"),
		connectorauth.AccessMetaSecretName("connector-gitlab"),
	} {
		if store.has(name) {
			t.Errorf("%s must be deleted", name)
		}
	}

	st, err := srv.GetConnectorAuthStatus(ctx,
		&tenantv1.GetConnectorAuthStatusRequest{Connector: "connector-gitlab"})
	if err != nil {
		t.Fatal(err)
	}
	if st.GetState() != tenantv1.ConnectorAuthState_CONNECTOR_AUTH_STATE_UNAUTHORIZED {
		t.Errorf("state after revoke = %v, want UNAUTHORIZED", st.GetState())
	}
}

func TestRevokeConnectorGrant_IsIdempotent(t *testing.T) {
	store := newFakeConnectorSecrets()
	srv := newConnectorAuthServer(t, store, &fakeProver{store: store})

	resp, err := srv.RevokeConnectorGrant(ctxWithTenant(t, "acme"),
		&tenantv1.RevokeConnectorGrantRequest{Connector: "connector-gitlab"})
	if err != nil {
		t.Fatal(err)
	}
	if resp.GetHadGrant() {
		t.Error("revoking an unauthorized connector must report had_grant=false")
	}
}

func TestRevokeConnectorGrant_RevokesAtTheVendor(t *testing.T) {
	var (
		formMu  sync.Mutex
		gotForm url.Values
	)
	vendor := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		formMu.Lock()
		gotForm = r.PostForm
		formMu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	defer vendor.Close()

	store := newFakeConnectorSecrets()
	prover := &fakeProver{store: store}
	srv, err := NewConnectorAuthAdminServer(ConnectorAuthAdminConfig{
		Secrets:    store,
		Prover:     prover,
		Status:     connectorauth.NewStatusBook(),
		HTTPClient: vendor.Client(),
		Now:        func() time.Time { return fixedNow },
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx := ctxWithTenant(t, "acme")

	seedGrant(ctx, t, store, prover, "connector-gitlab", func(g *connectorauth.Grant) {
		g.RevocationEndpoint = vendor.URL
	})
	resp, err := srv.RevokeConnectorGrant(ctx,
		&tenantv1.RevokeConnectorGrantRequest{Connector: "connector-gitlab"})
	if err != nil {
		t.Fatal(err)
	}
	if !resp.GetVendorRevoked() {
		t.Error("vendor_revoked must be true when the vendor acknowledged")
	}
	formMu.Lock()
	form := gotForm
	formMu.Unlock()
	if form.Get("token") != "rt-1" || form.Get("token_type_hint") != "refresh_token" {
		t.Errorf("vendor revocation form = %v", form)
	}
}

// A vendor that cannot be reached must not block local revocation: the platform
// mints no further tokens either way.
func TestRevokeConnectorGrant_LocalDeletionSurvivesAVendorFailure(t *testing.T) {
	store := newFakeConnectorSecrets()
	prover := &fakeProver{store: store}
	srv := newConnectorAuthServer(t, store, prover)
	ctx := ctxWithTenant(t, "acme")

	seedGrant(ctx, t, store, prover, "connector-gitlab", func(g *connectorauth.Grant) {
		g.RevocationEndpoint = "http://127.0.0.1:1/unreachable"
	})
	resp, err := srv.RevokeConnectorGrant(ctx,
		&tenantv1.RevokeConnectorGrantRequest{Connector: "connector-gitlab"})
	if err != nil {
		t.Fatal(err)
	}
	if resp.GetVendorRevoked() {
		t.Error("vendor_revoked must be false when the vendor call failed")
	}
	if store.has(connectorauth.GrantSecretName("connector-gitlab")) {
		t.Error("the local grant must be deleted regardless")
	}
}

// ---------------------------------------------------------------------------
// Constructor + dependency validation
// ---------------------------------------------------------------------------

func TestNewConnectorAuthAdminServer_RequiresItsDependencies(t *testing.T) {
	store := newFakeConnectorSecrets()
	if _, err := NewConnectorAuthAdminServer(ConnectorAuthAdminConfig{Prover: &fakeProver{store: store}}); err == nil {
		t.Error("a nil secret store must be refused")
	}
	if _, err := NewConnectorAuthAdminServer(ConnectorAuthAdminConfig{Secrets: store}); err == nil {
		t.Error("a nil prover must be refused")
	}
	// Nil Status, HTTPClient, Pending, CallbackBaseURL and Now are tolerated
	// with defaults.
	if _, err := NewConnectorAuthAdminServer(ConnectorAuthAdminConfig{
		Secrets: store, Prover: &fakeProver{store: store},
	}); err != nil {
		t.Errorf("optional deps must default: %v", err)
	}
}

func TestRevokeConnectorGrant_RequiresAConnectorName(t *testing.T) {
	store := newFakeConnectorSecrets()
	srv := newConnectorAuthServer(t, store, &fakeProver{store: store})

	_, err := srv.RevokeConnectorGrant(ctxWithTenant(t, "acme"),
		&tenantv1.RevokeConnectorGrantRequest{})
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("err = %v, want InvalidArgument", err)
	}
}

// A stored-but-unreadable grant is functionally no grant: the fix is to
// re-authorize, which is what UNAUTHORIZED tells the operator.
func TestGetConnectorAuthStatus_UnreadableGrantReadsUnauthorized(t *testing.T) {
	store := newFakeConnectorSecrets()
	srv := newConnectorAuthServer(t, store, &fakeProver{store: store})
	_ = store.Put(context.Background(), connectorauth.GrantSecretName("connector-gitlab"), []byte("not json"))

	resp, err := srv.GetConnectorAuthStatus(ctxWithTenant(t, "acme"),
		&tenantv1.GetConnectorAuthStatusRequest{Connector: "connector-gitlab"})
	if err != nil {
		t.Fatal(err)
	}
	if resp.GetState() != tenantv1.ConnectorAuthState_CONNECTOR_AUTH_STATE_UNAUTHORIZED {
		t.Errorf("state = %v, want UNAUTHORIZED", resp.GetState())
	}
}

// Corrupt expiry metadata must not break the status view — the grant fields
// still render; only the expiry is absent.
func TestGetConnectorAuthStatus_ToleratesCorruptAccessMetadata(t *testing.T) {
	store := newFakeConnectorSecrets()
	prover := &fakeProver{store: store}
	srv := newConnectorAuthServer(t, store, prover)
	ctx := ctxWithTenant(t, "acme")

	seedGrant(ctx, t, store, prover, "connector-gitlab", nil)
	_ = store.Put(ctx, connectorauth.AccessMetaSecretName("connector-gitlab"), []byte("not json"))

	resp, err := srv.GetConnectorAuthStatus(ctx,
		&tenantv1.GetConnectorAuthStatusRequest{Connector: "connector-gitlab"})
	if err != nil {
		t.Fatal(err)
	}
	if resp.GetState() != tenantv1.ConnectorAuthState_CONNECTOR_AUTH_STATE_AUTHORIZED {
		t.Errorf("state = %v, want AUTHORIZED", resp.GetState())
	}
	if resp.GetAccessTokenExpiresAt() != nil {
		t.Error("corrupt metadata must yield no expiry, not a fabricated one")
	}
}

// A grant whose revocation endpoint is not even a URL: local deletion still
// proceeds; vendor_revoked stays false.
func TestRevokeConnectorGrant_ToleratesAMalformedRevocationEndpoint(t *testing.T) {
	store := newFakeConnectorSecrets()
	prover := &fakeProver{store: store}
	srv := newConnectorAuthServer(t, store, prover)
	ctx := ctxWithTenant(t, "acme")

	seedGrant(ctx, t, store, prover, "connector-gitlab", func(g *connectorauth.Grant) {
		g.RevocationEndpoint = "::not a url::"
	})
	resp, err := srv.RevokeConnectorGrant(ctx,
		&tenantv1.RevokeConnectorGrantRequest{Connector: "connector-gitlab"})
	if err != nil {
		t.Fatal(err)
	}
	if resp.GetVendorRevoked() {
		t.Error("an unusable revocation endpoint cannot have been acknowledged")
	}
	if store.has(connectorauth.GrantSecretName("connector-gitlab")) {
		t.Error("local deletion must proceed regardless")
	}
}

// ---------------------------------------------------------------------------
// The Unavailable stub
// ---------------------------------------------------------------------------

func TestUnavailableConnectorAuthServer_AnswersUnavailable(t *testing.T) {
	stub := NewUnavailableConnectorAuthServer()
	ctx := context.Background()

	if _, err := stub.GetConnectorAuthStatus(ctx, &tenantv1.GetConnectorAuthStatusRequest{}); status.Code(err) != codes.Unavailable {
		t.Errorf("GetConnectorAuthStatus err = %v, want Unavailable", err)
	}
	if _, err := stub.StartConnectorAuthorization(ctx, &tenantv1.StartConnectorAuthorizationRequest{}); status.Code(err) != codes.Unavailable {
		t.Errorf("StartConnectorAuthorization err = %v, want Unavailable", err)
	}
	if _, err := stub.CompleteConnectorAuthorization(ctx, &tenantv1.CompleteConnectorAuthorizationRequest{}); status.Code(err) != codes.Unavailable {
		t.Errorf("CompleteConnectorAuthorization err = %v, want Unavailable", err)
	}
	if _, err := stub.RevokeConnectorGrant(ctx, &tenantv1.RevokeConnectorGrantRequest{}); status.Code(err) != codes.Unavailable {
		t.Errorf("RevokeConnectorGrant err = %v, want Unavailable", err)
	}
	if _, err := stub.SetConnectorSecret(ctx, &tenantv1.SetConnectorSecretRequest{}); status.Code(err) != codes.Unavailable {
		t.Errorf("SetConnectorSecret err = %v, want Unavailable", err)
	}
}

// ---------------------------------------------------------------------------
// StartConnectorAuthorization + FinishAuthorization vendor-failure branches
// ---------------------------------------------------------------------------

func TestStartConnectorAuthorization_FailsWhenDiscoveryFails(t *testing.T) {
	// A vendor that answers nothing at its well-known paths fails discovery.
	vendor := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer vendor.Close()
	store := newFakeConnectorSecrets()
	pending := connectorauth.NewPendingStore(5*time.Minute, func() time.Time { return fixedNow })
	srv := newAuthorizeFlowServer(t, store, &fakeProver{store: store}, pending, vendor.Client())

	_, err := srv.StartConnectorAuthorization(ctxWithTenant(t, "acme"),
		&tenantv1.StartConnectorAuthorizationRequest{Connector: "connector-gitlab", InstanceUrl: vendor.URL})
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("err = %v, want FailedPrecondition", err)
	}
}

func TestStartConnectorAuthorization_FailsWhenRegistrationFails(t *testing.T) {
	// Discovery succeeds but dynamic client registration is refused.
	mux := http.NewServeMux()
	var srvURL string
	mux.HandleFunc("/.well-known/oauth-authorization-server", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{
			"authorization_endpoint": srvURL + "/oauth/authorize",
			"token_endpoint":         srvURL + "/oauth/token",
			"registration_endpoint":  srvURL + "/oauth/register",
		})
	})
	mux.HandleFunc("/oauth/register", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
	})
	vendor := httptest.NewServer(mux)
	defer vendor.Close()
	srvURL = vendor.URL
	store := newFakeConnectorSecrets()
	pending := connectorauth.NewPendingStore(5*time.Minute, func() time.Time { return fixedNow })
	srv := newAuthorizeFlowServer(t, store, &fakeProver{store: store}, pending, vendor.Client())

	_, err := srv.StartConnectorAuthorization(ctxWithTenant(t, "acme"),
		&tenantv1.StartConnectorAuthorizationRequest{Connector: "connector-gitlab", InstanceUrl: vendor.URL})
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("err = %v, want FailedPrecondition", err)
	}
}

func TestCompleteConnectorAuthorization_FailsWhenTheExchangeIsRefused(t *testing.T) {
	// The token endpoint refuses the code exchange.
	vendor := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":"invalid_grant"}`))
	}))
	defer vendor.Close()
	store := newFakeConnectorSecrets()
	pending := connectorauth.NewPendingStore(5*time.Minute, func() time.Time { return fixedNow })
	srv := newAuthorizeFlowServer(t, store, &fakeProver{store: store}, pending, vendor.Client())

	seedPending(pending, "state-x", "connector-gitlab", vendor.URL, "acme")

	_, err := srv.CompleteConnectorAuthorization(ctxWithTenant(t, "acme"),
		&tenantv1.CompleteConnectorAuthorizationRequest{Connector: "connector-gitlab", Code: "bad", State: "state-x"})
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("err = %v, want FailedPrecondition", err)
	}
}

// TestCompleteConnectorAuthorization_RequiresStateAndCode rejects an empty
// state or code.
func TestCompleteConnectorAuthorization_RequiresStateAndCode(t *testing.T) {
	store := newFakeConnectorSecrets()
	pending := connectorauth.NewPendingStore(5*time.Minute, func() time.Time { return fixedNow })
	vendor, _ := tokenVendor(t, "rt")
	srv := newAuthorizeFlowServer(t, store, &fakeProver{store: store}, pending, vendor.Client())

	if _, err := srv.CompleteConnectorAuthorization(ctxWithTenant(t, "acme"),
		&tenantv1.CompleteConnectorAuthorizationRequest{Code: "c"}); status.Code(err) != codes.InvalidArgument {
		t.Errorf("missing state: err = %v, want InvalidArgument", err)
	}
}

// TestFinishAuthorization_RequiresAConfiguredStore fails when the pending store
// is not configured on the daemon.
func TestFinishAuthorization_RequiresAConfiguredStore(t *testing.T) {
	store := newFakeConnectorSecrets()
	// A server built without a Pending store cannot finish an authorization.
	srv := newConnectorAuthServer(t, store, &fakeProver{store: store})
	if _, err := srv.FinishAuthorization(context.Background(), "s", "c", ""); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("err = %v, want FailedPrecondition", err)
	}
}

// ---------------------------------------------------------------------------
// SetConnectorSecret (ADR-0015 — auth: secret connectors)
// ---------------------------------------------------------------------------

// A static credential lands in the connector's access secret — the same name
// an OAuth access token uses, so the materializer publishes both alike — with
// a static grant beside it that names the human who supplied it. The status
// reads AUTHORIZED with that human, and no credential material is echoed.
func TestSetConnectorSecret_StoresTheCredentialAndAStaticGrant(t *testing.T) {
	store := newFakeConnectorSecrets()
	prover := &fakeProver{store: store}
	srv := newConnectorAuthServer(t, store, prover)
	ctx := ctxWithTenant(t, "acme")

	resp, err := srv.SetConnectorSecret(ctx, &tenantv1.SetConnectorSecretRequest{
		Connector: "github", Secret: []byte("ghp_static"),
	})
	if err != nil {
		t.Fatalf("SetConnectorSecret: %v", err)
	}
	if got, _ := store.Resolve(ctx, connectorauth.AccessSecretName("github")); string(got) != "ghp_static" {
		t.Errorf("access secret = %q, want the credential verbatim", got)
	}
	raw, err := store.Resolve(ctx, connectorauth.GrantSecretName("github"))
	if err != nil {
		t.Fatalf("a static grant must be stored: %v", err)
	}
	grant, err := connectorauth.UnmarshalGrant(raw)
	if err != nil {
		t.Fatalf("stored grant must parse: %v", err)
	}
	if !grant.Static || grant.AuthorizedBy != "user:user-1" || !grant.AuthorizedAt.Equal(fixedNow) {
		t.Errorf("grant = %+v, want static, authorized by user:user-1 at fixedNow", grant)
	}
	if prover.calls != 0 {
		t.Errorf("a static credential has nothing to prove; prover called %d times", prover.calls)
	}
	st := resp.GetStatus()
	if st.GetState() != tenantv1.ConnectorAuthState_CONNECTOR_AUTH_STATE_AUTHORIZED {
		t.Errorf("state = %v, want AUTHORIZED", st.GetState())
	}
	if st.GetAuthorizedBy() != "user:user-1" {
		t.Errorf("authorized_by = %q, want user:user-1", st.GetAuthorizedBy())
	}
	if st.GetAccessTokenExpiresAt() != nil {
		t.Error("a static credential has no expiry to report")
	}
	if strings.Contains(st.String(), "ghp_static") {
		t.Error("status must never carry the credential")
	}
}

// Setting the credential again replaces it in place and clears any refresh
// bookkeeping a previous OAuth grant left behind, so the connector never reads
// REFRESH_FAILING for a credential that has no refresh.
func TestSetConnectorSecret_ReplacesInPlaceAndClearsStaleRefreshState(t *testing.T) {
	store := newFakeConnectorSecrets()
	prover := &fakeProver{store: store}
	srv := newConnectorAuthServer(t, store, prover)
	ctx := ctxWithTenant(t, "acme")
	seedGrant(ctx, t, store, prover, "github", nil)
	srv.book.Record("acme", "github", errors.New("vendor refused"), fixedNow)

	if _, err := srv.SetConnectorSecret(ctx, &tenantv1.SetConnectorSecretRequest{
		Connector: "github", Secret: []byte("ghp_new"),
	}); err != nil {
		t.Fatalf("SetConnectorSecret: %v", err)
	}
	if got, _ := store.Resolve(ctx, connectorauth.AccessSecretName("github")); string(got) != "ghp_new" {
		t.Errorf("access secret = %q, want the replacement", got)
	}
	if store.has(connectorauth.AccessMetaSecretName("github")) {
		t.Error("stale access metadata must be cleared")
	}
	st, err := srv.GetConnectorAuthStatus(ctx, &tenantv1.GetConnectorAuthStatusRequest{Connector: "github"})
	if err != nil {
		t.Fatalf("status: %v", err)
	}
	if st.GetState() != tenantv1.ConnectorAuthState_CONNECTOR_AUTH_STATE_AUTHORIZED || st.GetLastRefreshError() != "" {
		t.Errorf("state = %v error = %q, want AUTHORIZED with no refresh error", st.GetState(), st.GetLastRefreshError())
	}
}

// Revoking a static credential deletes the grant and the credential with no
// vendor call — there is no vendor grant to revoke — and the connector reads
// UNAUTHORIZED again.
func TestSetConnectorSecret_RevokeRemovesTheCredential(t *testing.T) {
	store := newFakeConnectorSecrets()
	srv := newConnectorAuthServer(t, store, &fakeProver{store: store})
	ctx := ctxWithTenant(t, "acme")
	if _, err := srv.SetConnectorSecret(ctx, &tenantv1.SetConnectorSecretRequest{
		Connector: "github", Secret: []byte("ghp_static"),
	}); err != nil {
		t.Fatalf("SetConnectorSecret: %v", err)
	}

	resp, err := srv.RevokeConnectorGrant(ctx, &tenantv1.RevokeConnectorGrantRequest{Connector: "github"})
	if err != nil {
		t.Fatalf("RevokeConnectorGrant: %v", err)
	}
	if !resp.GetHadGrant() || resp.GetVendorRevoked() {
		t.Errorf("had_grant=%v vendor_revoked=%v, want true/false", resp.GetHadGrant(), resp.GetVendorRevoked())
	}
	if store.has(connectorauth.AccessSecretName("github")) || store.has(connectorauth.GrantSecretName("github")) {
		t.Error("credential and grant must be gone after revoke")
	}
	st, _ := srv.GetConnectorAuthStatus(ctx, &tenantv1.GetConnectorAuthStatusRequest{Connector: "github"})
	if st.GetState() != tenantv1.ConnectorAuthState_CONNECTOR_AUTH_STATE_UNAUTHORIZED {
		t.Errorf("state = %v, want UNAUTHORIZED", st.GetState())
	}
}

// The request needs a connector and a non-empty credential, and the call needs
// an accountable identity — a credential nobody supplied is refused.
func TestSetConnectorSecret_RequiresConnectorSecretAndIdentity(t *testing.T) {
	store := newFakeConnectorSecrets()
	srv := newConnectorAuthServer(t, store, &fakeProver{store: store})
	ctx := ctxWithTenant(t, "acme")

	cases := []struct {
		name string
		ctx  context.Context
		req  *tenantv1.SetConnectorSecretRequest
		code codes.Code
	}{
		{"no connector", ctx, &tenantv1.SetConnectorSecretRequest{Secret: []byte("x")}, codes.InvalidArgument},
		{"no secret", ctx, &tenantv1.SetConnectorSecretRequest{Connector: "github"}, codes.InvalidArgument},
		{"no tenant", context.Background(), &tenantv1.SetConnectorSecretRequest{Connector: "github", Secret: []byte("x")}, codes.PermissionDenied},
		{"no identity", auth.WithTenant(context.Background(), auth.MustNewTenantID("acme")), &tenantv1.SetConnectorSecretRequest{Connector: "github", Secret: []byte("x")}, codes.PermissionDenied},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := srv.SetConnectorSecret(tc.ctx, tc.req)
			if status.Code(err) != tc.code {
				t.Fatalf("code = %v, want %v (err=%v)", status.Code(err), tc.code, err)
			}
		})
	}
	if store.has(connectorauth.GrantSecretName("github")) || store.has(connectorauth.AccessSecretName("github")) {
		t.Error("a refused call must store nothing")
	}
}

// A store failure on the credential write stores no grant: a grant never
// exists without its credential, so a half-written connector reads
// UNAUTHORIZED rather than a broken AUTHORIZED.
func TestSetConnectorSecret_StoreFailureLeavesNoGrant(t *testing.T) {
	store := newFakeConnectorSecrets()
	failing := &failingPutStore{fakeConnectorSecrets: store, fail: connectorauth.AccessSecretName("github")}
	srv, err := NewConnectorAuthAdminServer(ConnectorAuthAdminConfig{
		Secrets: failing, Prover: &fakeProver{store: store}, Status: connectorauth.NewStatusBook(),
		Now: func() time.Time { return fixedNow },
	})
	if err != nil {
		t.Fatalf("NewConnectorAuthAdminServer: %v", err)
	}
	ctx := ctxWithTenant(t, "acme")
	_, err = srv.SetConnectorSecret(ctx, &tenantv1.SetConnectorSecretRequest{Connector: "github", Secret: []byte("x")})
	if status.Code(err) != codes.Internal {
		t.Fatalf("code = %v, want Internal (err=%v)", status.Code(err), err)
	}
	if store.has(connectorauth.GrantSecretName("github")) {
		t.Error("no grant may be stored when the credential write failed")
	}
}

// A store failure on the grant write, or on clearing stale access metadata,
// is surfaced as Internal; the connector then reads UNAUTHORIZED (no grant)
// or keeps its previous state, never a half-applied AUTHORIZED.
func TestSetConnectorSecret_LaterStoreFailuresAreInternal(t *testing.T) {
	for _, failName := range []string{
		connectorauth.GrantSecretName("github"),
		connectorauth.AccessMetaSecretName("github"),
	} {
		store := newFakeConnectorSecrets()
		_ = store.Put(context.Background(), connectorauth.AccessMetaSecretName("github"), []byte("{}"))
		failing := &failingPutStore{fakeConnectorSecrets: store, fail: failName}
		srv, err := NewConnectorAuthAdminServer(ConnectorAuthAdminConfig{
			Secrets: failing, Prover: &fakeProver{store: store}, Status: connectorauth.NewStatusBook(),
			Now: func() time.Time { return fixedNow },
		})
		if err != nil {
			t.Fatalf("NewConnectorAuthAdminServer: %v", err)
		}
		ctx := ctxWithTenant(t, "acme")
		_, err = srv.SetConnectorSecret(ctx, &tenantv1.SetConnectorSecretRequest{Connector: "github", Secret: []byte("x")})
		if status.Code(err) != codes.Internal {
			t.Errorf("%s: code = %v, want Internal (err=%v)", failName, status.Code(err), err)
		}
	}
}

// failingPutStore fails Put and Delete for one name and delegates everything
// else.
type failingPutStore struct {
	*fakeConnectorSecrets
	fail string
}

func (f *failingPutStore) Put(ctx context.Context, name string, value []byte) error {
	if name == f.fail {
		return errors.New("broker unavailable")
	}
	return f.fakeConnectorSecrets.Put(ctx, name, value)
}

func (f *failingPutStore) Delete(ctx context.Context, name string) error {
	if name == f.fail {
		return errors.New("broker unavailable")
	}
	return f.fakeConnectorSecrets.Delete(ctx, name)
}

// ---------------------------------------------------------------------------
// Revoke (shared by the tenant RPC and the operator finalizer, ADR-0015 §5)
// ---------------------------------------------------------------------------

// A broker failure on the grant read is NOT the idempotent no-grant case: the
// caller must not believe access is gone while the grant may still be live.
func TestRevokeConnectorGrant_BrokerFailureIsInternalNotNoGrant(t *testing.T) {
	store := newFakeConnectorSecrets()
	failing := &failingResolveStore{fakeConnectorSecrets: store}
	srv, err := NewConnectorAuthAdminServer(ConnectorAuthAdminConfig{
		Secrets: failing, Prover: &fakeProver{store: store}, Status: connectorauth.NewStatusBook(),
	})
	if err != nil {
		t.Fatalf("NewConnectorAuthAdminServer: %v", err)
	}
	_, err = srv.RevokeConnectorGrant(ctxWithTenant(t, "acme"), &tenantv1.RevokeConnectorGrantRequest{Connector: "github"})
	if status.Code(err) != codes.Internal {
		t.Fatalf("code = %v, want Internal (err=%v)", status.Code(err), err)
	}
}

// An empty grant blob reads as no grant; a failing delete surfaces Internal
// through the tenant RPC.
func TestRevokeConnectorGrant_EmptyGrantAndDeleteFailure(t *testing.T) {
	store := newFakeConnectorSecrets()
	ctx := ctxWithTenant(t, "acme")
	srv := newConnectorAuthServer(t, store, &fakeProver{store: store})
	_ = store.Put(ctx, connectorauth.GrantSecretName("github"), nil)
	resp, err := srv.RevokeConnectorGrant(ctx, &tenantv1.RevokeConnectorGrantRequest{Connector: "github"})
	if err != nil || resp.GetHadGrant() {
		t.Fatalf("an empty grant blob must read as no grant: had=%v err=%v", resp.GetHadGrant(), err)
	}

	prover := &fakeProver{store: store}
	seedGrant(ctx, t, store, prover, "gitlab", nil)
	failing := &failingPutStore{fakeConnectorSecrets: store, fail: connectorauth.AccessSecretName("gitlab")}
	srv2, err := NewConnectorAuthAdminServer(ConnectorAuthAdminConfig{
		Secrets: failing, Prover: prover, Status: connectorauth.NewStatusBook(),
	})
	if err != nil {
		t.Fatalf("NewConnectorAuthAdminServer: %v", err)
	}
	if _, err := srv2.RevokeConnectorGrant(ctx, &tenantv1.RevokeConnectorGrantRequest{Connector: "gitlab"}); status.Code(err) != codes.Internal {
		t.Fatalf("code = %v, want Internal (err=%v)", status.Code(err), err)
	}
}

// failingResolveStore fails every Resolve with a non-NotFound error.
type failingResolveStore struct{ *fakeConnectorSecrets }

func (f *failingResolveStore) Resolve(_ context.Context, _ string) ([]byte, error) {
	return nil, errors.New("broker unavailable")
}
