// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package server

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	openfga "github.com/openfga/go-sdk"
	fgaclient "github.com/openfga/go-sdk/client"
	"google.golang.org/grpc/codes"

	authv3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"

	"github.com/zeroroot-ai/gibson/internal/server/extauthz/fga"
)

// sessionAwareFGA is a FGAClient stub that returns different decisions
// depending on the FGA relation being checked:
//
//   - "active_session" -> sessionAllowed (the session gate decision)
//   - anything else    -> rpcAllowed     (the per-RPC FGA decision)
//
// This allows tests to exercise the session gate independently of the
// per-RPC authz check.
type sessionAwareFGA struct {
	rpcAllowed     bool
	sessionAllowed bool
	calls          int32
}

func (m *sessionAwareFGA) Check(_ context.Context) fgaclient.SdkClientCheckRequestInterface {
	return &sessionAwareReq{m: m}
}

type sessionAwareReq struct {
	m    *sessionAwareFGA
	body fgaclient.ClientCheckRequest
}

func (r *sessionAwareReq) Body(b fgaclient.ClientCheckRequest) fgaclient.SdkClientCheckRequestInterface {
	r.body = b
	return r
}

func (r *sessionAwareReq) Options(_ fgaclient.ClientCheckOptions) fgaclient.SdkClientCheckRequestInterface {
	return r
}

func (r *sessionAwareReq) Execute() (*fgaclient.ClientCheckResponse, error) {
	atomic.AddInt32(&r.m.calls, 1)
	var allowed bool
	if r.body.Relation == "active_session" {
		allowed = r.m.sessionAllowed
	} else {
		allowed = r.m.rpcAllowed
	}
	return &fgaclient.ClientCheckResponse{CheckResponse: openfga.CheckResponse{Allowed: &allowed}}, nil
}

func (r *sessionAwareReq) GetAuthorizationModelIdOverride() *string  { return nil } //nolint:revive,staticcheck // method name set by openfga SDK request interface
func (r *sessionAwareReq) GetStoreIdOverride() *string               { return nil } //nolint:revive,staticcheck // method name set by openfga SDK request interface
func (r *sessionAwareReq) GetContext() context.Context               { return context.Background() }
func (r *sessionAwareReq) GetBody() *fgaclient.ClientCheckRequest    { b := r.body; return &b }
func (r *sessionAwareReq) GetOptions() *fgaclient.ClientCheckOptions { return nil }

// errorSessionFGA returns an error only for the active_session relation check.
// For all other relations it returns rpcAllowed. This lets tests drive the
// checkSessionGate error path (FGA unavailable → Unavailable response) while
// keeping the per-RPC check healthy.
type errorSessionFGA struct {
	rpcAllowed bool
	sessionErr error
}

func (m *errorSessionFGA) Check(_ context.Context) fgaclient.SdkClientCheckRequestInterface {
	return &errorSessionReq{m: m}
}

type errorSessionReq struct {
	m    *errorSessionFGA
	body fgaclient.ClientCheckRequest
}

func (r *errorSessionReq) Body(b fgaclient.ClientCheckRequest) fgaclient.SdkClientCheckRequestInterface {
	r.body = b
	return r
}
func (r *errorSessionReq) Options(_ fgaclient.ClientCheckOptions) fgaclient.SdkClientCheckRequestInterface {
	return r
}
func (r *errorSessionReq) Execute() (*fgaclient.ClientCheckResponse, error) {
	if r.body.Relation == "active_session" {
		return nil, r.m.sessionErr
	}
	v := r.m.rpcAllowed
	return &fgaclient.ClientCheckResponse{CheckResponse: openfga.CheckResponse{Allowed: &v}}, nil
}
func (r *errorSessionReq) GetAuthorizationModelIdOverride() *string  { return nil } //nolint:revive,staticcheck // method name set by openfga SDK request interface
func (r *errorSessionReq) GetStoreIdOverride() *string               { return nil } //nolint:revive,staticcheck // method name set by openfga SDK request interface
func (r *errorSessionReq) GetContext() context.Context               { return context.Background() }
func (r *errorSessionReq) GetBody() *fgaclient.ClientCheckRequest    { b := r.body; return &b }
func (r *errorSessionReq) GetOptions() *fgaclient.ClientCheckOptions { return nil }

// sessionGateTestYAML: one USER-only rule-mode RPC, one SERVICE-only rule-mode
// RPC, and one USER-only self-mode RPC for session gate server tests.
const sessionGateTestYAML = `entries:
  "/test.v1.S/UserOp":
    relation: "member"
    object_type: "tenant"
    object_deriver: "tenant_from_identity"
    allowed_identities:
      - USER
  "/test.v1.S/SAOp":
    relation: "member"
    object_type: "tenant"
    object_deriver: "tenant_from_identity"
    allowed_identities:
      - SERVICE
  "/test.v1.S/SelfOp":
    self: true
    allowed_identities:
      - USER
`

func buildServerForSessionGateTests(t *testing.T, rpcAllowed, sessionAllowed bool) *EnvoyAuthzServer {
	t.Helper()
	reg, err := fga.LoadRegistry([]byte(sessionGateTestYAML))
	if err != nil {
		t.Fatalf("LoadRegistry: %v", err)
	}
	mock := &sessionAwareFGA{rpcAllowed: rpcAllowed, sessionAllowed: sessionAllowed}
	checker := fga.NewChecker(mock, reg)
	cc := fga.NewCachedChecker(checker, 0, 0)
	return NewEnvoyAuthzServer(Config{
		Cache:  cc,
		Logger: newTestLogger(),
	})
}

// makeSessionGateRequest builds a CheckRequest for the given method with an
// oidc-user JWT. Tenant is embedded in the JWT claim (not the header) so the
// gateway takes the "JWT-only tenant" path.
func makeSessionGateRequest(t *testing.T, method, subject, tenant string, iatUnix int64) *authv3.CheckRequest {
	t.Helper()
	claims := map[string]any{
		"iss":    "https://zitadel.example",
		"sub":    subject,
		"tenant": tenant,
		"iat":    iatUnix,
	}
	return &authv3.CheckRequest{
		Attributes: &authv3.AttributeContext{
			Request: &authv3.AttributeContext_Request{
				Http: &authv3.AttributeContext_HttpRequest{
					Path: method,
					Headers: map[string]string{
						headerJWTPayload: encodePayload(t, claims),
					},
				},
			},
		},
	}
}

// TestSessionGate_TokenAfterRevokedAt_Allowed — token iat is after revoked_at,
// FGA session gate returns true -> the request passes.
func TestSessionGate_TokenAfterRevokedAt_Allowed(t *testing.T) {
	t.Parallel()
	srv := buildServerForSessionGateTests(t, true /* rpc */, true /* session gate */)
	req := makeSessionGateRequest(t, "/test.v1.S/UserOp", "u-1", "acme", time.Now().Unix())

	resp, err := srv.Check(context.Background(), req)
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if codes.Code(resp.GetStatus().GetCode()) != codes.OK { //nolint:gosec // gRPC status code is a controlled small value
		t.Errorf("expected OK (valid session), got %v: %s",
			resp.GetStatus().GetCode(), resp.GetStatus().GetMessage())
	}
}

// TestSessionGate_TokenBeforeRevokedAt_Denied — token iat is before revoked_at,
// FGA session gate returns false -> the request is denied, even though the per-RPC
// authz check passed.
func TestSessionGate_TokenBeforeRevokedAt_Denied(t *testing.T) {
	t.Parallel()
	// Per-RPC check would allow (rpcAllowed=true), but the session gate denies.
	srv := buildServerForSessionGateTests(t, true /* rpc */, false /* session: revoked */)
	req := makeSessionGateRequest(t, "/test.v1.S/UserOp", "u-1", "acme", time.Now().Unix()-3600)

	resp, err := srv.Check(context.Background(), req)
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if codes.Code(resp.GetStatus().GetCode()) != codes.PermissionDenied { //nolint:gosec // gRPC status code is a controlled small value
		t.Errorf("expected PermissionDenied (revoked session), got %v: %s",
			resp.GetStatus().GetCode(), resp.GetStatus().GetMessage())
	}
}

// TestSessionGate_AbsentTuple_Denied — no active_session tuple in FGA -> denied
// (fail-closed). This covers the case where backfill has not yet run or the
// tuple was never written.
func TestSessionGate_AbsentTuple_Denied(t *testing.T) {
	t.Parallel()
	// FGA returns false for the session gate (simulates absent tuple).
	srv := buildServerForSessionGateTests(t, true /* rpc */, false /* session: absent */)
	req := makeSessionGateRequest(t, "/test.v1.S/UserOp", "u-new", "acme", time.Now().Unix())

	resp, err := srv.Check(context.Background(), req)
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if codes.Code(resp.GetStatus().GetCode()) != codes.PermissionDenied { //nolint:gosec // gRPC status code is a controlled small value
		t.Errorf("expected PermissionDenied (absent session tuple, fail-closed), got %v: %s",
			resp.GetStatus().GetCode(), resp.GetStatus().GetMessage())
	}
}

// TestSessionGate_MachinePrincipal_GateSkipped — a service-account (SA) principal
// (client-credentials) hits a SERVICE-allowed RPC. The session gate MUST be
// skipped for machine principals — they are revoked at the key/credential level,
// not the session level.
//
// The session gate is guarded by `id.CredentialType == headers.CredentialOIDCUser`
// in checkSessionGate. Service accounts have credential type "client-credentials",
// so the gate is a no-op for them regardless of their FGA decisions.
func TestSessionGate_MachinePrincipal_GateSkipped(t *testing.T) {
	t.Parallel()

	// Session gate returns false — proves it's not consulted for SAs.
	mock := &sessionAwareFGA{rpcAllowed: true, sessionAllowed: false}
	reg, err := fga.LoadRegistry([]byte(sessionGateTestYAML))
	if err != nil {
		t.Fatalf("LoadRegistry: %v", err)
	}
	cc := fga.NewCachedChecker(fga.NewChecker(mock, reg), 0, 0)
	srv := NewEnvoyAuthzServer(Config{Cache: cc, Logger: newTestLogger()})

	// Build a client-credentials (SA) request: client_id == sub marks it as SERVICE class.
	claims := map[string]any{
		"iss":       "https://zitadel.example",
		"sub":       "svc-account-1",
		"client_id": "svc-account-1",
		"tenant":    "acme",
		// no iat — machine principals have no session iat to revoke
	}
	req := &authv3.CheckRequest{
		Attributes: &authv3.AttributeContext{
			Request: &authv3.AttributeContext_Request{
				Http: &authv3.AttributeContext_HttpRequest{
					Path: "/test.v1.S/SAOp",
					Headers: map[string]string{
						headerJWTPayload: encodePayload(t, claims),
					},
				},
			},
		},
	}

	resp, err := srv.Check(context.Background(), req)
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	// The request should be allowed (rpcAllowed=true). The session gate must
	// not have fired: if it had, sessionAllowed=false would have denied the request.
	if codes.Code(resp.GetStatus().GetCode()) != codes.OK { //nolint:gosec // gRPC status code is a controlled small value
		t.Errorf("expected OK for SA principal (session gate must be skipped), got %v: %s",
			resp.GetStatus().GetCode(), resp.GetStatus().GetMessage())
	}
	// Confirm the session gate was NOT called: exactly 1 FGA call (the per-RPC check).
	// If the session gate had fired there would be 2 calls.
	if got := atomic.LoadInt32(&mock.calls); got != 1 {
		t.Errorf("expected exactly 1 FGA call (per-RPC only, no session gate for SA), got %d", got)
	}
}

// TestSessionGate_ZeroIAT_DeniedFailClosed — an OIDC user with a valid tenant
// but no `iat` claim in the JWT hits a session gate check. Because
// TokenIssuedAt is zero, checkSessionGate treats the token as the oldest
// possible (fail-closed) and returns PermissionDenied immediately, without
// calling FGA.
func TestSessionGate_ZeroIAT_DeniedFailClosed(t *testing.T) {
	t.Parallel()
	srv := buildServerForSessionGateTests(t, true /* rpc */, true /* session gate */)

	// Build a request with an OIDC user JWT that omits the `iat` claim.
	claims := map[string]any{
		"iss":    "https://zitadel.example",
		"sub":    "u-no-iat",
		"tenant": "acme",
		// deliberately no "iat"
	}
	req := &authv3.CheckRequest{
		Attributes: &authv3.AttributeContext{
			Request: &authv3.AttributeContext_Request{
				Http: &authv3.AttributeContext_HttpRequest{
					Path: "/test.v1.S/UserOp",
					Headers: map[string]string{
						headerJWTPayload: encodePayload(t, claims),
					},
				},
			},
		},
	}

	resp, err := srv.Check(context.Background(), req)
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if codes.Code(resp.GetStatus().GetCode()) != codes.PermissionDenied { //nolint:gosec // gRPC status code is a controlled small value
		t.Errorf("expected PermissionDenied (missing iat → fail-closed), got %v: %s",
			resp.GetStatus().GetCode(), resp.GetStatus().GetMessage())
	}
}

// TestSessionGate_FGAError_Unavailable — the FGA backend returns an error
// when CheckActiveSession is called. checkSessionGate must respond with
// Unavailable (not a silent allow or a deny with PermissionDenied) so the
// client can distinguish infrastructure failures from policy denials.
func TestSessionGate_FGAError_Unavailable(t *testing.T) {
	t.Parallel()

	reg, err := fga.LoadRegistry([]byte(sessionGateTestYAML))
	if err != nil {
		t.Fatalf("LoadRegistry: %v", err)
	}
	fgaErr := errors.New("fga: dial tcp: connection refused")
	mock := &errorSessionFGA{rpcAllowed: true, sessionErr: fgaErr}
	cc := fga.NewCachedChecker(fga.NewChecker(mock, reg), 0, 0)
	srv := NewEnvoyAuthzServer(Config{Cache: cc, Logger: newTestLogger()})

	req := makeSessionGateRequest(t, "/test.v1.S/UserOp", "u-1", "acme", time.Now().Unix())

	resp, err := srv.Check(context.Background(), req)
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if codes.Code(resp.GetStatus().GetCode()) != codes.Unavailable { //nolint:gosec // gRPC status code is a controlled small value
		t.Errorf("expected Unavailable (FGA error in session gate), got %v: %s",
			resp.GetStatus().GetCode(), resp.GetStatus().GetMessage())
	}
}

// TestSessionGate_SelfMode_TenantFromHeader_GateFires — the case that matters
// for real sign-ins: Zitadel user JWTs carry NO tenant claim, so on a
// self-mode RPC the identity's tenant is empty and the request names its
// tenant only in x-gibson-tenant. The revocation gate must still run — a
// revoked user must not keep reading their own data just because the RPC
// derives no FGA object from a tenant.
//
// The stub answers the session gate with "revoked", so the request can only
// be denied if the gate actually ran, and the recorded object proves it ran
// against the tenant the request named.
func TestSessionGate_SelfMode_TenantFromHeader_GateFires(t *testing.T) {
	t.Parallel()
	reg, err := fga.LoadRegistry([]byte(sessionGateTestYAML))
	if err != nil {
		t.Fatalf("LoadRegistry: %v", err)
	}
	mock := &sessionObjectRecorder{sessionAllowed: false}
	cc := fga.NewCachedChecker(fga.NewChecker(mock, reg), 0, 0)
	srv := NewEnvoyAuthzServer(Config{Cache: cc, Logger: newTestLogger()})

	// No tenant claim in the JWT — exactly what Zitadel issues for a user.
	claims := map[string]any{
		"iss": "https://zitadel.example",
		"sub": "u-self",
		"iat": time.Now().Unix(),
	}
	req := &authv3.CheckRequest{
		Attributes: &authv3.AttributeContext{
			Request: &authv3.AttributeContext_Request{
				Http: &authv3.AttributeContext_HttpRequest{
					Path: "/test.v1.S/SelfOp",
					Headers: map[string]string{
						headerJWTPayload: encodePayload(t, claims),
						headerTenantHint: "acme",
					},
				},
			},
		},
	}

	resp, err := srv.Check(context.Background(), req)
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if codes.Code(resp.GetStatus().GetCode()) != codes.PermissionDenied { //nolint:gosec // gRPC status code is a controlled small value
		t.Errorf("expected PermissionDenied (revoked session on a self-mode RPC), got %v: %s",
			resp.GetStatus().GetCode(), resp.GetStatus().GetMessage())
	}
	objs := mock.sessionObjects()
	if len(objs) != 1 || objs[0] != "tenant:acme" {
		t.Errorf("active_session checked against %v, want exactly [tenant:acme] — the gate must "+
			"use the tenant the request names when the identity carries none", objs)
	}
}

// makeTenantlessSelfRequest builds a self-mode CheckRequest for a user JWT that
// names NO tenant anywhere (no tenant claim, no x-gibson-tenant header) — the
// sign-in bootstrap shape that used to pass through un-gated.
func makeTenantlessSelfRequest(t *testing.T, subject string, iatUnix int64) *authv3.CheckRequest {
	t.Helper()
	claims := map[string]any{
		"iss": "https://zitadel.example",
		"sub": subject,
		"iat": iatUnix,
	}
	return &authv3.CheckRequest{
		Attributes: &authv3.AttributeContext{
			Request: &authv3.AttributeContext_Request{
				Http: &authv3.AttributeContext_HttpRequest{
					Path: "/test.v1.S/SelfOp",
					Headers: map[string]string{
						headerJWTPayload: encodePayload(t, claims),
					},
				},
			},
		},
	}
}

// TestSessionGate_SelfMode_NoTenant_Revoked_Denied — THE gibson#1244 bug-closer.
// A tenant-less self-mode request presenting a REVOKED session must now be
// DENIED, gated on the user-scoped active_session object. Before this change it
// passed through un-gated because there was no per-tenant object to check.
func TestSessionGate_SelfMode_NoTenant_Revoked_Denied(t *testing.T) {
	t.Parallel()
	now := time.Now()
	// Tuple present, revoked at `now`; token issued an hour earlier → revoked.
	mock := &userScopedSessionFGA{present: true, revokedAt: now}
	srv := buildServerForUserScopedGate(t, mock)

	req := makeTenantlessSelfRequest(t, "u-self", now.Add(-time.Hour).Unix())
	resp, err := srv.Check(context.Background(), req)
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if codes.Code(resp.GetStatus().GetCode()) != codes.PermissionDenied { //nolint:gosec // gRPC status code is a controlled small value
		t.Errorf("expected PermissionDenied (revoked session, tenant-less), got %v: %s",
			resp.GetStatus().GetCode(), resp.GetStatus().GetMessage())
	}
	// The gate must have checked the user-scoped object — not passed through.
	if objs := mock.sessionObjects(); len(objs) == 0 || objs[0] != "user:u-self" {
		t.Errorf("user-scoped active_session checked against %v, want it to include user:u-self", objs)
	}
}

// TestSessionGate_SelfMode_NoTenant_BootstrapAllowed — a tenant-less request
// with NO user-scoped tuple yet (a genuinely-first sign-in not provisioned into
// any tenant) must still PASS. Denying it would make sign-in unrecoverable.
func TestSessionGate_SelfMode_NoTenant_BootstrapAllowed(t *testing.T) {
	t.Parallel()
	mock := &userScopedSessionFGA{present: false, rpcAllowed: true}
	srv := buildServerForUserScopedGate(t, mock)

	req := makeTenantlessSelfRequest(t, "u-new", time.Now().Unix())
	resp, err := srv.Check(context.Background(), req)
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if codes.Code(resp.GetStatus().GetCode()) != codes.OK { //nolint:gosec // gRPC status code is a controlled small value
		t.Errorf("expected OK (sign-in bootstrap: absent user-scoped tuple), got %v: %s",
			resp.GetStatus().GetCode(), resp.GetStatus().GetMessage())
	}
	// The gate did run (no blind pass-through) — it just allowed on absence.
	if objs := mock.sessionObjects(); len(objs) == 0 {
		t.Error("expected the user-scoped gate to run and probe existence, but no active_session check was made")
	}
}

// TestSessionGate_SelfMode_NoTenant_ValidSession_Allowed — a tenant-less request
// with a present, not-revoked user-scoped tuple passes on the fast path.
func TestSessionGate_SelfMode_NoTenant_ValidSession_Allowed(t *testing.T) {
	t.Parallel()
	mock := &userScopedSessionFGA{present: true, revokedAt: time.Unix(0, 0), rpcAllowed: true}
	srv := buildServerForUserScopedGate(t, mock)

	req := makeTenantlessSelfRequest(t, "u-self", time.Now().Unix())
	resp, err := srv.Check(context.Background(), req)
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if codes.Code(resp.GetStatus().GetCode()) != codes.OK { //nolint:gosec // gRPC status code is a controlled small value
		t.Errorf("expected OK (valid tenant-less session), got %v: %s",
			resp.GetStatus().GetCode(), resp.GetStatus().GetMessage())
	}
}

func buildServerForUserScopedGate(t *testing.T, mock fga.FGAClient) *EnvoyAuthzServer {
	t.Helper()
	reg, err := fga.LoadRegistry([]byte(sessionGateTestYAML))
	if err != nil {
		t.Fatalf("LoadRegistry: %v", err)
	}
	cc := fga.NewCachedChecker(fga.NewChecker(mock, reg), 0, 0)
	return NewEnvoyAuthzServer(Config{Cache: cc, Logger: newTestLogger()})
}

// userScopedSessionFGA faithfully models the USER-SCOPED active_session tuple
// (user:<id>, active_session, user:<id>): it evaluates the token_not_revoked
// condition (token_issued_at > revoked_at) against the iat carried in the Check
// context — exactly as OpenFGA would — so the CheckUserSession absent-vs-revoked
// disambiguation can be exercised end-to-end through the server. Every other
// relation (the per-RPC check) answers rpcAllowed.
type userScopedSessionFGA struct {
	present    bool
	revokedAt  time.Time
	rpcAllowed bool

	mu      sync.Mutex
	objects []string
}

func (m *userScopedSessionFGA) Check(_ context.Context) fgaclient.SdkClientCheckRequestInterface {
	return &userScopedSessionReq{m: m}
}

func (m *userScopedSessionFGA) sessionObjects() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]string(nil), m.objects...)
}

type userScopedSessionReq struct {
	m    *userScopedSessionFGA
	body fgaclient.ClientCheckRequest
}

func (r *userScopedSessionReq) Body(b fgaclient.ClientCheckRequest) fgaclient.SdkClientCheckRequestInterface {
	r.body = b
	return r
}

func (r *userScopedSessionReq) Options(_ fgaclient.ClientCheckOptions) fgaclient.SdkClientCheckRequestInterface {
	return r
}

func (r *userScopedSessionReq) Execute() (*fgaclient.ClientCheckResponse, error) {
	allowed := r.m.rpcAllowed
	if r.body.Relation == "active_session" {
		r.m.mu.Lock()
		r.m.objects = append(r.m.objects, r.body.Object)
		r.m.mu.Unlock()
		allowed = false
		if r.m.present && r.body.Context != nil {
			if raw, ok := (*r.body.Context)["token_issued_at"]; ok {
				if s, ok := raw.(string); ok {
					if iat, perr := time.Parse(time.RFC3339, s); perr == nil {
						allowed = iat.After(r.m.revokedAt)
					}
				}
			}
		}
	}
	return &fgaclient.ClientCheckResponse{CheckResponse: openfga.CheckResponse{Allowed: &allowed}}, nil
}

func (r *userScopedSessionReq) GetAuthorizationModelIdOverride() *string  { return nil } //nolint:revive,staticcheck // method name set by openfga SDK request interface
func (r *userScopedSessionReq) GetStoreIdOverride() *string               { return nil } //nolint:revive,staticcheck // method name set by openfga SDK request interface
func (r *userScopedSessionReq) GetContext() context.Context               { return context.Background() }
func (r *userScopedSessionReq) GetBody() *fgaclient.ClientCheckRequest    { b := r.body; return &b }
func (r *userScopedSessionReq) GetOptions() *fgaclient.ClientCheckOptions { return nil }

// sessionObjectRecorder answers the active_session relation with
// sessionAllowed and records which object each session check named. Recording
// the object is the point: a stub that only counted calls could not show the
// gate ran against the tenant the request carried.
type sessionObjectRecorder struct {
	sessionAllowed bool
	rpcAllowed     bool

	mu      sync.Mutex
	objects []string
}

func (m *sessionObjectRecorder) Check(_ context.Context) fgaclient.SdkClientCheckRequestInterface {
	return &sessionObjectReq{m: m}
}

func (m *sessionObjectRecorder) sessionObjects() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]string(nil), m.objects...)
}

type sessionObjectReq struct {
	m    *sessionObjectRecorder
	body fgaclient.ClientCheckRequest
}

func (r *sessionObjectReq) Body(b fgaclient.ClientCheckRequest) fgaclient.SdkClientCheckRequestInterface {
	r.body = b
	return r
}

func (r *sessionObjectReq) Options(_ fgaclient.ClientCheckOptions) fgaclient.SdkClientCheckRequestInterface {
	return r
}

func (r *sessionObjectReq) Execute() (*fgaclient.ClientCheckResponse, error) {
	allowed := r.m.rpcAllowed
	if r.body.Relation == "active_session" {
		r.m.mu.Lock()
		r.m.objects = append(r.m.objects, r.body.Object)
		r.m.mu.Unlock()
		allowed = r.m.sessionAllowed
	}
	return &fgaclient.ClientCheckResponse{CheckResponse: openfga.CheckResponse{Allowed: &allowed}}, nil
}

func (r *sessionObjectReq) GetAuthorizationModelIdOverride() *string  { return nil } //nolint:revive,staticcheck // method name set by openfga SDK request interface
func (r *sessionObjectReq) GetStoreIdOverride() *string               { return nil } //nolint:revive,staticcheck // method name set by openfga SDK request interface
func (r *sessionObjectReq) GetContext() context.Context               { return context.Background() }
func (r *sessionObjectReq) GetBody() *fgaclient.ClientCheckRequest    { b := r.body; return &b }
func (r *sessionObjectReq) GetOptions() *fgaclient.ClientCheckOptions { return nil }

// TestSessionGate_SelfMode_WithTenant_GateFires — a self-mode RPC with an
// OIDC user that has a tenant in its JWT. Self-mode entries skip the FGA
// per-RPC check (AllowedIdentities is enforced but no FGA tuple query runs),
// then checkSessionGate fires for the OIDC user. If the session gate denies,
// the overall response is PermissionDenied, proving the gate is wired into
// the self-mode path (lines 218-221 of envoy_extauthz.go).
func TestSessionGate_SelfMode_WithTenant_GateFires(t *testing.T) {
	t.Parallel()
	// Session gate returns false (revoked). Per-RPC FGA is not consulted for
	// self-mode entries, so rpcAllowed is irrelevant here — only sessionAllowed
	// matters for the gate.
	srv := buildServerForSessionGateTests(t, true /* rpc, unused for self-mode */, false /* session: revoked */)

	// Self-mode RPC: SelfOp is defined as self:true + allowed_identities: USER.
	// The user JWT carries a tenant claim so TokenIssuedAt can be set and the
	// gate actually fires (non-empty tenant, non-zero iat).
	claims := map[string]any{
		"iss":    "https://zitadel.example",
		"sub":    "u-self",
		"tenant": "acme",
		"iat":    time.Now().Unix(),
	}
	req := &authv3.CheckRequest{
		Attributes: &authv3.AttributeContext{
			Request: &authv3.AttributeContext_Request{
				Http: &authv3.AttributeContext_HttpRequest{
					Path: "/test.v1.S/SelfOp",
					Headers: map[string]string{
						headerJWTPayload: encodePayload(t, claims),
					},
				},
			},
		},
	}

	resp, err := srv.Check(context.Background(), req)
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	// The session gate fires and denies (sessionAllowed=false).
	if codes.Code(resp.GetStatus().GetCode()) != codes.PermissionDenied { //nolint:gosec // gRPC status code is a controlled small value
		t.Errorf("expected PermissionDenied (session gate fires on self-mode + revoked), got %v: %s",
			resp.GetStatus().GetCode(), resp.GetStatus().GetMessage())
	}
}
