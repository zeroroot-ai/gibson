// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package server

import (
	"context"
	"sync"
	"testing"
	"time"

	authv3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	openfga "github.com/openfga/go-sdk"
	fgaclient "github.com/openfga/go-sdk/client"
	"google.golang.org/grpc/codes"

	"github.com/zeroroot-ai/gibson/internal/platform/authz/registry"
	"github.com/zeroroot-ai/gibson/internal/server/extauthz/fga"
)

// The signup-progress RPCs accept the service identity of the dashboard only
// (D11, gibson#761). These tests load the GENERATED registry, so they fail
// when the proto annotation of either RPC changes.

const (
	signupProgressGet = "/gibson.tenant.v1.UserService/GetSignupProgress"
	signupProgressSet = "/gibson.tenant.v1.UserService/SetSignupProgress"

	// dashboardSub is the numeric subject of the dashboard machine user. The
	// fake FGA store holds one signup_service tuple, for this subject only.
	dashboardSub = "300000000000000001"
)

// signupTupleFGA holds exactly one tuple:
// user:<dashboardSub> signup_service system_tenant:_system. It records each
// question, so a test can tell which question FGA was asked.
type signupTupleFGA struct {
	mu       sync.Mutex
	requests []fgaclient.ClientCheckRequest
}

func (m *signupTupleFGA) Check(_ context.Context) fgaclient.SdkClientCheckRequestInterface {
	return &signupTupleReq{m: m}
}

func (m *signupTupleFGA) captured() []fgaclient.ClientCheckRequest {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]fgaclient.ClientCheckRequest(nil), m.requests...)
}

type signupTupleReq struct {
	m    *signupTupleFGA
	body fgaclient.ClientCheckRequest
}

func (r *signupTupleReq) Body(b fgaclient.ClientCheckRequest) fgaclient.SdkClientCheckRequestInterface {
	r.body = b
	return r
}

func (r *signupTupleReq) Options(_ fgaclient.ClientCheckOptions) fgaclient.SdkClientCheckRequestInterface {
	return r
}

func (r *signupTupleReq) Execute() (*fgaclient.ClientCheckResponse, error) {
	r.m.mu.Lock()
	r.m.requests = append(r.m.requests, r.body)
	r.m.mu.Unlock()
	allowed := r.body.User == "user:"+dashboardSub &&
		r.body.Relation == "signup_service" &&
		r.body.Object == "system_tenant:_system"
	return &fgaclient.ClientCheckResponse{CheckResponse: openfga.CheckResponse{Allowed: &allowed}}, nil
}

func (r *signupTupleReq) GetAuthorizationModelIdOverride() *string  { return nil } //nolint:revive,staticcheck // method name set by openfga SDK request interface
func (r *signupTupleReq) GetStoreIdOverride() *string               { return nil } //nolint:revive,staticcheck // method name set by openfga SDK request interface
func (r *signupTupleReq) GetContext() context.Context               { return context.Background() }
func (r *signupTupleReq) GetBody() *fgaclient.ClientCheckRequest    { b := r.body; return &b }
func (r *signupTupleReq) GetOptions() *fgaclient.ClientCheckOptions { return nil }

func buildSignupProgressServer(t *testing.T) (*EnvoyAuthzServer, *signupTupleFGA) {
	t.Helper()
	reg, err := fga.LoadRegistry(registry.YAML())
	if err != nil {
		t.Fatalf("load the generated registry: %v", err)
	}
	mock := &signupTupleFGA{}
	cc := fga.NewCachedChecker(fga.NewChecker(mock, reg), 0, 0)
	return NewEnvoyAuthzServer(Config{
		Component:  testComponentVerifier(t),
		Cache:      cc,
		Logger:     newTestLogger(),
		OrgTenants: &fakeOrgTenantResolver{},
	}), mock
}

// signupProgressRequest builds a Check request for method. A nil claims map
// sends no token at all.
func signupProgressRequest(t *testing.T, method string, claims map[string]any) *authv3.CheckRequest {
	t.Helper()
	hdrs := map[string]string{}
	if claims != nil {
		hdrs[headerJWTPayload] = encodePayload(t, claims)
	}
	return &authv3.CheckRequest{
		Attributes: &authv3.AttributeContext{
			Request: &authv3.AttributeContext_Request{
				Http: &authv3.AttributeContext_HttpRequest{Path: method, Headers: hdrs},
			},
		},
	}
}

// serviceClaims is the token of a machine user: its client id is its subject,
// so ext-authz classes it as a SERVICE (client-credentials) identity. It
// carries no tenant, as the dashboard call does.
func serviceClaims(sub string) map[string]any {
	return map[string]any{
		"iss":       "https://zitadel.example",
		"sub":       sub,
		"client_id": sub,
		"iat":       time.Now().Unix(),
	}
}

func TestSignupProgress_AcceptsTheDashboardServiceIdentityOnly(t *testing.T) {
	t.Parallel()

	person := map[string]any{
		"iss":                                   "https://zitadel.example",
		"sub":                                   "person-1",
		"urn:zitadel:iam:user:resourceowner:id": "org-acme",
		"iat":                                   time.Now().Unix(),
	}

	cases := []struct {
		name   string
		claims map[string]any
		want   codes.Code
	}{
		{"no token", nil, codes.Unauthenticated},
		{"the token of a person", person, codes.PermissionDenied},
		{"a different service", serviceClaims("300000000000000002"), codes.PermissionDenied},
		{"the dashboard service", serviceClaims(dashboardSub), codes.OK},
	}
	for _, method := range []string{signupProgressGet, signupProgressSet} {
		for _, tc := range cases {
			t.Run(method+"/"+tc.name, func(t *testing.T) {
				t.Parallel()
				srv, _ := buildSignupProgressServer(t)
				resp, err := srv.Check(context.Background(), signupProgressRequest(t, method, tc.claims))
				if err != nil {
					t.Fatalf("Check: %v", err)
				}
				//nolint:gosec // gRPC status code is a controlled small value
				if got := codes.Code(resp.GetStatus().GetCode()); got != tc.want {
					t.Errorf("got %v, want %v: %s", got, tc.want, resp.GetStatus().GetMessage())
				}
			})
		}
	}
}

// TestSignupProgress_AsksFGAForSignupService proves which question decides the
// dashboard call: signup_service on the one system object, with no tenant.
func TestSignupProgress_AsksFGAForSignupService(t *testing.T) {
	t.Parallel()
	srv, mock := buildSignupProgressServer(t)
	resp, err := srv.Check(context.Background(), signupProgressRequest(t, signupProgressSet, serviceClaims(dashboardSub)))
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if codes.Code(resp.GetStatus().GetCode()) != codes.OK { //nolint:gosec // gRPC status code is a controlled small value
		t.Fatalf("expected OK for the dashboard, got %v", resp.GetStatus().GetCode())
	}
	asked := mock.captured()
	if len(asked) != 1 {
		t.Fatalf("FGA got %d questions, want 1: %+v", len(asked), asked)
	}
	if q := asked[0]; q.Relation != "signup_service" || q.Object != "system_tenant:_system" {
		t.Errorf("FGA question = %s on %s, want signup_service on system_tenant:_system", q.Relation, q.Object)
	}
}

// TestServiceWithoutTenant_TenantRuleStillDenied proves that the tenantless
// service path is limited to system-object rules. A service account with no
// tenant header on a tenant-derived rule is still refused before FGA.
func TestServiceWithoutTenant_TenantRuleStillDenied(t *testing.T) {
	t.Parallel()
	srv := buildServerForTenantTests(t, true) // FGA allows every question
	req := makeCheckRequest(t, "/test.v1.S/Op", serviceClaims("svc-1"), "")
	resp, err := srv.Check(context.Background(), req)
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if codes.Code(resp.GetStatus().GetCode()) != codes.PermissionDenied { //nolint:gosec // gRPC status code is a controlled small value
		t.Errorf("expected PermissionDenied for a tenantless service on a tenant rule, got %v",
			resp.GetStatus().GetCode())
	}
}
