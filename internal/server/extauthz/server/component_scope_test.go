// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package server

import (
	"context"
	"crypto/ed25519"
	"net/http"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	openfga "github.com/openfga/go-sdk"
	fgaclient "github.com/openfga/go-sdk/client"
	"google.golang.org/genproto/googleapis/rpc/code"

	authv3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"

	"github.com/zeroroot-ai/gibson/internal/server/extauthz/cgjwt"
	"github.com/zeroroot-ai/gibson/internal/server/extauthz/fga"
)

// componentScopeTestYAML: one COMPONENT-allowed rule-mode RPC whose object is
// derived from the caller's own verified component_scope claim.
const componentScopeTestYAML = `entries:
  "/gibson.daemon.discovery.v1.DiscoveryService/ListFindings":
    relation: "can_read_as_component"
    object_type: "component"
    object_deriver: "component_from_identity"
    allowed_identities:
      - COMPONENT
`

const scopeTestMethod = "/gibson.daemon.discovery.v1.DiscoveryService/ListFindings"

// objectCapturingFGA records the object of the last Check, so a test can prove
// WHICH component the request was authorized against — not merely that it was
// allowed.
type objectCapturingFGA struct {
	allowed    bool
	calls      int
	lastObject string
	lastUser   string
}

func (m *objectCapturingFGA) Check(_ context.Context) fgaclient.SdkClientCheckRequestInterface {
	return &objectCapturingReq{m: m}
}

type objectCapturingReq struct{ m *objectCapturingFGA }

func (r *objectCapturingReq) Body(b fgaclient.ClientCheckRequest) fgaclient.SdkClientCheckRequestInterface {
	r.m.calls++
	r.m.lastObject = b.Object
	r.m.lastUser = b.User
	return r
}

func (r *objectCapturingReq) Options(_ fgaclient.ClientCheckOptions) fgaclient.SdkClientCheckRequestInterface {
	return r
}

func (r *objectCapturingReq) Execute() (*fgaclient.ClientCheckResponse, error) {
	v := r.m.allowed
	return &fgaclient.ClientCheckResponse{CheckResponse: openfga.CheckResponse{Allowed: &v}}, nil
}
func (r *objectCapturingReq) GetAuthorizationModelIdOverride() *string  { return nil }
func (r *objectCapturingReq) GetStoreIdOverride() *string               { return nil }
func (r *objectCapturingReq) GetContext() context.Context               { return context.Background() }
func (r *objectCapturingReq) GetBody() *fgaclient.ClientCheckRequest    { return nil }
func (r *objectCapturingReq) GetOptions() *fgaclient.ClientCheckOptions { return nil }

// mintComponentJWTScoped mints a component agent+jwt whose component_scope
// claim is scope. An empty scope omits the claim entirely (the shape an
// older SDK produces).
func mintComponentJWTScoped(t *testing.T, priv ed25519.PrivateKey, kid, scope string) string {
	t.Helper()
	claims := jwt.MapClaims{
		"iss": "host-1", "sub": kid, "aud": componentTestAudience,
		"iat":    time.Now().Add(-time.Second).Unix(),
		"exp":    time.Now().Add(55 * time.Second).Unix(),
		"jti":    componentTestJTI(),
		"method": scopeTestMethod,
	}
	if scope != "" {
		claims["component_scope"] = scope
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims)
	tok.Header["kid"] = kid
	tok.Header["typ"] = "agent+jwt"
	signed, err := tok.SignedString(priv)
	if err != nil {
		t.Fatal(err)
	}
	return signed
}

func buildComponentScopeServer(t *testing.T, mock fga.FGAClient, descBase string) *EnvoyAuthzServer {
	t.Helper()
	reg, err := fga.LoadRegistry([]byte(componentScopeTestYAML))
	if err != nil {
		t.Fatal(err)
	}
	cv, err := cgjwt.NewComponentVerifier(cgjwt.ComponentConfig{
		KeysBaseURL:       descBase,
		TTL:               time.Minute,
		ExpectedAudiences: []string{componentTestAudience},
		HTTPClient:        &http.Client{Timeout: 5 * time.Second},
	})
	if err != nil {
		t.Fatal(err)
	}
	return NewEnvoyAuthzServer(Config{
		Cache:     fga.NewCachedChecker(fga.NewChecker(mock, reg), 0, 0),
		Component: cv,
		Logger:    newTestLogger(),
	})
}

// componentCheckRequestWithHeaders is componentCheckRequest plus attacker-
// supplied extra request headers.
func componentCheckRequestWithHeaders(method, cgToken string, extra map[string]string) *authv3.CheckRequest {
	h := map[string]string{headerCapabilityGrant: cgToken}
	for k, v := range extra {
		h[k] = v
	}
	return &authv3.CheckRequest{
		Attributes: &authv3.AttributeContext{
			Request: &authv3.AttributeContext_Request{
				Http: &authv3.AttributeContext_HttpRequest{
					Path:    method,
					Headers: h,
				},
			},
		},
	}
}

// TestComponentScope_VerifiedClaimSelectsTheObject: the happy path. The FGA
// question must name the component from the token's own verified claim.
func TestComponentScope_VerifiedClaimSelectsTheObject(t *testing.T) {
	pub, priv := mustGenEd25519(t)
	desc := componentDescriptorServer(t, pub, "agent-1", "agent_principal:9", "acme", "active")
	mock := &objectCapturingFGA{allowed: true}
	srv := buildComponentScopeServer(t, mock, desc.URL+"/capabilitygrant/v1/keys")

	tok := mintComponentJWTScoped(t, priv, "agent-1", "component:hello-world")
	resp, err := srv.Check(context.Background(), componentCheckRequestWithHeaders(scopeTestMethod, tok, nil))
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if resp.GetStatus().GetCode() != int32(code.Code_OK) {
		t.Fatalf("status = %d, want OK; msg=%s", resp.GetStatus().GetCode(), resp.GetStatus().GetMessage())
	}
	if mock.lastObject != "component:hello-world" {
		t.Errorf("FGA object = %q, want component:hello-world", mock.lastObject)
	}
	if mock.lastUser != "agent_principal:9" {
		t.Errorf("FGA user = %q, want agent_principal:9", mock.lastUser)
	}
}

// TestComponentScope_HeadersCannotAssertScope is the load-bearing test: a
// component authenticates with a token that carries NO component_scope, and
// tries to supply one over every plausible request header instead. The
// gateway must deny — a component that could name its own object could name
// any component's object, and the FGA check would then be asking a question
// the caller wrote.
//
// The assertion is deliberately two-sided: the request is denied AND FGA is
// never consulted, so there is no object for a stray tuple to match.
func TestComponentScope_HeadersCannotAssertScope(t *testing.T) {
	pub, priv := mustGenEd25519(t)
	desc := componentDescriptorServer(t, pub, "agent-1", "agent_principal:9", "acme", "active")
	// allowed:true — if the object were ever derived from a header, this mock
	// would say yes and the test would catch an ALLOW, not merely a deny.
	mock := &objectCapturingFGA{allowed: true}
	srv := buildComponentScopeServer(t, mock, desc.URL+"/capabilitygrant/v1/keys")

	tok := mintComponentJWTScoped(t, priv, "agent-1", "") // no verified scope
	spoofed := map[string]string{
		"x-gibson-identity-component-scope": "component:victim",
		"x-gibson-component-scope":          "component:victim",
		"x-component-scope":                 "component:victim",
		"component-scope":                   "component:victim",
		"x-gibson-identity-subject":         "agent_principal:1",
		"x-gibson-identity-tenant":          "acme",
		"x-gibson-tenant":                   "acme",
	}
	resp, err := srv.Check(context.Background(), componentCheckRequestWithHeaders(scopeTestMethod, tok, spoofed))
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if resp.GetStatus().GetCode() != int32(code.Code_PERMISSION_DENIED) {
		t.Fatalf("status = %d, want PermissionDenied — a request header must not be able to "+
			"name the component the request is authorized against", resp.GetStatus().GetCode())
	}
	if mock.calls != 0 {
		t.Fatalf("FGA was consulted %d time(s) with object %q; an unresolvable object must deny "+
			"before any question is asked", mock.calls, mock.lastObject)
	}
}

// TestComponentScope_HeaderCannotOverrideVerifiedScope: the same attack from
// a component that DOES have a scope, aiming it at a different component. The
// verified claim wins; the header is inert.
func TestComponentScope_HeaderCannotOverrideVerifiedScope(t *testing.T) {
	pub, priv := mustGenEd25519(t)
	desc := componentDescriptorServer(t, pub, "agent-1", "agent_principal:9", "acme", "active")
	mock := &objectCapturingFGA{allowed: true}
	srv := buildComponentScopeServer(t, mock, desc.URL+"/capabilitygrant/v1/keys")

	tok := mintComponentJWTScoped(t, priv, "agent-1", "component:hello-world")
	spoofed := map[string]string{
		"x-gibson-identity-component-scope": "component:victim",
		"x-component-scope":                 "component:victim",
	}
	resp, err := srv.Check(context.Background(), componentCheckRequestWithHeaders(scopeTestMethod, tok, spoofed))
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if resp.GetStatus().GetCode() != int32(code.Code_OK) {
		t.Fatalf("status = %d, want OK", resp.GetStatus().GetCode())
	}
	if mock.lastObject != "component:hello-world" {
		t.Fatalf("FGA object = %q, want component:hello-world — the header overrode the "+
			"verified claim", mock.lastObject)
	}
}

// TestComponentScope_MalformedScopeDenies: a scope that would change the
// MEANING of the object reference (a second type prefix) is rejected rather
// than concatenated into one.
func TestComponentScope_MalformedScopeDenies(t *testing.T) {
	for _, scope := range []string{
		"component:evil:system_tenant",
		"component:evil#member",
		"component:evil name",
		"component:",
	} {
		scope := scope
		t.Run(scope, func(t *testing.T) {
			pub, priv := mustGenEd25519(t)
			desc := componentDescriptorServer(t, pub, "agent-1", "agent_principal:9", "acme", "active")
			mock := &objectCapturingFGA{allowed: true}
			srv := buildComponentScopeServer(t, mock, desc.URL+"/capabilitygrant/v1/keys")

			tok := mintComponentJWTScoped(t, priv, "agent-1", scope)
			resp, err := srv.Check(context.Background(), componentCheckRequestWithHeaders(scopeTestMethod, tok, nil))
			if err != nil {
				t.Fatalf("Check: %v", err)
			}
			if resp.GetStatus().GetCode() != int32(code.Code_PERMISSION_DENIED) {
				t.Fatalf("status = %d, want PermissionDenied for scope %q", resp.GetStatus().GetCode(), scope)
			}
			if mock.calls != 0 {
				t.Fatalf("FGA consulted with object %q for malformed scope %q", mock.lastObject, scope)
			}
		})
	}
}

// TestComponentScope_VerifierReadsClaimAfterSignature pins that the claim is
// carried out of the verifier at all — the field the deriver depends on.
func TestComponentScope_VerifierReadsClaimAfterSignature(t *testing.T) {
	pub, priv := mustGenEd25519(t)
	desc := componentDescriptorServer(t, pub, "agent-1", "agent_principal:9", "acme", "active")
	cv, err := cgjwt.NewComponentVerifier(cgjwt.ComponentConfig{
		KeysBaseURL:       desc.URL + "/capabilitygrant/v1/keys",
		TTL:               time.Minute,
		ExpectedAudiences: []string{componentTestAudience},
		HTTPClient:        desc.Client(),
	})
	if err != nil {
		t.Fatal(err)
	}

	id, err := cv.Verify(context.Background(), mintComponentJWTScoped(t, priv, "agent-1", "component:hello-world"), scopeTestMethod)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if id.ComponentScope != "component:hello-world" {
		t.Errorf("ComponentScope = %q, want component:hello-world", id.ComponentScope)
	}

	// A token signed by a key the descriptor does not publish never reaches
	// the claim-reading path, so no scope escapes an unverified token.
	_, otherPriv := mustGenEd25519(t)
	if _, err := cv.Verify(context.Background(),
		mintComponentJWTScoped(t, otherPriv, "agent-1", "component:victim"), scopeTestMethod); err == nil {
		t.Fatal("Verify accepted a token signed with an unpublished key")
	}
}
