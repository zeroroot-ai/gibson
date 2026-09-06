// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package server

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
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

// capturingFGA records the FGA user of the last Check so the component path can
// be asserted to query the typed principal (e.g. agent_principal:9).
type capturingFGA struct {
	allowed  bool
	lastUser string
}

func (m *capturingFGA) Check(_ context.Context) fgaclient.SdkClientCheckRequestInterface {
	return &capturingReq{m: m}
}

type capturingReq struct{ m *capturingFGA }

func (r *capturingReq) Body(b fgaclient.ClientCheckRequest) fgaclient.SdkClientCheckRequestInterface {
	r.m.lastUser = b.User
	return r
}
func (r *capturingReq) Options(_ fgaclient.ClientCheckOptions) fgaclient.SdkClientCheckRequestInterface {
	return r
}
func (r *capturingReq) Execute() (*fgaclient.ClientCheckResponse, error) {
	v := r.m.allowed
	return &fgaclient.ClientCheckResponse{CheckResponse: openfga.CheckResponse{Allowed: &v}}, nil
}
func (r *capturingReq) GetAuthorizationModelIdOverride() *string  { return nil }
func (r *capturingReq) GetStoreIdOverride() *string               { return nil }
func (r *capturingReq) GetContext() context.Context               { return context.Background() }
func (r *capturingReq) GetBody() *fgaclient.ClientCheckRequest    { return nil }
func (r *capturingReq) GetOptions() *fgaclient.ClientCheckOptions { return nil }

// componentTestYAML: one COMPONENT-allowed rule-mode RPC, mirroring WhoAmI.
const componentTestYAML = `entries:
  "/gibson.identity.v1.IdentityService/WhoAmI":
    relation: "member"
    object_type: "tenant"
    object_deriver: "tenant_from_identity"
    allowed_identities:
      - USER
      - SERVICE
      - COMPONENT
`

func componentDescriptorServer(t *testing.T, pub ed25519.PublicKey, kid, principal, tenant, status string) *httptest.Server {
	t.Helper()
	doc := map[string]any{
		"keys": []map[string]string{{
			"kty": "OKP", "crv": "Ed25519",
			"x":   base64.RawURLEncoding.EncodeToString(pub),
			"kid": kid, "alg": "EdDSA", "use": "sig",
		}},
		"principal": principal, "tenant": tenant, "status": status,
	}
	body, _ := json.Marshal(doc)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, "/"+kid) {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		_, _ = w.Write(body)
	}))
	t.Cleanup(srv.Close)
	return srv
}

// componentTestAudience is the aud these tests mint and the verifiers pin.
// ComponentConfig.ExpectedAudiences is required, so it can no longer be left
// out of a test verifier either.
const componentTestAudience = "https://daemon/x"

// componentTestJTI returns a distinct jti per call. Component tokens are
// single-use now, so tests that mint several against one verifier must not
// share a jti.
var componentJTISeq atomic.Int64

func componentTestJTI() string {
	return fmt.Sprintf("j%d", componentJTISeq.Add(1))
}

// componentTestMethod is the gRPC method mintComponentJWT binds its tokens to;
// every componentCheckRequest in this file presents them at this same path, so
// the request-binding check (gibson#1246) is satisfied and the tests exercise
// the authz path rather than failing at method binding.
const componentTestMethod = "/gibson.identity.v1.IdentityService/WhoAmI"

func mintComponentJWT(t *testing.T, priv ed25519.PrivateKey, kid string) string {
	t.Helper()
	tok := jwt.NewWithClaims(jwt.SigningMethodEdDSA, jwt.MapClaims{
		"iss": "host-1", "sub": kid, "aud": componentTestAudience,
		"iat":    time.Now().Add(-time.Second).Unix(),
		"exp":    time.Now().Add(55 * time.Second).Unix(),
		"jti":    componentTestJTI(),
		"method": componentTestMethod, "component_scope": "component:hello",
	})
	tok.Header["kid"] = kid
	tok.Header["typ"] = "agent+jwt"
	signed, err := tok.SignedString(priv)
	if err != nil {
		t.Fatal(err)
	}
	return signed
}

func buildComponentServer(t *testing.T, mock fga.FGAClient, descBase string) *EnvoyAuthzServer {
	t.Helper()
	reg, err := fga.LoadRegistry([]byte(componentTestYAML))
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

func componentCheckRequest(method, cgToken string) *authv3.CheckRequest {
	// Note: NO x-jwt-payload — the component presents only x-capability-grant.
	return &authv3.CheckRequest{
		Attributes: &authv3.AttributeContext{
			Request: &authv3.AttributeContext_Request{
				Http: &authv3.AttributeContext_HttpRequest{
					Path:    method,
					Headers: map[string]string{headerCapabilityGrant: cgToken},
				},
			},
		},
	}
}

func mustGenEd25519(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return pub, priv
}

func TestComponentAuth_AllowsAndQueriesTypedPrincipal(t *testing.T) {
	pub, priv := mustGenEd25519(t)
	desc := componentDescriptorServer(t, pub, "agent-1", "agent_principal:9", "acme", "active")
	mock := &capturingFGA{allowed: true}
	srv := buildComponentServer(t, mock, desc.URL+"/capabilitygrant/v1/keys")

	tok := mintComponentJWT(t, priv, "agent-1")
	resp, err := srv.Check(context.Background(), componentCheckRequest("/gibson.identity.v1.IdentityService/WhoAmI", tok))
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if resp.GetStatus().GetCode() != int32(code.Code_OK) {
		t.Fatalf("status = %d, want OK; msg=%s", resp.GetStatus().GetCode(), resp.GetStatus().GetMessage())
	}
	// The FGA check must run against the daemon-asserted typed principal, not a
	// user: prefix.
	if mock.lastUser != "agent_principal:9" {
		t.Errorf("FGA user = %q, want agent_principal:9", mock.lastUser)
	}
}

func TestComponentAuth_DeniesWhenFGADenies(t *testing.T) {
	pub, priv := mustGenEd25519(t)
	desc := componentDescriptorServer(t, pub, "agent-1", "agent_principal:9", "acme", "active")
	srv := buildComponentServer(t, &capturingFGA{allowed: false}, desc.URL+"/capabilitygrant/v1/keys")

	tok := mintComponentJWT(t, priv, "agent-1")
	resp, err := srv.Check(context.Background(), componentCheckRequest("/gibson.identity.v1.IdentityService/WhoAmI", tok))
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if resp.GetStatus().GetCode() != int32(code.Code_PERMISSION_DENIED) {
		t.Errorf("status = %d, want PermissionDenied", resp.GetStatus().GetCode())
	}
}

// TestComponentAuth_RejectsCrossRPCReplay — gibson#1246 end to end: a component
// token minted for one method, presented at another, is refused at the gateway
// (Unauthenticated) and never reaches FGA. This is the cross-RPC replay the
// method binding closes; it proves Check threads the request method into Verify.
func TestComponentAuth_RejectsCrossRPCReplay(t *testing.T) {
	pub, priv := mustGenEd25519(t)
	desc := componentDescriptorServer(t, pub, "agent-1", "agent_principal:9", "acme", "active")
	mock := &capturingFGA{allowed: true}
	srv := buildComponentServer(t, mock, desc.URL+"/capabilitygrant/v1/keys")

	// Minted for componentTestMethod (WhoAmI) but presented at a different RPC.
	tok := mintComponentJWT(t, priv, "agent-1")
	resp, err := srv.Check(context.Background(), componentCheckRequest("/gibson.identity.v1.IdentityService/ListAgents", tok))
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if resp.GetStatus().GetCode() != int32(code.Code_UNAUTHENTICATED) {
		t.Fatalf("status = %d, want Unauthenticated (token bound to a different method)", resp.GetStatus().GetCode())
	}
	if mock.lastUser != "" {
		t.Errorf("FGA was consulted (user=%q) for a method-mismatched token; it must be rejected before authz", mock.lastUser)
	}
}

func TestComponentAuth_BadTokenIsUnauthenticated(t *testing.T) {
	pub, _ := mustGenEd25519(t)
	_, otherPriv := mustGenEd25519(t) // sign with an unpublished key
	desc := componentDescriptorServer(t, pub, "agent-1", "agent_principal:9", "acme", "active")
	srv := buildComponentServer(t, &capturingFGA{allowed: true}, desc.URL+"/capabilitygrant/v1/keys")

	tok := mintComponentJWT(t, otherPriv, "agent-1")
	resp, err := srv.Check(context.Background(), componentCheckRequest("/gibson.identity.v1.IdentityService/WhoAmI", tok))
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if resp.GetStatus().GetCode() != int32(code.Code_UNAUTHENTICATED) {
		t.Errorf("status = %d, want Unauthenticated for a present-but-invalid component token", resp.GetStatus().GetCode())
	}
}
