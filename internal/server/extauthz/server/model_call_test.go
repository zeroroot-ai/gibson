// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package server

import (
	"context"
	"crypto/ed25519"
	"errors"
	"net/http"
	"sync"
	"testing"
	"time"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	authv3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	"github.com/golang-jwt/jwt/v5"
	openfga "github.com/openfga/go-sdk"
	fgaclient "github.com/openfga/go-sdk/client"
	"google.golang.org/grpc/codes"
	"google.golang.org/protobuf/types/known/structpb"

	"github.com/zeroroot-ai/gibson/internal/server/extauthz/cgjwt"
	"github.com/zeroroot-ai/gibson/internal/server/extauthz/fga"
	"github.com/zeroroot-ai/gibson/internal/server/extauthz/modelcall"
)

// modelFGA answers only the tuples in allow. Every other question gets "no".
// err, when set, fails each question.
type modelFGA struct {
	mu    sync.Mutex
	allow map[string]bool
	err   error
	asked []fgaclient.ClientCheckRequest
	// gateClosed answers "no" to the mission gate question (relation active).
	// The gate is open by default, so a test of the access check need not
	// repeat the tuple of the mission.
	gateClosed bool
	// gateErr fails the mission gate question only.
	gateErr error
	// errOn limits err to the questions of one relation. Empty means err
	// fails each question.
	errOn string
}

func tupleKey(user, relation, object string) string { return user + "|" + relation + "|" + object }

func (m *modelFGA) Check(_ context.Context) fgaclient.SdkClientCheckRequestInterface {
	return &modelFGAReq{m: m}
}

func (m *modelFGA) questions() []fgaclient.ClientCheckRequest {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]fgaclient.ClientCheckRequest(nil), m.asked...)
}

// modelFGAReq answers the Check request of the OpenFGA client. It embeds the
// interface for GetAuthorizationModelIdOverride and GetStoreIdOverride, whose
// names the SDK fixes. The code under test never calls these two methods.
type modelFGAReq struct {
	fgaclient.SdkClientCheckRequestInterface
	m    *modelFGA
	body fgaclient.ClientCheckRequest
}

func (r *modelFGAReq) Body(b fgaclient.ClientCheckRequest) fgaclient.SdkClientCheckRequestInterface {
	r.body = b
	return r
}

func (r *modelFGAReq) Options(_ fgaclient.ClientCheckOptions) fgaclient.SdkClientCheckRequestInterface {
	return r
}

func (r *modelFGAReq) Execute() (*fgaclient.ClientCheckResponse, error) {
	r.m.mu.Lock()
	r.m.asked = append(r.m.asked, r.body)
	err := r.m.err
	if r.m.errOn != "" && r.body.Relation != r.m.errOn {
		err = nil
	}
	v := r.m.allow[tupleKey(r.body.User, r.body.Relation, r.body.Object)]
	if r.body.Relation == "active" {
		v = !r.m.gateClosed
		if r.m.gateErr != nil {
			err = r.m.gateErr
		}
	}
	r.m.mu.Unlock()
	if err != nil {
		return nil, err
	}
	return &fgaclient.ClientCheckResponse{CheckResponse: openfga.CheckResponse{Allowed: &v}}, nil
}

func (r *modelFGAReq) GetContext() context.Context               { return context.Background() }
func (r *modelFGAReq) GetBody() *fgaclient.ClientCheckRequest    { b := r.body; return &b }
func (r *modelFGAReq) GetOptions() *fgaclient.ClientCheckOptions { return nil }

const (
	modelTenant   = "acme"
	modelProvider = "anthropic"
	modelName1    = "claude-sonnet-5-5"
)

var (
	members     = "tenant:" + modelTenant + "#member"
	providerObj = "provider:" + modelTenant + "/" + modelProvider
	modelObj    = "model:" + modelTenant + "/" + modelName1
)

// buildModelServer wires a server with a task grant verifier and the given FGA.
func buildModelServer(t *testing.T, fgaClient fga.FGAClient) (*EnvoyAuthzServer, ed25519.PrivateKey) {
	t.Helper()
	return buildModelServerWithReplay(t, fgaClient, &memReplay{seen: map[string]bool{}})
}

// buildModelServerWithReplay is buildModelServer with a given replay store.
func buildModelServerWithReplay(
	t *testing.T, fgaClient fga.FGAClient, replay cgjwt.ReplayStore,
) (*EnvoyAuthzServer, ed25519.PrivateKey) {
	t.Helper()
	pub, priv := mustGenEd25519(t)
	keys := startCGKeyServer(t, pub)
	verifier, err := cgjwt.NewVerifier(cgjwt.Config{
		KeysBaseURL:      keys.URL + "/capabilitygrant/v1/keys",
		ExpectedIssuer:   grantIssuer,
		ExpectedAudience: grantAudience,
		HTTPClient:       keys.Client(),
		ReplayStore:      replay,
	})
	if err != nil {
		t.Fatal(err)
	}
	reg, err := fga.LoadRegistry([]byte(grantTestYAML))
	if err != nil {
		t.Fatal(err)
	}
	srv := NewEnvoyAuthzServer(Config{
		Component:  testComponentVerifier(t),
		Cache:      fga.NewCachedChecker(fga.NewChecker(fgaClient, reg), 0, 0),
		CGJWT:      verifier,
		Logger:     newTestLogger(),
		OrgTenants: &fakeOrgTenantResolver{},
	})
	return srv, priv
}

// modelRequest builds the CheckRequest that the gateway sends for a model call.
func modelRequest(path, routeTenant, provider, model, grant string, extraHeaders map[string]string) *authv3.CheckRequest {
	hdrs := map[string]string{}
	if grant != "" {
		hdrs[headerCapabilityGrant] = grant
	}
	for k, v := range extraHeaders {
		hdrs[k] = v
	}
	// The caller claims its route with two headers. ext-authz runs before any
	// route, so it gets no context extension.
	if routeTenant != "" {
		hdrs[modelcall.HeaderRouteTenant] = routeTenant
	}
	if provider != "" {
		hdrs[modelcall.HeaderRouteProvider] = provider
	}
	attrs := &authv3.AttributeContext{
		Request: &authv3.AttributeContext_Request{
			Http: &authv3.AttributeContext_HttpRequest{Path: path, Method: http.MethodPost, Headers: hdrs},
		},
	}
	if model != "" {
		attrs.MetadataContext = &corev3.Metadata{FilterMetadata: map[string]*structpb.Struct{
			modelcall.MetadataNamespace: {Fields: map[string]*structpb.Value{
				modelcall.MetadataModel: structpb.NewStringValue(model),
			}},
		}}
	}
	return &authv3.CheckRequest{Attributes: attrs}
}

func mintModelGrant(t *testing.T, priv ed25519.PrivateKey, tenant string, routes []string) string {
	t.Helper()
	return mintTaskGrant(t, priv, tenant, routes, time.Now().Add(10*time.Minute))
}

func statusOf(t *testing.T, resp *authv3.CheckResponse, err error) codes.Code {
	t.Helper()
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	return codes.Code(resp.GetStatus().GetCode()) //nolint:gosec // controlled small value
}

func headerAction(resp *authv3.CheckResponse, name string) (string, corev3.HeaderValueOption_HeaderAppendAction, bool) {
	for _, h := range resp.GetOkResponse().GetHeaders() {
		if h.GetHeader().GetKey() == name {
			return h.GetHeader().GetValue(), h.GetAppendAction(), true
		}
	}
	return "", 0, false
}

func removed(resp *authv3.CheckResponse, name string) bool {
	for _, n := range resp.GetOkResponse().GetHeadersToRemove() {
		if n == name {
			return true
		}
	}
	return false
}

func TestModelCall_AllowedSetsTheFourHeaders(t *testing.T) {
	t.Parallel()
	mock := &modelFGA{allow: map[string]bool{tupleKey(members, "can_use", modelObj): true}}
	srv, priv := buildModelServer(t, mock)
	grant := mintModelGrant(t, priv, modelTenant, []string{modelcall.RouteResponses})

	req := modelRequest(modelcall.RouteResponses, modelTenant, modelProvider, modelName1, grant, nil)
	resp, err := srv.Check(context.Background(), req)
	if got := statusOf(t, resp, err); got != codes.OK {
		t.Fatalf("status = %v, want OK", got)
	}
	want := map[string]string{
		modelcall.HeaderTenant: modelTenant, modelcall.HeaderSubject: taskGrantSubject,
		modelcall.HeaderMission: "mission-1", modelcall.HeaderTask: "task-1",
	}
	for name, value := range want {
		got, action, ok := headerAction(resp, name)
		if !ok || got != value {
			t.Errorf("%s = %q (present %v), want %q", name, got, ok, value)
		}
		if action != corev3.HeaderValueOption_OVERWRITE_IF_EXISTS_OR_ADD {
			t.Errorf("%s append action = %v, want OVERWRITE_IF_EXISTS_OR_ADD", name, action)
		}
	}
}

func TestModelCall_FGAIsAskedWithTheExactModelAndTheProvider(t *testing.T) {
	t.Parallel()
	mock := &modelFGA{} // nothing is allowed
	srv, priv := buildModelServer(t, mock)
	grant := mintModelGrant(t, priv, modelTenant, []string{modelcall.RouteResponses})
	resp, err := srv.Check(context.Background(),
		modelRequest(modelcall.RouteResponses, modelTenant, modelProvider, modelName1, grant, nil))
	if got := statusOf(t, resp, err); got != codes.PermissionDenied {
		t.Fatalf("status = %v, want PermissionDenied", got)
	}
	asked := mock.questionsAbout("can_use")
	if len(asked) != 2 {
		t.Fatalf("FGA was asked %d questions, want 2: %+v", len(asked), asked)
	}
	for i, wantObj := range []string{modelObj, providerObj} {
		if asked[i].User != members || asked[i].Relation != "can_use" || asked[i].Object != wantObj {
			t.Errorf("question %d = %+v, want %s can_use %s", i, asked[i], members, wantObj)
		}
	}
}

func TestModelCall_ProviderGrantAllowsAnyModel(t *testing.T) {
	t.Parallel()
	mock := &modelFGA{allow: map[string]bool{tupleKey(members, "can_use", providerObj): true}}
	srv, priv := buildModelServer(t, mock)
	grant := mintModelGrant(t, priv, modelTenant, []string{modelcall.RouteResponses})
	resp, err := srv.Check(context.Background(),
		modelRequest(modelcall.RouteResponses, modelTenant, modelProvider, "claude-other", grant, nil))
	if got := statusOf(t, resp, err); got != codes.OK {
		t.Fatalf("status = %v, want OK", got)
	}
}

func TestModelCall_DenyPaths(t *testing.T) {
	t.Parallel()
	allowAll := func() *modelFGA {
		return &modelFGA{allow: map[string]bool{
			tupleKey(members, "can_use", modelObj):    true,
			tupleKey(members, "can_use", providerObj): true,
		}}
	}
	tests := []struct {
		name string
		// build returns the request and the FGA stub that it uses.
		build     func(t *testing.T, priv ed25519.PrivateKey) *authv3.CheckRequest
		fga       *modelFGA
		want      codes.Code
		noFGAAsk  bool
		listRoute bool
	}{
		{
			name: "FGA forbids the model and the provider",
			fga:  &modelFGA{},
			build: func(t *testing.T, priv ed25519.PrivateKey) *authv3.CheckRequest {
				t.Helper()
				g := mintModelGrant(t, priv, modelTenant, []string{modelcall.RouteResponses})
				return modelRequest(modelcall.RouteResponses, modelTenant, modelProvider, modelName1, g, nil)
			},
			want: codes.PermissionDenied,
		},
		{
			name: "a token of tenant A on the route of tenant B",
			fga:  allowAll(),
			build: func(t *testing.T, priv ed25519.PrivateKey) *authv3.CheckRequest {
				t.Helper()
				g := mintModelGrant(t, priv, "tenant-a", []string{modelcall.RouteResponses})
				return modelRequest(modelcall.RouteResponses, "tenant-b", modelProvider, modelName1, g, nil)
			},
			want:     codes.PermissionDenied,
			noFGAAsk: true,
		},
		{
			name: "a task grant that does not list the route",
			fga:  allowAll(),
			build: func(t *testing.T, priv ed25519.PrivateKey) *authv3.CheckRequest {
				t.Helper()
				g := mintModelGrant(t, priv, modelTenant, []string{"/other.v1.S/Elsewhere"})
				return modelRequest(modelcall.RouteResponses, modelTenant, modelProvider, modelName1, g, nil)
			},
			want:     codes.PermissionDenied,
			noFGAAsk: true,
		},
		{
			name: "no credential",
			fga:  allowAll(),
			build: func(_ *testing.T, _ ed25519.PrivateKey) *authv3.CheckRequest {
				return modelRequest(modelcall.RouteResponses, modelTenant, modelProvider, modelName1, "", nil)
			},
			want:     codes.Unauthenticated,
			noFGAAsk: true,
		},
		{
			name: "an expired grant",
			fga:  allowAll(),
			build: func(t *testing.T, priv ed25519.PrivateKey) *authv3.CheckRequest {
				t.Helper()
				g := mintTaskGrant(t, priv, modelTenant, []string{modelcall.RouteResponses}, time.Now().Add(-time.Minute))
				return modelRequest(modelcall.RouteResponses, modelTenant, modelProvider, modelName1, g, nil)
			},
			want:     codes.Unauthenticated,
			noFGAAsk: true,
		},
		{
			name: "a grant that this daemon did not sign",
			fga:  allowAll(),
			build: func(t *testing.T, _ ed25519.PrivateKey) *authv3.CheckRequest {
				t.Helper()
				_, other := mustGenEd25519(t)
				g := mintModelGrant(t, other, modelTenant, []string{modelcall.RouteResponses})
				return modelRequest(modelcall.RouteResponses, modelTenant, modelProvider, modelName1, g, nil)
			},
			want:     codes.Unauthenticated,
			noFGAAsk: true,
		},
		{
			name: "a call that names no model",
			fga:  allowAll(),
			build: func(t *testing.T, priv ed25519.PrivateKey) *authv3.CheckRequest {
				t.Helper()
				g := mintModelGrant(t, priv, modelTenant, []string{modelcall.RouteResponses})
				return modelRequest(modelcall.RouteResponses, modelTenant, modelProvider, "", g, nil)
			},
			want:     codes.PermissionDenied,
			noFGAAsk: true,
		},
		{
			name: "a route that sends no tenant",
			fga:  allowAll(),
			build: func(t *testing.T, priv ed25519.PrivateKey) *authv3.CheckRequest {
				t.Helper()
				g := mintModelGrant(t, priv, modelTenant, []string{modelcall.RouteResponses})
				return modelRequest(modelcall.RouteResponses, "", modelProvider, modelName1, g, nil)
			},
			want:     codes.PermissionDenied,
			noFGAAsk: true,
		},
		{
			name: "a model name that cannot form an FGA object",
			fga:  allowAll(),
			build: func(t *testing.T, priv ed25519.PrivateKey) *authv3.CheckRequest {
				t.Helper()
				g := mintModelGrant(t, priv, modelTenant, []string{modelcall.RouteResponses})
				return modelRequest(modelcall.RouteResponses, modelTenant, modelProvider, "bad name#x", g, nil)
			},
			want:     codes.PermissionDenied,
			noFGAAsk: true,
		},
		{
			name: "FGA is down",
			fga:  &modelFGA{err: errors.New("fga down")},
			build: func(t *testing.T, priv ed25519.PrivateKey) *authv3.CheckRequest {
				t.Helper()
				g := mintModelGrant(t, priv, modelTenant, []string{modelcall.RouteResponses})
				return modelRequest(modelcall.RouteResponses, modelTenant, modelProvider, modelName1, g, nil)
			},
			want: codes.Unavailable,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			srv, priv := buildModelServer(t, tt.fga)
			resp, err := srv.Check(context.Background(), tt.build(t, priv))
			if got := statusOf(t, resp, err); got != tt.want {
				t.Fatalf("status = %v, want %v", got, tt.want)
			}
			if resp.GetOkResponse() != nil {
				t.Error("a deny carries an OK response body")
			}
			if tt.noFGAAsk && len(tt.fga.questions()) != 0 {
				t.Errorf("FGA was asked before the refusal: %+v", tt.fga.questions())
			}
		})
	}
}

// The model list has no model name. It needs the provider relation.
func TestModelCall_ListNeedsTheProviderRelation(t *testing.T) {
	t.Parallel()
	t.Run("provider grant allows", func(t *testing.T) {
		t.Parallel()
		mock := &modelFGA{allow: map[string]bool{tupleKey(members, "can_use", providerObj): true}}
		srv, priv := buildModelServer(t, mock)
		g := mintModelGrant(t, priv, modelTenant, []string{modelcall.RouteModels})
		resp, err := srv.Check(context.Background(),
			modelRequest(modelcall.RouteModels, modelTenant, modelProvider, "", g, nil))
		if got := statusOf(t, resp, err); got != codes.OK {
			t.Fatalf("status = %v, want OK", got)
		}
		if asked := mock.questionsAbout("can_use"); len(asked) != 1 || asked[0].Object != providerObj {
			t.Errorf("FGA questions = %+v, want one question on %s", asked, providerObj)
		}
	})
	t.Run("a grant on one model does not allow the list", func(t *testing.T) {
		t.Parallel()
		mock := &modelFGA{allow: map[string]bool{tupleKey(members, "can_use", modelObj): true}}
		srv, priv := buildModelServer(t, mock)
		g := mintModelGrant(t, priv, modelTenant, []string{modelcall.RouteModels})
		resp, err := srv.Check(context.Background(),
			modelRequest(modelcall.RouteModels, modelTenant, modelProvider, "", g, nil))
		if got := statusOf(t, resp, err); got != codes.PermissionDenied {
			t.Fatalf("status = %v, want PermissionDenied", got)
		}
	})
	t.Run("a token of another tenant is refused", func(t *testing.T) {
		t.Parallel()
		mock := &modelFGA{allow: map[string]bool{tupleKey("tenant:other#member", "can_use", providerObj): true}}
		srv, priv := buildModelServer(t, mock)
		g := mintModelGrant(t, priv, "other", []string{modelcall.RouteModels})
		resp, err := srv.Check(context.Background(),
			modelRequest(modelcall.RouteModels, modelTenant, modelProvider, "", g, nil))
		if got := statusOf(t, resp, err); got != codes.PermissionDenied {
			t.Fatalf("status = %v, want PermissionDenied", got)
		}
	})
}

// A component with its own token is a second kind of caller. It has no mission
// and no task, so those two headers are removed.
func TestModelCall_ComponentToken(t *testing.T) {
	t.Parallel()
	const componentModelRoute = modelcall.RouteResponses
	pub, priv := mustGenEd25519(t)
	build := func(t *testing.T, tenant string, mock *modelFGA) (*EnvoyAuthzServer, string) {
		t.Helper()
		desc := componentDescriptorServer(t, pub, "agent-1", "agent_principal:9", tenant, "active")
		srv := buildComponentServer(t, mock, desc.URL+"/capabilitygrant/v1/keys")
		tok := mintComponentJWTFor(t, priv, "agent-1", componentModelRoute)
		return srv, tok
	}

	t.Run("allowed through the typed principal", func(t *testing.T) {
		t.Parallel()
		mock := &modelFGA{allow: map[string]bool{tupleKey("agent_principal:9", "can_use", modelObj): true}}
		srv, tok := build(t, modelTenant, mock)
		resp, err := srv.Check(context.Background(),
			modelRequest(componentModelRoute, modelTenant, modelProvider, modelName1, tok, nil))
		if got := statusOf(t, resp, err); got != codes.OK {
			t.Fatalf("status = %v, want OK", got)
		}
		if v, _, ok := headerAction(resp, modelcall.HeaderSubject); !ok || v != "agent_principal:9" {
			t.Errorf("subject = %q (present %v), want agent_principal:9", v, ok)
		}
		for _, name := range []string{modelcall.HeaderMission, modelcall.HeaderTask} {
			if !removed(resp, name) {
				t.Errorf("%s must be removed: the component has no mission or task", name)
			}
		}
	})
	t.Run("a component of another tenant is refused", func(t *testing.T) {
		t.Parallel()
		mock := &modelFGA{allow: map[string]bool{tupleKey("agent_principal:9", "can_use", modelObj): true}}
		srv, tok := build(t, "other", mock)
		resp, err := srv.Check(context.Background(),
			modelRequest(componentModelRoute, modelTenant, modelProvider, modelName1, tok, nil))
		if got := statusOf(t, resp, err); got != codes.PermissionDenied {
			t.Fatalf("status = %v, want PermissionDenied", got)
		}
		if len(mock.questions()) != 0 {
			t.Errorf("FGA was asked before the tenant refusal: %+v", mock.questions())
		}
	})
}

// mintComponentJWTFor signs a component token that is bound to one method.
func mintComponentJWTFor(t *testing.T, priv ed25519.PrivateKey, kid, method string) string {
	t.Helper()
	tok := jwt.NewWithClaims(jwt.SigningMethodEdDSA, jwt.MapClaims{
		"iss": "host-1", "sub": kid, "aud": componentTestAudience,
		"iat":    time.Now().Add(-time.Second).Unix(),
		"exp":    time.Now().Add(55 * time.Second).Unix(),
		"jti":    componentTestJTI(),
		"method": method, "component_scope": "component:hello",
	})
	tok.Header["kid"] = kid
	tok.Header["typ"] = "agent+jwt"
	signed, err := tok.SignedString(priv)
	if err != nil {
		t.Fatal(err)
	}
	return signed
}

// questionsAbout returns the FGA questions with the given relation.
func (m *modelFGA) questionsAbout(relation string) []fgaclient.ClientCheckRequest {
	var out []fgaclient.ClientCheckRequest
	for _, q := range m.questions() {
		if q.Relation == relation {
			out = append(out, q)
		}
	}
	return out
}

// A model call of a mission that is not active is refused. The gate is the
// tuple that the daemon changes when the mission pauses or ends (gibson#1389).
func TestModelCall_MissionGate(t *testing.T) {
	t.Parallel()
	allowModel := func() map[string]bool {
		return map[string]bool{tupleKey(members, "can_use", modelObj): true}
	}
	call := func(t *testing.T, mock *modelFGA) codes.Code {
		t.Helper()
		srv, priv := buildModelServer(t, mock)
		g := mintModelGrant(t, priv, modelTenant, []string{modelcall.RouteResponses})
		resp, err := srv.Check(context.Background(),
			modelRequest(modelcall.RouteResponses, modelTenant, modelProvider, modelName1, g, nil))
		return statusOf(t, resp, err)
	}

	t.Run("an active mission passes, and the gate question is exact", func(t *testing.T) {
		t.Parallel()
		mock := &modelFGA{allow: allowModel()}
		if got := call(t, mock); got != codes.OK {
			t.Fatalf("status = %v, want OK", got)
		}
		gate := mock.questionsAbout("active")
		if len(gate) != 1 || gate[0].User != "tenant:"+modelTenant || gate[0].Object != "mission:mission-1" {
			t.Errorf("gate questions = %+v, want tenant:%s active mission:mission-1", gate, modelTenant)
		}
	})
	t.Run("a mission that is not active is refused before the access check", func(t *testing.T) {
		t.Parallel()
		mock := &modelFGA{allow: allowModel(), gateClosed: true}
		if got := call(t, mock); got != codes.PermissionDenied {
			t.Fatalf("status = %v, want PermissionDenied", got)
		}
		if asked := mock.questionsAbout("can_use"); len(asked) != 0 {
			t.Errorf("the access check ran for a mission that is not active: %+v", asked)
		}
	})
	t.Run("FGA is down for the gate", func(t *testing.T) {
		t.Parallel()
		mock := &modelFGA{allow: allowModel(), gateErr: errors.New("fga down")}
		if got := call(t, mock); got != codes.Unavailable {
			t.Fatalf("status = %v, want Unavailable", got)
		}
	})
	t.Run("the model list of a mission that is not active is refused", func(t *testing.T) {
		t.Parallel()
		mock := &modelFGA{
			allow:      map[string]bool{tupleKey(members, "can_use", providerObj): true},
			gateClosed: true,
		}
		srv, priv := buildModelServer(t, mock)
		g := mintModelGrant(t, priv, modelTenant, []string{modelcall.RouteModels})
		resp, err := srv.Check(context.Background(),
			modelRequest(modelcall.RouteModels, modelTenant, modelProvider, "", g, nil))
		if got := statusOf(t, resp, err); got != codes.PermissionDenied {
			t.Fatalf("status = %v, want PermissionDenied", got)
		}
	})
}

// mintGrantWithInitiator signs a task grant that carries the initiator claim.
func mintGrantWithInitiator(t *testing.T, priv ed25519.PrivateKey, tenant, initiator string) string {
	t.Helper()
	claims := jwt.MapClaims{
		"iss": grantIssuer, "aud": grantAudience,
		"sub": taskGrantSubject, "tenant": tenant,
		"mission_id": "mission-1", "task_id": "task-1", "jti": "jti-ini",
		"iat":          time.Now().Add(-time.Minute).Unix(),
		"exp":          time.Now().Add(10 * time.Minute).Unix(),
		"allowed_rpcs": []string{modelcall.RouteResponses},
	}
	if initiator != "" {
		claims[modelcall.InitiatorClaim] = initiator
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims)
	tok.Header["kid"] = grantKID
	signed, err := tok.SignedString(priv)
	if err != nil {
		t.Fatal(err)
	}
	return signed
}

// A tenant that turned the default grant off and granted one user: an agent of a
// mission of that user passes, and an agent of a mission of another user is
// refused. The tenant members have no grant, so the claim is the only way in.
func TestModelCall_TheInitiatorOfTheMissionIsTheSubject(t *testing.T) {
	t.Parallel()
	newMock := func() *modelFGA {
		return &modelFGA{allow: map[string]bool{tupleKey("user:alice", "can_use", providerObj): true}}
	}
	call := func(t *testing.T, mock *modelFGA, initiator string) codes.Code {
		t.Helper()
		srv, priv := buildModelServer(t, mock)
		g := mintGrantWithInitiator(t, priv, modelTenant, initiator)
		resp, err := srv.Check(context.Background(),
			modelRequest(modelcall.RouteResponses, modelTenant, modelProvider, modelName1, g, nil))
		return statusOf(t, resp, err)
	}

	t.Run("a mission of the granted user passes", func(t *testing.T) {
		t.Parallel()
		mock := newMock()
		if got := call(t, mock, "user:alice"); got != codes.OK {
			t.Fatalf("status = %v, want OK", got)
		}
		for _, q := range mock.questionsAbout("can_use") {
			if q.User != "user:alice" {
				t.Errorf("the access check asked about %q, want only user:alice", q.User)
			}
		}
	})
	t.Run("a mission of another user is refused", func(t *testing.T) {
		t.Parallel()
		if got := call(t, newMock(), "user:bob"); got != codes.PermissionDenied {
			t.Fatalf("status = %v, want PermissionDenied", got)
		}
	})
	t.Run("a grant with no claim falls back to the tenant members", func(t *testing.T) {
		t.Parallel()
		if got := call(t, newMock(), ""); got != codes.PermissionDenied {
			t.Fatalf("status = %v, want PermissionDenied: the members have no grant", got)
		}
		mock := &modelFGA{allow: map[string]bool{tupleKey(members, "can_use", providerObj): true}}
		if got := call(t, mock, ""); got != codes.OK {
			t.Fatalf("status = %v, want OK with the default grant", got)
		}
	})
	t.Run("a claim that is not a user is refused", func(t *testing.T) {
		t.Parallel()
		for _, bad := range []string{"tenant:acme#member", "user:", "user:a b", "agent_principal:9"} {
			if got := call(t, newMock(), bad); got != codes.PermissionDenied {
				t.Errorf("initiator %q: status = %v, want PermissionDenied", bad, got)
			}
		}
	})
}

// A mission that is only submitted has no tuple, so the gate answers "no".
func TestModelCall_ASubmittedMissionIsRefused(t *testing.T) {
	t.Parallel()
	mock := &modelFGA{
		allow:      map[string]bool{tupleKey(members, "can_use", modelObj): true},
		gateClosed: true, // an absent tuple is a "no" for FGA
	}
	srv, priv := buildModelServer(t, mock)
	g := mintModelGrant(t, priv, modelTenant, []string{modelcall.RouteResponses})
	resp, err := srv.Check(context.Background(),
		modelRequest(modelcall.RouteResponses, modelTenant, modelProvider, modelName1, g, nil))
	if got := statusOf(t, resp, err); got != codes.PermissionDenied {
		t.Fatalf("status = %v, want PermissionDenied", got)
	}
	if asked := mock.questionsAbout("can_use"); len(asked) != 0 {
		t.Errorf("the access check ran: %+v", asked)
	}
}

// A route header that is missing, empty or repeated gives a refusal, and FGA is
// not asked.
func TestModelCall_RouteHeaderDefectsAreRefused(t *testing.T) {
	t.Parallel()
	mock := &modelFGA{allow: map[string]bool{tupleKey(members, "can_use", modelObj): true}}
	srv, priv := buildModelServer(t, mock)
	grant := mintModelGrant(t, priv, modelTenant, []string{modelcall.RouteResponses})

	cases := map[string]func(*authv3.CheckRequest){
		"no tenant header":    func(r *authv3.CheckRequest) { delete(reqHeaders(r), modelcall.HeaderRouteTenant) },
		"no provider header":  func(r *authv3.CheckRequest) { delete(reqHeaders(r), modelcall.HeaderRouteProvider) },
		"empty tenant header": func(r *authv3.CheckRequest) { reqHeaders(r)[modelcall.HeaderRouteTenant] = " " },
		"repeated tenant":     func(r *authv3.CheckRequest) { reqHeaders(r)[modelcall.HeaderRouteTenant] = modelTenant + ",other" },
		"repeated provider":   func(r *authv3.CheckRequest) { reqHeaders(r)[modelcall.HeaderRouteProvider] = modelProvider + ",x" },
	}
	for name, mutate := range cases {
		req := modelRequest(modelcall.RouteResponses, modelTenant, modelProvider, modelName1, grant, nil)
		mutate(req)
		resp, err := srv.Check(context.Background(), req)
		if got := statusOf(t, resp, err); got != codes.PermissionDenied {
			t.Errorf("%s: status = %v, want PermissionDenied", name, got)
		}
	}
	if len(mock.questions()) != 0 {
		t.Errorf("FGA was asked %d times for a call with a bad route header", len(mock.questions()))
	}
}

// A caller of tenant A that sends the route header of tenant B is refused. The
// refusal comes before FGA.
func TestModelCall_TheHeaderOfAnotherTenantIsRefused(t *testing.T) {
	t.Parallel()
	mock := &modelFGA{allow: map[string]bool{tupleKey(members, "can_use", modelObj): true}}
	srv, priv := buildModelServer(t, mock)
	grant := mintModelGrant(t, priv, modelTenant, []string{modelcall.RouteResponses}) // a grant of tenant A
	req := modelRequest(modelcall.RouteResponses, "tenant-b", modelProvider, modelName1, grant, nil)
	resp, err := srv.Check(context.Background(), req)
	if got := statusOf(t, resp, err); got != codes.PermissionDenied {
		t.Fatalf("status = %v, want PermissionDenied", got)
	}
	if len(mock.questions()) != 0 {
		t.Error("FGA was asked for a call that claims another tenant")
	}
}

func reqHeaders(r *authv3.CheckRequest) map[string]string {
	return r.GetAttributes().GetRequest().GetHttp().GetHeaders()
}

// A gateway call that holds a copy of a trusted header is refused with 403,
// before FGA. The refusal does not change the request, so the trace of the call
// must end with a status that the trace receiver drops. A model call and an A2A
// call are both refused.
func TestGatewayCall_ACallerCopyOfATrustedHeaderIsRefused(t *testing.T) {
	t.Parallel()
	mock := &modelFGA{allow: map[string]bool{tupleKey(members, "can_use", modelObj): true}}
	srv, priv := buildModelServer(t, mock)
	grant := mintModelGrant(t, priv, modelTenant, []string{modelcall.RouteResponses})

	for _, h := range []string{
		modelcall.HeaderTenant, modelcall.HeaderSubject, modelcall.HeaderMission, modelcall.HeaderTask,
	} {
		for _, path := range []string{modelcall.RouteResponses, "/"} {
			req := modelRequest(path, modelTenant, modelProvider, modelName1, grant, map[string]string{h: "tenant-b"})
			resp := srv.gatewayCallResponse(context.Background(), req)
			if got := statusOf(t, resp, nil); got != codes.PermissionDenied {
				t.Errorf("%s on %s: status = %v, want PermissionDenied", h, path, got)
			}
			if code := resp.GetDeniedResponse().GetStatus().GetCode(); code != http.StatusForbidden {
				t.Errorf("%s on %s: HTTP status = %v, want 403", h, path, code)
			}
		}
	}
	if len(mock.questions()) != 0 {
		t.Errorf("FGA was asked %d times for a call with a trusted header", len(mock.questions()))
	}
}
