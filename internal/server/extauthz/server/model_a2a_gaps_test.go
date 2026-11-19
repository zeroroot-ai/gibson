// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package server

import (
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	fgaclient "github.com/openfga/go-sdk/client"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"

	"github.com/zeroroot-ai/gibson/internal/server/extauthz/agentcall"
	"github.com/zeroroot-ai/gibson/internal/server/extauthz/modelcall"
)

// userFGA fails the check of the users in errUsers and answers the rest from
// the allow map of the embedded stub.
type userFGA struct {
	*modelFGA
	errUsers map[string]bool
}

type userFGAReq struct {
	modelFGAReq
	errUsers map[string]bool
}

func (u *userFGA) Check(_ context.Context) fgaclient.SdkClientCheckRequestInterface {
	return &userFGAReq{modelFGAReq: modelFGAReq{m: u.modelFGA}, errUsers: u.errUsers}
}

func (r *userFGAReq) Body(b fgaclient.ClientCheckRequest) fgaclient.SdkClientCheckRequestInterface {
	r.body = b
	return r
}

func (r *userFGAReq) Execute() (*fgaclient.ClientCheckResponse, error) {
	if r.errUsers[r.body.User] {
		return nil, errors.New("fga down for " + r.body.User)
	}
	return r.modelFGAReq.Execute()
}

func TestModelCallResponse_RefusesAMissingRouteTenantAndAnUnknownPath(t *testing.T) {
	t.Parallel()
	srv, priv := buildModelServer(t, &modelFGA{})
	grant := mintModelGrant(t, priv, modelTenant, []string{modelcall.RouteResponses})
	tests := []struct {
		name   string
		tenant string
		path   string
	}{
		{"no route tenant", "", modelcall.RouteResponses},
		{"unknown path", modelTenant, "/v1/other"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			req := modelRequest(tt.path, tt.tenant, modelProvider, modelName1, grant, nil)
			resp := srv.modelCallResponse(context.Background(), req, tt.tenant, modelProvider)
			if got := codes.Code(resp.GetStatus().GetCode()); got != codes.PermissionDenied { //nolint:gosec // small value
				t.Fatalf("status = %v, want PermissionDenied", got)
			}
		})
	}
}

func TestModelCall_AProviderNameThatCannotFormAnObjectIsRefused(t *testing.T) {
	t.Parallel()
	mock := &modelFGA{}
	srv, priv := buildModelServer(t, mock)
	grant := mintModelGrant(t, priv, modelTenant, []string{modelcall.RouteResponses})
	req := modelRequest(modelcall.RouteResponses, modelTenant, "bad#provider", modelName1, grant, nil)
	resp, err := srv.Check(peerContext(t, gatewaySVID), req)
	if got := statusOf(t, resp, err); got != codes.PermissionDenied {
		t.Fatalf("status = %v, want PermissionDenied", got)
	}
	if len(mock.questions()) != 0 {
		t.Errorf("FGA was asked for an object that cannot exist: %+v", mock.questions())
	}
}

func TestModelCall_FGAFailureOnTheAccessCheckIsUnavailable(t *testing.T) {
	t.Parallel()
	mock := &modelFGA{err: errors.New("fga down"), errOn: "can_use"}
	srv, priv := buildModelServer(t, mock)
	grant := mintModelGrant(t, priv, modelTenant, []string{modelcall.RouteResponses})
	req := modelRequest(modelcall.RouteResponses, modelTenant, modelProvider, modelName1, grant, nil)
	resp, err := srv.Check(peerContext(t, gatewaySVID), req)
	if got := statusOf(t, resp, err); got != codes.Unavailable {
		t.Fatalf("status = %v, want Unavailable", got)
	}
}

func TestModelCall_ARefusedComponentTokenIsFinal(t *testing.T) {
	t.Parallel()
	pub, priv := mustGenEd25519(t)
	desc := componentDescriptorServer(t, pub, "agent-1", "agent_principal:9", modelTenant, "revoked")
	mock := &modelFGA{allow: map[string]bool{tupleKey("agent_principal:9", "can_use", modelObj): true}}
	srv := buildComponentServer(t, mock, desc.URL+"/capabilitygrant/v1/keys")
	tok := mintComponentJWTFor(t, priv, "agent-1", modelcall.RouteResponses)
	req := modelRequest(modelcall.RouteResponses, modelTenant, modelProvider, modelName1, tok, nil)
	resp, err := srv.Check(context.Background(), req)
	if got := statusOf(t, resp, err); got == codes.OK {
		t.Fatalf("a revoked component was allowed")
	}
	if len(mock.questionsAbout("can_use")) != 0 {
		t.Errorf("FGA was asked about a refused component")
	}
}

func TestCanUseAndCheckAny_KeepAnErrorOnlyWhenNoUserIsAllowed(t *testing.T) {
	t.Parallel()
	inner := &modelFGA{allow: map[string]bool{
		tupleKey("user:ok", "can_use", modelObj):     true,
		tupleKey("user:ok", "can_execute", modelObj): true,
	}}
	srv, _ := buildModelServer(t, &userFGA{modelFGA: inner, errUsers: map[string]bool{"user:bad": true}})
	ctx := context.Background()
	tests := []struct {
		name    string
		users   []string
		allowed bool
		wantErr bool
	}{
		{"an empty user is skipped", []string{"", "user:ok"}, true, false},
		{"another user allows after an error", []string{"user:bad", "user:ok"}, true, false},
		{"an error decides when nothing allows", []string{"user:bad", "user:none"}, false, true},
		{"no allow and no error", []string{"user:none"}, false, false},
	}
	for _, tt := range tests {
		t.Run("canUse "+tt.name, func(t *testing.T) {
			got, err := srv.canUse(ctx, tt.users, []string{modelObj})
			if got != tt.allowed || (err != nil) != tt.wantErr {
				t.Fatalf("canUse = %v, %v", got, err)
			}
		})
		t.Run("checkAny "+tt.name, func(t *testing.T) {
			got, err := srv.checkAny(ctx, tt.users, "can_execute", modelObj)
			if got != tt.allowed || (err != nil) != tt.wantErr {
				t.Fatalf("checkAny = %v, %v", got, err)
			}
		})
	}
}

// a2aGrantWith mints an A2A task grant that carries extra claims.
func a2aGrantWith(t *testing.T, priv ed25519.PrivateKey, extra jwt.MapClaims) string {
	t.Helper()
	claims := jwt.MapClaims{
		"iss": grantIssuer, "aud": grantAudience,
		"sub": taskGrantSubject, "tenant": modelTenant,
		"mission_id": "mission-1", "task_id": "task-1", "jti": "jti-extra",
		"iat":          time.Now().Add(-time.Minute).Unix(),
		"exp":          time.Now().Add(10 * time.Minute).Unix(),
		"allowed_rpcs": a2aGrantRoutes,
	}
	for k, v := range extra {
		claims[k] = v
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims)
	tok.Header["kid"] = grantKID
	signed, err := tok.SignedString(priv)
	if err != nil {
		t.Fatal(err)
	}
	return signed
}

func TestA2ACall_AnInitiatorThatIsNotAnFGAUserIsRefused(t *testing.T) {
	t.Parallel()
	mock := &modelFGA{allow: allowExecute()}
	srv, priv := a2aServer(t, mock)
	g := a2aGrantWith(t, priv, jwt.MapClaims{modelcall.InitiatorClaim: "user:alice#member"})
	if got := checkA2A(t, srv, a2aRequest(agentcall.RouteA2A, g, nil)); got != codes.PermissionDenied {
		t.Fatalf("status = %v, want PermissionDenied", got)
	}
	if len(mock.questionsAbout("can_execute")) != 0 {
		t.Errorf("FGA was asked for a refused initiator")
	}
}

func TestA2ACall_FGAFailureIsUnavailable(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name  string
		errOn string
		allow map[string]bool
	}{
		{"the component check", "can_execute", nil},
		{"the outside agent lookup", "owner", nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			mock := &modelFGA{allow: tt.allow, err: errors.New("fga down"), errOn: tt.errOn}
			srv, priv := a2aServer(t, mock)
			g := mintA2AGrant(t, priv, modelTenant, "mission-1", "task-1", a2aGrantRoutes)
			if got := checkA2A(t, srv, a2aRequest(agentcall.RouteA2A, g, nil)); got != codes.Unavailable {
				t.Fatalf("status = %v, want Unavailable", got)
			}
		})
	}
}

func TestA2ACall_ANameThatCannotBeAnOutsideAgentGoesToTheComponentCheck(t *testing.T) {
	t.Parallel()
	long := strings.Repeat("a", 97)
	object := "component:agent/" + long
	mock := &modelFGA{allow: map[string]bool{tupleKey(members, "can_execute", object): true}}
	srv, priv := a2aServer(t, mock)
	g := mintA2AGrant(t, priv, modelTenant, "mission-1", "task-1", a2aGrantRoutes)
	req := a2aRequest(agentcall.RouteA2A, g, map[string]string{agentcall.HeaderRouteAgent: long})
	if got := checkA2A(t, srv, req); got != codes.OK {
		t.Fatalf("status = %v, want OK", got)
	}
	if got := mock.questionsAbout("owner"); len(got) != 0 {
		t.Errorf("the outside agent lookup ran for a name that cannot form the object: %+v", got)
	}
}

func TestTaskGrant_ASignatureFromAnotherKeyIsUnauthenticated(t *testing.T) {
	t.Parallel()
	srv, _ := buildModelServer(t, &modelFGA{})
	_, other := mustGenEd25519(t)
	g := mintModelGrant(t, other, modelTenant, []string{modelcall.RouteResponses})
	req := modelRequest(modelcall.RouteResponses, modelTenant, modelProvider, modelName1, g, nil)
	resp, err := srv.Check(peerContext(t, gatewaySVID), req)
	if got := statusOf(t, resp, err); got != codes.Unauthenticated {
		t.Fatalf("status = %v, want Unauthenticated", got)
	}
}

func TestTLSPeerSVID_RefusesAPeerWithoutASpiffeID(t *testing.T) {
	t.Parallel()
	httpsURL, err := url.Parse("https://example.org/x")
	if err != nil {
		t.Fatal(err)
	}
	tlsPeer := func(certs ...*x509.Certificate) context.Context {
		return peer.NewContext(context.Background(), &peer.Peer{
			AuthInfo: credentials.TLSInfo{State: tls.ConnectionState{PeerCertificates: certs}},
		})
	}
	tests := []struct {
		name string
		ctx  context.Context
	}{
		{"no peer", context.Background()},
		{"no TLS info", peer.NewContext(context.Background(), &peer.Peer{})},
		{"no certificate", tlsPeer()},
		{"no URI", tlsPeer(&x509.Certificate{})},
		{"a URI that is not spiffe", tlsPeer(&x509.Certificate{URIs: []*url.URL{httpsURL}})},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if id, ok := tlsPeerSVID(tt.ctx); ok || id != "" {
				t.Fatalf("tlsPeerSVID = %q, %v", id, ok)
			}
		})
	}
}

func TestTaskGrant_AnExpiredGrantIsUnauthenticated(t *testing.T) {
	t.Parallel()
	srv, priv := buildModelServer(t, &modelFGA{})
	g := mintTaskGrant(t, priv, modelTenant, []string{modelcall.RouteResponses}, time.Now().Add(-time.Hour))
	req := modelRequest(modelcall.RouteResponses, modelTenant, modelProvider, modelName1, g, nil)
	resp, err := srv.Check(peerContext(t, gatewaySVID), req)
	if got := statusOf(t, resp, err); got != codes.Unauthenticated {
		t.Fatalf("status = %v, want Unauthenticated", got)
	}
}

func TestDaemonCall_AnInitiatorThatIsNotAnFGAUserIsRefused(t *testing.T) {
	t.Parallel()
	srv, priv, mock := dcServer(t)
	claims := dcClaims("chat", modelcall.RouteResponses, modelTenant, "user:u1#member")
	g := signDC(t, priv, modelcall.DaemonCallTokenType, claims)
	req := modelRequest(modelcall.RouteResponses, modelTenant, modelProvider, modelName1, g, nil)
	resp, err := srv.Check(gw(t), req)
	if got := statusOf(t, resp, err); got != codes.PermissionDenied {
		t.Fatalf("status = %v, want PermissionDenied", got)
	}
	if len(mock.questionsAbout("can_use")) != 0 {
		t.Error("FGA was asked for a refused initiator")
	}
}
