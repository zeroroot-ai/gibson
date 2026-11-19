// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package server

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	authv3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	"github.com/golang-jwt/jwt/v5"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"google.golang.org/grpc/codes"

	"github.com/zeroroot-ai/gibson/internal/server/extauthz/agentcall"
	"github.com/zeroroot-ai/gibson/internal/server/extauthz/modelcall"
)

const (
	inboundKID       = "agent-1"
	inboundPrincipal = "agent_principal:9"
	inboundAgent     = "recon"
	inboundObject    = "published_mission:acme/recon"
)

// inboundDescriptor serves the key descriptor of the daemon for one agent
// identity. A status other than "active" stands for a revoked identity.
func inboundDescriptor(t *testing.T, pub ed25519.PublicKey, status string, capabilities []string) string {
	t.Helper()
	doc := map[string]any{
		"keys": []map[string]string{{
			"kty": "OKP", "crv": "Ed25519",
			"x":   base64.RawURLEncoding.EncodeToString(pub),
			"kid": inboundKID, "alg": "EdDSA", "use": "sig",
		}},
		"principal": inboundPrincipal, "tenant": modelTenant, "status": status,
		"capabilities": capabilities,
	}
	body, _ := json.Marshal(doc)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(body) }))
	t.Cleanup(srv.Close)
	return srv.URL + "/capabilitygrant/v1/keys"
}

// mintInboundJWT signs the token of an outside caller for one path.
func mintInboundJWT(t *testing.T, priv ed25519.PrivateKey, typ, method string) string {
	t.Helper()
	tok := jwt.NewWithClaims(jwt.SigningMethodEdDSA, jwt.MapClaims{
		"iss": "host-1", "sub": inboundKID, "aud": componentTestAudience,
		"iat":    time.Now().Add(-time.Second).Unix(),
		"exp":    time.Now().Add(55 * time.Second).Unix(),
		"jti":    componentTestJTI(),
		"method": method,
	})
	tok.Header["kid"] = inboundKID
	tok.Header["typ"] = typ
	signed, err := tok.SignedString(priv)
	if err != nil {
		t.Fatal(err)
	}
	return signed
}

func inboundRequest(path, token string, extra map[string]string) *authv3.CheckRequest {
	h := map[string]string{}
	if token != "" {
		h[headerCapabilityGrant] = token
	}
	for k, v := range extra {
		h[k] = v
	}
	return &authv3.CheckRequest{Attributes: &authv3.AttributeContext{
		Request: &authv3.AttributeContext_Request{
			Http: &authv3.AttributeContext_HttpRequest{Path: path, Method: http.MethodPost, Headers: h},
		},
	}}
}

type inboundCase struct {
	status       string
	capabilities []string
	allow        map[string]bool
	fgaErr       error
}

// inboundServer builds ext-authz with the Edge identity on, an FGA that answers
// the tuples of the case, and a descriptor that describes the case.
func inboundServer(t *testing.T, c inboundCase) (*EnvoyAuthzServer, ed25519.PrivateKey, *modelFGA) {
	t.Helper()
	pub, priv := mustGenEd25519(t)
	status := c.status
	if status == "" {
		status = "active"
	}
	mock := &modelFGA{allow: c.allow, err: c.fgaErr}
	srv := buildComponentServer(t, mock, inboundDescriptor(t, pub, status, c.capabilities))
	srv.edgeIDs = idSet([]string{edgeSVID})
	srv.gatewayIDs = idSet([]string{gatewaySVID})
	return srv, priv, mock
}

func grantedInbound() map[string]bool {
	return map[string]bool{tupleKey(inboundPrincipal, "can_originate", inboundObject): true}
}

var originateCeiling = []string{"mission:originate"}

func TestInboundA2A_AllowsAGrantedCallerAndSetsTheTrustedHeaders(t *testing.T) {
	t.Parallel()
	for name, path := range map[string]string{
		"the JSON-RPC endpoint": agentcall.InboundPathFor(inboundAgent),
		"the Agent Card":        agentcall.InboundCardPathFor(inboundAgent),
	} {
		t.Run(name, func(t *testing.T) {
			srv, priv, mock := inboundServer(t, inboundCase{capabilities: originateCeiling, allow: grantedInbound()})
			// The caller sends forged copies of the trusted headers and a route.
			req := inboundRequest(path, mintInboundJWT(t, priv, "agent+jwt", path), map[string]string{
				modelcall.HeaderTenant: "evil", modelcall.HeaderSubject: "user:evil",
				modelcall.HeaderMission: "m-evil", modelcall.HeaderTask: "t-evil",
				modelcall.HeaderRouteTenant: "evil", agentcall.HeaderRouteAgent: "other",
			})

			resp, err := srv.Check(peerContext(t, edgeSVID), req)
			if got := statusOf(t, resp, err); got != codes.OK {
				t.Fatalf("status = %v, want OK", got)
			}
			// The tenant is the tenant of the descriptor, and the subject is its principal.
			for hdr, want := range map[string]string{
				modelcall.HeaderTenant: modelTenant, modelcall.HeaderSubject: inboundPrincipal,
			} {
				v, action, ok := headerAction(resp, hdr)
				if !ok || v != want || action != 2 /* OVERWRITE_IF_EXISTS_OR_ADD */ {
					t.Errorf("%s = %q (action %v, set %v), want %q with overwrite", hdr, v, action, ok, want)
				}
			}
			for _, hdr := range []string{modelcall.HeaderMission, modelcall.HeaderTask} {
				if !removed(resp, hdr) {
					t.Errorf("the header %s must be removed, since the call has no mission", hdr)
				}
			}
			q := mock.questions()
			if len(q) != 1 || q[0].User != inboundPrincipal || q[0].Relation != "can_originate" ||
				q[0].Object != inboundObject {
				t.Errorf("FGA was asked %+v, want can_originate of %s on %s", q, inboundPrincipal, inboundObject)
			}
		})
	}
}

func TestInboundA2A_Refusals(t *testing.T) {
	t.Parallel()
	path := agentcall.InboundPathFor(inboundAgent)
	tests := []struct {
		name  string
		c     inboundCase
		peer  string
		path  string
		token func(t *testing.T, priv ed25519.PrivateKey) string
		extra map[string]string
		want  codes.Code
	}{
		{
			name: "a caller with no grant to the definition", c: inboundCase{capabilities: originateCeiling},
			peer: edgeSVID, path: path, want: codes.PermissionDenied,
		},
		{
			name: "an agent that is not published", c: inboundCase{capabilities: originateCeiling, allow: grantedInbound()},
			peer: edgeSVID, path: agentcall.InboundPathFor("unpublished"), want: codes.PermissionDenied,
			token: func(t *testing.T, priv ed25519.PrivateKey) string {
				t.Helper()
				return mintInboundJWT(t, priv, "agent+jwt", agentcall.InboundPathFor("unpublished"))
			},
		},
		{
			name: "a grant that belongs to another tenant",
			c: inboundCase{capabilities: originateCeiling, allow: map[string]bool{
				tupleKey(inboundPrincipal, "can_originate", "published_mission:other/recon"): true,
			}},
			peer: edgeSVID, path: path, want: codes.PermissionDenied,
		},
		{
			name: "a caller with no mission:originate ceiling", c: inboundCase{allow: grantedInbound()},
			peer: edgeSVID, path: path, want: codes.PermissionDenied,
		},
		{
			name: "a caller with another ceiling", c: inboundCase{capabilities: []string{"mission:delegate"}, allow: grantedInbound()},
			peer: edgeSVID, path: path, want: codes.PermissionDenied,
		},
		{
			name: "a revoked identity",
			c:    inboundCase{status: "revoked", capabilities: originateCeiling, allow: grantedInbound()},
			peer: edgeSVID, path: path, want: codes.Unauthenticated,
		},
		{
			name: "a call with a Zitadel token and no Capability Grant",
			c:    inboundCase{capabilities: originateCeiling, allow: grantedInbound()},
			peer: edgeSVID, path: path, want: codes.Unauthenticated,
			token: func(*testing.T, ed25519.PrivateKey) string { return "" },
			extra: map[string]string{headerJWTPayload: "eyJzdWIiOiJ1MSJ9", "authorization": "Bearer zitadel"},
		},
		{
			name: "a call with an API key and no Capability Grant",
			c:    inboundCase{capabilities: originateCeiling, allow: grantedInbound()},
			peer: edgeSVID, path: path, want: codes.Unauthenticated,
			token: func(*testing.T, ed25519.PrivateKey) string { return "" },
			extra: map[string]string{"x-api-key": "k-1"},
		},
		{
			name: "a daemon task grant instead of a component token",
			c:    inboundCase{capabilities: originateCeiling, allow: grantedInbound()},
			peer: edgeSVID, path: path, want: codes.PermissionDenied,
			token: func(t *testing.T, priv ed25519.PrivateKey) string {
				t.Helper()
				return mintInboundJWT(t, priv, "JWT", path)
			},
		},
		{
			name: "a token that is bound to another path",
			c:    inboundCase{capabilities: originateCeiling, allow: grantedInbound()},
			peer: edgeSVID, path: path, want: codes.Unauthenticated,
			token: func(t *testing.T, priv ed25519.PrivateKey) string {
				t.Helper()
				return mintInboundJWT(t, priv, "agent+jwt", agentcall.InboundPathFor("other"))
			},
		},
		{
			name: "a path that names no valid agent",
			c:    inboundCase{capabilities: originateCeiling, allow: grantedInbound()},
			peer: edgeSVID, path: "/a2a/inbound/Bad!", want: codes.PermissionDenied,
		},
		{
			name: "the gateway identity on an inbound path",
			c:    inboundCase{capabilities: originateCeiling, allow: grantedInbound()},
			peer: gatewaySVID, path: path, want: codes.PermissionDenied,
		},
		{
			name: "FGA that does not answer",
			c:    inboundCase{capabilities: originateCeiling, allow: grantedInbound(), fgaErr: errors.New("fga down")},
			peer: edgeSVID, path: path, want: codes.Unavailable,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv, priv, _ := inboundServer(t, tt.c)
			token := mintInboundJWT(t, priv, "agent+jwt", tt.path)
			if tt.token != nil {
				token = tt.token(t, priv)
			}
			resp, err := srv.Check(peerContext(t, tt.peer), inboundRequest(tt.path, token, tt.extra))
			if got := statusOf(t, resp, err); got != tt.want {
				t.Fatalf("status = %v, want %v", got, tt.want)
			}
		})
	}
}

// A refusal for the missing ceiling must come before the question to FGA, so a
// caller with no ceiling causes no FGA load.
func TestInboundA2A_NoCeilingAsksNoFGAQuestion(t *testing.T) {
	t.Parallel()
	srv, priv, mock := inboundServer(t, inboundCase{allow: grantedInbound()})
	path := agentcall.InboundPathFor(inboundAgent)

	resp, err := srv.Check(peerContext(t, edgeSVID), inboundRequest(path, mintInboundJWT(t, priv, "agent+jwt", path), nil))
	if got := statusOf(t, resp, err); got != codes.PermissionDenied {
		t.Fatalf("status = %v, want PermissionDenied", got)
	}
	if q := mock.questions(); len(q) != 0 {
		t.Errorf("FGA was asked %+v, want no question", q)
	}
}

func TestInboundA2A_CountsEachRefusalByReason(t *testing.T) {
	srv, priv, _ := inboundServer(t, inboundCase{capabilities: originateCeiling})
	path := agentcall.InboundPathFor(inboundAgent)
	before := testutil.ToFloat64(extauthzInboundA2ADeniedTotal.WithLabelValues(inboundDenyNoGrant))

	resp, err := srv.Check(peerContext(t, edgeSVID), inboundRequest(path, mintInboundJWT(t, priv, "agent+jwt", path), nil))
	if got := statusOf(t, resp, err); got != codes.PermissionDenied {
		t.Fatalf("status = %v, want PermissionDenied", got)
	}
	if got := testutil.ToFloat64(extauthzInboundA2ADeniedTotal.WithLabelValues(inboundDenyNoGrant)); got != before+1 {
		t.Errorf("the no-grant counter = %v, want %v", got, before+1)
	}
}

// A revoke applies at the next call. ext-authz keeps the key descriptor of an agent
// for the cache time, but the inbound class reads it for each call. The first call
// of the identity passes, the daemon then withholds the descriptor, and the second
// call fails inside the cache time.
func TestInboundA2A_ARevokeAppliesAtTheNextCall(t *testing.T) {
	pub, priv := mustGenEd25519(t)
	var revoked atomic.Bool
	doc := map[string]any{
		"keys": []map[string]string{{
			"kty": "OKP", "crv": "Ed25519", "x": base64.RawURLEncoding.EncodeToString(pub), "kid": inboundKID,
		}},
		"principal": inboundPrincipal, "tenant": modelTenant, "status": "active", "capabilities": originateCeiling,
	}
	body, _ := json.Marshal(doc)
	desc := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if revoked.Load() {
			http.Error(w, "unknown key", http.StatusNotFound)
			return
		}
		_, _ = w.Write(body)
	}))
	t.Cleanup(desc.Close)
	srv := buildComponentServer(t, &modelFGA{allow: grantedInbound()}, desc.URL+"/capabilitygrant/v1/keys")
	srv.edgeIDs = idSet([]string{edgeSVID})
	path := agentcall.InboundPathFor(inboundAgent)
	call := func() codes.Code {
		resp, err := srv.Check(peerContext(t, edgeSVID), inboundRequest(path, mintInboundJWT(t, priv, "agent+jwt", path), nil))
		return statusOf(t, resp, err)
	}

	if got := call(); got != codes.OK {
		t.Fatalf("before the revoke: status = %v, want OK", got)
	}
	revoked.Store(true)
	if got := call(); got != codes.Unauthenticated {
		t.Fatalf("after the revoke: status = %v, want Unauthenticated", got)
	}
}
