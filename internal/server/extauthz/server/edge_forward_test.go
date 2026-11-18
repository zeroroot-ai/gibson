// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package server

import (
	"context"
	"crypto/ed25519"
	"testing"
	"time"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	authv3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	"github.com/golang-jwt/jwt/v5"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"google.golang.org/grpc/codes"

	"github.com/zeroroot-ai/gibson/internal/server/extauthz/headers"
	"github.com/zeroroot-ai/gibson/internal/server/extauthz/modelcall"
)

func edge(t *testing.T) context.Context { return peerContext(t, edgeSVID) }

func TestEdgeForward_AGoodGrantPassesAndSetsOnlyTheTwoIdentityHeaders(t *testing.T) {
	t.Parallel()
	srv, priv, mock := dcServer(t)
	g := mintModelGrant(t, priv, modelTenant, []string{modelcall.RouteResponses})
	forged := map[string]string{modelcall.HeaderTenant: "x", modelcall.HeaderSubject: "y"}
	req := modelRequest(modelcall.EdgeModelPrefix+"v1/responses", modelTenant, modelProvider, "", g, forged)
	resp, err := srv.Check(edge(t), req)
	if got := statusOf(t, resp, err); got != codes.OK {
		t.Fatalf("status = %v, want OK", got)
	}
	ok := resp.GetOkResponse()
	if len(ok.GetHeadersToRemove()) != 0 {
		t.Errorf("the class removed headers: %v", ok.GetHeadersToRemove())
	}
	set := map[string]string{}
	for _, h := range ok.GetHeaders() {
		if h.GetAppendAction() != corev3.HeaderValueOption_OVERWRITE_IF_EXISTS_OR_ADD {
			t.Errorf("header %s is not set with overwrite", h.GetHeader().GetKey())
		}
		set[h.GetHeader().GetKey()] = h.GetHeader().GetValue()
	}
	if len(set) != 2 || set[headers.HeaderTenant] != modelTenant || set[headers.HeaderSubject] == "" {
		t.Errorf("want exactly the identity tenant and subject from the grant, got %v", set)
	}
	for _, trusted := range []string{modelcall.HeaderTenant, modelcall.HeaderSubject, modelcall.HeaderMission, modelcall.HeaderTask} {
		if _, bad := set[trusted]; bad {
			t.Errorf("the class set the trusted header %s", trusted)
		}
	}
	if len(mock.questions()) != 0 {
		t.Errorf("FGA was asked %d times: the class does nothing but the grant check", len(mock.questions()))
	}
}

// The agent prefix has the same rule.
func TestEdgeForward_TheAgentPrefixHasTheSameRule(t *testing.T) {
	t.Parallel()
	srv, priv, _ := dcServer(t)
	g := mintModelGrant(t, priv, modelTenant, []string{"/a2a"})
	resp, err := srv.Check(edge(t), modelRequest(modelcall.EdgeAgentPrefix+"agent/analyst", modelTenant, "", "", g, nil))
	if got := statusOf(t, resp, err); got != codes.OK {
		t.Fatalf("status = %v, want OK", got)
	}
}

// A grant that passes the Edge check also passes the gateway check a moment
// later: a task grant is not single use.
func TestEdgeForward_TheSameGrantPassesAtTheGateway(t *testing.T) {
	t.Parallel()
	srv, priv, _ := dcServer(t)
	g := mintModelGrant(t, priv, modelTenant, []string{modelcall.RouteResponses})
	for range 2 {
		resp, err := srv.Check(edge(t), modelRequest(modelcall.EdgeModelPrefix+"v1/responses", modelTenant, modelProvider, "", g, nil))
		if got := statusOf(t, resp, err); got != codes.OK {
			t.Fatalf("Edge check: status = %v", got)
		}
		resp, err = srv.Check(gw(t), modelRequest(modelcall.RouteResponses, modelTenant, modelProvider, modelName1, g, nil))
		if got := statusOf(t, resp, err); got != codes.OK {
			t.Fatalf("gateway check: status = %v", got)
		}
	}
}

// A daemon call grant never comes through the Edge. The class refuses it and
// writes no replay record, so the grant still works at the gateway.
func TestEdgeForward_ADaemonCallGrantIsRefusedWithoutAReplayRecord(t *testing.T) {
	t.Parallel()
	srv, priv, _ := dcServer(t)
	g := signDC(t, priv, modelcall.DaemonCallTokenType, dcClaims("chat", modelcall.RouteResponses, modelTenant, "user:u1"))
	before := testutil.ToFloat64(extauthzEdgeForwardDeniedTotal.WithLabelValues(forwardDenyDaemonCall))
	resp, err := srv.Check(edge(t), modelRequest(modelcall.EdgeModelPrefix+"v1/responses", modelTenant, modelProvider, "", g, nil))
	if got := statusOf(t, resp, err); got != codes.PermissionDenied {
		t.Fatalf("status = %v, want PermissionDenied", got)
	}
	if testutil.ToFloat64(extauthzEdgeForwardDeniedTotal.WithLabelValues(forwardDenyDaemonCall)) != before+1 {
		t.Error("the refusal was not counted with the reason daemon_call_grant")
	}
	resp, err = srv.Check(gw(t), modelRequest(modelcall.RouteResponses, modelTenant, modelProvider, modelName1, g, nil))
	if got := statusOf(t, resp, err); got != codes.OK {
		t.Fatalf("the grant was used up by the Edge refusal: status = %v", got)
	}
}

func TestEdgeForward_Refusals(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name   string
		build  func(t *testing.T, s *EnvoyAuthzServer, priv ed25519.PrivateKey) string
		mutate func(*authv3.CheckRequest)
		want   codes.Code
	}{
		{"no grant", func(*testing.T, *EnvoyAuthzServer, ed25519.PrivateKey) string { return "" }, nil, codes.Unauthenticated},
		{"a garbage grant", func(*testing.T, *EnvoyAuthzServer, ed25519.PrivateKey) string { return "a.b.c" }, nil, codes.Unauthenticated},
		{"an expired grant", func(t *testing.T, _ *EnvoyAuthzServer, p ed25519.PrivateKey) string {
			return mintTaskGrant(t, p, modelTenant, []string{modelcall.RouteResponses}, time.Now().Add(-time.Hour))
		}, nil, codes.Unauthenticated},
		{"a grant signed by another key", func(t *testing.T, _ *EnvoyAuthzServer, _ ed25519.PrivateKey) string {
			_, other := mustGenEd25519(t)
			return mintModelGrant(t, other, modelTenant, []string{modelcall.RouteResponses})
		}, nil, codes.Unauthenticated},
		{"a component token", func(t *testing.T, _ *EnvoyAuthzServer, p ed25519.PrivateKey) string {
			tok := jwt.NewWithClaims(jwt.SigningMethodEdDSA, jwt.MapClaims{"sub": "x"})
			tok.Header["typ"] = componentTokenType
			tok.Header["kid"] = grantKID
			s, err := tok.SignedString(p)
			if err != nil {
				t.Fatal(err)
			}
			return s
		}, nil, codes.PermissionDenied},
		{"the route header names another tenant", okGrant, func(r *authv3.CheckRequest) {
			reqHeaders(r)[modelcall.HeaderRouteTenant] = "tenant-b"
		}, codes.PermissionDenied},
		{"no route tenant header", okGrant, func(r *authv3.CheckRequest) {
			delete(reqHeaders(r), modelcall.HeaderRouteTenant)
		}, codes.PermissionDenied},
		{"a repeated route tenant header", okGrant, func(r *authv3.CheckRequest) {
			reqHeaders(r)[modelcall.HeaderRouteTenant] = modelTenant + "," + modelTenant
		}, codes.PermissionDenied},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			srv, priv, mock := dcServer(t)
			g := c.build(t, srv, priv)
			req := modelRequest(modelcall.EdgeModelPrefix+"v1/responses", modelTenant, modelProvider, "", g, nil)
			if c.mutate != nil {
				c.mutate(req)
			}
			resp, err := srv.Check(edge(t), req)
			if got := statusOf(t, resp, err); got != c.want {
				t.Fatalf("status = %v, want %v", got, c.want)
			}
			if resp.GetOkResponse() != nil {
				t.Error("a refusal carries an OK body")
			}
			if len(mock.questions()) != 0 {
				t.Error("FGA was asked")
			}
		})
	}
}

func okGrant(t *testing.T, _ *EnvoyAuthzServer, p ed25519.PrivateKey) string {
	return mintModelGrant(t, p, modelTenant, []string{modelcall.RouteResponses})
}

// A path that is only close to a prefix is not on the class. It takes the normal
// Edge flow and is refused for lack of credentials.
func TestEdgeForward_APathOffThePrefixIsNotOnTheClass(t *testing.T) {
	t.Parallel()
	srv, priv, _ := dcServer(t)
	g := mintModelGrant(t, priv, modelTenant, []string{modelcall.RouteResponses})
	for _, path := range []string{"/gateway/modelx/v1/responses", "/gateway/", "/v1/responses"} {
		resp, err := srv.Check(edge(t), modelRequest(path, modelTenant, modelProvider, "", g, nil))
		if got := statusOf(t, resp, err); got == codes.OK {
			t.Errorf("%s: the call was allowed", path)
		}
	}
}

// The gateway identity never uses the class: a forward path from it is not a
// model path, so it is refused as an A2A call.
func TestEdgeForward_TheGatewayIdentityDoesNotUseTheClass(t *testing.T) {
	t.Parallel()
	srv, priv, _ := dcServer(t)
	g := mintModelGrant(t, priv, modelTenant, []string{modelcall.RouteResponses})
	resp, err := srv.Check(gw(t), modelRequest(modelcall.EdgeModelPrefix+"v1/responses", modelTenant, modelProvider, "", g, nil))
	if got := statusOf(t, resp, err); got != codes.PermissionDenied {
		t.Fatalf("status = %v, want PermissionDenied", got)
	}
}

// The gateway does not read the identity headers of the Edge rate limit. A value
// that a caller forges there changes no decision and is not copied to the
// trusted headers.
func TestEdgeForward_TheGatewayIgnoresTheIdentityHeaders(t *testing.T) {
	t.Parallel()
	srv, priv, _ := dcServer(t)
	g := mintModelGrant(t, priv, modelTenant, []string{modelcall.RouteResponses})
	forged := map[string]string{headers.HeaderTenant: "other-tenant", headers.HeaderSubject: "forged-admin"}
	resp, err := srv.Check(gw(t), modelRequest(modelcall.RouteResponses, modelTenant, modelProvider, modelName1, g, forged))
	if got := statusOf(t, resp, err); got != codes.OK {
		t.Fatalf("status = %v, want OK", got)
	}
	for _, h := range resp.GetOkResponse().GetHeaders() {
		if v := h.GetHeader().GetValue(); v == "other-tenant" || v == "forged-admin" {
			t.Errorf("the forged identity value reached header %s", h.GetHeader().GetKey())
		}
	}
}
