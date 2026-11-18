// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package server

import (
	"context"
	"crypto/ed25519"
	"errors"
	"net/http"
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
	a2aAgent       = "scout"
	a2aBank        = "bank-9"
	a2aAgentObject = "component:agent/" + a2aAgent
)

var a2aGrantRoutes = agentcall.GrantRoutes()

// mintA2AGrant signs a task grant with the given routes, mission and task.
func mintA2AGrant(t *testing.T, priv ed25519.PrivateKey, tenant, mission, task string, routes []string) string {
	t.Helper()
	claims := jwt.MapClaims{
		"iss": grantIssuer, "aud": grantAudience,
		"sub": taskGrantSubject, "tenant": tenant,
		"mission_id": mission, "task_id": task, "jti": "jti-a2a",
		"iat":          time.Now().Add(-time.Minute).Unix(),
		"exp":          time.Now().Add(10 * time.Minute).Unix(),
		"allowed_rpcs": routes,
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims)
	tok.Header["kid"] = grantKID
	signed, err := tok.SignedString(priv)
	if err != nil {
		t.Fatal(err)
	}
	return signed
}

// a2aRequest builds the CheckRequest that the gateway sends for an A2A call. A
// header with the value "-" is left out.
func a2aRequest(path, grant string, headers map[string]string) *authv3.CheckRequest {
	h := map[string]string{
		modelcall.HeaderRouteTenant: modelTenant,
		agentcall.HeaderRouteAgent:  a2aAgent,
	}
	for k, v := range headers {
		if v == "-" {
			delete(h, k)
			continue
		}
		h[k] = v
	}
	if grant != "" {
		h[headerCapabilityGrant] = grant
	}
	return &authv3.CheckRequest{Attributes: &authv3.AttributeContext{
		Request: &authv3.AttributeContext_Request{
			Http: &authv3.AttributeContext_HttpRequest{Path: path, Method: http.MethodPost, Headers: h},
		},
	}}
}

func a2aServer(t *testing.T, mock *modelFGA) (*EnvoyAuthzServer, ed25519.PrivateKey) {
	t.Helper()
	srv, priv := buildModelServer(t, mock)
	srv.edgeIDs = idSet([]string{edgeSVID})
	srv.gatewayIDs = idSet([]string{gatewaySVID})
	return srv, priv
}

func allowExecute() map[string]bool {
	return map[string]bool{tupleKey(members, "can_execute", a2aAgentObject): true}
}

func checkA2A(t *testing.T, srv *EnvoyAuthzServer, req *authv3.CheckRequest) codes.Code {
	t.Helper()
	resp, err := srv.Check(peerContext(t, gatewaySVID), req)
	return statusOf(t, resp, err)
}

func TestA2ACall_AllowedSetsTheFourHeadersAndKeepsTheRoute(t *testing.T) {
	t.Parallel()
	mock := &modelFGA{allow: allowExecute()}
	srv, priv := a2aServer(t, mock)
	g := mintA2AGrant(t, priv, modelTenant, "mission-1", "task-1", a2aGrantRoutes)
	// The caller sends forged copies of the trusted headers.
	req := a2aRequest(agentcall.RouteA2A, g, map[string]string{
		modelcall.HeaderTenant: "evil", modelcall.HeaderSubject: "user:evil", modelcall.HeaderMission: "m-evil",
	})
	resp, err := srv.Check(peerContext(t, gatewaySVID), req)
	if got := statusOf(t, resp, err); got != codes.OK {
		t.Fatalf("status = %v, want OK", got)
	}
	for name, want := range map[string]string{
		modelcall.HeaderTenant: modelTenant, modelcall.HeaderSubject: taskGrantSubject,
		modelcall.HeaderMission: "mission-1", modelcall.HeaderTask: "task-1",
	} {
		v, action, ok := headerAction(resp, name)
		if !ok || v != want || action != 2 /* OVERWRITE_IF_EXISTS_OR_ADD */ {
			t.Errorf("%s = %q (%v, set %v), want %q with overwrite", name, v, action, ok, want)
		}
	}
	for _, keep := range []string{agentcall.HeaderRouteAgent, agentcall.HeaderRouteBank, modelcall.HeaderRouteTenant} {
		if removed(resp, keep) {
			t.Errorf("the route header %s must stay", keep)
		}
	}
	// The question is the right to execute the agent, for the tenant members,
	// and the mission gate was asked.
	asked := mock.questionsAbout("can_execute")
	if len(asked) != 1 || asked[0].User != members || asked[0].Object != a2aAgentObject {
		t.Errorf("questions = %+v", asked)
	}
	if gate := mock.questionsAbout("active"); len(gate) != 1 || gate[0].Object != "mission:mission-1" {
		t.Errorf("gate = %+v", gate)
	}
}

func TestA2ACall_ABankNeedsCanSendOnTheBank(t *testing.T) {
	t.Parallel()
	hdr := map[string]string{agentcall.HeaderRouteBank: a2aBank}
	t.Run("can_send on the bank allows", func(t *testing.T) {
		t.Parallel()
		mock := &modelFGA{allow: map[string]bool{tupleKey(members, "can_send", "bank:"+a2aBank): true}}
		srv, priv := a2aServer(t, mock)
		g := mintA2AGrant(t, priv, modelTenant, "mission-1", "task-1", a2aGrantRoutes)
		if got := checkA2A(t, srv, a2aRequest(agentcall.RouteA2A, g, hdr)); got != codes.OK {
			t.Fatalf("status = %v, want OK", got)
		}
		if len(mock.questionsAbout("can_execute")) != 0 {
			t.Error("a bank call asks can_send only")
		}
	})
	t.Run("can_execute on the agent does not allow a bank", func(t *testing.T) {
		t.Parallel()
		mock := &modelFGA{allow: allowExecute()}
		srv, priv := a2aServer(t, mock)
		g := mintA2AGrant(t, priv, modelTenant, "mission-1", "task-1", a2aGrantRoutes)
		if got := checkA2A(t, srv, a2aRequest(agentcall.RouteA2A, g, hdr)); got != codes.PermissionDenied {
			t.Fatalf("status = %v, want PermissionDenied", got)
		}
	})
}

func TestA2ACall_TheInitiatorIsTheFGASubject(t *testing.T) {
	t.Parallel()
	mock := &modelFGA{allow: map[string]bool{tupleKey("user:u1", "can_execute", a2aAgentObject): true}}
	srv, priv := a2aServer(t, mock)
	claims := jwt.MapClaims{
		"iss": grantIssuer, "aud": grantAudience, "sub": taskGrantSubject, "tenant": modelTenant,
		"mission_id": "mission-1", "task_id": "task-1", "jti": "jti-ini-a2a",
		"iat": time.Now().Add(-time.Minute).Unix(), "exp": time.Now().Add(10 * time.Minute).Unix(),
		"allowed_rpcs": a2aGrantRoutes, modelcall.InitiatorClaim: "user:u1",
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims)
	tok.Header["kid"] = grantKID
	g, err := tok.SignedString(priv)
	if err != nil {
		t.Fatal(err)
	}
	if got := checkA2A(t, srv, a2aRequest(agentcall.RouteA2A, g, nil)); got != codes.OK {
		t.Fatalf("status = %v, want OK", got)
	}
}

func TestA2ACall_AgentCardNeedsOnlyTheRightToSeeTheAgent(t *testing.T) {
	t.Parallel()
	cardPath := "/agents/" + a2aAgent + agentcall.CardPath
	t.Run("can_execute is enough, and no bank right is asked", func(t *testing.T) {
		t.Parallel()
		mock := &modelFGA{allow: allowExecute()}
		srv, priv := a2aServer(t, mock)
		g := mintA2AGrant(t, priv, modelTenant, "mission-1", "task-1", a2aGrantRoutes)
		// A card call with a bank header still asks the card relation only.
		req := a2aRequest(cardPath, g, map[string]string{agentcall.HeaderRouteBank: a2aBank})
		if got := checkA2A(t, srv, req); got != codes.OK {
			t.Fatalf("status = %v, want OK", got)
		}
		if len(mock.questionsAbout("can_send")) != 0 {
			t.Error("a card call asks no delegation right")
		}
	})
	t.Run("the path and the route name different agents", func(t *testing.T) {
		t.Parallel()
		mock := &modelFGA{allow: allowExecute()}
		srv, priv := a2aServer(t, mock)
		g := mintA2AGrant(t, priv, modelTenant, "mission-1", "task-1", a2aGrantRoutes)
		req := a2aRequest(cardPath, g, map[string]string{agentcall.HeaderRouteAgent: "other"})
		if got := checkA2A(t, srv, req); got != codes.PermissionDenied {
			t.Fatalf("status = %v, want PermissionDenied", got)
		}
		if len(mock.questions()) != 0 {
			t.Error("FGA was asked before the refusal")
		}
	})
	t.Run("no right to execute the agent", func(t *testing.T) {
		t.Parallel()
		srv, priv := a2aServer(t, &modelFGA{allow: map[string]bool{}})
		g := mintA2AGrant(t, priv, modelTenant, "mission-1", "task-1", a2aGrantRoutes)
		if got := checkA2A(t, srv, a2aRequest(cardPath, g, nil)); got != codes.PermissionDenied {
			t.Fatalf("status = %v, want PermissionDenied", got)
		}
	})
}

// Each refusal has a test, with its counter reason.
func TestA2ACall_Refusals(t *testing.T) {
	t.Parallel()
	good := func(t *testing.T, mock *modelFGA) (*EnvoyAuthzServer, string) {
		srv, priv := a2aServer(t, mock)
		return srv, mintA2AGrant(t, priv, modelTenant, "mission-1", "task-1", a2aGrantRoutes)
	}
	cases := []struct {
		name   string
		reason string
		want   codes.Code
		run    func(t *testing.T) (*EnvoyAuthzServer, *authv3.CheckRequest, *modelFGA)
	}{
		{"no grant", "unauthenticated", codes.Unauthenticated, func(t *testing.T) (*EnvoyAuthzServer, *authv3.CheckRequest, *modelFGA) {
			mock := &modelFGA{allow: allowExecute()}
			srv, _ := good(t, mock)
			return srv, a2aRequest(agentcall.RouteA2A, "", nil), mock
		}},
		{"the grant does not list the A2A route", "", codes.PermissionDenied, func(t *testing.T) (*EnvoyAuthzServer, *authv3.CheckRequest, *modelFGA) {
			mock := &modelFGA{allow: allowExecute()}
			srv, priv := a2aServer(t, mock)
			g := mintA2AGrant(t, priv, modelTenant, "mission-1", "task-1", []string{modelcall.RouteResponses})
			return srv, a2aRequest(agentcall.RouteA2A, g, nil), mock
		}},
		{"the grant tenant is not the route tenant", a2aDenyTenant, codes.PermissionDenied, func(t *testing.T) (*EnvoyAuthzServer, *authv3.CheckRequest, *modelFGA) {
			mock := &modelFGA{allow: allowExecute()}
			srv, g := good(t, mock)
			return srv, a2aRequest(agentcall.RouteA2A, g, map[string]string{modelcall.HeaderRouteTenant: "globex"}), mock
		}},
		{"no route tenant", a2aDenyRoute, codes.PermissionDenied, func(t *testing.T) (*EnvoyAuthzServer, *authv3.CheckRequest, *modelFGA) {
			mock := &modelFGA{allow: allowExecute()}
			srv, g := good(t, mock)
			return srv, a2aRequest(agentcall.RouteA2A, g, map[string]string{modelcall.HeaderRouteTenant: "-"}), mock
		}},
		{"no route agent", a2aDenyRoute, codes.PermissionDenied, func(t *testing.T) (*EnvoyAuthzServer, *authv3.CheckRequest, *modelFGA) {
			mock := &modelFGA{allow: allowExecute()}
			srv, g := good(t, mock)
			return srv, a2aRequest(agentcall.RouteA2A, g, map[string]string{agentcall.HeaderRouteAgent: "-"}), mock
		}},
		{"a repeated route agent", a2aDenyRoute, codes.PermissionDenied, func(t *testing.T) (*EnvoyAuthzServer, *authv3.CheckRequest, *modelFGA) {
			mock := &modelFGA{allow: allowExecute()}
			srv, g := good(t, mock)
			return srv, a2aRequest(agentcall.RouteA2A, g, map[string]string{agentcall.HeaderRouteAgent: "scout,other"}), mock
		}},
		{"a route agent that cannot be an FGA name", a2aDenyRoute, codes.PermissionDenied, func(t *testing.T) (*EnvoyAuthzServer, *authv3.CheckRequest, *modelFGA) {
			mock := &modelFGA{allow: allowExecute()}
			srv, g := good(t, mock)
			return srv, a2aRequest(agentcall.RouteA2A, g, map[string]string{agentcall.HeaderRouteAgent: "x/../y"}), mock
		}},
		{"a route bank that cannot be an FGA name", a2aDenyRoute, codes.PermissionDenied, func(t *testing.T) (*EnvoyAuthzServer, *authv3.CheckRequest, *modelFGA) {
			mock := &modelFGA{allow: allowExecute()}
			srv, g := good(t, mock)
			return srv, a2aRequest(agentcall.RouteA2A, g, map[string]string{agentcall.HeaderRouteBank: "b#member"}), mock
		}},
		{"a path that is not an A2A path", a2aDenyPath, codes.PermissionDenied, func(t *testing.T) (*EnvoyAuthzServer, *authv3.CheckRequest, *modelFGA) {
			mock := &modelFGA{allow: allowExecute()}
			srv, g := good(t, mock)
			return srv, a2aRequest("/a2a/agent", g, nil), mock
		}},
		{"a grant with no mission is refused by the grant check", "", codes.Unauthenticated, func(t *testing.T) (*EnvoyAuthzServer, *authv3.CheckRequest, *modelFGA) {
			mock := &modelFGA{allow: allowExecute()}
			srv, priv := a2aServer(t, mock)
			g := mintA2AGrant(t, priv, modelTenant, "", "", a2aGrantRoutes)
			return srv, a2aRequest(agentcall.RouteA2A, g, nil), mock
		}},
		{"a mission that is not active", a2aDenyMission, codes.PermissionDenied, func(t *testing.T) (*EnvoyAuthzServer, *authv3.CheckRequest, *modelFGA) {
			mock := &modelFGA{allow: allowExecute(), gateClosed: true}
			srv, g := good(t, mock)
			return srv, a2aRequest(agentcall.RouteA2A, g, nil), mock
		}},
		{"FGA is down for the mission gate", a2aDenyFGAUnavailable, codes.Unavailable, func(t *testing.T) (*EnvoyAuthzServer, *authv3.CheckRequest, *modelFGA) {
			mock := &modelFGA{allow: allowExecute(), gateErr: errors.New("fga down")}
			srv, g := good(t, mock)
			return srv, a2aRequest(agentcall.RouteA2A, g, nil), mock
		}},
		{"FGA denies the delegation", a2aDenyFGA, codes.PermissionDenied, func(t *testing.T) (*EnvoyAuthzServer, *authv3.CheckRequest, *modelFGA) {
			mock := &modelFGA{allow: map[string]bool{}}
			srv, g := good(t, mock)
			return srv, a2aRequest(agentcall.RouteA2A, g, nil), mock
		}},
		{"FGA is down for the delegation", a2aDenyFGAUnavailable, codes.Unavailable, func(t *testing.T) (*EnvoyAuthzServer, *authv3.CheckRequest, *modelFGA) {
			mock := &modelFGA{err: errors.New("fga down")}
			srv, g := good(t, mock)
			return srv, a2aRequest(agentcall.RouteA2A, g, nil), mock
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// The counters are global, so the subtests run in sequence.
			srv, req, mock := tc.run(t)
			var before float64
			if tc.reason != "" {
				before = testutil.ToFloat64(extauthzA2ACallDeniedTotal.WithLabelValues(tc.reason))
			}
			resp, err := srv.Check(peerContext(t, gatewaySVID), req)
			if got := statusOf(t, resp, err); got != tc.want {
				t.Fatalf("status = %v, want %v", got, tc.want)
			}
			if resp.GetOkResponse() != nil {
				t.Fatal("a refused call must carry no ok response")
			}
			if tc.reason != "" && testutil.ToFloat64(extauthzA2ACallDeniedTotal.WithLabelValues(tc.reason)) != before+1 {
				t.Errorf("the refusal was not counted with the reason %s", tc.reason)
			}
			// A refusal that comes before the FGA decision asks no relation.
			switch tc.reason {
			case a2aDenyTenant, a2aDenyRoute, a2aDenyPath, "unauthenticated", "":
				if n := len(mock.questionsAbout("can_execute")) + len(mock.questionsAbout("can_send")); n != 0 {
					t.Errorf("FGA was asked %d delegation questions before the refusal", n)
				}
			}
		})
	}
}

// The A2A route is for the gateway identity. The Edge and a stranger cannot
// reach it.
func TestA2ACall_OnlyTheGatewayIdentityMakesIt(t *testing.T) {
	t.Parallel()
	mock := &modelFGA{allow: allowExecute()}
	srv, priv := a2aServer(t, mock)
	g := mintA2AGrant(t, priv, modelTenant, "mission-1", "task-1", a2aGrantRoutes)
	req := a2aRequest(agentcall.RouteA2A, g, nil)
	for name, ctx := range map[string]context.Context{
		"from a stranger": peerContext(t, "spiffe://example.org/platform/other"),
		"with no peer":    context.Background(),
	} {
		resp, err := srv.Check(ctx, req)
		if got := statusOf(t, resp, err); got != codes.PermissionDenied {
			t.Errorf("%s: status = %v, want PermissionDenied", name, got)
		}
	}
	if len(mock.questions()) != 0 {
		t.Error("FGA was asked before the peer refusal")
	}
}
