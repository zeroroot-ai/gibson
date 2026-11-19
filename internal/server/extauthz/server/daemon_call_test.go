// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package server

import (
	"context"
	"crypto/ed25519"
	"errors"
	"sync"
	"testing"
	"time"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	"github.com/golang-jwt/jwt/v5"
	"google.golang.org/grpc/codes"

	"github.com/zeroroot-ai/gibson/internal/server/extauthz/cgjwt"
	"github.com/zeroroot-ai/gibson/internal/server/extauthz/modelcall"
)

// memReplay is an in-memory replay store.
type memReplay struct {
	mu   sync.Mutex
	seen map[string]bool
	err  error
}

func (m *memReplay) Admit(_ context.Context, kid, jti string, _ time.Duration) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.err != nil {
		return false, m.err
	}
	k := kid + "/" + jti
	if m.seen[k] {
		return false, nil
	}
	m.seen[k] = true
	return true, nil
}

// dcClaims is a valid chat grant. A test changes it.
func dcClaims(purpose, route, tenant, ini string) jwt.MapClaims {
	c := jwt.MapClaims{
		"iss": grantIssuer, "aud": grantAudience, "sub": modelcall.DaemonSubject(purpose),
		"tenant": tenant, modelcall.ClaimPurpose: purpose, modelcall.ClaimRoute: route,
		"iat": time.Now().Add(-time.Second).Unix(), "exp": time.Now().Add(50 * time.Second).Unix(),
		"jti": "jti-" + time.Now().Format("150405.000000000"),
	}
	if ini != "" {
		c[modelcall.InitiatorClaim] = ini
	}
	return c
}

func signDC(t *testing.T, priv ed25519.PrivateKey, typ string, c jwt.MapClaims) string {
	t.Helper()
	tok := jwt.NewWithClaims(jwt.SigningMethodEdDSA, c)
	tok.Header["kid"] = grantKID
	tok.Header["typ"] = typ
	s, err := tok.SignedString(priv)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func dcServer(t *testing.T) (*EnvoyAuthzServer, ed25519.PrivateKey, *modelFGA) {
	t.Helper()
	mock := &modelFGA{allow: map[string]bool{
		tupleKey(members, "can_use", modelObj):   true,
		tupleKey("user:u1", "can_use", modelObj): true,
	}}
	srv, priv := buildModelServer(t, mock)
	srv.edgeIDs = idSet([]string{edgeSVID})
	srv.gatewayIDs = idSet([]string{gatewaySVID})
	return srv, priv, mock
}

func gw(t *testing.T) context.Context {
	t.Helper()
	return peerContext(t, gatewaySVID)
}

func TestDaemonCall_ChatAllowedForTheInitiator(t *testing.T) {
	t.Parallel()
	srv, priv, mock := dcServer(t)
	g := signDC(t, priv, modelcall.DaemonCallJWTType, dcClaims("chat", modelcall.RouteResponses, modelTenant, "user:u1"))
	forged := map[string]string{modelcall.HeaderMission: "forged", modelcall.HeaderTask: "forged"}
	req := modelRequest(modelcall.RouteResponses, modelTenant, modelProvider, modelName1, g, forged)
	resp, err := srv.Check(gw(t), req)
	if got := statusOf(t, resp, err); got != codes.OK {
		t.Fatalf("status = %v, want OK", got)
	}
	if v, a, ok := headerAction(resp, modelcall.HeaderSubject); !ok || v != "user:u1" ||
		a != corev3.HeaderValueOption_OVERWRITE_IF_EXISTS_OR_ADD {
		t.Errorf("subject = %q ok=%v", v, ok)
	}
	if v, _, ok := headerAction(resp, modelcall.HeaderTenant); !ok || v != modelTenant {
		t.Errorf("tenant = %q ok=%v", v, ok)
	}
	if !removed(resp, modelcall.HeaderMission) || !removed(resp, modelcall.HeaderTask) {
		t.Error("the mission and task headers were not removed")
	}
	for _, q := range mock.questions() {
		if q.Relation == "active" {
			t.Error("the mission gate was asked for a daemon call")
		}
	}
}

func TestDaemonCall_EmbeddingUsesTheTenantMembersAndTheDaemonSubject(t *testing.T) {
	t.Parallel()
	srv, priv, _ := dcServer(t)
	g := signDC(t, priv, modelcall.DaemonCallJWTType, dcClaims("embedding", modelcall.RouteEmbeddings, modelTenant, ""))
	req := modelRequest(modelcall.RouteEmbeddings, modelTenant, modelProvider, modelName1, g, nil)
	resp, err := srv.Check(gw(t), req)
	if got := statusOf(t, resp, err); got != codes.OK {
		t.Fatalf("status = %v, want OK", got)
	}
	if v, _, _ := headerAction(resp, modelcall.HeaderSubject); v != "component:daemon:embedding" {
		t.Errorf("subject = %q", v)
	}
}

func TestDaemonCall_ModelListNeedsNoModel(t *testing.T) {
	t.Parallel()
	mock := &modelFGA{allow: map[string]bool{tupleKey(members, "can_use", providerObj): true}}
	srv, priv := buildModelServer(t, mock)
	srv.edgeIDs = idSet([]string{edgeSVID})
	srv.gatewayIDs = idSet([]string{gatewaySVID})
	g := signDC(t, priv, modelcall.DaemonCallJWTType, dcClaims("model_list", modelcall.RouteModels, modelTenant, ""))
	req := modelRequest(modelcall.RouteModels, modelTenant, modelProvider, "", g, nil)
	resp, err := srv.Check(gw(t), req)
	if got := statusOf(t, resp, err); got != codes.OK {
		t.Fatalf("status = %v, want OK", got)
	}
}

// Each refusal gives a denial, and FGA is not asked.
func TestDaemonCall_Refusals(t *testing.T) {
	t.Parallel()
	type tc struct {
		name   string
		typ    string
		claims func() jwt.MapClaims
		path   string
		tenant string // route tenant header
		ctx    func(*testing.T) context.Context
	}
	ok := func() jwt.MapClaims {
		return dcClaims("chat", modelcall.RouteResponses, modelTenant, "user:u1")
	}
	with := func(f func(jwt.MapClaims)) func() jwt.MapClaims {
		return func() jwt.MapClaims { c := ok(); f(c); return c }
	}
	cases := []tc{
		{name: "the route header names another tenant", typ: modelcall.DaemonCallJWTType, claims: ok,
			path: modelcall.RouteResponses, tenant: "tenant-b"},
		{name: "another path than the grant route", typ: modelcall.DaemonCallJWTType, claims: ok,
			path: modelcall.RouteEmbeddings},
		{name: "a mission claim", typ: modelcall.DaemonCallJWTType,
			claims: with(func(c jwt.MapClaims) { c["mission_id"] = "m1" }), path: modelcall.RouteResponses},
		{name: "a task grant with the daemon type", typ: modelcall.DaemonCallJWTType,
			claims: with(func(c jwt.MapClaims) {
				c["mission_id"], c["task_id"] = "m1", "t1"
				c["allowed_rpcs"] = []string{modelcall.RouteResponses}
			}), path: modelcall.RouteResponses},
		{name: "a purpose outside the set", typ: modelcall.DaemonCallJWTType,
			claims: with(func(c jwt.MapClaims) { c[modelcall.ClaimPurpose] = "admin" }), path: modelcall.RouteResponses},
		{name: "a route that the purpose does not own", typ: modelcall.DaemonCallJWTType,
			claims: with(func(c jwt.MapClaims) { c[modelcall.ClaimRoute] = modelcall.RouteModels }), path: modelcall.RouteModels},
		{name: "chat with no initiator", typ: modelcall.DaemonCallJWTType,
			claims: with(func(c jwt.MapClaims) { delete(c, modelcall.InitiatorClaim) }), path: modelcall.RouteResponses},
		{name: "a lifetime over 60 seconds", typ: modelcall.DaemonCallJWTType,
			claims: with(func(c jwt.MapClaims) { c["exp"] = time.Now().Add(5 * time.Minute).Unix() }),
			path:   modelcall.RouteResponses},
		{name: "an expired grant", typ: modelcall.DaemonCallJWTType,
			claims: with(func(c jwt.MapClaims) {
				c["iat"], c["exp"] = time.Now().Add(-2*time.Minute).Unix(), time.Now().Add(-time.Minute).Unix()
			}), path: modelcall.RouteResponses},
		{name: "a model path from the Edge", typ: modelcall.DaemonCallJWTType, claims: ok,
			path: modelcall.RouteResponses, ctx: func(t *testing.T) context.Context {
				t.Helper()
				return peerContext(t, edgeSVID)
			}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			srv, priv, mock := dcServer(t)
			g := signDC(t, priv, c.typ, c.claims())
			tenant := c.tenant
			if tenant == "" {
				tenant = modelTenant
			}
			req := modelRequest(c.path, tenant, modelProvider, modelName1, g, nil)
			ctx := gw(t)
			if c.ctx != nil {
				ctx = c.ctx(t)
			}
			resp, err := srv.Check(ctx, req)
			if got := statusOf(t, resp, err); got == codes.OK {
				t.Fatal("the call was allowed")
			}
			if resp.GetOkResponse() != nil {
				t.Error("a refusal carries an OK body")
			}
			if len(mock.questions()) != 0 {
				t.Errorf("FGA was asked %d times", len(mock.questions()))
			}
		})
	}
}

// A grant is accepted one time.
func TestDaemonCall_ReplayIsRefused(t *testing.T) {
	t.Parallel()
	srv, priv, _ := dcServer(t)
	g := signDC(t, priv, modelcall.DaemonCallJWTType, dcClaims("chat", modelcall.RouteResponses, modelTenant, "user:u1"))
	req := modelRequest(modelcall.RouteResponses, modelTenant, modelProvider, modelName1, g, nil)
	if resp, err := srv.Check(gw(t), req); statusOf(t, resp, err) != codes.OK {
		t.Fatal("the first call was refused")
	}
	if resp, err := srv.Check(gw(t), req); statusOf(t, resp, err) == codes.OK {
		t.Fatal("the second use of one grant was allowed")
	}
}

// When the replay store does not answer, the call is refused with Unavailable.
func TestDaemonCall_ReplayStoreDownFailsClosed(t *testing.T) {
	t.Parallel()
	mock := &modelFGA{allow: map[string]bool{tupleKey("user:u1", "can_use", modelObj): true}}
	srv, priv := buildModelServerWithReplay(t, mock, &memReplay{seen: map[string]bool{}, err: errTestStore})
	srv.edgeIDs = idSet([]string{edgeSVID})
	srv.gatewayIDs = idSet([]string{gatewaySVID})
	g := signDC(t, priv, modelcall.DaemonCallJWTType, dcClaims("chat", modelcall.RouteResponses, modelTenant, "user:u1"))
	req := modelRequest(modelcall.RouteResponses, modelTenant, modelProvider, modelName1, g, nil)
	resp, err := srv.Check(gw(t), req)
	if got := statusOf(t, resp, err); got != codes.Unavailable {
		t.Fatalf("status = %v, want Unavailable", got)
	}
}

// A task grant is never read as a daemon call grant: it has no daemon type, so
// it takes the task grant path and keeps its own rules (a model route in its
// allowed methods).
func TestDaemonCall_ATaskGrantStaysATaskGrant(t *testing.T) {
	t.Parallel()
	srv, priv, _ := dcServer(t)
	g := mintModelGrant(t, priv, modelTenant, []string{modelcall.RouteResponses})
	if cgjwtIsDaemon(g) {
		t.Fatal("a task grant reads as a daemon call grant")
	}
	req := modelRequest(modelcall.RouteResponses, modelTenant, modelProvider, modelName1, g, nil)
	resp, err := srv.Check(gw(t), req)
	if got := statusOf(t, resp, err); got != codes.OK {
		t.Fatalf("status = %v, want OK for a task grant", got)
	}
	if v, _, _ := headerAction(resp, modelcall.HeaderMission); v != "mission-1" {
		t.Errorf("mission header = %q, want the task grant mission", v)
	}
}

// A daemon call grant on an Edge route (a gRPC method) is not accepted as a task
// grant, a component token, or anything else.
func TestDaemonCall_OnAnEdgeRouteIsNotAccepted(t *testing.T) {
	t.Parallel()
	srv, priv, _ := dcServer(t)
	g := signDC(t, priv, modelcall.DaemonCallJWTType, dcClaims("chat", modelcall.RouteResponses, modelTenant, "user:u1"))
	resp, err := srv.Check(peerContext(t, edgeSVID), soleGrantRequest(g))
	if got := statusOf(t, resp, err); got == codes.OK {
		t.Fatal("a daemon call grant passed on an Edge route")
	}
}

var errTestStore = errors.New("store down")

func cgjwtIsDaemon(token string) bool { return cgjwt.IsDaemonCallToken(token) }
