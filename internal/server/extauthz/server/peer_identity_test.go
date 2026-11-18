// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package server

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net/url"
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"

	"github.com/zeroroot-ai/gibson/internal/server/extauthz/fga"
	"github.com/zeroroot-ai/gibson/internal/server/extauthz/modelcall"
)

const (
	edgeSVID    = "spiffe://example.org/platform/envoy"
	gatewaySVID = "spiffe://example.org/platform/agentgateway"
)

func peerContext(t *testing.T, svid string) context.Context {
	t.Helper()
	cert := &x509.Certificate{}
	if svid != "" {
		u, err := url.Parse(svid)
		if err != nil {
			t.Fatal(err)
		}
		cert.URIs = []*url.URL{u}
	}
	return peer.NewContext(context.Background(), &peer.Peer{
		AuthInfo: credentials.TLSInfo{State: tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}}},
	})
}

// buildPeerServer is a model server with the peer check on.
func buildPeerServer(t *testing.T, gateways []string) (*EnvoyAuthzServer, string, *modelFGA) {
	t.Helper()
	mock := &modelFGA{allow: map[string]bool{tupleKey(members, "can_use", modelObj): true}}
	srv, priv := buildModelServer(t, mock)
	srv.edgeIDs = idSet([]string{edgeSVID})
	srv.gatewayIDs = idSet(gateways)
	return srv, mintModelGrant(t, priv, modelTenant, []string{modelcall.RouteResponses}), mock
}

// A model call is accepted from the gateway identity only.
func TestPeer_ModelCallNeedsTheGatewayIdentity(t *testing.T) {
	t.Parallel()
	srv, grant, mock := buildPeerServer(t, []string{gatewaySVID})
	req := modelRequest(modelcall.RouteResponses, modelTenant, modelProvider, modelName1, grant, nil)

	resp, err := srv.Check(peerContext(t, gatewaySVID), req)
	if got := statusOf(t, resp, err); got != codes.OK {
		t.Fatalf("from the gateway: status = %v, want OK", got)
	}
	for name, ctx := range map[string]context.Context{
		"from the Edge":                     peerContext(t, edgeSVID),
		"from a stranger":                   peerContext(t, "spiffe://example.org/platform/other"),
		"with no peer":                      context.Background(),
		"with a peer that has no SPIFFE ID": peerContext(t, ""),
	} {
		before := len(mock.questions())
		resp, err := srv.Check(ctx, req)
		if got := statusOf(t, resp, err); got != codes.PermissionDenied {
			t.Errorf("%s: status = %v, want PermissionDenied", name, got)
		}
		if len(mock.questions()) != before {
			t.Errorf("%s: FGA was asked before the refusal", name)
		}
	}
}

// An A2A call of the agent gateway has the same rule.
func TestPeer_AnA2ACallNeedsTheGatewayIdentity(t *testing.T) {
	t.Parallel()
	srv, _, _ := buildPeerServer(t, []string{gatewaySVID})
	req := modelRequest("/a2a/agent", "", "", "", "", nil)
	req.Attributes.ContextExtensions = map[string]string{modelcall.ExtAgent: "analyst"}
	resp, err := srv.Check(peerContext(t, edgeSVID), req)
	if got := statusOf(t, resp, err); got != codes.PermissionDenied {
		t.Fatalf("A2A call from the Edge: status = %v, want PermissionDenied", got)
	}
}

// An Edge route is accepted from the Edge identity only. The gateway identity
// gets a refusal for it, and so does no peer.
func TestPeer_EdgeRouteNeedsTheEdgeIdentity(t *testing.T) {
	t.Parallel()
	srv, _, _ := buildPeerServer(t, []string{gatewaySVID})
	edgeRoute := soleGrantRequest("no-grant") // a call with no gateway extension

	// From the Edge, the peer check passes and the call reaches the credential
	// check, which refuses the bad grant. That is not a peer refusal.
	before := peerRefusals(t)
	if resp, err := srv.Check(peerContext(t, edgeSVID), edgeRoute); err != nil || resp == nil {
		t.Fatalf("Edge: %v", err)
	}
	if peerRefusals(t) != before {
		t.Error("the Edge was refused as a peer")
	}
	resp, err := srv.Check(peerContext(t, gatewaySVID), edgeRoute)
	if got := statusOf(t, resp, err); got != codes.PermissionDenied {
		t.Errorf("an Edge route from the gateway: status = %v, want PermissionDenied", got)
	}
	if peerRefusals(t) != before+1 {
		t.Error("the refusal was not counted as a peer refusal")
	}
}

// With no gateway identity configured, no gateway call is accepted.
func TestPeer_NoGatewayIdentityRefusesEachGatewayCall(t *testing.T) {
	t.Parallel()
	srv, grant, _ := buildPeerServer(t, nil)
	req := modelRequest(modelcall.RouteResponses, modelTenant, modelProvider, modelName1, grant, nil)
	for _, svid := range []string{gatewaySVID, edgeSVID} {
		resp, err := srv.Check(peerContext(t, svid), req)
		if got := statusOf(t, resp, err); got != codes.PermissionDenied {
			t.Errorf("peer %s: status = %v, want PermissionDenied", svid, got)
		}
	}
}

// The check is off when no Edge identity is set (tests only).
func TestPeer_OffWithoutAnEdgeIdentity(t *testing.T) {
	t.Parallel()
	srv, grant, _ := buildPeerServer(t, nil)
	srv.edgeIDs = nil
	resp, err := srv.Check(context.Background(),
		modelRequest(modelcall.RouteResponses, modelTenant, modelProvider, modelName1, grant, nil))
	if got := statusOf(t, resp, err); got != codes.OK {
		t.Fatalf("status = %v, want OK with the check off", got)
	}
}

func peerRefusals(t *testing.T) float64 {
	t.Helper()
	return testutil.ToFloat64(extauthzPeerRefusedTotal.WithLabelValues("edge_route_from_other_peer"))
}

var _ fga.FGAClient = (*modelFGA)(nil)
