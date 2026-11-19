// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package server

import (
	"context"
	"strings"

	authv3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"

	"github.com/zeroroot-ai/gibson/internal/server/extauthz/modelcall"
)

var extauthzPeerRefusedTotal = promauto.NewCounterVec(prometheus.CounterOpts{
	Name: "extauthz_peer_refused_total",
	Help: "ext-authz checks refused because the peer identity does not own the route, by reason.",
}, []string{"reason"})

var (
	extauthzEdgeForwardDeniedTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "extauthz_edge_forward_denied_total",
		Help: "Gateway forward calls of the Edge that ext-authz refused, by reason.",
	}, []string{"reason"})
	extauthzEdgeForwardAllowedTotal = promauto.NewCounter(prometheus.CounterOpts{
		Name: "extauthz_edge_forward_allowed_total",
		Help: "Gateway forward calls of the Edge that passed the grant check.",
	})
)

func idSet(ids []string) map[string]struct{} {
	out := make(map[string]struct{}, len(ids))
	for _, id := range ids {
		if id = strings.TrimSpace(id); id != "" {
			out[id] = struct{}{}
		}
	}
	return out
}

// tlsPeerSVID returns the SPIFFE ID of the TLS peer of the call.
func tlsPeerSVID(ctx context.Context) (string, bool) {
	p, ok := peer.FromContext(ctx)
	if !ok {
		return "", false
	}
	info, ok := p.AuthInfo.(credentials.TLSInfo)
	if !ok || len(info.State.PeerCertificates) == 0 {
		return "", false
	}
	for _, u := range info.State.PeerCertificates[0].URIs {
		if u != nil && u.Scheme == "spiffe" {
			return u.String(), true
		}
	}
	return "", false
}

// peerKind decides which kind of caller the TLS peer is. It returns
// gateway=true for the identity of the gateway, and a deny response for a peer
// that is neither the gateway nor the Edge. With no Edge identity configured the
// check is off (tests only): the kind then follows the path, and no response is
// returned. A peer with no SPIFFE ID is refused when the check is on.
func (s *EnvoyAuthzServer) peerKind(ctx context.Context, method string) (gateway bool, deny *authv3.CheckResponse) {
	if len(s.edgeIDs) == 0 {
		return modelcall.IsModelPath(method), nil
	}
	svid, found := tlsPeerSVID(ctx)
	if found {
		if _, ok := s.gatewayIDs[svid]; ok {
			return true, nil
		}
		if _, ok := s.edgeIDs[svid]; ok {
			return false, nil
		}
	}
	extauthzPeerRefusedTotal.WithLabelValues("unknown_peer").Inc()
	s.log.WarnContext(ctx, "ext-authz: the peer is neither the Edge nor the gateway",
		"peer", svid, "method", method)
	return false, denyForbidden()
}
