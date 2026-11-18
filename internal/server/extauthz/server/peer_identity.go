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
)

var extauthzPeerRefusedTotal = promauto.NewCounterVec(prometheus.CounterOpts{
	Name: "extauthz_peer_refused_total",
	Help: "ext-authz checks refused because the peer identity does not own the route, by reason.",
}, []string{"reason"})

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

// peerRefusal returns a deny response when the peer does not own the route, and
// nil when it does or when the check is off. A gateway call needs the identity
// of the gateway. Every other call needs the identity of the Edge. A peer with no
// SPIFFE ID is refused when the check is on.
func (s *EnvoyAuthzServer) peerRefusal(ctx context.Context, gatewayCall bool, method string) *authv3.CheckResponse {
	if len(s.edgeIDs) == 0 {
		return nil
	}
	want, reason := s.edgeIDs, "edge_route_from_other_peer"
	if gatewayCall {
		want, reason = s.gatewayIDs, "gateway_call_from_other_peer"
	}
	svid, found := tlsPeerSVID(ctx)
	if _, ok := want[svid]; found && ok {
		return nil
	}
	extauthzPeerRefusedTotal.WithLabelValues(reason).Inc()
	s.log.WarnContext(ctx, "ext-authz: the peer does not own the route",
		"reason", reason, "peer", svid, "method", method, "gateway_call", gatewayCall)
	return denyForbidden()
}
