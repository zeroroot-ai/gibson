// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package api

import (
	"context"
	"strings"

	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
)

// peerSPIFFEID returns the SPIFFE ID of the TLS peer certificate of the
// connection, or "" when the connection has no such certificate. A handler
// that must know which workload dialed it reads this, not an identity header:
// a call through the edge has Envoy as its TLS peer.
func peerSPIFFEID(ctx context.Context) string {
	p, ok := peer.FromContext(ctx)
	if !ok {
		return ""
	}
	tlsInfo, ok := p.AuthInfo.(credentials.TLSInfo)
	if !ok || len(tlsInfo.State.PeerCertificates) == 0 {
		return ""
	}
	for _, u := range tlsInfo.State.PeerCertificates[0].URIs {
		if u != nil && strings.HasPrefix(u.Scheme, "spiffe") {
			return u.String()
		}
	}
	return ""
}
